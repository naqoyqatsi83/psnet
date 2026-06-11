use std::collections::HashMap;
use std::fs;
use crate::types::{Connection, ConnProto, TcpState};

/// Parse IP and port from hex format like "0100007F:0019"
fn parse_ip_port(s: &str) -> Option<(std::net::IpAddr, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 { return None; }
    let hex_ip = parts[0];
    let hex_port = parts[1];
    let ip_bytes = hex_ip.as_bytes();
    if ip_bytes.len() != 8 { return None; }
    let mut ip_u32 = 0u32;
    for i in 0..8 {
        let nibble = u8::from_str_radix(&hex_ip[i..i+1], 16).ok()? as u32;
        ip_u32 = (ip_u32 << 4) | nibble;
    }
    let port = u16::from_str_radix(hex_port, 16).ok()?;
    let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::from(ip_u32));
    Some((ip, port))
}

/// Parse TCP state hex code to TcpState
fn parse_tcp_state(state_str: &str) -> Option<TcpState> {
    let code = u8::from_str_radix(state_str, 16).unwrap_or(0);
    match code {
        1 => Some(TcpState::Established),
        2 => Some(TcpState::SynSent),
        3 => Some(TcpState::SynReceived),
        4 => Some(TcpState::FinWait1),
        5 => Some(TcpState::FinWait2),
        6 => Some(TcpState::TimeWait),
        7 => Some(TcpState::Closed),
        8 => Some(TcpState::CloseWait),
        9 => Some(TcpState::LastAck),
        10 => Some(TcpState::Listen),
        11 => Some(TcpState::Closing),
        _ => Some(TcpState::Unknown(code as u32)),
    }
}

/// Build a map from socket inode -> (pid, process_name)
fn build_inode_map() -> HashMap<u32, (u32, String)> {
    let mut map = HashMap::new();
    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };
    for entry in proc_dir {
        let entry = match entry { Ok(e) => e, Err(_) => continue };
        let path = entry.path();
        let dir_name = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name,
            None => continue,
        };
        let pid: u32 = match dir_name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        // Read process name from /proc/[pid]/comm
        let comm_path = format!("/proc/{}/comm", pid);
        let proc_name = match fs::read_to_string(&comm_path) {
            Ok(name) => name.trim().to_string(),
            Err(_) => continue,
        };
        // Scan file descriptors for socket inodes
        let fd_dir_path = format!("/proc/{}/fd", pid);
        let fd_dir = match fs::read_dir(&fd_dir_path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        for fd_entry in fd_dir {
            let fd_entry = match fd_entry { Ok(e) => e, Err(_) => continue };
            let link_path = match fd_entry.path().read_link() {
                Ok(lp) => lp,
                Err(_) => continue,
            };
            if let Some(link_str) = link_path.to_str() {
                if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                    let inode_str = &link_str[8..link_str.len()-1];
                    if let Ok(inode) = inode_str.parse::<u32>() {
                        map.entry(inode).or_insert((pid, proc_name.clone()));
                    }
                }
            }
        }
    }
    map
}

/// Parse a /proc/net file (tcp, tcp6, udp, udp6) into connections
fn read_proc_net_file(path: &str, proto: ConnProto, include_ipv6: bool, inode_map: &HashMap<u32, (u32, String)>) -> Vec<Connection> {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    let mut connections = Vec::new();
    let mut lines = content.lines();
    // Skip header line
    if lines.next().is_none() { return connections; }
    for line in lines {
        // /proc/net/tcp format:
        // sl local_address rem_address st tx_queue:rx_queue tr:tm->when retrnsmt  uid  timeout inode
        // fields: 0:skip, 1:local, 2:remote, 3:state, 4-6:skip, 7:uid, 8:timeout, 9:inode, 10-12:skip
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 { continue; }
        let local_addr_port = fields[1];
        let remote_addr_port = fields[2];
        let (local_ip, local_port) = match parse_ip_port(local_addr_port) {
            Some(p) => p,
            None => continue,
        };
        let (remote_ip, remote_port) = match parse_ip_port(remote_addr_port) {
            Some(p) => p,
            None => (std::net::IpAddr::from(std::net::Ipv4Addr::UNSPECIFIED), 0),
        };
        // Clear remote for listening sockets: local_port nonzero but remote port 0
        let (remote_addr, remote_port_opt) = if remote_port == 0 {
            (None, None)
        } else {
            (Some(remote_ip), Some(remote_port))
        };
        // Filter IPv6 if not requested
        if !include_ipv6 {
            if local_ip.is_ipv6() { continue; }
        }
        let state = if proto == ConnProto::Tcp {
            parse_tcp_state(fields[3]).or(Some(crate::types::TcpState::Unknown(0)))
        } else {
            None
        };
        let inode: u32 = fields[9].parse().unwrap_or(0);
        let (pid, proc_name) = inode_map.get(&inode)
            .map(|&(p, ref n)| (p, n.clone()))
            .unwrap_or((0, "?".to_string()));

        connections.push(Connection {
            proto,
            local_addr: local_ip,
            local_port,
            remote_addr,
            remote_port: remote_port_opt,
            state,
            pid,
            process_name: proc_name,
            dns_hostname: None,
        });
    }
    connections
}

pub fn fetch_connections(_pid_cache: &mut HashMap<u32, String>) -> Vec<Connection> {
    // Build inode map once, reuse for all 4 proc/net files
    let inode_map = build_inode_map();
    let mut all = Vec::new();
    // TCP IPv4
    all.extend(read_proc_net_file("/proc/net/tcp", ConnProto::Tcp, false, &inode_map));
    // TCP IPv6
    all.extend(read_proc_net_file("/proc/net/tcp6", ConnProto::Tcp, true, &inode_map));
    // UDP IPv4
    all.extend(read_proc_net_file("/proc/net/udp", ConnProto::Udp, false, &inode_map));
    // UDP IPv6
    all.extend(read_proc_net_file("/proc/net/udp6", ConnProto::Udp, true, &inode_map));
    all
}

/// Get full executable path for a PID.
pub fn get_process_full_path(pid: u32) -> Option<String> {
    let exe = format!("/proc/{}/exe", pid);
    fs::read_link(&exe)
        .ok()
        .and_then(|p| p.to_str().map(String::from))
}
