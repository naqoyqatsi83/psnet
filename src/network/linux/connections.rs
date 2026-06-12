use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use crate::types::{Connection, ConnProto, TcpState};

/// Connection tuple used to look up process info from `ss -tunp` output.
type ConnTuple = (ConnProto, IpAddr, u16, IpAddr, u16);

/// Parse IP and port from hex format like "0100007F:0019"
fn parse_ip_port(s: &str) -> Option<(IpAddr, u16)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 { return None; }
    let hex_ip = parts[0];
    let hex_port = parts[1];
    let ip_bytes = hex_ip.as_bytes();
    if ip_bytes.len() != 8 { return None; }
    // /proc/net/tcp stores addresses as hex in little-endian byte order,
    // e.g. 127.0.0.1 → "0100007F" (bytes 01,00,00,7F → reversed → 7F,00,00,01)
    let b0 = u8::from_str_radix(&hex_ip[0..2], 16).ok()?;
    let b1 = u8::from_str_radix(&hex_ip[2..4], 16).ok()?;
    let b2 = u8::from_str_radix(&hex_ip[4..6], 16).ok()?;
    let b3 = u8::from_str_radix(&hex_ip[6..8], 16).ok()?;
    let ip = IpAddr::V4(Ipv4Addr::new(b3, b2, b1, b0));
    let port = u16::from_str_radix(hex_port, 16).ok()?;
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

/// Build a map from socket inode -> (pid, process_name).
///
/// Also returns a secondary UID→username map for use when inode
/// resolution fails (process owned by a different user).
fn build_inode_maps() -> (HashMap<u32, (u32, String)>, HashMap<u32, String>) {
    let mut inode_map = HashMap::new();
    let mut uid_name_map: HashMap<u32, String> = HashMap::new();
    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return (inode_map, uid_name_map),
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
        // Read UID from /proc/[pid]/status (world-readable)
        let uid = read_uid_for_pid(pid);
        if let Some(uid) = uid {
            uid_name_map.entry(uid).or_insert_with(|| proc_name.clone());
        }
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
                        inode_map.entry(inode).or_insert((pid, proc_name.clone()));
                    }
                }
            }
        }
    }
    (inode_map, uid_name_map)
}

/// Read the real UID from /proc/[pid]/status.
fn read_uid_for_pid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if line.starts_with("Uid:") {
            return line.split_whitespace().nth(1)?.parse().ok();
        }
    }
    None
}

/// Resolve a UID to a human-readable username via /etc/passwd.
fn uid_to_username(uid: u32) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    for line in passwd.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            if let Ok(u) = parts[2].parse::<u32>() {
                if u == uid {
                    return Some(parts[0].to_string());
                }
            }
        }
    }
    None
}

/// Build a process map from `ss -tunp` output, keyed by connection tuple.
///
/// Falls back to `sudo -n ss -tunp` when the normal `ss` invocation doesn't
/// include the `users:` process info column (happens when running without
/// `CAP_NET_ADMIN` on some distributions).
fn build_ss_map() -> HashMap<ConnTuple, (u32, String)> {
    // Try normal ss first.
    let mut text = String::new();
    if let Ok(o) = std::process::Command::new("ss")
        .args(["-tunp"])
        .output()
    {
        if o.status.success() {
            let t = String::from_utf8_lossy(&o.stdout).to_string();
            if t.contains("users:") {
                text = t;
            }
        }
    }

    // If normal ss didn't show process info, try sudo -n ss -tunp.
    if text.is_empty() {
        if let Ok(o) = std::process::Command::new("sudo")
            .args(["-n", "ss", "-tunp"])
            .output()
        {
            if o.status.success() {
                let t = String::from_utf8_lossy(&o.stdout).to_string();
                if t.contains("users:") {
                    text = t;
                }
            }
        }
    }

    let mut map = HashMap::new();

    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 { continue; }

        let netid = fields[0];
        let state_str = fields[1];
        let local = fields[4];
        let peer = fields[5];

        let proto = match netid {
            "tcp" | "tcp6" => ConnProto::Tcp,
            "udp" | "udp6" => ConnProto::Udp,
            _ => continue,
        };

        let Some((local_ip, local_port)) = parse_ss_addr_port(local) else { continue };
        let Some((remote_ip, remote_port)) = parse_ss_addr_port(peer) else { continue };

        // Skip listening sockets — they have no meaningful remote and aren't
        // useful for the connections tab (already handled by the listen filter).
        if remote_port == 0 && fields.len() > 1 {
            let state_upper = state_str.to_uppercase();
            if state_upper == "LISTEN" { continue; }
        }

        // Parse process info from the Process column (field 6, may be absent)
        let proc_field = if fields.len() > 6 { fields[6] } else { "" };
        if proc_field.is_empty() || !proc_field.starts_with("users:") {
            continue;
        }

        if let Some((name, pid)) = parse_ss_process_field(proc_field) {
            let key = (proto, local_ip, local_port, remote_ip, remote_port);
            map.entry(key).or_insert((pid, name));
        }
    }

    map
}

/// Parse an ss address:port field like "192.168.1.1:443" or "[::1]:53".
/// Handles "*" as port 0 (used by ss for wildcard peer ports).
fn parse_ss_addr_port(s: &str) -> Option<(IpAddr, u16)> {
    if s.starts_with('[') {
        // IPv6: [addr]:port or [addr]:*
        let closing_bracket = s.rfind(']')?;
        let ip_str = &s[1..closing_bracket];
        let port_str = s.get(closing_bracket + 2..)?;
        let ip: IpAddr = ip_str.parse().ok()?;
        let port: u16 = if port_str == "*" { 0 } else { port_str.parse().ok()? };
        Some((ip, port))
    } else {
        // IPv4: addr:port or addr:*
        let colon = s.rfind(':')?;
        let ip_str = &s[..colon];
        let port_str = &s[colon + 1..];
        let ip: IpAddr = ip_str.parse().ok()?;
        let port: u16 = if port_str == "*" { 0 } else { port_str.parse().ok()? };
        Some((ip, port))
    }
}

/// Parse the ss process field: `users:(("name",pid=N,fd=N))`.
/// Extracts the first process name and pid found.
fn parse_ss_process_field(field: &str) -> Option<(String, u32)> {
    let name_start = field.find('"')?;
    let rest = &field[name_start + 1..];
    let name_end = rest.find('"')?;
    let name = rest[..name_end].to_string();

    let pid_prefix = "pid=";
    let pid_start = field.find(pid_prefix)?;
    let pid_str = &field[pid_start + pid_prefix.len()..];
    let pid_end = pid_str.find(|c: char| !c.is_ascii_digit()).unwrap_or(pid_str.len());
    let pid: u32 = pid_str[..pid_end].parse().ok()?;

    Some((name, pid))
}

/// Parse a /proc/net file (tcp, tcp6, udp, udp6) into connections
fn read_proc_net_file(
    path: &str,
    proto: ConnProto,
    include_ipv6: bool,
    inode_map: &HashMap<u32, (u32, String)>,
    ss_map: &HashMap<ConnTuple, (u32, String)>,
    uid_name_map: &HashMap<u32, String>,
) -> Vec<Connection> {
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
            None => (IpAddr::from(Ipv4Addr::UNSPECIFIED), 0),
        };
        // Clear remote for listening sockets
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
            parse_tcp_state(fields[3]).or(Some(TcpState::Unknown(0)))
        } else {
            None
        };
        let uid: u32 = fields[7].parse().unwrap_or(0);
        let inode: u32 = fields[9].parse().unwrap_or(0);

        // Try inode map first, then fall back to ss-derived connection tuple map.
        // When both fail, use UID-based process name lookup as last resort
        // (works for processes owned by other users).
        let (pid, proc_name) = inode_map.get(&inode)
            .map(|&(p, ref n)| (p, n.clone()))
            .or_else(|| {
                let ss_key = (proto, local_ip, local_port, remote_ip, remote_port);
                ss_map.get(&ss_key).map(|&(p, ref n)| (p, n.clone()))
            })
            .unwrap_or_else(|| {
                // Fallback: show UID-based identifier
                let uname = uid_to_username(uid)
                    .unwrap_or_default();
                if uname.is_empty() {
                    match uid_name_map.get(&uid) {
                        Some(name) => (0, format!("{} [UID {}]", name, uid)),
                        None => (0, format!("[UID {}]", uid)),
                    }
                } else {
                    (0, format!("{} [UID {}]", uname, uid))
                }
            });

        connections.push(Connection {
            proto,
            local_addr: local_ip,
            local_port,
            remote_addr,
            remote_port: remote_port_opt,
            state,
            pid,
            process_name: proc_name,
            uid,
            dns_hostname: None,
        });
    }
    connections
}

pub fn fetch_connections(_pid_cache: &mut HashMap<u32, String>) -> Vec<Connection> {
    let (inode_map, uid_name_map) = build_inode_maps();
    let ss_map = build_ss_map();
    let mut all = Vec::new();
    all.extend(read_proc_net_file("/proc/net/tcp", ConnProto::Tcp, false, &inode_map, &ss_map, &uid_name_map));
    all.extend(read_proc_net_file("/proc/net/tcp6", ConnProto::Tcp, true, &inode_map, &ss_map, &uid_name_map));
    all.extend(read_proc_net_file("/proc/net/udp", ConnProto::Udp, false, &inode_map, &ss_map, &uid_name_map));
    all.extend(read_proc_net_file("/proc/net/udp6", ConnProto::Udp, true, &inode_map, &ss_map, &uid_name_map));
    all
}

/// Get full executable path for a PID.
pub fn get_process_full_path(pid: u32) -> Option<String> {
    let exe = format!("/proc/{}/exe", pid);
    fs::read_link(&exe)
        .ok()
        .and_then(|p| p.to_str().map(String::from))
}

/// Read /proc/[pid]/cmdline, replacing NUL separators with spaces.
pub fn get_cmdline(pid: u32) -> String {
    let path = format!("/proc/{}/cmdline", pid);
    match fs::read_to_string(&path) {
        Ok(s) => s.replace('\0', " ").trim().to_string(),
        Err(_) => String::new(),
    }
}
