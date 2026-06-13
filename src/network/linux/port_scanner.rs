//! TCP connect port scanner for LAN devices.
//! Runs in a background thread, reports progress and results via a shared queue.

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct PortScanResult {
    pub ports: Vec<(u16, String)>,
    pub duration_ms: u64,
}

#[derive(Clone, Debug)]
pub enum PortScanEvent {
    Progress { scanned: usize, total: usize },
    MultiProgress { current: usize, total: usize },
    Complete(PortScanResult),
}

const PORT_TIMEOUT_MS: u64 = 150;
const CONCURRENCY: usize = 200;
const HOST_CONCURRENCY: usize = 5;

pub const COMMON_PORTS: &[(u16, &str)] = &[
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (80, "HTTP"), (110, "POP3"), (111, "SunRPC"),
    (135, "MSRPC"), (139, "NetBIOS"), (143, "IMAP"),
    (389, "LDAP"), (443, "HTTPS"), (445, "SMB"), (993, "IMAPS"),
    (995, "POP3S"), (1433, "MSSQL"), (1521, "Oracle-DB"),
    (2049, "NFS"), (3306, "MySQL"), (3389, "RDP"),
    (5432, "PostgreSQL"), (5900, "VNC"), (5901, "VNC-1"),
    (5985, "WinRM"), (6379, "Redis"), (8080, "HTTP-Alt"),
    (8443, "HTTPS-Alt"), (9090, "Prometheus"), (9100, "NodeExporter"),
    (9200, "Elasticsearch"), (11211, "Memcached"), (27017, "MongoDB"),
];

/// Scan a list of IPs in parallel batches of HOST_CONCURRENCY.
/// Emits MultiProgress for overall status and individual Complete per IP.
pub fn start_multi_scan(
    ips: Vec<IpAddr>,
    full: bool,
    events: Arc<Mutex<VecDeque<(IpAddr, PortScanEvent)>>>,
    cancel: Arc<AtomicBool>,
) {
    let ports: Arc<Vec<u16>> = Arc::new(if full {
        (1..=65535).collect()
    } else {
        COMMON_PORTS.iter().map(|(p, _)| *p).collect()
    });
    let total = ips.len();
    std::thread::spawn(move || {
        for batch_start in (0..total).step_by(HOST_CONCURRENCY) {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            let batch_end = (batch_start + HOST_CONCURRENCY).min(total);
            std::thread::scope(|s| {
                for i in batch_start..batch_end {
                    let ip = ips[i];
                    let events = events.clone();
                    let cancel = cancel.clone();
                    let ports = Arc::clone(&ports);
                    s.spawn(move || {
                        if let Ok(mut q) = events.lock() {
                            q.push_back((ip, PortScanEvent::MultiProgress {
                                current: i + 1,
                                total,
                            }));
                        }
                        do_scan(ip, &ports, events, cancel);
                    });
                }
            });
        }
    });
}

/// Start a quick scan of common ports on the given IP.
pub fn start_common_scan(
    ip: IpAddr,
    events: Arc<Mutex<VecDeque<(IpAddr, PortScanEvent)>>>,
    cancel: Arc<AtomicBool>,
) {
    let ports: Vec<u16> = COMMON_PORTS.iter().map(|(p, _)| *p).collect();
    std::thread::spawn(move || {
        do_scan(ip, &ports, events, cancel);
    });
}

/// Start a full scan of all 1-65535 ports on the given IP.
pub fn start_full_scan(
    ip: IpAddr,
    events: Arc<Mutex<VecDeque<(IpAddr, PortScanEvent)>>>,
    cancel: Arc<AtomicBool>,
) {
    let ports: Vec<u16> = (1..=65535).collect();
    std::thread::spawn(move || {
        do_scan(ip, &ports, events, cancel);
    });
}

fn do_scan(
    ip: IpAddr,
    ports: &[u16],
    events: Arc<Mutex<VecDeque<(IpAddr, PortScanEvent)>>>,
    cancel: Arc<AtomicBool>,
) {
    let start = Instant::now();
    let found: Arc<Mutex<Vec<u16>>> = Arc::new(Mutex::new(Vec::new()));
    let total = ports.len();
    let mut scanned = 0usize;
    let mut last_pct = 0usize;

    for chunk in ports.chunks(CONCURRENCY) {
        if cancel.load(Ordering::Relaxed) {
            return;
        }

        std::thread::scope(|s| {
            for &port in chunk {
                let f = found.clone();
                s.spawn(move || {
                    let addr = SocketAddr::new(ip, port);
                    if TcpStream::connect_timeout(&addr, Duration::from_millis(PORT_TIMEOUT_MS)).is_ok() {
                        if let Ok(mut guard) = f.lock() {
                            guard.push(port);
                        }
                    }
                });
            }
        });

        scanned += chunk.len();
        let pct = (scanned * 100) / total;
        if pct >= last_pct + 5 {
            last_pct = pct;
            if let Ok(mut q) = events.lock() {
                q.push_back((ip, PortScanEvent::Progress { scanned, total }));
            }
        }
    }

    let duration = start.elapsed();
    let ports = found.lock().map(|f| f.clone()).unwrap_or_default();
    let mut port_list: Vec<(u16, String)> = ports
        .into_iter()
        .map(|p| (p, service_name(p).unwrap_or_default()))
        .collect();
    port_list.sort_by_key(|(p, _)| *p);

    if let Ok(mut q) = events.lock() {
        q.push_back((
            ip,
            PortScanEvent::Complete(PortScanResult {
                ports: port_list,
                duration_ms: duration.as_millis() as u64,
            }),
        ));
    }
}

/// Look up service name for a port using common ports + /etc/services.
pub fn service_name(port: u16) -> Option<String> {
    if let Some(&(_, name)) = COMMON_PORTS.iter().find(|&&(p, _)| p == port) {
        return Some(name.to_string());
    }
    if port <= 1023 {
        if let Ok(content) = std::fs::read_to_string("/etc/services") {
            for line in content.lines() {
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    let proto_parts: Vec<&str> = parts[1].split('/').collect();
                    if proto_parts.len() == 2 && proto_parts[1] == "tcp" {
                        if let Ok(p) = proto_parts[0].parse::<u16>() {
                            if p == port {
                                return Some(parts[0].to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}
