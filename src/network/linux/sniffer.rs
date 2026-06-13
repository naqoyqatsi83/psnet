//! Packet sniffer for Linux using libpcap.
//!
//! Captures packets on the specified interface, decodes Ethernet/IPv4/TCP-UDP,
//! extracts printable ASCII snippets from payloads, and stores them in a
//! thread-safe ring buffer for the UI.
//!
//! Requires root privileges or CAP_NET_RAW to capture packets. If permission
//! is denied, the sniffer will be disabled and an error message will be available.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use pcap::{Capture, Device, Packet as PcapPacket};
use std::process::Command;

use crate::types::{ConnProto, PacketDirection, PacketSnippet};

/// Thread-safe packet snippet buffer.
pub struct PacketSniffer {
    pub snippets: Arc<Mutex<VecDeque<PacketSnippet>>>,
    pub max_snippets: usize,
    pub active: Arc<AtomicBool>,
    pub error_msg: Arc<Mutex<Option<String>>>,
    handle: Option<thread::JoinHandle<()>>,
    total_added: Arc<AtomicUsize>,
    consumed_count: usize,
}

impl PacketSniffer {
    /// Create a new sniffer with the given buffer capacity.
    pub fn new(max_snippets: usize) -> Self {
        Self {
            snippets: Arc::new(Mutex::new(VecDeque::with_capacity(max_snippets))),
            max_snippets,
            active: Arc::new(AtomicBool::new(false)),
            error_msg: Arc::new(Mutex::new(None)),
            handle: None,
            total_added: Arc::new(AtomicUsize::new(0)),
            consumed_count: 0,
        }
    }

    /// Start the sniffer on a background thread listening on all interfaces.
    /// If pcap fails to open a device (e.g., due to lack of permissions),
    /// sets an error message and returns without starting capture.
    pub fn start(&mut self) {
        if self.active.load(Ordering::Relaxed) {
            return;
        }

        let snippets = Arc::clone(&self.snippets);
        let active = Arc::clone(&self.active);
        let error_msg = Arc::clone(&self.error_msg);
        let max = self.max_snippets;
        let total_added = Arc::clone(&self.total_added);

        // Clear any previous error
        if let Ok(mut e) = error_msg.lock() {
            *e = None;
        }

        self.active.store(true, Ordering::Relaxed);

        self.handle = Some(thread::spawn(move || {
            sniffer_thread(snippets, active, error_msg, max, total_added);
        }));
    }

    /// Stop the sniffer.
    pub fn stop(&mut self) {
        self.active.store(false, Ordering::Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }

    /// Get new packets added since the last call to drain_new.
    pub fn drain_new(&mut self) -> Vec<PacketSnippet> {
        let total = self.total_added.load(Ordering::Relaxed);
        if total <= self.consumed_count {
            return Vec::new();
        }
        let new_count = total - self.consumed_count;
        self.consumed_count = total;
        let lock = match self.snippets.lock() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        let len = lock.len();
        let skip = len.saturating_sub(new_count);
        lock.iter().skip(skip).cloned().collect()
    }

    /// Get recent snippets for display.
    pub fn recent(&self, count: usize) -> Vec<PacketSnippet> {
        let lock = match self.snippets.lock() {
            Ok(guard) => guard,
            Err(_) => return Vec::new(),
        };
        lock.iter()
            .rev()
            .take(count)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect()
    }

    /// Get the error message if sniffer failed to start.
    pub fn get_error(&self) -> Option<String> {
        self.error_msg.lock().ok().and_then(|e| e.clone())
    }
}

impl Drop for PacketSniffer {
    fn drop(&mut self) {
        self.stop();
    }
}

// ─── Background thread ──────────────────────────────────────────────────────

fn sniffer_thread(
    snippets: Arc<Mutex<VecDeque<PacketSnippet>>>,
    active: Arc<AtomicBool>,
    error_msg: Arc<Mutex<Option<String>>>,
    max_snippets: usize,
    total_added: Arc<AtomicUsize>,
) {
    // Find a suitable capture device.
    // Prefer "any" pseudo-device if available, otherwise first non-loopback.
    let device = {
        let devices = match Device::list() {
            Ok(d) => d,
            Err(e) => {
                let _ = set_error(&error_msg, &format!("Failed to list devices: {}", e));
                active.store(false, Ordering::Relaxed);
                return;
            }
        };
        // If PSNET_INTERFACE is set and non-empty, use that interface explicitly
        if let Ok(iface) = std::env::var("PSNET_INTERFACE") {
            if !iface.is_empty() {
                if let Some(dev) = devices.iter().find(|d| d.name == iface) {
                    dev.clone()
                } else {
                    let _ = set_error(&error_msg, &format!("Interface '{}' not found", iface));
                    active.store(false, Ordering::Relaxed);
                    return;
                }
            } else {
                // Empty PSNET_INTERFACE, auto-select
                let any = devices.iter().find(|d| d.name == "any");
                if let Some(dev) = any {
                    dev.clone()
                } else {
                    let non_lo = devices.iter().find(|d| {
                        let name = &d.name;
                        !name.contains("lo") &&
                        !name.contains("docker") &&
                        !name.contains("veth") &&
                        !name.contains("br-") &&
                        !name.contains("virbr") &&
                        !name.contains("bnep") &&
                        !name.contains("bluetooth") &&
                        !name.contains("nfqueue") &&
                        !name.contains("dbus")
                    });
                    if let Some(dev) = non_lo {
                        dev.clone()
                    } else {
                        let _ = set_error(&error_msg, "No suitable network interface found");
                        active.store(false, Ordering::Relaxed);
                        return;
                    }
                }
            }
        } else {
            // No PSNET_INTERFACE, auto-select
            let any = devices.iter().find(|d| d.name == "any");
            if let Some(dev) = any {
                dev.clone()
            } else {
                let non_lo = devices.iter().find(|d| {
                    let name = &d.name;
                    !name.contains("lo") &&
                    !name.contains("docker") &&
                    !name.contains("veth") &&
                    !name.contains("br-") &&
                    !name.contains("virbr")
                });
                if let Some(dev) = non_lo {
                    dev.clone()
                } else {
                    let _ = set_error(&error_msg, "No suitable network interface found");
                    active.store(false, Ordering::Relaxed);
                    return;
                }
            }
        }
    };

    // Build capture using builder pattern: promiscuous mode, snaplen 65536, timeout 100ms.
    let cap_builder = match Capture::from_device(device) {
        Ok(builder) => builder,
        Err(e) => {
            let _ = set_error(&error_msg, &format!("Failed to create capture builder: {}", e));
            active.store(false, Ordering::Relaxed);
            return;
        }
    };

    let cap_builder = cap_builder
        .promisc(true)
        .snaplen(65536)
        .timeout(100);

    let mut cap = match cap_builder.open() {
        Ok(cap) => cap,
        Err(e) => {
            let msg = format!(
                "Failed to open packet capture device ({}). Run as root or grant CAP_NET_RAW capability.",
                e
            );
            let _ = set_error(&error_msg, &msg);
            active.store(false, Ordering::Relaxed);
            return;
        }
    };

    // Clear any previous error — we're live
    if let Ok(mut e) = error_msg.lock() {
        *e = None;
    }

    // Get local IPv4 address for direction determination (best-effort)
    let local_ip_v4 = match get_local_ipv4() {
        Some(ip) => ip,
        None => 0,
    };

    // ── Capture loop ──
    while active.load(Ordering::Relaxed) {
        match cap.next_packet() {
            Ok(pkt) => {
                if let Some(snippet) = parse_packet(&pkt, local_ip_v4) {
                    if let Ok(mut lock) = snippets.lock() {
                        lock.push_back(snippet);
                        total_added.fetch_add(1, Ordering::Relaxed);
                        while lock.len() > max_snippets {
                            lock.pop_front();
                        }
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                continue;
            }
            Err(e) => {
                let _ = set_error(&error_msg, &format!("Capture error: {}", e));
                active.store(false, Ordering::Relaxed);
                break;
            }
        }
    }
}

// ─── Packet parsing ──────────────────────────────────────────────────────────

/// Find the offset of the IPv4 header in a captured packet by checking
/// for the EtherType marker (0x0800) at known positions for different
/// link-layer types. Falls back to checking for raw IP at offset 0.
fn find_ipv4_offset(data: &[u8]) -> Option<usize> {
    // Ethernet II: 14-byte header, EtherType at bytes 12-13
    if data.len() > 14 && data[12] == 0x08 && data[13] == 0x00 {
        return Some(14);
    }
    // Linux SLL (cooked): 16-byte header, EtherType at bytes 14-15
    if data.len() > 16 && data[14] == 0x08 && data[15] == 0x00 {
        return Some(16);
    }
    // Raw IP / unknown link layer: check version nibble at offset 0
    if data.len() > 20 && (data[0] >> 4) == 4 {
        return Some(0);
    }
    None
}

fn parse_packet(pkt: &PcapPacket, local_ip_v4: u32) -> Option<PacketSnippet> {
    let data = pkt.data;
    if data.len() < 20 {
        return None;
    }

    let ip_start = match find_ipv4_offset(data) {
        Some(off) => off,
        None => return None,
    };

    if data.len() < ip_start + 20 {
        return None;
    }

    // IP header
    let version = (data[ip_start] >> 4) & 0xF;
    if version != 4 {
        return None;
    }
    let ihl = (data[ip_start] & 0xF) as usize * 4;
    if data.len() < ip_start + ihl {
        return None;
    }

    let protocol = data[ip_start + 9];
    let src_ip_bytes: [u8; 4] = [
        data[ip_start + 12],
        data[ip_start + 13],
        data[ip_start + 14],
        data[ip_start + 15],
    ];
    let dst_ip_bytes: [u8; 4] = [
        data[ip_start + 16],
        data[ip_start + 17],
        data[ip_start + 18],
        data[ip_start + 19],
    ];
    let src_ip = Ipv4Addr::from(src_ip_bytes);
    let dst_ip = Ipv4Addr::from(dst_ip_bytes);

    // Skip loopback
    if src_ip.is_loopback() && dst_ip.is_loopback() {
        return None;
    }

    // Extract additional IP header fields
    let ttl = data[ip_start + 8];
    let ip_total_len = u16::from_be_bytes([data[ip_start + 2], data[ip_start + 3]]);
    let ip_id = u16::from_be_bytes([data[ip_start + 4], data[ip_start + 5]]);

    let (src_port, dst_port, payload_offset, tcp_flags, tcp_seq, tcp_ack_num, tcp_window) = match protocol {
        6 => {
            // TCP
            let tcp_offset = ip_start + ihl;
            if data.len() < tcp_offset + 20 {
                return None;
            }
            let sp = u16::from_be_bytes([data[tcp_offset], data[tcp_offset + 1]]);
            let dp = u16::from_be_bytes([data[tcp_offset + 2], data[tcp_offset + 3]]);
            let tcp_hdr_len = ((data[tcp_offset + 12] >> 4) & 0xF) as usize * 4;
            let flags = data[tcp_offset + 13];
            let seq = u32::from_be_bytes([
                data[tcp_offset + 4],
                data[tcp_offset + 5],
                data[tcp_offset + 6],
                data[tcp_offset + 7],
            ]);
            let ack = u32::from_be_bytes([
                data[tcp_offset + 8],
                data[tcp_offset + 9],
                data[tcp_offset + 10],
                data[tcp_offset + 11],
            ]);
            let win = u16::from_be_bytes([data[tcp_offset + 14], data[tcp_offset + 15]]);
            (sp, dp, tcp_offset + tcp_hdr_len, flags, seq, ack, win)
        }
        17 => {
            // UDP
            let udp_offset = ip_start + ihl;
            if data.len() < udp_offset + 8 {
                return None;
            }
            let sp = u16::from_be_bytes([data[udp_offset], data[udp_offset + 1]]);
            let dp = u16::from_be_bytes([data[udp_offset + 2], data[udp_offset + 3]]);
            (sp, dp, udp_offset + 8, 0u8, 0u32, 0u32, 0u16)
        }
        _ => return None,
    };

    // Extract payload and snippet
    let has_payload = payload_offset < data.len() && data.len() > payload_offset;
    let payload = if has_payload { &data[payload_offset..] } else { &[] };
    let payload_size = payload.len();

    // Extract printable ASCII snippet (up to 200 chars)
    let snippet = if !payload.is_empty() {
        extract_best_snippet(payload, 200)
    } else {
        String::new()
    };

    // Filter: For TCP, ignore pure ACK without payload; show SYN/FIN/RST.
    if snippet.is_empty() {
        if protocol == 6 {
            let is_syn = tcp_flags & 0x02 != 0;
            let is_fin = tcp_flags & 0x01 != 0;
            let is_rst = tcp_flags & 0x04 != 0;
            if !is_syn && !is_fin && !is_rst {
                return None;
            }
        } else if payload.is_empty() {
            return None;
        }
    }

    // Extract raw payload bytes (up to 256 bytes)
    let raw_payload = if payload_offset < data.len() {
        data[payload_offset..data.len().min(payload_offset + 256)].to_vec()
    } else {
        Vec::new()
    };

    // Determine direction based on local IP
    let src_raw = u32::from_ne_bytes(src_ip_bytes);
    let direction = if src_raw == local_ip_v4 {
        PacketDirection::Outbound
    } else {
        PacketDirection::Inbound
    };

    Some(PacketSnippet {
        timestamp: chrono::Local::now().time(),
        direction,
        src_ip: IpAddr::V4(src_ip),
        dst_ip: IpAddr::V4(dst_ip),
        src_port,
        dst_port,
        protocol: if protocol == 6 { ConnProto::Tcp } else { ConnProto::Udp },
        snippet,
        payload_size,
        ttl,
        ip_total_len,
        ip_id,
        tcp_flags,
        tcp_seq,
        tcp_ack_num,
        tcp_window,
        raw_payload,
    })
}

/// Find the most readable substring in the payload.
fn extract_best_snippet(data: &[u8], max_len: usize) -> String {
    let mut runs: Vec<(usize, usize)> = Vec::new();
    let mut run_start: Option<usize> = None;

    for (i, &byte) in data.iter().enumerate() {
        let is_text = (byte >= 0x20 && byte <= 0x7E)
            || byte == b'\r'
            || byte == b'\n'
            || byte == b'\t';
        match (is_text, run_start) {
            (true, None) => run_start = Some(i),
            (false, Some(start)) => {
                if i - start >= 6 {
                    runs.push((start, i));
                }
                run_start = None;
            }
            _ => {}
        }
    }
    if let Some(start) = run_start {
        if data.len() - start >= 6 {
            runs.push((start, data.len()));
        }
    }

    if runs.is_empty() {
        return String::new();
    }

    let best_run = runs.iter().max_by_key(|(start, end)| {
        let slice = &data[*start..*end];
        let len = slice.len();
        let text_chars = slice.iter().filter(|&&b| {
            b.is_ascii_alphanumeric() || b == b' ' || b == b'/' || b == b':'
                || b == b'.' || b == b',' || b == b'-' || b == b'='
        }).count();
        let ratio = (text_chars * 100) / len.max(1);
        len * ratio
    });

    let (start, end) = match best_run {
        Some(r) => *r,
        None => return String::new(),
    };

    let slice = &data[start..end];

    let text_chars = slice.iter().filter(|&&b| {
        b.is_ascii_alphanumeric() || b == b' ' || b == b'/' || b == b':'
            || b == b'.' || b == b',' || b == b'-' || b == b'='
            || b == b'_' || b == b'?' || b == b'&' || b == b'"'
            || b == b'\'' || b == b'{' || b == b'}' || b == b'['
            || b == b']' || b == b'\n' || b == b'\r'
    }).count();
    let ratio = (text_chars * 100) / slice.len().max(1);
    if ratio < 40 {
        return String::new();
    }

    let mut result = String::with_capacity(max_len);
    let mut last_was_ws = false;

    for &byte in slice.iter() {
        if result.len() >= max_len {
            break;
        }
        if byte >= 0x20 && byte <= 0x7E {
            result.push(byte as char);
            last_was_ws = false;
        } else if byte == b'\r' || byte == b'\n' || byte == b'\t' {
            if !last_was_ws {
                result.push_str(" | ");
                last_was_ws = true;
            }
        }
    }

    let trimmed = result.trim_end_matches(" | ").trim();
    trimmed.to_string()
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn set_error(error_msg: &Arc<Mutex<Option<String>>>, msg: &str) -> Result<(), ()> {
    if let Ok(mut e) = error_msg.lock() {
        *e = Some(msg.to_string());
    }
    Ok(())
}

/// Get the local IPv4 address (non-loopback) as u32 in network byte order.
/// Uses the `ip` command to enumerate network interfaces.
fn get_local_ipv4() -> Option<u32> {
    let output = Command::new("ip")
        .args(["-o", "addr", "show"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 { continue; }
        let iface = parts[1];
        if iface == "lo" { continue; }
        let cidr = parts[3];
        if !cidr.contains('/') { continue; }
        let ip_str = cidr.split('/').next()?;
        if let Ok(ipv4) = ip_str.parse::<std::net::Ipv4Addr>() {
            if !ipv4.is_loopback() && !ipv4.is_unspecified() {
                return Some(u32::from_ne_bytes(ipv4.octets()));
            }
        }
    }
    None
}
