use chrono::Utc;
use std::collections::HashMap;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::types::LanDevice;
use super::oui::lookup as mac_vendor_lookup;

// Scan phase constants
pub const SCAN_PHASE_ARP: u8 = 0;
pub const SCAN_PHASE_DNS: u8 = 1;

struct DeviceUpdate {
    ip: Ipv4Addr,
    mac: String,
    hostname: Option<String>,
    discovery_info: String,
    open_ports: String,
}

pub struct NetworkScanner {
    pub devices: Vec<LanDevice>,
    pending: Arc<Mutex<Vec<DeviceUpdate>>>,
    scanning: Arc<AtomicU8>,
    scan_seen_ips: std::collections::HashSet<IpAddr>,
    was_scanning: bool,
    pub last_scan: Option<Instant>,
    pub local_ip: Option<Ipv4Addr>,
    pub gateway: Option<Ipv4Addr>,
    pub subnet_mask: Option<Ipv4Addr>,
    scan_tick: u32,
    pub custom_labels: HashMap<String, String>,
    labels_path: PathBuf,
    pub dhcp_hostnames: Mutex<HashMap<IpAddr, String>>,
}

impl NetworkScanner {
    pub fn new() -> Self {
        let (local_ip, subnet_mask, gateway) = get_local_subnet();
        let labels_path = Self::labels_path();
        let custom_labels = Self::load_labels(&labels_path);
        Self {
            devices: Vec::new(),
            pending: Arc::new(Mutex::new(Vec::new())),
            scanning: Arc::new(AtomicU8::new(0)),
            scan_seen_ips: std::collections::HashSet::new(),
            was_scanning: false,
            last_scan: None,
            local_ip,
            gateway,
            subnet_mask,
            scan_tick: 0,
            custom_labels,
            labels_path,
            dhcp_hostnames: Mutex::new(HashMap::new()),
        }
    }

    pub fn start_scan(&self) {
        self.scanning.store(1, Ordering::Relaxed);
        let mut pending = self.pending.lock().unwrap();
        pending.clear();
        // Read ARP cache from /proc/net/arp
        if let Ok(content) = fs::read_to_string("/proc/net/arp") {
            let mut lines = content.lines();
            // skip header
            lines.next();
            for line in lines {
                let fields: Vec<&str> = line.split_whitespace().collect();
                if fields.len() < 6 { continue; }
                let ip = match fields[0].parse::<IpAddr>() {
                    Ok(ip) => ip,
                    Err(_) => continue,
                };
                // Only IPv4 for now
                if let IpAddr::V4(v4) = ip {
                    let mac = fields[3].to_string();
                    if mac == "00:00:00:00:00:00" { continue; }
                    let hostname = None; // fields[5] in /proc/net/arp is the interface, not a hostname
                    pending.push(DeviceUpdate {
                        ip: v4,
                        mac,
                        hostname,
                        discovery_info: "ARP".to_string(),
                        open_ports: String::new(),
                    });
                }
            }
        }
        self.scanning.store(2, Ordering::Relaxed); // phase done
    }

    pub fn poll_results(&mut self) -> Option<Vec<LanDevice>> {
        let mut pending = self.pending.lock().unwrap();
        if pending.is_empty() {
            self.scanning.store(0, Ordering::Relaxed);
            return None;
        }
        let now = Utc::now().naive_utc().time();

        // Index existing devices by MAC and by IP for merging.
        let mut by_mac: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
        let mut by_ip: std::collections::HashMap<IpAddr, usize> = std::collections::HashMap::new();
        for (i, d) in self.devices.iter().enumerate() {
            if !d.mac.is_empty() {
                by_mac.entry(d.mac.clone()).or_insert(i);
            }
            by_ip.entry(d.ip).or_insert(i);
        }

        let pending_updates: Vec<DeviceUpdate> = pending.drain(..).collect();
        let mut seen_macs: std::collections::HashSet<String> = std::collections::HashSet::new();

        for upd in &pending_updates {
            let mac_str = &upd.mac;
            let ip = IpAddr::V4(upd.ip);

            // Resolve hostname: prioritize DHCP, then ARP, then IP
            let dhcp_name = self.dhcp_hostnames.lock().unwrap().get(&ip).cloned();
            let hostname = dhcp_name.or_else(|| upd.hostname.clone()).unwrap_or_else(|| upd.ip.to_string());
            let label = self.custom_labels.get(mac_str).cloned();
            let vendor = Some(mac_vendor_lookup(mac_str).unwrap_or("Unknown").to_string());

            // Try to match an existing device — prefer MAC, fall back to IP.
            let existing_idx = by_mac.get(mac_str).copied()
                .or_else(|| by_ip.get(&ip).copied());

            if let Some(idx) = existing_idx {
                let dev = &mut self.devices[idx];
                dev.mac = mac_str.clone();
                dev.ip = ip;
                dev.last_seen = now;
                dev.is_online = true;
                if let Some(label) = label {
                    dev.hostname = Some(label);
                } else {
                    dev.hostname = Some(hostname);
                }
                dev.vendor = vendor;
                seen_macs.insert(dev.mac.clone());
            } else {
                // New device — not seen before in ARP
                self.devices.push(LanDevice {
                    ip,
                    mac: mac_str.clone(),
                    hostname: Some(hostname),
                    vendor,
                    first_seen: now,
                    last_seen: now,
                    is_online: true,
                    custom_name: label,
                    discovery_info: upd.discovery_info.clone(),
                    open_ports: upd.open_ports.clone(),
                    bytes_sent: 0,
                    bytes_received: 0,
                    tick_sent: 0,
                    tick_received: 0,
                    speed_sent: 0.0,
                    speed_received: 0.0,
                });
            }
        }

        // Mark devices not seen in this ARP scan as offline.
        for dev in &mut self.devices {
            if !dev.mac.is_empty() && !seen_macs.contains(&dev.mac) {
                dev.is_online = false;
            }
        }

        self.last_scan = Some(Instant::now());
        Some(self.devices.clone())
    }
    pub fn tick(&mut self) {
        self.scan_tick += 1;
        if self.scan_tick % 15 == 1 {
            self.start_scan();
        }
    }
    pub fn is_scanning(&self) -> bool {
        self.scanning.load(Ordering::Relaxed) != 0
    }
    pub fn scan_progress(&self) -> (usize, usize) { (0, 0) }
    pub fn scan_phase(&self) -> u8 { 0 }
    pub fn set_label(&mut self, mac: &str, label: String) {
        if label.is_empty() {
            self.custom_labels.remove(mac);
        } else {
            self.custom_labels.insert(mac.to_string(), label);
        }
        if let Ok(json) = serde_json::to_string_pretty(&self.custom_labels) {
            let _ = std::fs::create_dir_all(self.labels_path.parent().unwrap());
            let _ = std::fs::write(&self.labels_path, json);
        }
        for d in &mut self.devices {
            if d.mac == mac {
                d.custom_name = self.custom_labels.get(mac).cloned();
            }
        }
    }
    pub fn online_count(&self) -> usize {
        self.devices.iter().filter(|d| d.is_online).count()
    }

    fn labels_path() -> PathBuf {
        if let Some(data_dir) = dirs::data_dir() {
            let dir = data_dir.join("psnet");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("device_labels.json")
        } else {
            PathBuf::from("psnet_device_labels.json")
        }
    }

    fn load_labels(path: &PathBuf) -> HashMap<String, String> {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default()
    }
}

fn get_local_subnet() -> (Option<Ipv4Addr>, Option<Ipv4Addr>, Option<Ipv4Addr>) {
    use std::process::Command;

    // 1. Find default gateway and its interface from `ip route show default`
    let mut gateway: Option<Ipv4Addr> = None;
    let mut primary_iface: Option<String> = None;
    if let Ok(output) = Command::new("ip").args(["route", "show", "default"]).output() {
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // default via 192.168.1.1 dev wlan0 ...
            if parts.len() >= 5 && parts[0] == "default" && parts[1] == "via" {
                if let Ok(gw) = parts[2].parse::<Ipv4Addr>() {
                    gateway = Some(gw);
                    primary_iface = Some(parts[4].to_string());
                    break;
                }
            }
        }
    }

    // 2. Get IP and prefix for the primary interface (or first non-loopback)
    let mut local_ip: Option<Ipv4Addr> = None;
    let mut netmask: Option<Ipv4Addr> = None;

    fn parse_addr(iface: &str) -> Option<(Ipv4Addr, Ipv4Addr)> {
        let output = Command::new("ip").args(["-4", "-o", "addr", "show", iface]).output().ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 { continue; }
            let cidr = parts[3];
            let mut slash = cidr.split('/');
            let ip_str = slash.next()?;
            let prefix_str = slash.next()?;
            let prefix = prefix_str.parse::<u8>().ok()?;
            let ip = ip_str.parse::<Ipv4Addr>().ok()?;
            let mask = Ipv4Addr::from((0xFFFFFFFFu32 << (32 - prefix)) & 0xFFFFFFFF);
            return Some((ip, mask));
        }
        None
    }

    if let Some(ref iface) = primary_iface {
        if let Some((ip, mask)) = parse_addr(iface) {
            local_ip = Some(ip);
            netmask = Some(mask);
        }
    }

    // Fallback: scan all non-loopback interfaces
    if local_ip.is_none() {
        if let Ok(output) = Command::new("ip").args(["-4", "-o", "addr", "show"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() < 4 { continue; }
                let iface = parts[1].split(':').last().unwrap_or(parts[1]);
                if iface == "lo" { continue; }
                if let Some((ip, mask)) = parse_addr(iface) {
                    local_ip = Some(ip);
                    netmask = Some(mask);
                    break;
                }
            }
        }
    }

    (local_ip, netmask, gateway)
}
