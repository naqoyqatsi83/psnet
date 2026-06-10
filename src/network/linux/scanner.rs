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
                    let hostname = if fields[5] != "?" { Some(fields[5].to_string()) } else { None };
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
        let mut devices = Vec::new();
        let now = Utc::now().naive_utc().time();
        for upd in pending.drain(..) {
            let mac_str = upd.mac.clone();
            // Resolve hostname: prioritize DHCP, then ARP, then IP
            let dhcp_name = self.dhcp_hostnames.lock().unwrap().get(&IpAddr::V4(upd.ip)).cloned();
            let mut hostname = dhcp_name.or_else(|| upd.hostname.clone()).unwrap_or_else(|| upd.ip.to_string());
            if let Some(label) = self.custom_labels.get(&mac_str) {
                hostname = label.clone();
            }
            let vendor = Some(mac_vendor_lookup(&mac_str).unwrap_or("Unknown").to_string());
            devices.push(LanDevice {
                ip: IpAddr::V4(upd.ip),
                mac: mac_str.clone(),
                hostname: Some(hostname),
                vendor,
                first_seen: now,
                last_seen: now,
                is_online: true,
                custom_name: self.custom_labels.get(&mac_str).cloned(),
                discovery_info: upd.discovery_info,
                open_ports: upd.open_ports,
                bytes_sent: 0,
                bytes_received: 0,
                tick_sent: 0,
                tick_received: 0,
                speed_sent: 0.0,
                speed_received: 0.0,
            });
        }
        self.devices = devices.clone();
        self.last_scan = Some(Instant::now());
        Some(devices)
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
    (None, None, None)
}
