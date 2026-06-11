use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::network::oui::lookup as oui_lookup;
use crate::types::{LanDevice, NetworkCategory};

#[derive(Debug, Clone)]
pub struct RemoteNetwork {
    pub name: String,
    pub network: String,
    pub netmask: String,
    pub gateway: Option<String>,
    pub category: NetworkCategory,
    pub metric: u32,
    pub iface: String,
    pub devices: Vec<LanDevice>,
}

pub struct NetworksScanner {
    pub networks: Vec<RemoteNetwork>,
    scan_tick: u32,
    pub scanning: bool,
    pending: Arc<Mutex<Option<Vec<LanDevice>>>>,
    last_scan: Option<Instant>,
    pub primary_ip: Option<Ipv4Addr>,
    results_ready: bool,
    /// Persistent store of known BT devices across scans.
    /// Devices not seen in the latest scan are marked offline rather than removed.
    known_bt_devices: Vec<LanDevice>,
}

impl NetworksScanner {
    pub fn new(primary_ip: Option<Ipv4Addr>) -> Self {
        Self {
            networks: Vec::new(),
            scan_tick: 0,
            scanning: false,
            pending: Arc::new(Mutex::new(None)),
            last_scan: None,
            primary_ip,
            results_ready: false,
            known_bt_devices: Vec::new(),
        }
    }

    pub fn tick(&mut self) {
        if self.scan_tick == 0 {
            self.start_scan();
        }
        self.scan_tick += 1;
        if self.scan_tick % 2 == 0 {
            self.start_scan();
        }
    }

    pub fn is_scanning(&self) -> bool {
        self.scanning
    }

    pub fn poll_results(&mut self) -> bool {
        if self.results_ready {
            self.results_ready = false;
            true
        } else {
            false
        }
    }

    pub fn scan_progress(&self) -> (usize, usize) {
        (0, 0)
    }

    pub fn scan_phase(&self) -> u8 {
        0
    }

    pub fn get_networks(&self) -> &[RemoteNetwork] {
        &self.networks
    }

    /// Scan for Bluetooth devices visible to the adapter.
    ///
    /// Combines multiple sources:
    /// - `bluetoothctl paired-devices` — officially paired via Bluez
    /// - `bluetoothctl devices` — all devices Bluez has ever seen
    /// - `hcitool con` — currently active ACL connections (catches devices
    ///   connected via Docker containers or other non-Bluez stacks)
    fn collect_bt_devices() -> Vec<(String, String)> {
        let mut seen = HashSet::new();
        let mut results = Vec::new();

        // Source 1: bluetoothctl paired-devices
        if let Ok(output) = Command::new("bluetoothctl").args(["paired-devices"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() < 3 || parts[0] != "Device" { continue; }
                let mac = parts[1].to_uppercase();
                if seen.insert(mac.clone()) {
                    results.push((mac, parts[2].to_string()));
                }
            }
        }

        // Source 2: bluetoothctl devices (all known, not just paired)
        if let Ok(output) = Command::new("bluetoothctl").args(["devices"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() < 3 || parts[0] != "Device" { continue; }
                let mac = parts[1].to_uppercase();
                if seen.insert(mac.clone()) {
                    results.push((mac, parts[2].to_string()));
                }
            }
        }

        // Source 3: hcitool con — active ACL connections
        if let Ok(output) = Command::new("hcitool").args(["con"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let trimmed = line.trim();
                if !trimmed.starts_with("< ACL ") { continue; }
                let mut parts = trimmed.split_whitespace();
                parts.next();
                parts.next();
                let Some(mac_raw) = parts.next() else { continue };
                let mac = mac_raw.to_uppercase();
                if seen.insert(mac.clone()) {
                    let name = Self::resolve_bt_name(&mac);
                    results.push((mac, name));
                }
            }
        }

        results
    }

    /// Try to resolve a BT device name from MAC.
    fn resolve_bt_name(mac: &str) -> String {
        if let Ok(output) = Command::new("hcitool").args(["name", mac]).output() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !name.is_empty() && name != "null" {
                return name;
            }
        }
        let oui = if mac.len() >= 8 { &mac[..8] } else { mac };
        format!("BT Device ({})", oui)
    }

    /// Merge freshly-scanned BT devices into the persistent known list.
    /// New devices are added with is_online=true; devices not seen this
    /// scan are marked is_online=false. Existing device names are updated
    /// if the scan found a better one (hcitool name may yield a real name
    /// on a later scan where bluetoothctl only had a placeholder).
    fn merge_bt_devices(&mut self, fresh_devices: Vec<(String, String)>) {
        let now = chrono::Local::now().time();

        // Mark all existing devices offline by default, re-enable below
        for dev in &mut self.known_bt_devices {
            dev.is_online = false;
        }

        for (mac, name) in fresh_devices {
            if let Some(existing) = self.known_bt_devices.iter_mut().find(|d| d.mac == mac) {
                // Update name if we have a better one
                if !name.starts_with("BT Device (") || existing.hostname.as_deref().map_or(true, |h| h.starts_with("BT Device (")) {
                    existing.hostname = Some(name);
                }
                existing.is_online = true;
                existing.last_seen = now;
            } else {
                let bt_vendor = oui_lookup(&mac).unwrap_or("Bluetooth").to_string();
                self.known_bt_devices.push(LanDevice {
                    ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    mac,
                    hostname: Some(name),
                    vendor: Some(bt_vendor),
                    first_seen: now,
                    last_seen: now,
                    is_online: true,
                    custom_name: None,
                    discovery_info: String::new(),
                    open_ports: String::new(),
                    bytes_sent: 0,
                    bytes_received: 0,
                    tick_sent: 0,
                    tick_received: 0,
                    speed_sent: 0.0,
                    speed_received: 0.0,
                });
            }
        }
    }

    pub fn start_scan(&mut self) {
        self.scanning = true;
        let mut nets = Vec::new();
        let output = Command::new("ip")
            .args(["-4", "-o", "addr", "show"])
            .output();
        let Ok(output) = output else {
            self.scanning = false;
            return;
        };
        let text = String::from_utf8_lossy(&output.stdout);
        for line in text.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 { continue; }
            let iface_with_idx = parts[1];
            let iface = iface_with_idx.split(':').last().unwrap_or(iface_with_idx);
            let cidr = parts[3];
            if !cidr.contains('/') { continue; }
            let mut slash = cidr.split('/');
            let Some(ip_str) = slash.next() else { continue; };
            let Some(prefix_str) = slash.next() else { continue; };
            let Ok(prefix) = prefix_str.parse::<u8>() else { continue; };
            let Ok(ip) = ip_str.parse::<Ipv4Addr>() else { continue; };
            let netmask = Ipv4Addr::from((0xFFFFFFFFu32 << (32 - prefix)) & 0xFFFFFFFF);
            let network_addr = Ipv4Addr::from(u32::from(ip) & u32::from(netmask));
            let gateway = None;

            let iface_lower = iface.to_lowercase();
            if iface_lower.contains("lo") {
                continue;
            }

            let category = if iface_lower.contains("docker") {
                NetworkCategory::Docker
            } else if iface_lower.contains("veth") || iface_lower.contains("br-") || iface_lower.contains("virbr") {
                NetworkCategory::Virtual
            } else if iface_lower.contains("tun") || iface_lower.contains("tap") {
                NetworkCategory::Tunnel
            } else if iface_lower.contains("wsl") {
                NetworkCategory::Wsl
            } else if iface_lower.contains("hyperv") || iface_lower.contains("vm") || iface_lower.contains("virtual") {
                NetworkCategory::HyperV
            } else if iface_lower.contains("bluetooth") || iface_lower.contains("bnep") {
                NetworkCategory::Bluetooth
            } else {
                NetworkCategory::Secondary
            };

            // Get MAC address for this interface
            let mac_addr = fs::read_to_string(format!("/sys/class/net/{}/address", iface))
                .map(|s| s.trim().to_string().to_uppercase())
                .unwrap_or_default();

            // Get operational state (UP/DOWN)
            let operstate = fs::read_to_string(format!("/sys/class/net/{}/operstate", iface))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            let is_online = operstate == "up";

            // Get hostname for this machine
            let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
                .ok()
                .map(|s| s.trim().to_string());

            // Build a device entry for this interface
            let device = LanDevice {
                ip: IpAddr::V4(ip),
                mac: mac_addr,
                hostname: hostname.clone(),
                vendor: None,
                first_seen: chrono::Local::now().time(),
                last_seen: chrono::Local::now().time(),
                is_online,
                custom_name: None,
                discovery_info: String::new(),
                open_ports: String::new(),
                bytes_sent: 0,
                bytes_received: 0,
                tick_sent: 0,
                tick_received: 0,
                speed_sent: 0.0,
                speed_received: 0.0,
            };

            let name = iface.to_string();
            let network = format!("{}/{}", network_addr, prefix);
            let netmask_str = netmask.to_string();
            let metric = 0;
            nets.push(RemoteNetwork {
                name,
                network,
                netmask: netmask_str,
                gateway,
                category,
                metric,
                iface: iface.to_string(),
                devices: vec![device],
            });
        }

        // ─── Bluetooth adapter detection (collector mode) ──────────────
        let bt_adapter_exists = fs::read_dir("/sys/class/bluetooth")
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);

        if bt_adapter_exists {
            // Scan fresh BT devices and merge into persistent store
            let fresh = Self::collect_bt_devices();
            self.merge_bt_devices(fresh);

            // Read adapter MAC
            let bt_mac = fs::read_to_string("/sys/class/bluetooth/hci0/address")
                .map(|s| s.trim().to_string().to_uppercase())
                .unwrap_or_default();
            // Read adapter name
            let bt_name = fs::read_to_string("/sys/class/bluetooth/hci0/name")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| "Bluetooth Adapter".to_string());

            // Check if any existing net is already a BT network
            let already_has_bt = nets.iter().any(|n| n.category == NetworkCategory::Bluetooth);
            if already_has_bt {
                // Inject known BT devices into the first BT network entry
                if let Some(bt_net) = nets.iter_mut().find(|n| n.category == NetworkCategory::Bluetooth) {
                    bt_net.devices = self.known_bt_devices.clone();
                }
            } else {
                nets.push(RemoteNetwork {
                    name: bt_name,
                    network: "N/A".to_string(),
                    netmask: "N/A".to_string(),
                    gateway: None,
                    category: NetworkCategory::Bluetooth,
                    metric: 0,
                    iface: "hci0".to_string(),
                    devices: self.known_bt_devices.clone(),
                });

                // If adapter has no MAC-based device entry, add one
                if !bt_mac.is_empty() && !nets.iter().any(|n| {
                    n.devices.iter().any(|d| d.mac == bt_mac)
                }) {
                    if let Some(last) = nets.last_mut() {
                        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
                            .ok()
                            .map(|s| s.trim().to_string());
                        let adapter_vendor = oui_lookup(&bt_mac).unwrap_or("Raspberry Pi").to_string();
                        last.devices.push(LanDevice {
                            ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                            mac: bt_mac,
                            hostname,
                            vendor: Some(adapter_vendor),
                            first_seen: chrono::Local::now().time(),
                            last_seen: chrono::Local::now().time(),
                            is_online: true,
                            custom_name: None,
                            discovery_info: String::new(),
                            open_ports: String::new(),
                            bytes_sent: 0,
                            bytes_received: 0,
                            tick_sent: 0,
                            tick_received: 0,
                            speed_sent: 0.0,
                            speed_received: 0.0,
                        });
                    }
                }
            }
        }

        self.networks = nets;
        self.results_ready = true;
        self.scanning = false;
    }
}
