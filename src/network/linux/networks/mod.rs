use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Instant;

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
        }
    }

    pub fn tick(&mut self) {
        if self.scan_tick == 0 {
            // Scan immediately on first tick
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
    fn scan_bluetooth_devices() -> Vec<LanDevice> {
        let mut seen = std::collections::HashSet::new();
        let mut devices = Vec::new();

        // Source 1: bluetoothctl paired-devices
        if let Ok(output) = Command::new("bluetoothctl").args(["paired-devices"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() < 3 || parts[0] != "Device" { continue; }
                let mac = parts[1].to_uppercase();
                if seen.insert(mac.clone()) {
                    devices.push(Self::make_bt_device(mac, parts[2].to_string()));
                }
            }
        }

        // Source 2: bluetoothctl devices (all known, not just paired)
        // This catches devices that Bluez has discovered but may not be paired.
        if let Ok(output) = Command::new("bluetoothctl").args(["devices"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() < 3 || parts[0] != "Device" { continue; }
                let mac = parts[1].to_uppercase();
                if seen.insert(mac.clone()) {
                    devices.push(Self::make_bt_device(mac, parts[2].to_string()));
                }
            }
        }

        // Source 3: hcitool con — active ACL connections.
        // These show MACs of devices currently connected at the HCI level,
        // regardless of whether Bluez knows about them. Useful when Docker
        // containers talk directly to the BT adapter.
        if let Ok(output) = Command::new("hcitool").args(["con"]).output() {
            let text = String::from_utf8_lossy(&output.stdout);
            for line in text.lines() {
                // Format: "    < ACL 00:11:22:33:44:55 handle 42 state 1 lm PERIPHERAL"
                let trimmed = line.trim();
                if !trimmed.starts_with("< ACL ") { continue; }
                // Extract MAC — second whitespace-delimited token after "< ACL"
                let mut parts = trimmed.split_whitespace();
                parts.next(); // skip "<"
                parts.next(); // skip "ACL"
                let Some(mac_raw) = parts.next() else { continue };
                let mac = mac_raw.to_uppercase();
                if seen.insert(mac.clone()) {
                    // Try to resolve a human-readable name via hcitool name
                    let name = Self::resolve_bt_name(&mac);
                    devices.push(Self::make_bt_device(mac, name));
                }
            }
        }

        devices
    }

    /// Try to resolve a BT device name from MAC.
    fn resolve_bt_name(mac: &str) -> String {
        if let Ok(output) = Command::new("hcitool").args(["name", mac]).output() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !name.is_empty() && name != "null" {
                return name;
            }
        }
        // Fallback: give a generic name from the MAC's OUI prefix
        let oui = if mac.len() >= 8 { &mac[..8] } else { mac };
        format!("BT Device ({})", oui)
    }

    fn make_bt_device(mac: String, hostname: String) -> LanDevice {
        LanDevice {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            mac,
            hostname: Some(hostname),
            vendor: Some("Bluetooth".to_string()),
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
        // ─── Bluetooth adapter detection ─────────────────────────────
        // Check if hci0 exists (BT adapter). If no BT network was added
        // from ip addr (e.g. bnep0 not connected), create one for the adapter.
        let bt_adapter_exists = fs::read_dir("/sys/class/bluetooth")
            .map(|mut d| d.next().is_some())
            .unwrap_or(false);

        if bt_adapter_exists {
            let already_has_bt = nets.iter().any(|n| n.category == NetworkCategory::Bluetooth);
            if !already_has_bt {
                // Read adapter MAC
                let bt_mac = fs::read_to_string("/sys/class/bluetooth/hci0/address")
                    .map(|s| s.trim().to_string().to_uppercase())
                    .unwrap_or_default();
                // Read adapter name
                let bt_name = fs::read_to_string("/sys/class/bluetooth/hci0/name")
                    .map(|s| s.trim().to_string())
                    .unwrap_or_else(|_| "Bluetooth Adapter".to_string());

                // Get paired devices from bluetoothctl (instant, no scan delay)
                let bt_devices = Self::scan_bluetooth_devices();

                nets.push(RemoteNetwork {
                    name: bt_name,
                    network: "N/A".to_string(),
                    netmask: "N/A".to_string(),
                    gateway: None,
                    category: NetworkCategory::Bluetooth,
                    metric: 0,
                    iface: "hci0".to_string(),
                    devices: bt_devices,
                });

                // If adapter has no MAC-based device entry, add one
                if !bt_mac.is_empty() && !nets.iter().any(|n| {
                    n.devices.iter().any(|d| d.mac == bt_mac)
                }) {
                    if let Some(last) = nets.last_mut() {
                        let hostname = fs::read_to_string("/proc/sys/kernel/hostname")
                            .ok()
                            .map(|s| s.trim().to_string());
                        last.devices.push(LanDevice {
                            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                            mac: bt_mac,
                            hostname,
                            vendor: Some("Bluetooth Adapter".to_string()),
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
