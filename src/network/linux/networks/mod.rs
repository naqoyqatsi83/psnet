use std::net::Ipv4Addr;
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
        self.scan_tick += 1;
        if self.scan_tick % 30 == 0 {
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
            } else if iface_lower.contains("bluetooth") {
                NetworkCategory::Bluetooth
            } else {
                NetworkCategory::Secondary
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
                devices: Vec::new(),
            });
        }
        self.networks = nets;
        self.results_ready = true;
        self.scanning = false;
    }
}
