// Platform-specific implementations for Linux
#[path = "linux/connections.rs"]
pub mod connections;
#[path = "linux/scanner.rs"]
pub mod scanner;
#[path = "linux/system_monitor.rs"]
pub mod system_monitor;
#[path = "linux/servers/mod.rs"]
pub mod servers;
#[path = "linux/networks/mod.rs"]
pub mod networks;
#[path = "linux/firewall.rs"]
pub mod firewall;
#[path = "linux/dns.rs"]
pub mod dns;
#[path = "linux/sniffer.rs"]
pub mod sniffer;
#[path = "linux/oui.rs"]
pub mod oui;
#[path = "linux/hostnames.rs"]
pub mod hostnames;

// Shared modules (platform-independent)
pub mod alerts;
pub mod bandwidth;
pub mod capture;
pub mod geoip;
pub mod protocols;
pub mod speed;
pub mod threats;
pub mod usage;
