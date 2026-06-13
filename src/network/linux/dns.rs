use std::net::IpAddr;
use std::collections::HashMap;

pub fn get_system_dns_servers() -> Vec<IpAddr> {
    Vec::new()
}

pub fn read_dns_cache() -> HashMap<IpAddr, String> {
    HashMap::new()
}

pub fn port_service_name(port: u16) -> Option<String> {
    super::port_scanner::service_name(port)
}

pub fn read_dns_cache_api() -> HashMap<IpAddr, String> {
    HashMap::new()
}

pub fn read_dns_cache_ipconfig() -> HashMap<IpAddr, String> {
    HashMap::new()
}
