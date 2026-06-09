use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListenProto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub name: String,
    pub exe_path: String,
    pub cmdline: String,
    pub product_name: String,
    pub file_description: String,
    pub company_name: String,
}

#[derive(Debug, Clone)]
pub struct RawListener {
    pub proto: ListenProto,
    pub bind_addr: IpAddr,
    pub port: u16,
    pub pid: u32,
}

pub fn enumerate_listeners() -> Vec<RawListener> {
    Vec::new()
}

pub fn resolve_process_info(_pids: &[u32]) -> HashMap<u32, ProcessInfo> {
    HashMap::new()
}
