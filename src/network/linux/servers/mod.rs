use std::collections::HashMap;

use crate::types::{ListeningPort, ListenProto, ServerCategory};
use super::connections::{fetch_connections, get_process_full_path};

pub struct ServersScanner {
    listening_ports: Vec<ListeningPort>,
    refresh_tick: u32,
    pub scroll_offset: usize,
    pub sort_column: usize,
    pub sort_ascending: bool,
    pub filter_text: String,
}

impl ServersScanner {
    pub fn new() -> Self {
        Self {
            listening_ports: Vec::new(),
            refresh_tick: 0,
            scroll_offset: 0,
            sort_column: 0,
            sort_ascending: true,
            filter_text: String::new(),
        }
    }

    pub fn tick(&mut self) {
        self.refresh_tick += 1;
        if self.refresh_tick % 30 == 0 {
            self.start_scan();
        }
    }

    pub fn get_listening_ports(&self) -> &[ListeningPort] {
        &self.listening_ports
    }

    pub fn start_scan(&mut self) {
        self.recompute_listening_ports();
    }

    pub fn is_scanning(&self) -> bool {
        false
    }

    pub fn filtered_servers(&self) -> Vec<&ListeningPort> {
        let mut v: Vec<&ListeningPort> = self.listening_ports.iter().collect();
        // Apply filter
        if !self.filter_text.is_empty() {
            let filter_lower = self.filter_text.to_lowercase();
            v.retain(|p| {
                p.process_name.to_lowercase().contains(&filter_lower)
                    || p.server_kind.to_string().to_lowercase().contains(&filter_lower)
            });
        }

        // Sort
        v.sort_by(|a, b| {
            let cmp = match self.sort_column {
                0 => a.port.cmp(&b.port),
                1 => a.process_name.cmp(&b.process_name),
                2 => a.pid.cmp(&b.pid),
                3 => a.user.cmp(&b.user),
                4 => a.bind_addr.cmp(&b.bind_addr),
                _ => a.port.cmp(&b.port),
            };
            if self.sort_ascending { cmp } else { cmp.reverse() }
        });
        v
    }

    fn recompute_listening_ports(&mut self) {
        let connections = fetch_connections(&mut HashMap::new());
        let mut ports = Vec::new();

        for conn in connections {
            if conn.remote_addr.is_some() {
                continue;
            }

            let listen_proto = match conn.proto {
                crate::types::ConnProto::Tcp => ListenProto::Tcp,
                crate::types::ConnProto::Udp => ListenProto::Udp,
            };

            let process_path = get_process_full_path(conn.pid);
            let exe_path = process_path.as_ref().map(|s| s.as_str()).unwrap_or("").to_string();
            let cmdline = Self::get_cmdline(conn.pid);

            let server_kind = Self::categorize_port(conn.local_port, listen_proto);

            ports.push(ListeningPort {
                proto: listen_proto,
                port: conn.local_port,
                pid: conn.pid,
                process_name: conn.process_name.clone(),
                process_path,
                cmdline,
                server_kind,
                bind_addr: conn.local_addr,
                user: String::new(),
                version: None,
                http_title: None,
                description: String::new(),
                is_responsive: false,
                details: String::new(),
                exe_path,
                detected_techs: Vec::new(),
                banner: None,
                product_name: None,
                company_name: None,
                response_headers: Vec::new(),
                first_seen: None,
            });
        }

        ports.sort_by_key(|p| p.port);
        self.listening_ports = ports;
    }

    fn get_cmdline(pid: u32) -> String {
        let path = format!("/proc/{}/cmdline", pid);
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| s.split('\0').next().map(String::from))
            .unwrap_or_default()
    }

    fn categorize_port(port: u16, proto: ListenProto) -> ServerCategory {
        match proto {
            ListenProto::Tcp => match port {
                20 | 21 => ServerCategory::Ftp,
                22 => ServerCategory::Ssh,
                23 => ServerCategory::Telnet,
                25 => ServerCategory::Smtp,
                53 => ServerCategory::Dns,
                80 => ServerCategory::Http,
                110 => ServerCategory::Pop3,
                143 => ServerCategory::Imap,
                443 => ServerCategory::Https,
                3306 => ServerCategory::Mysql,
                5432 => ServerCategory::Postgres,
                6379 => ServerCategory::Redis,
                8080 => ServerCategory::Http,
                9200 => ServerCategory::Elasticsearch,
                _ => ServerCategory::Custom,
            },
            ListenProto::Udp => match port {
                53 => ServerCategory::Dns,
                67 => ServerCategory::Dhcp,
                123 => ServerCategory::Ntp,
                5353 => ServerCategory::Mdns,
                _ => ServerCategory::Custom,
            },
        }
    }
}
