use std::net::IpAddr;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenProto {
    Tcp,
    Udp,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerCategory {
    Web,
    Database,
    Mail,
    FileTransfer,
    RemoteAccess,
    Media,
    Directory,
    Game,
    P2P,
    IoTOther,
    Other,
}

impl ServerCategory {
    pub fn color(&self) -> (u8, u8, u8) {
        match self {
            ServerCategory::Web => (80, 200, 120),
            ServerCategory::Database => (255, 165, 0),
            ServerCategory::Mail => (135, 206, 250),
            ServerCategory::FileTransfer => (255, 105, 180),
            ServerCategory::RemoteAccess => (148, 0, 211),
            ServerCategory::Media => (255, 69, 0),
            ServerCategory::Directory => (0, 255, 255),
            ServerCategory::Game => (255, 215, 0),
            ServerCategory::P2P => (0, 255, 0),
            ServerCategory::IoTOther => (128, 128, 128),
            ServerCategory::Other => (128, 128, 128),
        }
    }

    pub fn category(&self) -> &'static str {
        match self {
            ServerCategory::Web => "Web",
            ServerCategory::Database => "Database",
            ServerCategory::Mail => "Mail",
            ServerCategory::FileTransfer => "File Transfer",
            ServerCategory::RemoteAccess => "Remote Access",
            ServerCategory::Media => "Media",
            ServerCategory::Directory => "Directory",
            ServerCategory::Game => "Game",
            ServerCategory::P2P => "P2P",
            ServerCategory::IoTOther => "IoT/Other",
            ServerCategory::Other => "Other",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            ServerCategory::Web => "Serves HTTP/HTTPS content",
            ServerCategory::Database => "Database service",
            ServerCategory::Mail => "Mail server (SMTP/IMAP/POP)",
            ServerCategory::FileTransfer => "File transfer (FTP/SFTP)",
            ServerCategory::RemoteAccess => "Remote access (RDP/SSH/VNC)",
            ServerCategory::Media => "Media streaming",
            ServerCategory::Directory => "Directory service (LDAP)",
            ServerCategory::Game => "Game server",
            ServerCategory::P2P => "Peer-to-peer service",
            ServerCategory::IoTOther => "IoT or embedded service",
            ServerCategory::Other => "Other network service",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetectedTech {
    pub name: String,
    pub version: String,
    pub category: String,
}

#[derive(Debug, Clone)]
pub struct ListeningPort {
    pub proto: ListenProto,
    pub port: u16,
    pub pid: u32,
    pub process_name: String,
    pub process_path: String,
    pub server_kind: ServerCategory,
    pub version: Option<String>,
    pub is_responsive: bool,
    pub details: String,
    pub exe_path: String,
    pub detected_techs: Vec<DetectedTech>,
    pub http_title: Option<String>,
    pub banner: Option<String>,
    pub bind_addr: IpAddr,
    pub open_ports: String,
    pub cmdline: String,
    pub product_name: String,
    pub company_name: String,
    pub response_headers: Vec<(String, String)>,
    pub first_seen: DateTime<Utc>,
}

impl ListeningPort {
    pub fn display_icon(&self) -> String {
        match self.proto {
            ListenProto::Tcp => "➜".to_string(),
            ListenProto::Udp => "⬆".to_string(),
        }
    }

    pub fn display_name(&self) -> String {
        if !self.process_name.is_empty() {
            self.process_name.clone()
        } else {
            self.port.to_string()
        }
    }

    pub fn display_description(&self) -> String {
        let mut parts = Vec::new();
        if !self.details.is_empty() {
            parts.push(self.details.clone());
        }
        if !self.detected_techs.is_empty() {
            parts.push(format!("Tech: {}", self.detected_techs.iter().map(|t| t.name.clone()).collect::<Vec<_>>().join(", ")));
        }
        if let Some(title) = &self.http_title {
            parts.push(format!("HTTP: {}", title));
        }
        if let Some(banner) = &self.banner {
            parts.push(banner.clone());
        }
        parts.join(" • ")
    }
}
