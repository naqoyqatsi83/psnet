
#[derive(Debug, Clone)]
pub enum SystemEvent {
    HostsFileChanged(String),
    ProxyChanged(String),
    EvilTwinDetected(String),
    AppBinaryChanged { app: String, detail: String },
    InternetLost(String),
    InternetRestored,
}

pub struct SystemMonitor {
    hosts_hash: Option<u64>,
    tick_count: u64,
}

impl SystemMonitor {
    pub fn new() -> Self {
        Self { hosts_hash: None, tick_count: 0 }
    }

    pub fn tick(&mut self) -> Vec<SystemEvent> {
        let mut events = Vec::new();
        self.tick_count += 1;
        if self.tick_count % 30 == 0 {
            if let Some(desc) = self.check_hosts_file() {
                events.push(SystemEvent::HostsFileChanged(desc));
            }
        }
        events
    }

    fn check_hosts_file(&mut self) -> Option<String> {
        let path = "/etc/hosts";
        let content = std::fs::read(path).ok()?;
        let hash = fnv1a_hash(&content);
        match self.hosts_hash {
            None => { self.hosts_hash = Some(hash); None }
            Some(prev) if prev == hash => None,
            Some(_) => {
                self.hosts_hash = Some(hash);
                Some(format!("Hosts file modified (hash {:016x})", hash))
            }
        }
    }
}

fn fnv1a_hash(data: &[u8]) -> u64 {
    const FNV_OFFSET: u64 = 14695981039346656037;
    const FNV_PRIME: u64 = 1099511628211;
    let mut hash = FNV_OFFSET;
    for &byte in data {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}
