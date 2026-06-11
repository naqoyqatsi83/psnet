use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::types::{FirewallAppAction, FirewallMode, FirewallRule};

pub struct FirewallManager {
    pub rules: Vec<FirewallRule>,
    pub mode: FirewallMode,
    pub approved_apps: HashSet<String>,
    pub blocked_apps: HashSet<String>,
    pub pending_apps: Vec<String>,
    pub enabled: bool,
    pub scroll_offset: usize,
    pub refresh_tick: u32,
    pub filter_text: String,
    pub refresh_result: Arc<Mutex<Option<(Vec<FirewallRule>, bool)>>>,
    pub app_actions: HashMap<String, FirewallAppAction>,
    pub state_path: PathBuf,
    pub default_deny: bool,
}

impl FirewallManager {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            mode: FirewallMode::Normal,
            approved_apps: HashSet::new(),
            blocked_apps: HashSet::new(),
            pending_apps: Vec::new(),
            enabled: false,
            scroll_offset: 0,
            refresh_tick: 0,
            filter_text: String::new(),
            refresh_result: Arc::new(Mutex::new(None)),
            app_actions: HashMap::new(),
            state_path: Self::default_state_path(),
            default_deny: false,
        }
    }

    fn default_state_path() -> PathBuf {
        if let Some(data_dir) = dirs::data_dir() {
            let dir = data_dir.join("psnet");
            let _ = std::fs::create_dir_all(&dir);
            dir.join("firewall_state.json")
        } else {
            PathBuf::from("psnet_firewall_state.json")
        }
    }

    pub fn tick(&mut self) {}
    pub fn refresh_rules(&mut self) {}
    pub fn block_app(&mut self, _: &str) -> bool { false }
    pub fn toggle_ask_to_connect(&mut self) {}
    pub fn check_pending(&mut self, _: &str) {}
    pub fn is_psnet_blocked(&self, _: &str) -> bool { false }
    pub fn apply_action(&mut self, _: &str, _: Option<&str>, _: FirewallAppAction) -> bool { false }
    pub fn remove_psnet_rules(&mut self, _: &str) {}
    pub fn reset_all_psnet_rules(&mut self) {}
    pub fn get_app_action(&self, _: &str) -> Option<&FirewallAppAction> { None }
    pub fn toggle_default_policy(&mut self) {}
    pub fn effective_status(&self, name: &str) -> (&'static str, bool) {
        if self.blocked_apps.contains(name) {
            return ("BLOCKED", true);
        }
        match self.app_actions.get(name) {
            Some(FirewallAppAction::Deny) => ("DENY", true),
            Some(FirewallAppAction::Drop) => ("DROP", true),
            Some(FirewallAppAction::Allow) => ("ALLOW", false),
            None => ("ALLOWED", false),
        }
    }
}
