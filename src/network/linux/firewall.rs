use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::types::{Connection, FirewallAppAction, FirewallMode, FirewallRule};

use super::nftables;

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
    /// Human-readable name of the detected firewall backend.
    pub backend_name: String,

    // ─── Internal state ───────────────────────────────────────────
    /// app_name → [(nft_rule_handle, description)]
    rule_handles: HashMap<String, Vec<(u64, String)>>,
    /// app_name → [uid]
    uid_map: HashMap<String, Vec<u32>>,
    /// app_name → [cgroupv2_path]  (nftables socket cgroupv2 rules)
    cgroup_map: HashMap<String, Vec<String>>,
    /// app_name → [cgroupv2_path]  (iptables -m cgroup --path fallback)
    iptables_cgroup_paths: HashMap<String, Vec<String>>,
    /// Whether the `inet psnet-filter` table exists in nftables.
    nft_initialized: bool,
    /// Set when a rule change needs to be applied on the next tick.
    sync_needed: bool,
    /// Apps that were blocked but can't be enforced (same UID and no unique
    /// cgroup path to match on).
    pub unblockable_apps: Vec<String>,
}

impl FirewallManager {
    pub fn new() -> Self {
        let mut mgr = Self {
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
            backend_name: String::new(),
            rule_handles: HashMap::new(),
            uid_map: HashMap::new(),
            cgroup_map: HashMap::new(),
            iptables_cgroup_paths: HashMap::new(),
            nft_initialized: false,
            sync_needed: false,
            unblockable_apps: Vec::new(),
        };
        mgr.load_state();
        mgr.init_nftables();
        mgr
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

    // ─── Initialisation ───────────────────────────────────────────

    fn init_nftables(&mut self) {
        // Check explicit privilege level FIRST — before any nft probes — so
        // a non-root user without CAP_NET_ADMIN never gets a false ACTIVE
        // status even if the nft probe oddly succeeds on this system.
        if !nftables::can_manage_firewall() {
            self.enabled = false;
            self.backend_name = "no write access".into();
            self.clear_state();
            return;
        }

        if !nftables::available() {
            self.enabled = false;
            self.backend_name = "nft not found".into();
            self.clear_state();
            return;
        }
        self.backend_name = nftables::detect_backend();
        if nftables::ensure_table() {
            self.enabled = true;
            self.nft_initialized = true;
            // Re-sync saved state on next tick.
            self.sync_needed = true;
        } else {
            self.enabled = false;
            if nftables::can_manage_firewall() {
                self.backend_name = "table init failed".into();
            } else {
                self.backend_name = "no write access".into();
            }
            // Discard stale saved state — no rules can be enforced so showing
            // BLOCKED/DENY in the UI would be a false sense of control.
            self.clear_state();
        }
    }

    // ─── Periodic update (called every main tick) ─────────────────

    /// Sync rules for any app whose action is pending or whose connections
    /// have changed.  Called from `App::update()` with the current connection list.
    pub fn tick(&mut self, connections: &[Connection]) {
        if !self.nft_initialized {
            return;
        }

        if self.sync_needed {
            self.sync_pending_rules(connections);
            self.sync_needed = false;
        }

        // Periodic full reconciliation (every ~30 ticks).
        self.refresh_tick = self.refresh_tick.wrapping_add(1);
        if self.refresh_tick % 30 == 0 {
            self.reconcile_rules(connections);
        }

        // Recompute the list of blocked apps that can't be enforced
        // (same UID and no cgroup path).
        self.update_unblockable_apps(connections);
    }

    // ─── Action / blocking API ────────────────────────────────────

    /// Block an app by its process name or executable path.
    pub fn block_app(&mut self, app_path: &str) -> bool {
        if !self.nft_initialized {
            return false;
        }
        let name = Self::normalize_name(app_path);
        // We have no connections here, so just store and sync later.
        self.apply_action(&name, None, FirewallAppAction::Deny)
    }

    /// Apply an action to an app.  Connections are resolved on the next tick.
    pub fn apply_action(
        &mut self,
        name: &str,
        _path: Option<&str>,
        action: FirewallAppAction,
    ) -> bool {
        if !self.nft_initialized {
            return false;
        }
        let normalized = Self::normalize_name(name);

        match action {
            FirewallAppAction::Deny | FirewallAppAction::Drop => {
                if self.nft_initialized {
                    // Remove any existing rules for this app.
                    self.remove_psnet_rules_internal(&normalized);
                }
                self.app_actions.insert(normalized.clone(), action.clone());
                self.blocked_apps.insert(normalized.clone());
                self.sync_needed = true;
            }
            FirewallAppAction::Allow => {
                if self.nft_initialized {
                    self.remove_psnet_rules_internal(&normalized);
                }
                // Remove from app_actions entirely — Allow is the default
                // state and shows as "ALLOWED" in the UI.
                self.app_actions.remove(&normalized);
                self.blocked_apps.remove(&normalized);
            }
        }

        self.save_state();
        true
    }

    /// Remove all PSNET rules for a single app.
    pub fn remove_psnet_rules(&mut self, name: &str) {
        let normalized = Self::normalize_name(name);
        self.remove_psnet_rules_internal(&normalized);
        self.app_actions.remove(&normalized);
        self.blocked_apps.remove(&normalized);
        self.save_state();
    }

    /// Remove ALL PSNET rules — deletes the nftables table entirely.
    pub fn reset_all_psnet_rules(&mut self) {
        if self.nft_initialized {
            let _ = nftables::delete_table();
            // Re-create the empty table so future rules work.
            self.nft_initialized = nftables::ensure_table();
            self.enabled = self.nft_initialized;
        }
        self.app_actions.clear();
        self.blocked_apps.clear();
        self.rule_handles.clear();
        self.uid_map.clear();
        self.cgroup_map.clear();
        self.iptables_cgroup_paths.clear();
        nftables::cleanup_iptables_cgroup();
        self.save_state();
    }

    /// Re-read rules from nftables and reconcile with our state.
    pub fn refresh_rules(&mut self) {
        if !self.nft_initialized {
            return;
        }
        let current = nftables::list_rules();
        // Collect all handles we know about.
        let mut known_handles: HashSet<u64> = HashSet::new();
        for handles in self.rule_handles.values() {
            for (h, _) in handles {
                known_handles.insert(*h);
            }
        }

        // Find handles present in nftables that we know about (ours) vs orphaned.
        let live_handles: HashSet<u64> = current.iter().map(|(h, _)| *h).collect();

        // Remove stale entries from our map (handles we think we have but nft dropped).
        for handles in self.rule_handles.values_mut() {
            handles.retain(|(h, _)| live_handles.contains(h));
        }
        self.rule_handles.retain(|_, v| !v.is_empty());

        // Remove orphaned app_actions entries (nft has no rules for them).
        self.app_actions.retain(|_name, action| {
            matches!(action, FirewallAppAction::Allow)
        });
        self.blocked_apps.retain(|name| {
            self.rule_handles.contains_key(&name.to_lowercase())
        });

        self.refresh_tick = 0;
    }

    // ─── Query methods ────────────────────────────────────────────

    pub fn get_app_action(&self, name: &str) -> Option<&FirewallAppAction> {
        self.app_actions.get(&name.to_lowercase())
    }

    pub fn is_psnet_blocked(&self, name: &str) -> bool {
        match self.app_actions.get(&name.to_lowercase()) {
            Some(FirewallAppAction::Deny) | Some(FirewallAppAction::Drop) => true,
            _ => false,
        }
    }

    pub fn effective_status(&self, name: &str) -> (&'static str, bool) {
        if self.blocked_apps.contains(name) {
            return ("BLOCKED", true);
        }
        match self.app_actions.get(&name.to_lowercase()) {
            Some(FirewallAppAction::Deny) => ("DENY", true),
            Some(FirewallAppAction::Drop) => ("DROP", true),
            None => ("ALLOWED", false),
            // Allow entries are removed from the map on insertion, but if one
            // somehow exists treat it as ALLOWED.
            Some(FirewallAppAction::Allow) => ("ALLOWED", false),
        }
    }

    // ─── Mode toggles ─────────────────────────────────────────────

    pub fn toggle_ask_to_connect(&mut self) {
        self.mode = match self.mode {
            FirewallMode::Normal => FirewallMode::AskToConnect,
            FirewallMode::AskToConnect => FirewallMode::Lockdown,
            FirewallMode::Lockdown => FirewallMode::Normal,
        };
    }

    pub fn check_pending(&mut self, name: &str) {
        if self.mode == FirewallMode::AskToConnect {
            let lower = name.to_lowercase();
            if let Some(pos) = self.pending_apps.iter().position(|p| p == &lower) {
                self.pending_apps.remove(pos);
            }
        }
    }

    /// Toggle the default policy on the nftables output chain.
    pub fn toggle_default_policy(&mut self) {
        self.default_deny = !self.default_deny;
        if !self.nft_initialized {
            return;
        }
        let policy = if self.default_deny { "drop" } else { "accept" };
        let cmd = format!(
            "chain inet psnet-filter output {{ policy {}; }}\n",
            policy
        );
        let _ = nftables::run_nft_stdin(&cmd);
        self.save_state();
    }

    // ─── State persistence ────────────────────────────────────────

    fn save_state(&self) {
        #[derive(serde::Serialize)]
        struct State {
            app_actions: Vec<(String, String)>,
            uid_map: Vec<(String, Vec<u32>)>,
            default_deny: bool,
        }

        let app_actions: Vec<(String, String)> = self
            .app_actions
            .iter()
            .map(|(k, v)| {
                let s = match v {
                    FirewallAppAction::Allow => "Allow",
                    FirewallAppAction::Deny => "Deny",
                    FirewallAppAction::Drop => "Drop",
                };
                (k.clone(), s.to_string())
            })
            .collect();

        let uid_map: Vec<(String, Vec<u32>)> =
            self.uid_map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

        let state = State {
            app_actions,
            uid_map,
            default_deny: self.default_deny,
        };

        if let Ok(json) = serde_json::to_string(&state) {
            let _ = std::fs::write(&self.state_path, json);
        }
    }

    fn load_state(&mut self) {
        let Ok(data) = std::fs::read_to_string(&self.state_path) else {
            return;
        };
        #[derive(serde::Deserialize)]
        struct State {
            app_actions: Vec<(String, String)>,
            uid_map: Vec<(String, Vec<u32>)>,
            default_deny: bool,
        }
        let Ok(state) = serde_json::from_str::<State>(&data) else {
            return;
        };

        self.default_deny = state.default_deny;
        for (key, val) in &state.app_actions {
            let action = match val.as_str() {
                // "Allow" is the default — no need to persist it.
                "Allow" => continue,
                "Deny" => FirewallAppAction::Deny,
                "Drop" => FirewallAppAction::Drop,
                _ => continue,
            };
            self.app_actions.insert(key.clone(), action);
        }
        if state.app_actions.iter().any(|(_, a)| a == "Deny" || a == "Drop") {
            self.sync_needed = true;
        }
        for (key, uids) in &state.uid_map {
            self.uid_map.insert(key.clone(), uids.clone());
        }
    }

    // ─── Internal helpers ─────────────────────────────────────────

    /// Discard all app-level state (actions, blocked sets, rule caches).
    fn clear_state(&mut self) {
        self.app_actions.clear();
        self.blocked_apps.clear();
        self.rule_handles.clear();
        self.uid_map.clear();
        self.cgroup_map.clear();
        self.iptables_cgroup_paths.clear();
        self.unblockable_apps.clear();
        self.default_deny = false;
    }

    /// Normalise an app name (extract filename from paths, lower-cased).
    fn normalize_name(name: &str) -> String {
        if name.contains('/') || name.contains('\\') {
            std::path::Path::new(name)
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| name.to_string())
        } else {
            name.to_string()
        }
        .to_lowercase()
    }

    /// Remove all nftables rules tracked for a single app.
    fn remove_psnet_rules_internal(&mut self, normalized: &str) {
        if let Some(handles) = self.rule_handles.remove(normalized) {
            for (handle, _) in &handles {
                let _ = nftables::remove_rule(*handle);
            }
        }
        if let Some(paths) = self.iptables_cgroup_paths.remove(normalized) {
            for path in &paths {
                let _ = nftables::remove_iptables_cgroup_rule(path);
            }
        }
        self.uid_map.remove(normalized);
        self.cgroup_map.remove(normalized);
    }

    /// After loading state, try to recreate rules for all blocked apps.
    fn sync_pending_rules(&mut self, connections: &[Connection]) {
        let blocked: Vec<(String, FirewallAppAction)> = self
            .app_actions
            .iter()
            .filter(|(_, a)| matches!(a, FirewallAppAction::Deny | FirewallAppAction::Drop))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (name, action) in &blocked {
            if self.rule_handles.contains_key(name) {
                continue;
            }
            self.add_block_rules(name, action, connections);
        }
    }

    /// Reconcile rules every ~30 ticks — add rules for new PIDs / cgroup paths,
    /// remove stale ones for processes that died.
    fn reconcile_rules(&mut self, connections: &[Connection]) {
        let blocked: Vec<(String, FirewallAppAction)> = self
            .app_actions
            .iter()
            .filter(|(_, a)| matches!(a, FirewallAppAction::Deny | FirewallAppAction::Drop))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        for (name, action) in &blocked {
            let pids = self.resolve_pids_by_name(name, connections);

            // ── cgroup paths (nftables socket cgroupv2) ──
            let nft_cgroup_available = nftables::cgroupv2_path_supported();
            if nft_cgroup_available {
                let live_paths: Vec<String> = pids
                    .iter()
                    .filter_map(|pid| {
                        let path = nftables::get_cgroupv2_path(*pid)?;
                        if path.contains(".scope") || path.contains(".service") {
                            Some(path)
                        } else {
                            None
                        }
                    })
                    .collect();
                let known_paths = self.cgroup_map.get(name).cloned().unwrap_or_default();

                for path in &live_paths {
                    if !known_paths.contains(path) {
                        if let Some(handle) = nftables::add_rule_cgroup(path, action) {
                            self.rule_handles
                                .entry(name.clone())
                                .or_default()
                                .push((handle, format!("cgroupv2 \"{path}\"")));
                        }
                    }
                }

                for path in &known_paths {
                    if !live_paths.contains(path) {
                        if let Some(handles) = self.rule_handles.get(name) {
                            let to_remove: Vec<u64> = handles
                                .iter()
                                .filter(|(_, desc)| desc.contains(path))
                                .map(|(h, _)| *h)
                                .collect();
                            for h in to_remove {
                                let _ = nftables::remove_rule(h);
                            }
                        }
                    }
                }
                if live_paths != known_paths {
                    self.cgroup_map.insert(name.clone(), live_paths);
                }
            }

            // ── iptables cgroup fallback (when nft cgroupv2 syntax unavailable) ──
            let ipt_cgroup_ok = nftables::iptables_cgroup_supported();
            if !nft_cgroup_available && ipt_cgroup_ok {
                let live_paths: Vec<String> = pids
                    .iter()
                    .filter_map(|pid| {
                        let path = nftables::get_cgroupv2_path(*pid)?;
                        if path.contains(".scope") || path.contains(".service") {
                            Some(path)
                        } else {
                            None
                        }
                    })
                    .collect();
                let known_paths = self.iptables_cgroup_paths.get(name).cloned().unwrap_or_default();

                for path in &live_paths {
                    if !known_paths.contains(path) {
                        if nftables::add_iptables_cgroup_rule(path) {
                            self.iptables_cgroup_paths
                                .entry(name.clone())
                                .or_default()
                                .push(path.clone());
                        }
                    }
                }

                for path in &known_paths {
                    if !live_paths.contains(path) {
                        let _ = nftables::remove_iptables_cgroup_rule(path);
                    }
                }
                if live_paths != known_paths {
                    self.iptables_cgroup_paths.insert(name.clone(), live_paths);
                }
            }

            // ── UID fallback (for system services) ──────────────
            // Only used when NO cgroup method is available, and only for
            // system service UIDs (< 1000).  Blocking user UIDs (>= 1000)
            // would block all processes under that user.
            if !nft_cgroup_available && !ipt_cgroup_ok {
                let self_uid = unsafe { libc::geteuid() };
                let live_uids: Vec<u32> = pids
                    .iter()
                    .filter_map(|pid| {
                        let uid = nftables::get_uid_for_pid(*pid)?;
                        if uid == self_uid || uid >= 1000 { None } else { Some(uid) }
                    })
                    .collect();
                let known_uids = self.uid_map.get(name).cloned().unwrap_or_default();

                for uid in &live_uids {
                    if !known_uids.contains(uid) {
                        if let Some(handle) = nftables::add_rule_uid(*uid, action) {
                            self.rule_handles
                                .entry(name.clone())
                                .or_default()
                                .push((handle, format!("meta uid {uid}")));
                        }
                    }
                }
                for uid in &known_uids {
                    if !live_uids.contains(uid) {
                        if let Some(handles) = self.rule_handles.get(name) {
                            let to_remove: Vec<u64> = handles
                                .iter()
                                .filter(|(_, desc)| desc.contains(&format!("meta uid {uid}")))
                                .map(|(h, _)| *h)
                                .collect();
                            for h in to_remove {
                                let _ = nftables::remove_rule(h);
                            }
                        }
                    }
                }
                if live_uids != known_uids {
                    self.uid_map.insert(name.clone(), live_uids);
                }
            }
        }
    }

    /// Add nftables rules for a blocked app.
    ///
    /// Strategy (most-to-least preferred):
    /// 1. **cgroupv2 `socket cgroupv2 level <N> "<path>"`** — matches the app's
    ///    systemd scope unit.  Only that scope's sockets match (descendant-only
    ///    via `cgroup_is_descendant`).  This is the only method that works for
    ///    user UIDs (>= 1000).
    /// 2. **iptables `-m cgroup --path "<path>"`** — fallback when nftables
    ///    doesn't support `socket cgroupv2` with the `level` syntax.
    /// 3. **UID `meta skuid <N>`** — matches ALL processes under that UID, so
    ///    only safe for system service UIDs (< 1000) where the UID is dedicated.
    fn add_block_rules(
        &mut self,
        app_name: &str,
        action: &FirewallAppAction,
        connections: &[Connection],
    ) {
        let pids = self.resolve_pids_by_name(app_name, connections);
        if pids.is_empty() {
            return;
        }

        let self_uid = unsafe { libc::geteuid() };
        let mut any_cgroup_success = false;
        let mut uid_fallbacks = Vec::new();
        let nft_cgroup_ok = nftables::cgroupv2_path_supported();
        let ipt_cgroup_ok = nftables::iptables_cgroup_supported();

        for pid in &pids {
            let mut cgroup_worked = false;

            // Try nftables cgroupv2 path syntax first.
            if nft_cgroup_ok {
                if let Some(path) = nftables::get_cgroupv2_path(*pid) {
                    if path.contains(".scope") || path.contains(".service") {
                        if let Some(handle) = nftables::add_rule_cgroup(&path, action) {
                            self.rule_handles
                                .entry(app_name.to_string())
                                .or_default()
                                .push((handle, format!("cgroupv2 \"{path}\"")));
                            self.cgroup_map
                                .entry(app_name.to_string())
                                .or_default()
                                .push(path);
                            cgroup_worked = true;
                        }
                    }
                }
            }

            // Fallback: iptables -m cgroup --path.
            if !cgroup_worked && ipt_cgroup_ok {
                if let Some(ref path) = nftables::get_cgroupv2_path(*pid) {
                    if path.contains(".scope") || path.contains(".service") {
                        if nftables::add_iptables_cgroup_rule(path) {
                            self.iptables_cgroup_paths
                                .entry(app_name.to_string())
                                .or_default()
                                .push(path.clone());
                            cgroup_worked = true;
                        }
                    }
                }
            }

            if cgroup_worked {
                any_cgroup_success = true;
                continue;
            }

            // UID fallback — only for system service UIDs (< 1000) AND only
            // when NO pid for this app could use cgroup-based blocking (UID
            // is too broad — it blocks all apps under that user).
            if !any_cgroup_success {
                if let Some(uid) = nftables::get_uid_for_pid(*pid) {
                    if uid != self_uid && uid < 1000 {
                        uid_fallbacks.push(uid);
                    }
                }
            }
        }

        // Only add UID rules if cgroup-based blocking completely failed.
        if !any_cgroup_success {
            for uid in &uid_fallbacks {
                if let Some(handle) = nftables::add_rule_uid(*uid, action) {
                    self.rule_handles
                        .entry(app_name.to_string())
                        .or_default()
                        .push((handle, format!("meta uid {uid}")));
                }
            }
            if !uid_fallbacks.is_empty() {
                self.uid_map.insert(app_name.to_string(), uid_fallbacks);
            }
        }
    }

    /// Find blocked apps that can't be enforced — neither cgroupv2 nor UID
    /// blocking works for them.  Populates `unblockable_apps` for the UI.
    fn update_unblockable_apps(&mut self, connections: &[Connection]) {
        let self_uid = unsafe { libc::geteuid() };
        let mut unblockable = Vec::new();

        for (name, action) in &self.app_actions {
            if !matches!(action, FirewallAppAction::Deny | FirewallAppAction::Drop) {
                continue;
            }

            // Already enforced via nft cgroup, iptables cgroup, or UID — fine.
            if self.cgroup_map.contains_key(name)
                || self.iptables_cgroup_paths.contains_key(name)
                || self.uid_map.contains_key(name)
            {
                continue;
            }

            let pids = self.resolve_pids_by_name(name, connections);
            let has_scope_path = |pid: u32| -> bool {
                nftables::get_cgroupv2_path(pid)
                    .map(|p| p.contains(".scope") || p.contains(".service"))
                    .unwrap_or(false)
            };
            let nft_cgroup_ok = nftables::cgroupv2_path_supported();
            let ipt_cgroup_ok = nftables::iptables_cgroup_supported();
            let cgroup_enforceable = (nft_cgroup_ok || ipt_cgroup_ok)
                && pids.iter().any(|pid| has_scope_path(*pid));
            // UID blocking is only viable for system service UIDs (< 1000).
            let uid_enforceable = pids.iter().any(|pid| {
                nftables::get_uid_for_pid(*pid)
                    .map(|uid| uid != self_uid && uid < 1000)
                    .unwrap_or(false)
            });

            if !cgroup_enforceable && !uid_enforceable {
                unblockable.push(name.clone());
            }
        }

        self.unblockable_apps = unblockable;
    }

    /// Resolve PIDs for a process name from current connections (fast) or
    /// by scanning `/proc/*/comm` (fallback).
    fn resolve_pids_by_name(&self, name: &str, connections: &[Connection]) -> Vec<u32> {
        let mut pids = Vec::new();

        // Fast path: current connections.
        for conn in connections {
            if conn.process_name.to_lowercase() == name && conn.pid > 0 {
                if !pids.contains(&conn.pid) {
                    pids.push(conn.pid);
                }
            }
        }

        if !pids.is_empty() {
            return pids;
        }

        // Fallback: scan /proc.
        let Ok(entries) = std::fs::read_dir("/proc") else {
            return pids;
        };
        for entry in entries.flatten() {
            let pid_str = entry.file_name();
            let Ok(pid) = pid_str.to_string_lossy().parse::<u32>() else {
                continue;
            };
            let comm = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                .unwrap_or_default();
            let comm = comm.trim().to_lowercase();
            if comm == name || name.contains(&comm) || comm.contains(name) {
                if !pids.contains(&pid) {
                    pids.push(pid);
                }
            }
        }

        pids
    }
}
