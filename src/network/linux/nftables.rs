//! Raw nftables operations via the `nft` CLI.
//!
//! All functions shell out to `nft` (must be installed and the process must
//! have `CAP_NET_ADMIN`).  Every rule we add goes into the `inet psnet-filter`
//! table so it can be cleanly managed and removed.
//!
//! Where the running nftables version doesn't support `socket cgroupv2 level <N> "<path>"`
//! we fall back to `iptables-legacy -m cgroup --path` for per-app cgroupv2 path
//! matching.  The kernel supports path-based matching since 4.19.
//!
//! # Permission model
//! The binary needs `CAP_NET_ADMIN` for nft write operations and `CAP_NET_ADMIN`
//! for iptables operations.  At startup we probe whether direct write access
//! is available.  If not, we try `sudo -n nft` / `sudo -n iptables`.  The
//! chosen mode is cached for the lifetime of the process.

use std::io::Write;
use std::process::Command;
use std::sync::OnceLock;

use crate::types::FirewallAppAction;

/// nftables match keyword for socket UID (probed at runtime).
static UID_KEYWORD: OnceLock<&'static str> = OnceLock::new();

/// Whether `socket cgroupv2 level <N> "<path>"` syntax is supported.
static CGROUPV2_PATH_SUPPORTED: OnceLock<bool> = OnceLock::new();

/// Whether `iptables -m cgroup --path "<path>"` is available as fallback.
static IPTABLES_CGROUP_SUPPORTED: OnceLock<bool> = OnceLock::new();

/// Cached iptables binary name (prefer `iptables-legacy`).
static IPTABLES_BIN: OnceLock<&'static str> = OnceLock::new();

/// Return the best iptables binary: iptables-legacy if available, else iptables.
fn iptables_bin() -> &'static str {
    IPTABLES_BIN.get_or_init(|| {
        if Command::new("iptables-legacy")
            .arg("--version")
            .output()
            .ok()
            .map_or(false, |o| o.status.success())
        {
            "iptables-legacy"
        } else {
            "iptables"
        }
    })
}

/// Which invocation method we use to run nft write operations.
#[derive(Clone, Copy, Debug, PartialEq)]
enum NftMode {
    Direct,
    Sudo,
}

static WRITE_MODE: OnceLock<Option<NftMode>> = OnceLock::new();

fn probe_write_mode() -> Option<NftMode> {
    *WRITE_MODE.get_or_init(|| {
        if probe_try("nft") {
            Some(NftMode::Direct)
        } else if probe_try("sudo") {
            Some(NftMode::Sudo)
        } else {
            None
        }
    })
}

fn probe_try(prefix: &str) -> bool {
    let add = match prefix {
        "nft" => Command::new("nft")
            .args(["add", "table", "inet", "psnet-probe"])
            .output(),
        "sudo" => Command::new("sudo")
            .args(["-n", "nft", "add", "table", "inet", "psnet-probe"])
            .output(),
        _ => return false,
    };
    let _ = match prefix {
        "nft" => Command::new("nft")
            .args(["delete", "table", "inet", "psnet-probe"])
            .output(),
        "sudo" => Command::new("sudo")
            .args(["-n", "nft", "delete", "table", "inet", "psnet-probe"])
            .output(),
        _ => return false,
    };
    add.ok().map_or(false, |o| o.status.success())
}

/// Probe the UID keyword.  Assumes `inet psnet-filter` already exists.
fn probe_uid_keyword() -> &'static str {
    // skuid preferred (newer nftables).
    let r1 = nft_stdin("add rule inet psnet-filter output meta skuid 0 drop\n");
    let _ = nft_stdin("flush chain inet psnet-filter output\n");
    if r1.is_ok() {
        return "skuid";
    }
    // Fallback to uid.
    let r2 = nft_stdin("add rule inet psnet-filter output meta uid 0 drop\n");
    let _ = nft_stdin("flush chain inet psnet-filter output\n");
    if r2.is_ok() {
        return "uid";
    }
    "skuid"
}

/// Probe cgroupv2 path syntax in nftables.
///
/// Uses the `socket cgroupv2 level <N> "<path>"` form (the bare path syntax
/// without `level` is not supported by all nftables builds).
fn probe_cgroupv2_path_syntax() -> bool {
    let r = nft_stdin(
        "add rule inet psnet-filter output socket cgroupv2 level 1 \"system.slice\" drop\n",
    );
    let _ = nft_stdin("flush chain inet psnet-filter output\n");
    r.is_ok()
}

/// Probe iptables -m cgroup --path support (fallback for cgroupv2 blocking).
fn probe_iptables_cgroup() -> bool {
    let bin = iptables_bin();
    if bin.is_empty() {
        return false;
    }
    // Try adding a test rule with cgroup path "/".
    // Use -w (wait) to avoid "another app is holding xtables lock" errors.
    let add = Command::new(bin)
        .args(["-C", "OUTPUT", "-m", "cgroup", "--path", "/", "-j", "DROP", "-w", "2"])
        .output();
    if add.ok().map_or(false, |o| o.status.success()) {
        // Rule already exists (from a previous run), that's fine.
        return true;
    }
    let add = Command::new(bin)
        .args(["-A", "OUTPUT", "-m", "cgroup", "--path", "/", "-j", "DROP", "-w", "2"])
        .output();
    let ok = add.ok().map_or(false, |o| o.status.success());
    // Remove the test rule.
    let _ = Command::new(bin)
        .args(["-D", "OUTPUT", "-m", "cgroup", "--path", "/", "-j", "DROP", "-w", "2"])
        .output();
    ok
}

// ─── Public API ──────────────────────────────────────────────────────────

/// Check whether `nft` is available.
pub fn available() -> bool {
    Command::new("nft").arg("--version").output().is_ok()
}

/// Ensure the `inet psnet-filter` table exists and probe all features.
pub fn ensure_table() -> bool {
    if probe_write_mode().is_none() {
        return false;
    }

    let _ = nft(&["add", "table", "inet", "psnet-filter"]);
    let _ = nft(&[
        "add", "chain", "inet", "psnet-filter", "output",
        "{", "type", "filter", "hook", "output", "priority", "100;", "policy", "accept;", "}",
    ]);
    let _ = nft(&[
        "add", "chain", "inet", "psnet-filter", "input",
        "{", "type", "filter", "hook", "input", "priority", "100;", "policy", "accept;", "}",
    ]);

    if nft(&["list", "table", "inet", "psnet-filter"]).is_err() {
        return false;
    }

    UID_KEYWORD.get_or_init(probe_uid_keyword);

    let nft_cgroup = probe_cgroupv2_path_syntax();
    CGROUPV2_PATH_SUPPORTED.get_or_init(|| nft_cgroup);

    // Only probe iptables cgroup if nft cgroup path syntax is NOT available.
    if !nft_cgroup {
        let ipt_ok = probe_iptables_cgroup();
        IPTABLES_CGROUP_SUPPORTED.get_or_init(|| ipt_ok);
        if ipt_ok {
            init_iptables_cgroup_chain();
        }
    } else {
        IPTABLES_CGROUP_SUPPORTED.get_or_init(|| false);
    }

    true
}

/// Create the PSNET-CGROUP iptables chain and hook it into OUTPUT.
fn init_iptables_cgroup_chain() -> bool {
    let bin = iptables_bin();
    // Remove any residual chain from a previous crashed process.
    let _ = Command::new(bin)
        .args(["-D", "OUTPUT", "-j", "PSNET-CGROUP", "-w", "2"])
        .output();
    let _ = Command::new(bin)
        .args(["-F", "PSNET-CGROUP", "-w", "2"])
        .output();
    let _ = Command::new(bin)
        .args(["-X", "PSNET-CGROUP", "-w", "2"])
        .output();

    // Create the custom chain.
    let r1 = Command::new(bin)
        .args(["-N", "PSNET-CGROUP", "-w", "2"])
        .output();
    if !r1.ok().map_or(false, |o| o.status.success()) {
        return false;
    }
    // Hook it into the OUTPUT chain.
    let r2 = Command::new(bin)
        .args(["-I", "OUTPUT", "1", "-j", "PSNET-CGROUP", "-w", "2"])
        .output();
    r2.ok().map_or(false, |o| o.status.success())
}

/// Add a rule matching a cgroupv2 path via iptables.
pub fn add_iptables_cgroup_rule(path: &str) -> bool {
    let bin = iptables_bin();
    match Command::new(bin)
        .args(["-A", "PSNET-CGROUP", "-m", "cgroup", "--path", path, "-j", "DROP", "-w", "2"])
        .output()
    {
        Ok(o) if o.status.success() => true,
        Ok(_) => false,
        Err(_) => false,
    }
}

/// Remove a rule matching a cgroupv2 path via iptables.
pub fn remove_iptables_cgroup_rule(path: &str) -> bool {
    let bin = iptables_bin();
    let r = Command::new(bin)
        .args(["-D", "PSNET-CGROUP", "-m", "cgroup", "--path", path, "-j", "DROP", "-w", "2"])
        .output();
    r.ok().map_or(false, |o| o.status.success())
}

/// Flush and remove the PSNET-CGROUP iptables chain.
pub fn cleanup_iptables_cgroup() {
    let bin = iptables_bin();
    let _ = Command::new(bin)
        .args(["-D", "OUTPUT", "-j", "PSNET-CGROUP", "-w", "2"])
        .output();
    let _ = Command::new(bin)
        .args(["-F", "PSNET-CGROUP", "-w", "2"])
        .output();
    let _ = Command::new(bin)
        .args(["-X", "PSNET-CGROUP", "-w", "2"])
        .output();
}

/// Add an nftables rule matching a specific socket UID.
pub fn add_rule_uid(uid: u32, action: &FirewallAppAction) -> Option<u64> {
    let action_str = match action {
        FirewallAppAction::Deny | FirewallAppAction::Drop => "drop",
        FirewallAppAction::Allow => return None,
    };
    let kw = UID_KEYWORD.get().copied().unwrap_or("skuid");
    let cmd = format!(
        "add rule inet psnet-filter output meta {} {} {}\n",
        kw, uid, action_str
    );
    match nft_stdin(&cmd) {
        Ok(_) => {
            let handle = extract_last_handle();
            handle
        }
        Err(_) => None
    }
}

/// Remove a single nftables rule by its handle.
pub fn remove_rule(handle: u64) -> bool {
    nft(&[
        "delete", "rule", "inet", "psnet-filter", "output", "handle", &handle.to_string(),
    ]).is_ok()
}

/// List all PSNET nftables rules with their handles.
pub fn list_rules() -> Vec<(u64, String)> {
    let Ok(output) = nft(&["-a", "list", "chain", "inet", "psnet-filter", "output"]) else {
        return Vec::new();
    };
    parse_rule_handles(&output)
}

/// Delete the entire `inet psnet-filter` nftables table.
pub fn delete_table() -> bool {
    nft(&["delete", "table", "inet", "psnet-filter"]).is_ok()
}

/// Detect the running firewall backend.
pub fn detect_backend() -> String {
    let Ok(output) = nft(&["list", "ruleset"]) else {
        return "none".into();
    };
    if output.contains("ufw") || output.contains("table inet ufw") {
        "ufw".into()
    } else if output.contains("table inet ") || output.contains("table ip ") {
        "nftables".into()
    } else {
        "none".into()
    }
}

/// Read UID for a PID from `/proc/<pid>/status`.
pub fn get_uid_for_pid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if line.starts_with("Uid:") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1].parse().ok();
            }
        }
    }
    None
}

/// Read the cgroupv2 path for a PID from `/proc/<pid>/cgroup`.
pub fn get_cgroupv2_path(pid: u32) -> Option<String> {
    let data = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    for line in data.lines() {
        if let Some(path) = line.strip_prefix("0::") {
            let path = path.trim().to_string();
            if !path.is_empty() {
                return Some(path);
            }
        }
    }
    None
}

/// Add an nftables rule matching a cgroupv2 path (using `socket cgroupv2 level <N>`).
/// Returns None when the path syntax isn't supported by the running nftables.
///
/// Uses the mandatory `level <N>` syntax for cross-compatibility (bare path
/// syntax isn't supported by all nftables builds).
pub fn add_rule_cgroup(path: &str, action: &FirewallAppAction) -> Option<u64> {
    if !CGROUPV2_PATH_SUPPORTED.get().copied().unwrap_or(false) {
        return None;
    }
    let action_str = match action {
        FirewallAppAction::Deny | FirewallAppAction::Drop => "drop",
        FirewallAppAction::Allow => return None,
    };
    // Strip leading / and compute the ancestor level count.
    let stripped = path.trim_start_matches('/');
    let level = stripped.split('/').count().max(1);
    let cmd = format!(
        "add rule inet psnet-filter output socket cgroupv2 level {} \"{}\" {}\n",
        level, stripped, action_str
    );
    match nft_stdin(&cmd) {
        Ok(_) => extract_last_handle(),
        Err(_) => None,
    }
}

/// Exposed for `toggle_default_policy` in firewall.rs.
pub fn run_nft_stdin(input: &str) -> Result<String, String> {
    nft_stdin(input)
}

/// Whether the nft cgroupv2 path-based syntax is supported.
pub fn cgroupv2_path_supported() -> bool {
    CGROUPV2_PATH_SUPPORTED.get().copied().unwrap_or(false)
}

/// Whether the iptables cgroupv2 path fallback is supported.
pub fn iptables_cgroup_supported() -> bool {
    IPTABLES_CGROUP_SUPPORTED.get().copied().unwrap_or(false)
}

/// Check whether the current process has `CAP_NET_ADMIN` in its effective set.
pub fn has_cap_net_admin_effective() -> bool {
    let data = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    for line in data.lines() {
        if line.starts_with("CapEff:") {
            if let Some(hex) = line["CapEff:".len()..].trim().split_whitespace().next() {
                let mask = u64::from_str_radix(hex, 16).unwrap_or(0);
                return (mask & (1u64 << 12)) != 0; // CAP_NET_ADMIN = 12
            }
        }
    }
    false
}

/// Whether the process has enough privileges to manage firewall rules.
/// Returns true if euid == 0 (root) OR CAP_NET_ADMIN is in the effective set.
pub fn can_manage_firewall() -> bool {
    (unsafe { libc::geteuid() == 0 }) || has_cap_net_admin_effective()
}

/// Read the kernel version string from `/proc/sys/kernel/osrelease`.
/// Returns something like `"5.15.0-91-generic"` or `None` on error.
pub fn kernel_version_str() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| s.trim().to_string())
}

/// Parse the kernel major.minor version.
/// Returns `(major, minor)` or `None` if parsing fails.
pub fn kernel_version() -> Option<(u32, u32)> {
    let s = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    let s = s.trim();
    let parts: Vec<&str> = s.splitn(3, '.').collect();
    if parts.len() < 2 {
        return None;
    }
    let major = parts[0].parse().ok()?;
    let minor = parts[1].parse().ok()?;
    Some((major, minor))
}

/// Whether the kernel is old enough that we cannot do per-app blocking.
/// cgroupv2 path-based socket matching (required for blocking individual
/// user apps without affecting the entire UID) needs kernel >= 4.19.
pub fn kernel_too_old_for_cgroup() -> bool {
    kernel_version()
        .map(|(major, minor)| major < 4 || (major == 4 && minor < 19))
        .unwrap_or(false)
}

// ─── Internal helpers ────────────────────────────────────────────────────

fn nft(args: &[&str]) -> Result<String, String> {
    match probe_write_mode() {
        Some(NftMode::Direct) | None => run_args("nft", &[], args),
        Some(NftMode::Sudo) => run_args("sudo", &["-n", "nft"], args),
    }
}

fn nft_stdin(input: &str) -> Result<String, String> {
    match probe_write_mode() {
        Some(NftMode::Direct) | None => pipe_stdin("nft", &[], input),
        Some(NftMode::Sudo) => pipe_stdin("sudo", &["-n", "nft"], input),
    }
}

fn run_args(bin: &str, prefix: &[&str], args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new(bin);
    cmd.args(prefix);
    cmd.args(args);
    let output = cmd
        .output()
        .map_err(|e| format!("{bin} exec error: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn pipe_stdin(bin: &str, prefix: &[&str], input: &str) -> Result<String, String> {
    let mut child = Command::new(bin)
        .args(prefix)
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("{bin} spawn error: {e}"))?;

    if let Some(ref mut stdin) = child.stdin {
        stdin
            .write_all(input.as_bytes())
            .map_err(|e| format!("{bin} stdin write error: {e}"))?;
    }
    drop(child.stdin.take());

    let output = child
        .wait_with_output()
        .map_err(|e| format!("{bin} wait error: {e}"))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

fn extract_last_handle() -> Option<u64> {
    let list = list_rules();
    list.last().map(|(h, _)| *h)
}

fn parse_rule_handles(output: &str) -> Vec<(u64, String)> {
    let mut rules = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if let Some(pos) = line.find("# handle ") {
            let handle_str = line[pos + 9..].trim();
            if let Ok(handle) = handle_str.parse::<u64>() {
                let desc = line[..pos].trim().to_string();
                rules.push((handle, desc));
            }
        }
    }
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rule_handles() {
        let output = r#"table inet psnet-filter {
    chain output {
        type filter hook output priority 100; policy accept;
        meta uid 1001 reject # handle 12
        tcp dport 443 ip daddr 10.0.0.5 reject with tcp reset # handle 13
    }
}"#;
        let rules = parse_rule_handles(output);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].0, 12);
        assert_eq!(rules[0].1, "meta uid 1001 reject");
        assert_eq!(rules[1].0, 13);
        assert_eq!(rules[1].1, "tcp dport 443 ip daddr 10.0.0.5 reject with tcp reset");
    }

    #[test]
    fn test_empty_output() {
        let rules = parse_rule_handles("");
        assert!(rules.is_empty());
    }

    #[test]
    fn test_no_handles() {
        let output =
            "table inet psnet-filter {\n    chain output {\n        policy accept;\n    }\n}";
        let rules = parse_rule_handles(output);
        assert!(rules.is_empty());
    }
}
