# Changelog

All notable changes to PSNET are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.2] - 2026-06-12

### Fixed

- **PID resolution on Debian 13/RPi** — fall back to `sudo -n ss -tunp` when running without `CAP_NET_ADMIN` and `ss` doesn't show the `users:` process column. Unprivileged users now see real PIDs instead of `-`.

## [1.1.1] - 2026-06-12

### Fixed

- **Firewall cgroupv2 syntax** — fixed `socket cgroupv2` syntax to use the required `level <N>` keyword form (bare path syntax not supported on all nftables builds)
- **UID fallback too broad** — per-app blocking no longer falls through to `meta skuid` UID rules when cgroupv2 succeeds, and UID rules are restricted to system service UIDs (< 1000) only. Fixes Firefox block affecting Spotify/Chrome
- **iptables fallback** — switched from `iptables` to `iptables-legacy` on systems where the nft-backed iptables doesn't support `-m cgroup --path`

## [1.1.0] - 2026-06-11

### Added

- **Full nftables firewall management** — per-app block/allow/drop via `nft` CLI
  - Three-tier blocking strategy: cgroupv2 via nftables `socket cgroupv2` → cgroupv2 via `iptables -m cgroup` → UID-based `meta skuid`
  - Per-app granularity using systemd scope unit cgroupv2 paths (Firefox block doesn't affect Chrome)
  - iptables cgroupv2 fallback for systems where nftables < 1.0.0
  - Firewall state persistence across restarts (`~/.local/share/psnet/firewall_state.json`)
  - Default policy toggle (ALLOW-ALL / DENY-ALL)
  - Rule reconciliation every 30 ticks (auto-add rules for new processes, clean up stale ones)
  - Unblockable app detection (apps sharing user UID with no unique cgroup path)
- **Kernel version check** — reads `/proc/sys/kernel/osrelease`, warns if kernel < 4.19 (cgroupv2 path matching not supported)
- **Privilege guard** — explicit `/proc/self/status CapEff` check; non-root users without `CAP_NET_ADMIN` see firewall as DISABLED with orange status bar warning
- **Ambient capability setup via capset syscall** — `CAP_NET_ADMIN`+`CAP_NET_RAW` raised as ambient caps so child processes (`ss`, `nft`) inherit them without sudo
- **OUI vendor lookup from embedded database** — 35,000+ MAC prefix database resolves device manufacturers (Apple, Dell, Intel, etc.) in Devices and Networks tabs
- **Color-coded toast messages** — orange for permission/firewall warnings, green for normal status messages
- **PID column in Connections view** — shows process PID next to process name
- **Version display in title bar** — shows `v1.1.0` next to "◈ PSNET" in the header

### Changed

- **Firewall tab** — complete rewrite from stubs to real nftables integration
- **Connections tab** — PID column added after process name
- **Status bar** — shows kernel version in disabled firewall warning when applicable
- **Dashboard map** — contrast toggle (`c` key) for high-visibility mode
- **Screenshot** — updated to show Linux port

### Fixed

- **Process resolution on ARM (Raspberry Pi)** — `CAP_NET_ADMIN` now raised as ambient capability so `ss -tunp` can resolve PIDs for all users' processes
- **IP byte order in /proc/net parsing** — corrected little-endian byte swap for IPv4 addresses
- **OUI lookup for network interface vendor** — Networks tab now shows correct adapter vendor
- **Bluetooth device vendor resolution** — uses OUI database instead of hardcoded labels
- **Firewall status alignment** — effective app status now correctly reflects actual rule presence
- **Toast message type consistency** — `ALLOW` normalized to `ALLOWED` across the firewall UI

### Security

- Firewall actions are blocked when process lacks `CAP_NET_ADMIN` — no false sense of control
- Stale firewall state from previous root sessions is automatically purged on unprivileged startup
- Kernel version validated before attempting cgroupv2 path-based blocking

## [1.0.0] - 2026-03-XX

### Added

- Initial Linux port of PSNET — complete reimplementation of the Windows codebase
- 9 interactive tabs: Dashboard, Connections, Servers, Packets, Topology, Alerts, Firewall, Devices, Networks
- Real-time traffic graphs with selectable time ranges (5m / 15m / 1h / 24h)
- World map with live connection dots colored by TCP state
- DNS-resolved hostnames with service port labeling
- 200+ server fingerprinting with Wappalyzer technology detection (6,500+ signatures)
- TCP exposure panel with bind address badges
- Wireshark-style packet inspector with protocol layer dissection
- Hub-and-spoke topology visualization
- Categorized security alert engine with snooze
- ARP-based LAN device discovery with OUI vendor lookup
- Multi-adapter view (Ethernet, Wi-Fi, VPNs, Docker, Bluetooth)
- 4 embedded databases: GeoIP (DB-IP), OUI (35K+ prefixes), fingerprints, Wappalyzer
- Interface cycling via `n` key or `PSNET_INTERFACE` env var
- CI/CD: x86_64 and ARM64 builds, deb + RPM packaging, GitHub Releases
