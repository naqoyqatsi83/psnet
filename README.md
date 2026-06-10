<p align="center">
  <img src="https://img.shields.io/badge/rust-1.70%2B-orange?style=for-the-badge&logo=rust&logoColor=white" alt="Rust">
  <img src="https://img.shields.io/badge/platform-Linux-1793D1?style=for-the-badge&logo=linux&logoColor=white" alt="Linux">
  <img src="https://img.shields.io/badge/TUI-ratatui-blue?style=for-the-badge" alt="Ratatui">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="MIT License">
</p>

<h1 align="center">
  ◈ PSNET
</h1>

<p align="center">
  <strong>A beautiful real-time network monitor for your terminal — Linux port.</strong>
  <br>
  <em>9 tabs. GeoIP maps. Device discovery. Firewall. Packet capture. All in one binary.</em>
</p>

<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Install</a> •
  <a href="#tabs">Tabs</a> •
  <a href="#keybindings">Keys</a> •
  <a href="#screenshots">Screenshots</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#credits">Credits</a>
</p>

---

## What is PSNET?

**PSNET** is a TUI network monitor built in Rust for Linux. A single binary gives you 9 interactive tabs covering everything from live speed graphs and active connections to a world map, LAN device discovery, firewall management, topology visualization, and packet capture — all in a beautiful dark terminal UI.

This is a **Linux port** of the original [psmux/psnet](https://github.com/psmux/psnet) Windows project, reimplemented using Linux-native sources (`/proc`, `/sys`, `netlink`, `pcap`, `iproute2`, `iptables`).

## Screenshots

<p align="center">
  <em>Screenshots coming soon — help by submitting one!</em>
</p>

---

## Features

### 📊 Dashboard (GlassWire-style)
- **Traffic graph** with selectable time ranges (5m / 15m / 1h / 24h)
- **World map** showing live connection dots colored by TCP state
- **Top countries** by connection count with proportional bars
- **Network health** gauge (score based on active connections, threats, alerts, firewall status)
- **Top apps** by bandwidth bar chart

### 🔗 Connections
- **DNS-resolved hostnames** — see `github.com` instead of `140.82.121.4`
- **Service labels** — `HTTPS/TCP`, `DNS/UDP`, `SSH/TCP` instead of raw port numbers
- **Color-coded by state** — ESTABLISHED green, SYN_SENT cyan, TIME_WAIT purple, CLOSE_WAIT orange
- **Sortable columns** — Process, Remote Host, Service, State, Local Port
- **Localhost filter** — hide `127.0.0.1` noise (toggle with `x`)
- **Live filtering** — type to search by process, hostname, port, or service
- **Detail popup** — press Enter for full connection details with GeoIP, bandwidth, and timing

### 🖥️ Servers (Listening Ports)
- **Service fingerprinting** — identifies 200+ server types (nginx, PostgreSQL, Redis, Docker, VS Code, etc.)
- **Wappalyzer technology detection** — HTTP banner analysis with 6,500+ technology signatures
- **TCP exposure panel** — at-a-glance view of how many ports are network-facing (`*`) vs localhost-only
- **Bind address badges** — each server card shows a colored badge: red `*` for all-interfaces, blue `127.0.0.1` for localhost, gold for specific IPs
- **Responsive status** — UP/silent indicators, TLS detection, active connection counts
- **Version detection** — extracted from banners and HTTP headers

### 📦 Packets (Wireshark-style)
- **Expert-level packet inspector** with severity indicators (Chat / Note / Warn / Error)
- **Protocol layer dissection** — Ethernet → IP → TCP/UDP → Application
- **DNS enrichment** — resolved hostnames shown alongside IPs
- **Hex + ASCII payload view** in detail popup
- **Filterable** by protocol, IP, port, or process

### 🗺️ Topology
- **Hub-and-spoke network diagram** — your machine at center, connected to gateway, DNS, LAN devices, and remote hosts
- **Live connection lines** colored by state
- **Scrollable** with device details

### 🚨 Alerts
- **Categorized security alerts** — suspicious hosts, unusual ports, threat intelligence matches
- **Split-pane layout** with independent scrolling per category
- **Detail popup** with full alert context and recommended actions

### 🛡️ Firewall
- **App-centric firewall management** — see which apps are making connections
- **Block/Allow per app** — toggle firewall rules directly from the TUI
- **Rule status indicators** — blocked (red), allowed (green), no rule (dim)

### 📡 Devices (LAN Scanner)
- **ARP-based device discovery** on your local network
- **OUI vendor lookup** — 35,000+ MAC prefix database identifies device manufacturers (Apple, Dell, Intel, etc.)
- **Sortable table** — IP, hostname, MAC, vendor, open ports, online status
- **Sent/received byte counters** per device

### 🌐 Networks
- **Multi-adapter view** — Ethernet, Wi-Fi, VPNs, Docker bridges, virtual interfaces
- **Bluetooth section** (collapsible)
- **Tunnel detection** — identifies VPN tunnels, mesh networks, and container overlays
- **Adapter status** — IP addresses, gateway, DNS, link speed

### ⚡ Always Visible
- **Speed section** (top) — download/upload sparkline waveforms, gauge bars, peak/total counters
- **Wire preview** (bottom) — live packet payload snippets with direction indicators (requires root / CAP_NET_RAW)
- **Title bar** — interface name, active/total connections, session timer, activity indicator

### 🌍 Embedded Databases
All data files compile into the binary — nothing to download or configure:
- **GeoIP** — DB-IP country-level database (~7 MB) for world map and country enrichment
- **Fingerprints** — 200+ server identification signatures
- **Wappalyzer** — 6,500+ web technology detection rules
- **OUI** — 35,000+ MAC vendor prefix database

---

## Installation

### From Source

```bash
git clone https://github.com/naqoyqatsi83/psnet.git
cd psnet
cargo build --release
sudo ./target/release/psnet
```

### Using Cargo

```bash
cargo install --git https://github.com/naqoyqatsi83/psnet.git
psnet
```

### Requirements

- **Linux** (tested on Ubuntu 24.04, should work on any modern distribution)
- **Rust 1.70+** for building from source
- **libpcap development headers** for building:

  | Distro | Command |
  |--------|---------|
  | Ubuntu/Debian | `sudo apt install libpcap0.8-dev` |
  | Fedora/RHEL | `sudo dnf install libpcap-devel` |
  | Arch | `sudo pacman -S libpcap` |
  | openSUSE | `sudo zypper install libpcap-devel` |

### Runtime Dependencies

These are typically pre-installed on all Linux distributions:

- `libpcap` — packet capture
- `iproute2` — local IP address detection (`ip` command)
- `iptables` or `nftables` — firewall rule reading
- `libc` — standard C library

### Root / Non-root

- **Run as root** — all features available including packet capture
- **Run without root** — packet capture will show a warning; set `CAP_NET_RAW` on the binary to enable it:
  ```bash
  sudo setcap cap_net_raw+ep ./target/release/psnet
  ```

### Interface Selection

Press `n` to cycle through available network interfaces. The current interface is shown in the title bar.

---

## Tabs

| # | Tab | Description |
|---|-----|-------------|
| 1 | **Dashboard** | GlassWire-style overview — traffic graph, world map, health gauge, top apps/countries |
| 2 | **Connections** | Live connection table with DNS hostnames, service labels, process names, state |
| 3 | **Servers** | Listening ports with fingerprinted service names, bind address badges, exposure panel |
| 4 | **Packets** | Wireshark-style packet inspector with protocol dissection and hex view |
| 5 | **Topology** | Hub-and-spoke network diagram of your machine's connections |
| 6 | **Alerts** | Categorized security alerts with severity and recommendations |
| 7 | **Firewall** | Per-app firewall management — block/allow apps |
| 8 | **Devices** | LAN device scanner with MAC vendor lookup, hostname resolution |
| 9 | **Networks** | Multi-adapter view — VPNs, Docker bridges, virtual interfaces |

Press `Tab` / `Shift+Tab` to cycle through them.

---

## Keybindings

### Global

| Key | Action |
|-----|--------|
| `q` / `Ctrl+C` | Quit |
| `Tab` / `Shift+Tab` | Next / Previous tab |
| `n` | Cycle network interface |
| `↑` `↓` | Scroll |
| `PgUp` `PgDn` | Scroll fast |
| `Home` `End` | Jump to top / bottom |
| `Enter` | Open detail popup for selected item |
| `Esc` | Close popup / Clear filter |

### Dashboard

| Key | Action |
|-----|--------|
| `1`-`4` | Select time range (5m / 15m / 1h / 24h) |
| `m` | Toggle full-screen world map |

### Connections

| Key | Action |
|-----|--------|
| `1`-`5` | Sort by column |
| `l` | Toggle LISTEN connections |
| `x` | Toggle localhost filter |
| `f` + typing | Live filter |

### Servers

| Key | Action |
|-----|--------|
| `s` | Trigger full scan (enumerate + probe + classify) |
| `o` | Open server's folder in file manager |
| `y` | Copy exe path to clipboard |
| `f` + typing | Live filter |

### Firewall

| Key | Action |
|-----|--------|
| `b` | Block selected app |
| `a` | Allow selected app |
| `d` | Delete firewall rule |

---

## How It Works

### Connection Tracking
Reads `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, `/proc/net/udp6` to enumerate all TCP/UDP connections with owning process PIDs. Process names are resolved via `/proc/<pid>/comm` and `/proc/<pid>/cmdline`.

### DNS Resolution
Reads `/etc/hosts` combined with periodic `getaddrinfo` lookups and service port mapping to show hostnames alongside IPs.

### GeoIP
The [DB-IP](https://db-ip.com/) country-level MaxMind-format database is embedded in the binary. Lookups are instantaneous — no network calls.

### Service Fingerprinting
A custom fingerprint database matches process names, ports, and banner patterns to identify 200+ server types. Additionally, HTTP responses are analyzed against the Wappalyzer technology database (6,500+ signatures).

### Device Discovery
ARP table enumeration via `/proc/net/arp` and `ip neigh` plus active probing discovers devices on the local network. MAC addresses are matched against a 35,000-entry OUI database to identify manufacturers.

### Packet Capture
Uses libpcap (requires root or `CAP_NET_RAW`) to capture packets. Headers are parsed for protocol/port information; payloads are extracted for the Wire preview. Supports promiscuous mode. Interface selection via `n` key or `PSNET_INTERFACE` environment variable.

### Firewall
Reads iptables/nftables rules via `iptables-save` command to show per-app firewall rules.

---

## Architecture

```
psnet/
├── Cargo.toml
├── data/
│   ├── dbip-country-lite.mmdb    # GeoIP country database (7 MB, embedded)
│   ├── fingerprints.json         # Server fingerprint signatures (embedded)
│   ├── oui.txt                   # MAC vendor prefixes (embedded)
│   └── wappalyzer.json           # Web technology signatures (embedded)
└── src/
    ├── main.rs                   # Entry point, event loop, terminal setup
    ├── app.rs                    # Application state, input handling, tick logic
    ├── types.rs                  # Shared types (Connection, TcpState, BottomTab, etc.)
    ├── utils.rs                  # Formatting helpers (speed, bytes, etc.)
    ├── network/
    │   ├── linux/                # Linux-specific implementations
    │   │   ├── connections.rs    # /proc/net/{tcp,udp}{,6} parser
    │   │   ├── dns.rs            # DNS cache reader + service port map
    │   │   ├── firewall.rs       # iptables/nftables rule reader
    │   │   ├── hostnames.rs      # Hostname resolution via /etc/hosts + getaddrinfo
    │   │   ├── networks/         # Multi-adapter discovery (sysfs /sys/class/net)
    │   │   ├── scanner.rs        # LAN device scanner (ARP, ip neigh)
    │   │   ├── servers/          # Listening port scanner + fingerprinting
    │   │   └── sniffer.rs        # libpcap packet capture
    │   ├── alerts.rs             # Alert engine — threat detection
    │   ├── bandwidth.rs          # Per-app bandwidth tracking
    │   ├── capture.rs            # Traffic event tracker (diff-based)
    │   ├── geoip.rs              # MaxMind GeoIP lookups
    │   ├── oui.rs                # MAC vendor OUI database
    │   ├── protocols.rs          # Protocol identification
    │   ├── speed.rs              # Network speed via sysinfo
    │   ├── system_monitor.rs     # System resource monitoring
    │   ├── threats.rs            # Threat intelligence
    │   └── usage.rs              # Network usage accounting
    └── ui/
        ├── mod.rs                # Master layout (title + speed + tabs + wire + status)
        ├── dashboard.rs          # Dashboard tab (traffic graph, world map, health)
        ├── connections.rs        # Connections tab (sortable table)
        ├── servers.rs            # Servers tab (card list + exposure panel)
        ├── packets_tab.rs        # Packets tab (Wireshark-style inspector)
        ├── topology.rs           # Topology tab (network diagram)
        ├── alerts.rs             # Alerts tab (categorized alerts)
        ├── firewall.rs           # Firewall tab (app block/allow)
        ├── devices.rs            # Devices tab (LAN scanner results)
        ├── networks.rs           # Networks tab (adapters, VPN, Docker, etc.)
        ├── detail_popup.rs       # Modal detail overlay
        ├── title.rs              # Title bar
        ├── speed.rs              # Speed sparklines + gauges
        ├── packets.rs            # Wire preview (always visible)
        ├── status.rs             # Tab menu + key hints
        └── widgets/              # Reusable chart widgets
            ├── bar_chart.rs
            ├── traffic_chart.rs
            ├── world_map.rs
            ├── health_gauge.rs
            └── ...
```

### Dependencies

| Crate | Purpose |
|-------|---------|
| [ratatui](https://github.com/ratatui/ratatui) | Terminal UI framework |
| [crossterm](https://github.com/crossterm-rs/crossterm) | Cross-platform terminal I/O |
| [sysinfo](https://github.com/GuillaumeGomez/sysinfo) | Network interface byte counters |
| [chrono](https://github.com/chronotope/chrono) | Timestamp formatting |
| [pcap](https://github.com/rust-pcap/rust-pcap) | libpcap bindings for packet capture |
| [serde](https://github.com/serde-rs/serde) + serde_json | Fingerprint/Wappalyzer JSON parsing |
| [maxminddb](https://github.com/oschwald/maxminddb-rust) | GeoIP database reader |
| [dns-lookup](https://github.com/keeperofdakeys/dns-lookup) | Hostname resolution |
| [dirs](https://github.com/dirs-dev/dirs-rs) | Platform directory paths |
| [nix](https://github.com/nix-rust/nix) | Unix system APIs (capabilities, users) |
| [procfs](https://github.com/eminence/procfs) | /proc filesystem parsing |

**System libraries:** libpcap (runtime), plus libpcap-dev for building.

---

## FAQ

**Q: Why Linux only?**
A: This is a Linux port of the original Windows PSNET. It uses Linux-specific sources (`/proc`, `/sys`, `iptables`, `libpcap`) that don't exist on other platforms.

**Q: Why does the Wire preview show nothing?**
A: Either you're not running as root (try `sudo psnet`), or the binary doesn't have `CAP_NET_RAW` (run `sudo setcap cap_net_raw+ep psnet`), or the traffic is encrypted (TLS) and has no readable ASCII payload.

**Q: Why do some connections show IPs instead of hostnames?**
A: Connections established before PSNET launched may not have cached DNS entries yet. Over time, more hostnames will resolve.

**Q: How do I switch capture interfaces?**
A: Press `n` to cycle through available interfaces. You can also set `PSNET_INTERFACE=enp10s0` environment variable to pin a specific interface at startup.

**Q: How big is the binary?**
A: ~12 MB. This includes 4 embedded databases (GeoIP 7 MB, OUI 1 MB, fingerprints, Wappalyzer). No additional files to download.

---

## Credits

This is a **Linux port** of the original [psnet](https://github.com/psmux/psnet) by [psmux](https://github.com/psmux). The original codebase was designed for Windows; all Linux-specific implementations were written from scratch using native Linux APIs.

> 🤖 **No humans were harmed (or involved) in the making of this port.**
> Every line of Linux code was generated, tested, and debugged entirely by
> [Claude Code](https://claude.ai/code) — an AI coding agent that ported the
> entire Windows codebase to Linux autonomously. The human just pressed `n`
> to cycle interfaces and drank coffee ☕.
>
> ⚠️ **No human takes responsibility for any issues, bugs, or network
> configurations you may encounter.** This code was written by an AI that
> doesn't own a computer. Use at your own risk. 😅

---

## Contributing

Contributions welcome! Areas that need work:

- 🐛 **Bug reports and fixes**
- 📦 **Packaging** — .deb (Ubuntu/Debian), .rpm (Fedora/SUSE), AUR (Arch)
- 🖼️ **Screenshots** — share your terminal in action
- 🧪 **Testing** — on different distros and configurations

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>◈ PSNET</strong> — See your network. Understand your network.
  <br><br>
  <em>Built with Rust 🦀 and love for the terminal.</em>
</p>
