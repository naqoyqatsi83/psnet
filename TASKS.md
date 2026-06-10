## Round 2 Tasks

### Packet Capture (root fix)
- [ ] Investigate why packet capture returns 0 packets when running as root
- [ ] Check pcap interface binding — verify correct interface is selected (not loopback)
- [ ] Check BPF filter logic — ensure filter isn't silently dropping all packets
- [ ] Test with promiscuous mode explicitly enabled for root sessions
- [ ] Test capture on all interfaces (not just default) when running as root
- [ ] Verify pcap permissions/capabilities work correctly for both root and cap_net_raw
- [ ] Add debug logging to packet capture path to trace where packets are lost
- [ ] Confirm fix works: capture shows live packets in TUI when run as root

### Ubuntu Installation Package
- [ ] Audit all runtime dependencies (libpcap, iptables/nftables, iproute2, etc.)
- [ ] Create debian package structure (DEBIAN/control, preinst, postinst, postrm)
- [ ] Write control file with correct Depends: field for all runtime libs
- [ ] Add postinst script: set cap_net_raw on binary so non-root capture works
- [ ] Add desktop entry / man page if applicable
- [ ] Build .deb with dpkg-deb and test install on clean Ubuntu 24.04
- [ ] Test: install from .deb, run without root, verify all features work
- [ ] Test: restricted features show correct warnings without cap_net_raw

### Raspberry Pi 4B (ARM v8) Port
- [ ] Add aarch64-unknown-linux-gnu target to Cargo.toml / .cargo/config.toml
- [ ] Set up cross-compilation toolchain (cross or cargo-zigbuild)
- [ ] Verify all Linux-native sources (/proc, /sys, iptables) work on RPi kernel
- [ ] Check any x86-specific assumptions in existing Linux code
- [ ] Build for aarch64 and fix any compilation errors
- [ ] Test binary on RPi 4B — verify TUI renders correctly on ARM
- [ ] Add aarch64 .deb package build target
- [ ] Document RPi setup steps in README (dependencies, cap_net_raw setup)

## Rules
- Mark tasks [x] as completed
- Do not stop until all tasks in Round 2 are [x]
