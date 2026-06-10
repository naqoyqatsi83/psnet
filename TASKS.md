# PSNet Linux Port — Task List

## Status
- [x] Servers — listening ports with process mapping (/proc/net/tcp, ss)
- [x] Networks — device discovery, DHCP, ARP (/proc/net/arp, ip neigh)
- [x] Packets — packet capture (libpcap, requires cap_net_raw)
- [x] Topology — network map
- [x] Alerts — system events (netlink, /proc)
- [x] Firewall — read iptables/nftables rules
- [x] No-root mode with warnings for restricted features
- [x] TUI verified on real Linux terminal

## Rules
- Mark tasks [x] as completed
- Do not stop until all tasks are [x]
