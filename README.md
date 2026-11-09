# NetGuard — LAN/WiFi Monitoring & Rogue-Device Detection Tool

A C++ network visibility tool for FYP demonstration: discovers devices on
your LAN, scans their open ports, passively lists nearby WiFi access
points, and flags anything not in your approved baseline — with a live
ncurses dashboard.

## What this tool deliberately does NOT do

It does not send deauthentication frames, jam RF spectrum, or disconnect
any device. Those actions are illegal to operate without a spectrum
license in most countries (including under PTA regulations in Pakistan)
regardless of who authorizes them, because they deny service to everyone
sharing the channel, not just a targeted device. Instead, it detects and
flags unauthorized devices for a human operator to act on through
legitimate means (switch-port shutdown, NAC quarantine, AP-level
single-client disconnect).

## Features

- **LAN device discovery** — ARP sweep of your subnet (`src/arp_scan.cpp`),
  equivalent to `arp-scan`/`nmap -sn`.
- **Port scanning** — TCP connect scan of discovered hosts (`src/port_scan.cpp`),
  equivalent to `nmap -sT`.
- **WiFi AP scanning** — passive scan via the standard `iw scan` mechanism
  (`src/wifi_scan.cpp`) — the same thing your laptop does to list networks.
- **Baseline/trust system** — approve devices as "Known" (stored in
  `data/known_lan.txt` / `data/known_wifi.txt`); anything else shows as
  "Unknown" and raises an alert event.
- **Suspicious flagging** — mark a device for human follow-up; the tool
  prints the legitimate operator actions to take (switch port shutdown,
  NAC quarantine, AP-level client kick) rather than acting on the network
  itself.
- **Live ncurses dashboard** — two live-updating tables + event log.
- **Audit log** — every event is timestamped to `logs/netguard.log`.

## Build

Requires: g++ (C++17), CMake, libncurses-dev, libpcap-dev.

```bash
sudo apt install libncurses-dev libpcap-dev cmake g++ iw
mkdir build && cd build
cmake ..
make -j4
```

## Run

Raw sockets (ARP) and WiFi scan triggering need root:

```bash
sudo ./netguard [interface]
```

If no interface is given, it auto-detects the first non-loopback,
UP IPv4 interface. Run from the project root (not `build/`) so it can
find `data/` and `logs/`.

## Dashboard controls

| Key | Action |
|---|---|
| Tab | Switch between LAN / WiFi panel |
| ↑ / ↓ | Move selection |
| `a` | Approve selected device/AP as Known (adds to baseline file) |
| `s` | Flag selected device/AP as Suspicious (shows suggested operator response) |
| `p` | Re-trigger a port scan on the selected LAN device |
| `q` | Quit |

## Project layout

```
include/   headers (types, module APIs)
src/       implementation
data/      known_lan.txt, known_wifi.txt — your approved baselines
logs/      netguard.log — audit trail
```

