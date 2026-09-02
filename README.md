# OmenRF Spectrum

Local spectrum and 802.11 packet-analysis dashboard for the MetaGeek Wi-Spy DBx3 and a Linux monitor-mode adapter.

## V3 functions

- Live DBx3 spectrum, average, peak hold, waterfall, and recordings
- Monitor-radio channel and 20/40/80 MHz width control
- Live frame rate, frame-type counts, RSSI, and observed APs
- PCAP recording and local AP discovery using a second Wi-Fi interface
- Slide-out packet inspector with bounded live header metadata, device inventory, and PCAP downloads
- Constrained Nmap discovery with fixed quick, inventory, service, and single-host profiles
- Live target validation against WOPR-II's directly connected RFC1918 routes
- Structured JSON scan recordings with exact-MAC correlation to observed wireless devices
- Unified investigation sessions that coordinate spectrum, PCAP, AP, and Nmap collection
- One-click single-host Deep Dive action for the selected IP address
- Responsive two-column analysis layout with selectable host inventory and a dedicated Deep Dive drawer
- Dual-radio workflow that identifies the monitor/packet interface separately from the active AP-scan interface

## Install on WOPR-II

Place this directory at `~/omenrf-spectrum`, ensure `~/spectools/spectool_raw` works without sudo, then:

```bash
cd ~/omenrf-spectrum
chmod +x install.sh
./install.sh
```

Open `http://WOPR-II-IP:8765`. Spectrum JSONL, packet PCAP, and network-scan JSON recordings are stored under `recordings/`.

Defaults are `wlan1` for packet capture and `wlan0` for discovery. Override them in the systemd environment with `CAPTURE_INTERFACE` and `SCAN_INTERFACE`.

On the dual-Linksys WOPR-II configuration, `CAPTURE_INTERFACE=mon0` continuously feeds packet metadata and PCAP recording while `SCAN_INTERFACE=wlan2` performs active AP discovery without retuning the packet radio or interrupting WOPR-II's primary network connection.

Nmap targets are never accepted as command-line arguments. The API accepts only a profile ID and an IPv4 address or CIDR, validates the target against live directly connected private routes, and launches a fixed argument list without a shell. Set the optional comma-separated `NMAP_INTERFACES` environment variable to restrict eligible routes further, for example `NMAP_INTERFACES=eth0,wlan0`.

## Packet-inspector API

```text
GET /api/capture/frames?after=0&limit=100&type=beacon&mac=00:11:22:33:44:55
GET /api/capture/devices
GET /api/capture/files
GET /api/capture/download?path=wifi-example.pcap
```

The live inspector keeps only the latest 1,000 structured 802.11 header summaries in memory and returns at most 200 at a time. It never returns raw payload text. Downloads are restricted to `.pcap` files located beneath `recordings/`, including investigation-session subdirectories.

## Network-scan API

```text
GET  /api/nmap/state
POST /api/nmap/run
```

The POST body is JSON:

```json
{"profile":"quick","target":"192.168.1.0/24"}
```

Valid profiles are `quick`, `inventory`, `services`, and `deep_host`. Deep-host scans accept exactly one IPv4 address. Completed results are saved under `recordings/nmap-*.json`.

The dashboard keeps the most recent discovery/inventory result visible while a selected-host Deep Dive runs. Hostnames appear when Nmap discovers reverse-DNS names. Deep Dive results include open services, versions, wireless MAC correlation, and output from Nmap's fixed `safe` script category.

## Investigation-session API

```text
GET  /api/investigation/state
POST /api/investigation/start
POST /api/investigation/stop
```

Starting a session requires a JSON body containing a connected private target, for example `{"target":"192.168.1.0/24"}`. It creates `recordings/investigations/<session-id>/`, begins spectrum and PCAP recording, starts AP discovery, launches the fixed Quick Discovery profile, and maintains `manifest.json`. Manual spectrum and PCAP controls are locked while the session owns those recorders.

## Service commands

```bash
sudo systemctl status omenrf-spectrum
sudo journalctl -u omenrf-spectrum -f
sudo systemctl restart omenrf-spectrum
```

This initial release uses Spectools' calibrated `spectool_raw` output. Spectools remains GPL-2.0-or-later; this project should be distributed under GPL-compatible terms.
