# OmenRF Spectrum

Local spectrum and 802.11 packet-analysis dashboard for the MetaGeek Wi-Spy DBx3 and a Linux monitor-mode adapter.

## V3 functions

- Live DBx3 spectrum, average, peak hold, waterfall, and recordings
- Monitor-radio channel and 20/40/80 MHz width control
- Live frame rate, frame-type counts, RSSI, and observed APs
- PCAP recording and local AP discovery using a second Wi-Fi interface
- Constrained Nmap discovery with fixed quick, inventory, service, and single-host profiles
- Live target validation against WOPR-II's directly connected RFC1918 routes
- Structured JSON scan recordings with exact-MAC correlation to observed wireless devices

## Install on WOPR-II

Place this directory at `~/omenrf-spectrum`, ensure `~/spectools/spectool_raw` works without sudo, then:

```bash
cd ~/omenrf-spectrum
chmod +x install.sh
./install.sh
```

Open `http://WOPR-II-IP:8765`. Spectrum JSONL, packet PCAP, and network-scan JSON recordings are stored under `recordings/`.

Defaults are `wlan1` for packet capture and `wlan0` for discovery. Override them in the systemd environment with `CAPTURE_INTERFACE` and `SCAN_INTERFACE`.

Nmap targets are never accepted as command-line arguments. The API accepts only a profile ID and an IPv4 address or CIDR, validates the target against live directly connected private routes, and launches a fixed argument list without a shell. Set the optional comma-separated `NMAP_INTERFACES` environment variable to restrict eligible routes further, for example `NMAP_INTERFACES=eth0,wlan0`.

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

## Service commands

```bash
sudo systemctl status omenrf-spectrum
sudo journalctl -u omenrf-spectrum -f
sudo systemctl restart omenrf-spectrum
```

This initial release uses Spectools' calibrated `spectool_raw` output. Spectools remains GPL-2.0-or-later; this project should be distributed under GPL-compatible terms.
