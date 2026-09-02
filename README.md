# OmenRF Spectrum

Local spectrum and 802.11 packet-analysis dashboard for the MetaGeek Wi-Spy DBx3 and a Linux monitor-mode adapter.

## V3 functions

- Live DBx3 spectrum, average, peak hold, waterfall, and recordings
- Monitor-radio channel and 20/40/80 MHz width control
- Live frame rate, frame-type counts, RSSI, and observed APs
- PCAP recording and local AP discovery using a second Wi-Fi interface

## Install on WOPR-II

Place this directory at `~/omenrf-spectrum`, ensure `~/spectools/spectool_raw` works without sudo, then:

```bash
cd ~/omenrf-spectrum
chmod +x install.sh
./install.sh
```

Open `http://WOPR-II-IP:8765`. Recordings are JSONL files under `recordings/`.

Defaults are `wlan1` for packet capture and `wlan0` for discovery. Override them in the systemd environment with `CAPTURE_INTERFACE` and `SCAN_INTERFACE`.

## Service commands

```bash
sudo systemctl status omenrf-spectrum
sudo journalctl -u omenrf-spectrum -f
sudo systemctl restart omenrf-spectrum
```

This initial release uses Spectools' calibrated `spectool_raw` output. Spectools remains GPL-2.0-or-later; this project should be distributed under GPL-compatible terms.
