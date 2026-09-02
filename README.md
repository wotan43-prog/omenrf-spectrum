# OmenRF Spectrum

Local dual-band spectrum dashboard for the MetaGeek Wi-Spy DBx3 using the GPL Spectools driver.

## Install on WOPR-II

Place this directory at `~/omenrf-spectrum`, ensure `~/spectools/spectool_raw` works without sudo, then:

```bash
cd ~/omenrf-spectrum
chmod +x install.sh
./install.sh
```

Open `http://WOPR-II-IP:8765`. Recordings are JSONL files under `recordings/`.

## Service commands

```bash
sudo systemctl status omenrf-spectrum
sudo journalctl -u omenrf-spectrum -f
sudo systemctl restart omenrf-spectrum
```

This initial release uses Spectools' calibrated `spectool_raw` output. Spectools remains GPL-2.0-or-later; this project should be distributed under GPL-compatible terms.
