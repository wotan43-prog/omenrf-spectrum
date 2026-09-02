#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
chmod +x "$HERE/server.py"
sudo tee /etc/systemd/system/omenrf-spectrum.service >/dev/null <<EOF
[Unit]
Description=OmenRF Wi-Spy DBx3 Spectrum Service
After=network.target
[Service]
Type=simple
User=$USER
WorkingDirectory=$HERE
Environment=SPECTOOL_RAW=$HOME/spectools/spectool_raw
ExecStart=/usr/bin/python3 $HERE/server.py
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now omenrf-spectrum
echo "Open http://$(hostname -I | awk '{print $1}'):8765"
