#!/usr/bin/env python3

import ipaddress
import re
import subprocess
import time
from pathlib import Path

MAC_RE = re.compile(
    r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b'
)

def run(cmd, timeout=3):
    try:
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
            check=False,
        )
        return p.stdout.strip()
    except Exception:
        return ""

def normalize_mac(value):
    if not value:
        return None

    m = MAC_RE.search(value)
    return m.group(0).upper() if m else None

def directly_connected(ip):
    out = run(["ip", "route", "get", ip], timeout=2)

    if not out:
        return False

    # A "via" route means the target is behind a router,
    # therefore its Ethernet MAC is not available locally.
    if " via " in f" {out} ":
        return False

    return " dev " in f" {out} "

def read_neighbor(ip):
    for cmd in (
        ["ip", "neigh", "show", "to", ip],
        ["ip", "neigh", "show", ip],
    ):
        mac = normalize_mac(run(cmd, timeout=2))
        if mac:
            return mac

    return None


def local_interface_mac(ip):
    out = run(["ip", "-o", "-4", "addr", "show"], timeout=2)

    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue

        iface = parts[1].rstrip(":")
        address = parts[3].split("/", 1)[0]

        if address == ip:
            try:
                return normalize_mac(
                    Path(f"/sys/class/net/{iface}/address").read_text()
                )
            except OSError:
                return None

    return None

def acquire_mac(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None

    if addr.version != 4:
        return None

    if addr.is_loopback or addr.is_multicast or addr.is_unspecified:
        return None

    local_mac = local_interface_mac(ip)
    if local_mac:
        return local_mac

    if not directly_connected(ip):
        return None

    mac = read_neighbor(ip)

    if mac:
        return mac

    # Trigger ARP resolution.
    run(
        ["ping", "-n", "-c", "1", "-W", "1", ip],
        timeout=2
    )

    time.sleep(0.1)

    return read_neighbor(ip)

if __name__ == "__main__":
    import json
    import sys

    for ip in sys.argv[1:]:
        print(json.dumps({
            "ip": ip,
            "mac": acquire_mac(ip)
        }))
