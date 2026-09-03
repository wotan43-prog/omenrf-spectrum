#!/usr/bin/env python3
import ipaddress
import json
import os
import socket
import subprocess

SOCKET = "/run/omenrf/udp-scan.sock"
PORTS = "53,67,68,69,123,137,161,162,500,514,520,623,1900,4500,5353,5683"

def directly_connected_private(ip):
    addr = ipaddress.ip_address(ip)
    if addr.version != 4 or not addr.is_private:
        return False

    result = subprocess.run(
        ["ip", "-j", "-4", "route", "get", str(addr)],
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    routes = json.loads(result.stdout or "[]")
    if not routes:
        return False

    route = routes[0]
    dev = route.get("dev")
    gateway = route.get("gateway")

    # Directly connected only; routed targets are rejected.
    return bool(dev) and not gateway

def run_scan(target):
    if not directly_connected_private(target):
        raise ValueError("target is not a directly connected private IPv4 host")

    command = [
        "/usr/bin/nmap",
        "-Pn",
        "-sU",
        "-sV",
        "--version-light",
        "-p", PORTS,
        "-T3",
        "--max-retries", "1",
        "--host-timeout", "45s",
        "-oX", "-",
        target,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )

    return {
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }

def main():
    os.makedirs("/run/omenrf", exist_ok=True)

    try:
        os.unlink(SOCKET)
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET)
    os.chmod(SOCKET, 0o660)

    # wotan owns the socket via the systemd unit.
    server.listen(8)

    while True:
        conn, _ = server.accept()
        with conn:
            try:
                raw = conn.recv(1024)
                request = json.loads(raw.decode())
                target = str(request.get("target", ""))
                response = run_scan(target)
            except Exception as exc:
                response = {
                    "returncode": 1,
                    "stdout": "",
                    "stderr": str(exc),
                }

            conn.sendall(json.dumps(response).encode())

if __name__ == "__main__":
    main()
