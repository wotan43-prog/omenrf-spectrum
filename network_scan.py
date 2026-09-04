import ipaddress
import json
import socket
import os
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from pathlib import Path


PRIVATE_V4 = tuple(ipaddress.ip_network(value) for value in (
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
))

PROFILES = {
    "quick": {
        "name": "Quick Discovery",
        "description": "Fast local host discovery without DNS lookups.",
        "args": ("-sn", "-PR", "-n", "-T4"),
        "timeout": 90,
        "max_hosts": 4096,
    },
    "inventory": {
        "name": "Device Inventory",
        "description": "Local host discovery with reverse-DNS names and MAC vendors.",
        "args": ("-sn", "-PR", "-R", "-T3"),
        "timeout": 180,
        "max_hosts": 1024,
    },
    "services": {
        "name": "Service Check",
        "description": "Checks the 100 most common TCP ports and lightly identifies services.",
        "args": ("-PR", "-sT", "-sV", "--version-light", "--top-ports", "100", "-T3", "--max-retries", "1", "--host-timeout", "45s"),
        "timeout": 300,
        "max_hosts": 256,
    },
    "deep_host": {
        "name": "TCP Deep Dive",
        "description": "Two-stage single-host assessment: fast port sweep, then targeted service identification.",
        "args": (),
        "timeout": 75,
        "staged": True,
        "discovery_args": ("-PR", "-sT", "--top-ports", "1000", "-T4", "--max-retries", "1", "--host-timeout", "30s"),
        "probe_args": ("-Pn", "-sT", "--script", "banner,http-title,http-headers,ssl-cert,ssh-hostkey", "--script-timeout", "5s", "-T4", "--max-retries", "1", "--host-timeout", "15s"),
        "max_hosts": 1,
    },
    "udp_host": {
        "name": "UDP Deep Dive",
        "description": "Targeted UDP reconnaissance of common infrastructure and discovery services.",
        "args": (
            "-Pn",
            "-sU",
            "-sV",
            "--version-light",
            "-p",
            "53,67,68,69,123,137,161,162,500,514,520,623,1900,4500,5353,5683",
            "-T3",
            "--max-retries",
            "1",
            "--host-timeout",
            "45s",
        ),
        "timeout": 90,
        "max_hosts": 1,
        "privileged_helper": "udp",
    },
}


def _is_private(network):
    return any(network.subnet_of(private) for private in PRIVATE_V4)


def connected_private_routes():
    """Return directly connected RFC1918 IPv4 routes from the live kernel table."""
    result = subprocess.run(
        ["ip", "-j", "-4", "route", "show", "scope", "link"],
        capture_output=True,
        text=True,
        timeout=5,
        check=True,
    )
    allowed_interfaces = {
        value.strip() for value in os.environ.get("NMAP_INTERFACES", "").split(",") if value.strip()
    }
    routes = []
    for route in json.loads(result.stdout or "[]"):
        destination = route.get("dst")
        interface = route.get("dev")
        if not destination or destination == "default" or interface == "lo":
            continue
        if allowed_interfaces and interface not in allowed_interfaces:
            continue
        try:
            network = ipaddress.ip_network(destination, strict=False)
        except ValueError:
            continue
        if network.version == 4 and _is_private(network):
            routes.append({"network": str(network), "interface": interface, "source": route.get("prefsrc")})
    unique = {(item["network"], item["interface"]): item for item in routes}
    return sorted(unique.values(), key=lambda item: (item["interface"] or "", item["network"]))


def validate_target(value, routes, max_hosts):
    value = (value or "").strip()
    if not value:
        raise ValueError("target is required")
    try:
        target = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError("target must be an IPv4 address or CIDR network") from exc
    if target.version != 4 or not _is_private(target):
        raise ValueError("target must be an RFC1918 private IPv4 address or network")
    connected = [ipaddress.ip_network(item["network"]) for item in routes]
    if not any(target.subnet_of(network) for network in connected):
        raise ValueError("target is not within a directly connected private subnet")
    if target.num_addresses > max_hosts:
        raise ValueError(f"profile is limited to {max_hosts} target addresses")
    return str(target.network_address) if target.prefixlen == 32 else str(target)


def parse_nmap_xml(text):
    root = ET.fromstring(text)
    hosts = []
    for node in root.findall("host"):
        status = node.find("status")
        addresses = {
            address.get("addrtype"): address.get("addr")
            for address in node.findall("address")
            if address.get("addr") and address.get("addrtype")
        }
        mac_node = next((address for address in node.findall("address") if address.get("addrtype") == "mac"), None)
        hostnames = [item.get("name") for item in node.findall("hostnames/hostname") if item.get("name")]
        ports = []
        for port in node.findall("ports/port"):
            port_state = port.find("state")
            service = port.find("service")
            ports.append({
                "protocol": port.get("protocol"),
                "port": int(port.get("portid")),
                "state": port_state.get("state") if port_state is not None else None,
                "service": service.get("name") if service is not None else None,
                "product": service.get("product") if service is not None else None,
                "version": service.get("version") if service is not None else None,
                "extra": service.get("extrainfo") if service is not None else None,
                "scripts": [
                    {"id": script.get("id"), "output": script.get("output")}
                    for script in port.findall("script")
                    if script.get("id") or script.get("output")
                ],
            })
        os_matches = []
        for match in node.findall("os/osmatch")[:3]:
            os_matches.append({"name": match.get("name"), "accuracy": int(match.get("accuracy", "0"))})
        hosts.append({
            "state": status.get("state") if status is not None else "unknown",
            "reason": status.get("reason") if status is not None else None,
            "ip": addresses.get("ipv4"),
            "mac": addresses.get("mac", "").lower() or None,
            "vendor": mac_node.get("vendor") if mac_node is not None else None,
            "hostnames": hostnames,
            "ports": ports,
            "os": os_matches,
            "scripts": [
                {"id": script.get("id"), "output": script.get("output")}
                for script in node.findall("hostscript/script")
                if script.get("id") or script.get("output")
            ],
        })
    runstats = root.find("runstats/finished")
    return {
        "hosts": hosts,
        "summary": runstats.get("summary") if runstats is not None else None,
        "elapsed_seconds": float(runstats.get("elapsed", "0")) if runstats is not None else None,
    }


class NetworkScanner:
    def __init__(self, root: Path, wireless_snapshot=None):
        self.root = root
        self.wireless_snapshot = wireless_snapshot or (lambda: [])
        self.lock = threading.Lock()
        self.running = None
        self.last_result = None
        self.last_inventory_result = None
        self.last_deep_result = None
        self.error = None
        self.history = []

    def state(self):
        try:
            routes = connected_private_routes()
            route_error = None
        except Exception as exc:
            routes = []
            route_error = str(exc)
        with self.lock:
            running = {
                key: value for key, value in (self.running or {}).items() if not key.startswith("_")
            } or None
            return {
                "profiles": [
                    {"id": key, "name": value["name"], "description": value["description"], "max_hosts": value["max_hosts"]}
                    for key, value in PROFILES.items()
                ],
                "allowed_targets": routes,
                "running": running,
                "last_result": self.last_result,
                "last_inventory_result": self.last_inventory_result,
                "last_deep_result": self.last_deep_result,
                "history": self.history[-10:],
                "error": self.error or route_error,
            }

    def start(self, profile_id, target_value, output_dir=None, session_id=None):
        if profile_id not in PROFILES:
            raise ValueError("unknown scan profile")
        profile = PROFILES[profile_id]
        routes = connected_private_routes()
        if not routes:
            raise ValueError("no directly connected RFC1918 subnet is available")
        target = validate_target(target_value, routes, profile["max_hosts"])
        with self.lock:
            if self.running:
                raise RuntimeError("a network scan is already running")
            job = {
                "id": f"nmap-{time.strftime('%Y%m%d-%H%M%S')}-{time.time_ns() % 1_000_000_000:09d}",
                "profile": profile_id,
                "profile_name": profile["name"],
                "target": target,
                "started_at": time.time(),
                "session_id": session_id,
                "_output_dir": str(output_dir) if output_dir else None,
            }
            self.running = job
            self.error = None
        threading.Thread(target=self._run, args=(job, profile), daemon=True).start()
        return {key: value for key, value in job.items() if not key.startswith("_")}

    def _run_nmap(self, args, target, timeout):
        result = subprocess.run(["nmap", *args, "-oX", "-", target], capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or f"nmap exited with status {result.returncode}")
        return result.stdout

    def _run_staged_deep_host(self, job, profile):
        with self.lock:
            if self.running and self.running.get("id") == job["id"]:
                self.running["stage"] = "port_sweep"
                self.running["open_ports"] = []
        sweep = parse_nmap_xml(self._run_nmap(profile["discovery_args"], job["target"], profile["timeout"]))
        open_ports = sorted({p["port"] for h in sweep["hosts"] for p in h.get("ports", []) if p.get("protocol") == "tcp" and p.get("state") == "open"})
        with self.lock:
            if self.running and self.running.get("id") == job["id"]:
                self.running["stage"] = "service_probe" if open_ports else "complete"
                self.running["open_ports"] = open_ports
        if not open_ports:
            return sweep, {"port_sweep_seconds": sweep.get("elapsed_seconds"), "service_probe_seconds": 0.0, "open_ports": []}
        args = [*profile["probe_args"], "-p", ",".join(str(p) for p in open_ports)]
        detail = parse_nmap_xml(self._run_nmap(args, job["target"], profile["timeout"]))
        prior = {h.get("ip"): h for h in sweep["hosts"]}
        for host in detail["hosts"]:
            old = prior.get(host.get("ip")) or {}
            for key in ("mac", "vendor"):
                if not host.get(key) and old.get(key): host[key] = old[key]
            if not host.get("ports") and old.get("ports"):
                host["ports"] = old["ports"]
        return detail, {"port_sweep_seconds": sweep.get("elapsed_seconds"), "service_probe_seconds": detail.get("elapsed_seconds"), "open_ports": open_ports}

    def _run(self, job, profile):
        command = ["nmap", *profile["args"], "-oX", "-", job["target"]]
        try:
            stage_metrics = None
            if profile.get("staged"):
                parsed, stage_metrics = self._run_staged_deep_host(job, profile)
                output = None
            elif profile.get("privileged_helper") == "udp":
                request = json.dumps({"target": job["target"]}).encode()

                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                    client.settimeout(profile["timeout"])
                    client.connect("/run/omenrf/udp-scan.sock")
                    client.sendall(request)

                    chunks = []
                    while True:
                        chunk = client.recv(65536)
                        if not chunk:
                            break
                        chunks.append(chunk)

                helper = json.loads(b"".join(chunks).decode())
                if helper.get("returncode") != 0:
                    raise RuntimeError(
                        helper.get("stderr")
                        or f"UDP helper exited with status {helper.get('returncode')}"
                    )

                output = helper.get("stdout", "")
            else:
                output = self._run_nmap(profile["args"], job["target"], profile["timeout"])

            if not profile.get("staged"):
                parsed = parse_nmap_xml(output)
            wireless = {
                (item.get("mac") or item.get("bssid", "")).lower(): item
                for item in self.wireless_snapshot()
                if item.get("mac") or item.get("bssid")
            }
            for host in parsed["hosts"]:
                match = wireless.get(host.get("mac") or "")
                host["wireless_match"] = {
                    "mac": match.get("mac") or match.get("bssid"),
                    "bssid": match.get("bssid") or match.get("mac"),
                    "ssid": match.get("ssid"),
                    "ap_name": match.get("ap_name") or match.get("device_name"),
                    "rssi": match.get("rssi"),
                    "roles": match.get("roles", []),
                } if match else None
            public_job = {key: value for key, value in job.items() if not key.startswith("_")}
            completed = {
                **public_job,
                "finished_at": time.time(),
                "status": "complete",
                "host_count": len(parsed["hosts"]),
                **parsed,
            }
            if stage_metrics is not None:
                completed["stages"] = stage_metrics
            output_dir = Path(job["_output_dir"]) if job.get("_output_dir") else self.root / "recordings"
            output_dir.mkdir(parents=True, exist_ok=True)
            output_path = output_dir / f"{job['id']}.json"
            completed["recording"] = str(output_path.relative_to(self.root / "recordings"))
            output_path.write_text(json.dumps(completed, indent=2) + "\n")
            with self.lock:
                self.last_result = completed
                if job["profile"] in {"deep_host", "udp_host"}:
                    self.last_deep_result = completed
                else:
                    self.last_inventory_result = completed
                self.history.append({key: completed.get(key) for key in ("id", "profile", "profile_name", "target", "started_at", "finished_at", "host_count", "recording")})
                self.error = None
        except Exception as exc:
            with self.lock:
                self.error = str(exc)
                public_job = {key: value for key, value in job.items() if not key.startswith("_")}
                failed = {**public_job, "finished_at": time.time(), "status": "error", "error": str(exc)}
                self.last_result = failed
                if job["profile"] in {"deep_host", "udp_host"}:
                    self.last_deep_result = failed
                else:
                    self.last_inventory_result = failed
        finally:
            with self.lock:
                self.running = None
