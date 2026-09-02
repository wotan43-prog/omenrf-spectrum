import json
import threading
import time
from pathlib import Path

from network_scan import connected_private_routes, validate_target


class InvestigationManager:
    def __init__(self, root: Path, radio, network_scanner, spectrum_start, spectrum_stop, spectrum_is_recording=lambda: False):
        self.root = root
        self.radio = radio
        self.network_scanner = network_scanner
        self.spectrum_start = spectrum_start
        self.spectrum_stop = spectrum_stop
        self.spectrum_is_recording = spectrum_is_recording
        self.lock = threading.RLock()
        self.active = None
        self.last_session = None

    def _manifest_path(self, session):
        return self.root / "recordings" / "investigations" / session["id"] / "manifest.json"

    def _write(self, session):
        path = self._manifest_path(session)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(session, indent=2) + "\n")
        temporary.replace(path)

    def _refresh(self, session):
        scan_state = self.network_scanner.state()
        job = session.get("network_scan", {})
        if scan_state.get("running") and scan_state["running"].get("session_id") == session["id"]:
            job["status"] = "running"
            job["job_id"] = scan_state["running"]["id"]
        result = scan_state.get("last_result")
        if result and result.get("session_id") == session["id"]:
            job.update({
                "status": result.get("status"),
                "job_id": result.get("id"),
                "host_count": result.get("host_count", 0),
                "recording": result.get("recording"),
                "error": result.get("error"),
            })
        session["network_scan"] = job
        return session

    def state(self):
        with self.lock:
            session = self.active or self.last_session
            if session:
                self._refresh(session)
                self._write(session)
            return {"active": bool(self.active), "session": dict(session) if session else None}

    def is_active(self):
        with self.lock:
            return bool(self.active)

    def start(self, target_value):
        with self.lock:
            if self.active:
                raise RuntimeError("an investigation session is already active")
            if self.spectrum_is_recording():
                raise RuntimeError("stop the existing spectrum recording before starting an investigation")
            if self.radio.state().get("recording"):
                raise RuntimeError("stop the existing packet capture before starting an investigation")
            if self.network_scanner.state().get("running"):
                raise RuntimeError("wait for the existing network scan before starting an investigation")
            routes = connected_private_routes()
            if not routes:
                raise ValueError("no directly connected RFC1918 subnet is available")
            target_value = (target_value or routes[0]["network"]).strip()
            target = validate_target(target_value, routes, 4096)
            session_id = f"investigation-{time.strftime('%Y%m%d-%H%M%S')}-{time.time_ns() % 1_000_000_000:09d}"
            relative_dir = Path("investigations") / session_id
            session_dir = self.root / "recordings" / relative_dir
            session_dir.mkdir(parents=True, exist_ok=False)
            session = {
                "id": session_id,
                "status": "starting",
                "started_at": time.time(),
                "finished_at": None,
                "target": target,
                "files": {
                    "spectrum": str(relative_dir / "spectrum.jsonl"),
                    "pcap": str(relative_dir / "wifi.pcap"),
                    "manifest": str(relative_dir / "manifest.json"),
                },
                "ap_discovery": {"status": "pending", "count": 0, "results": []},
                "network_scan": {"status": "pending", "profile": "quick", "host_count": 0},
                "errors": [],
            }
            self._write(session)
            spectrum_started = False
            packet_started = False
            try:
                self.spectrum_start(session_dir / "spectrum.jsonl")
                spectrum_started = True
                self.radio.start_recording(session_dir / "wifi.pcap", display_name=session["files"]["pcap"])
                packet_started = True
            except Exception:
                if spectrum_started:
                    self.spectrum_stop()
                if packet_started:
                    self.radio.stop_recording()
                raise
            session["status"] = "active"
            self.active = session
            self.last_session = session
            self._write(session)
        threading.Thread(target=self._discover, args=(session_id, session_dir, target), daemon=True).start()
        return self.state()

    def _discover(self, session_id, session_dir, target):
        try:
            self.network_scanner.start("quick", target, output_dir=session_dir, session_id=session_id)
        except Exception as exc:
            with self.lock:
                if self.active and self.active["id"] == session_id:
                    self.active["network_scan"].update({"status": "error", "error": str(exc)})
                    self.active["errors"].append(f"Network discovery: {exc}")
                    self._write(self.active)
        try:
            results = self.radio.scan()
            with self.lock:
                session = self.active if self.active and self.active["id"] == session_id else self.last_session
                if session and session["id"] == session_id:
                    session["ap_discovery"] = {"status": "complete", "count": len(results), "results": results}
                    self._write(session)
        except Exception as exc:
            with self.lock:
                session = self.active if self.active and self.active["id"] == session_id else self.last_session
                if session and session["id"] == session_id:
                    session["ap_discovery"].update({"status": "error", "error": str(exc)})
                    session["errors"].append(f"AP discovery: {exc}")
                    self._write(session)

    def stop(self):
        with self.lock:
            if not self.active:
                raise RuntimeError("no investigation session is active")
            session = self.active
            self.spectrum_stop()
            self.radio.stop_recording()
            self._refresh(session)
            session["status"] = "complete"
            session["finished_at"] = time.time()
            self.active = None
            self.last_session = session
            self._write(session)
            return {"active": False, "session": dict(session)}
