import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from investigation import InvestigationManager


class FakeRadio:
    def __init__(self):
        self.recording = None
        self.recording_path = None

    def state(self):
        return {"recording": self.recording}

    def start_recording(self, path, display_name=None):
        self.recording_path = Path(path)
        self.recording = display_name

    def stop_recording(self):
        self.recording = None

    def scan(self):
        return [{"bssid": "00:11:22:33:44:55", "ssid": "Test", "signal": -50, "freq": 2412}]


class FakeScanner:
    def __init__(self):
        self.job = None

    def start(self, profile, target, output_dir=None, session_id=None):
        self.job = {
            "id": "nmap-test",
            "profile": profile,
            "profile_name": "Quick Discovery",
            "target": target,
            "session_id": session_id,
        }
        return self.job

    def state(self):
        return {"running": self.job, "last_result": None, "error": None}


class InvestigationTests(unittest.TestCase):
    @patch("investigation.connected_private_routes")
    def test_existing_spectrum_recording_is_not_stopped(self, routes):
        routes.return_value = [{"network": "192.168.50.0/24", "interface": "eth0", "source": "192.168.50.2"}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "recordings").mkdir()
            spectrum = {"stopped": False}
            manager = InvestigationManager(
                root,
                FakeRadio(),
                FakeScanner(),
                lambda path: None,
                lambda: spectrum.update(stopped=True),
                lambda: True,
            )
            with self.assertRaisesRegex(RuntimeError, "existing spectrum recording"):
                manager.start("192.168.50.0/24")
            self.assertFalse(spectrum["stopped"])

    @patch("investigation.connected_private_routes")
    def test_session_coordinates_recorders_and_discovery(self, routes):
        routes.return_value = [{"network": "192.168.50.0/24", "interface": "eth0", "source": "192.168.50.2"}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "recordings").mkdir()
            radio = FakeRadio()
            scanner = FakeScanner()
            spectrum = {"path": None, "stopped": False}
            manager = InvestigationManager(
                root,
                radio,
                scanner,
                lambda path: spectrum.update(path=Path(path)),
                lambda: spectrum.update(stopped=True),
            )
            started = manager.start("192.168.50.0/24")
            session_id = started["session"]["id"]
            for _ in range(50):
                if manager.state()["session"]["ap_discovery"]["status"] == "complete":
                    break
                time.sleep(0.01)
            state = manager.state()
            self.assertTrue(state["active"])
            self.assertEqual(state["session"]["ap_discovery"]["count"], 1)
            self.assertEqual(scanner.job["session_id"], session_id)
            self.assertEqual(spectrum["path"].name, "spectrum.jsonl")
            self.assertEqual(radio.recording_path.name, "wifi.pcap")
            self.assertTrue((root / "recordings" / "investigations" / session_id / "manifest.json").exists())
            stopped = manager.stop()
            self.assertFalse(stopped["active"])
            self.assertTrue(spectrum["stopped"])
            self.assertIsNone(radio.recording)


if __name__ == "__main__":
    unittest.main()
