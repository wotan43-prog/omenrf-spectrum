import tempfile
import threading
import unittest
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from capture import PacketRadio, parse_frame_metadata


class CaptureMetadataTests(unittest.TestCase):
    @patch("capture.subprocess.run")
    def test_active_discovery_uses_scan_radio_and_persists_results(self, run):
        run.return_value = SimpleNamespace(stdout="""BSS aa:bb:cc:dd:ee:ff(on wlan2)
        freq: 5180
        signal: -52.50 dBm
        SSID: Omen Lab
        WPS:     * Device name: CORP-AP-02
        """)
        radio = PacketRadio.__new__(PacketRadio)
        radio.scan_iface = "wlan2"
        radio.scan_lock = threading.Lock()
        radio.lock = threading.Lock()
        radio.discovery = []
        radio.scan_error = None
        radio.scan_time = None
        results = radio.scan()
        self.assertEqual(run.call_args.args[0], ["iw", "dev", "wlan2", "scan"])
        self.assertEqual(results[0]["ssid"], "Omen Lab")
        self.assertEqual(results[0]["signal"], -52.5)
        self.assertEqual(results[0]["device_name"], "CORP-AP-02")
        self.assertIsNone(results[0]["ap_name"])
        self.assertIsNotNone(radio.scan_time)

    def test_parses_header_metadata_without_raw_payload(self):
        line = (
            "2412 MHz -48dBm signal Beacon (Omen Lab) "
            "BSSID:00:11:22:33:44:55 SA:00:11:22:33:44:55 "
            "DA:ff:ff:ff:ff:ff:ff length 128"
        )
        frame = parse_frame_metadata(line, 7, 1, now=123.5)
        self.assertEqual(frame["id"], 7)
        self.assertEqual(frame["type"], "beacon")
        self.assertEqual(frame["source"], "00:11:22:33:44:55")
        self.assertEqual(frame["destination"], "ff:ff:ff:ff:ff:ff")
        self.assertEqual(frame["ssid"], "Omen Lab")
        self.assertEqual(frame["rssi"], -48)
        self.assertEqual(frame["frequency_mhz"], 2412)
        self.assertEqual(frame["length"], 128)
        self.assertNotIn("raw", frame)

    def test_frame_snapshot_filters_and_caps_results(self):
        radio = PacketRadio.__new__(PacketRadio)
        radio.lock = threading.Lock()
        radio.frame_id = 3
        radio.frames = deque([
            {"id": 1, "type": "beacon", "source": "aa:aa:aa:aa:aa:aa", "destination": None, "bssid": "aa:aa:aa:aa:aa:aa"},
            {"id": 2, "type": "data", "source": "bb:bb:bb:bb:bb:bb", "destination": "aa:aa:aa:aa:aa:aa", "bssid": None},
            {"id": 3, "type": "ack", "source": None, "destination": "cc:cc:cc:cc:cc:cc", "bssid": None},
        ], maxlen=1000)
        result = radio.frame_snapshot(after=0, limit=1, kind="data", mac="aa:aa:aa:aa:aa:aa")
        self.assertEqual([frame["id"] for frame in result["frames"]], [2])
        self.assertEqual(result["next_cursor"], 3)

    def test_frame_snapshot_cursor_does_not_skip_a_backlog(self):
        radio = PacketRadio.__new__(PacketRadio)
        radio.lock = threading.Lock()
        radio.frame_id = 3
        radio.frames = deque([
            {"id": value, "type": "data", "source": None, "destination": None, "bssid": None}
            for value in range(1, 4)
        ], maxlen=1000)
        result = radio.frame_snapshot(after=1, limit=1)
        self.assertEqual([frame["id"] for frame in result["frames"]], [2])
        self.assertEqual(result["next_cursor"], 2)

    def test_recording_list_supports_investigation_subdirectories(self):
        with tempfile.TemporaryDirectory() as directory:
            radio = PacketRadio.__new__(PacketRadio)
            radio.root = Path(directory)
            radio.lock = threading.Lock()
            radio.recording_path = None
            radio.recording_started = None
            nested = radio.root / "recordings" / "investigations" / "session-test"
            nested.mkdir(parents=True)
            (nested / "wifi.pcap").write_bytes(b"pcap")
            files = radio.recording_files()
            self.assertEqual(files[0]["path"], "investigations/session-test/wifi.pcap")
            self.assertEqual(files[0]["size"], 4)


if __name__ == "__main__":
    unittest.main()
