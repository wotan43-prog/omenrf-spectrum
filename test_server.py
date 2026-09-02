import tempfile
import unittest
from pathlib import Path

from server import resolve_pcap_recording


class RecordingPathTests(unittest.TestCase):
    def test_allows_nested_pcap_beneath_recordings(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory) / "recordings"
            target = base / "investigations" / "session" / "wifi.pcap"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"pcap")
            self.assertEqual(resolve_pcap_recording(base, "investigations/session/wifi.pcap"), target)

    def test_rejects_traversal_and_non_pcap_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            base = root / "recordings"
            base.mkdir()
            (root / "outside.pcap").write_bytes(b"pcap")
            (base / "notes.json").write_text("{}")
            with self.assertRaises(FileNotFoundError):
                resolve_pcap_recording(base, "../outside.pcap")
            with self.assertRaises(FileNotFoundError):
                resolve_pcap_recording(base, "notes.json")


if __name__ == "__main__":
    unittest.main()
