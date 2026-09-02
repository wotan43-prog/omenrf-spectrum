import unittest

from network_scan import parse_nmap_xml, validate_target


ROUTES = [{"network": "192.168.50.0/24", "interface": "eth0", "source": "192.168.50.10"}]


class TargetValidationTests(unittest.TestCase):
    def test_accepts_connected_subnet(self):
        self.assertEqual(validate_target("192.168.50.0/24", ROUTES, 256), "192.168.50.0/24")

    def test_accepts_connected_host(self):
        self.assertEqual(validate_target("192.168.50.42", ROUTES, 1), "192.168.50.42")

    def test_rejects_other_private_subnet(self):
        with self.assertRaisesRegex(ValueError, "directly connected"):
            validate_target("192.168.60.0/24", ROUTES, 256)

    def test_rejects_public_target(self):
        with self.assertRaisesRegex(ValueError, "RFC1918"):
            validate_target("8.8.8.8", ROUTES, 1)

    def test_rejects_option_or_shell_text(self):
        for value in ("--script vuln", "192.168.50.1; id", "example.com"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_target(value, ROUTES, 256)

    def test_enforces_profile_size(self):
        with self.assertRaisesRegex(ValueError, "limited to 1"):
            validate_target("192.168.50.0/24", ROUTES, 1)


class XmlParsingTests(unittest.TestCase):
    def test_parses_host_vendor_and_service(self):
        xml = """<?xml version="1.0"?>
        <nmaprun><host><status state="up" reason="arp-response"/>
        <address addr="192.168.50.20" addrtype="ipv4"/>
        <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Example Corp"/>
        <hostnames><hostname name="access-point.local"/></hostnames>
        <ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.0"/></port></ports>
        </host><runstats><finished elapsed="1.25" summary="1 host up"/></runstats></nmaprun>"""
        result = parse_nmap_xml(xml)
        self.assertEqual(result["elapsed_seconds"], 1.25)
        self.assertEqual(result["hosts"][0]["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(result["hosts"][0]["vendor"], "Example Corp")
        self.assertEqual(result["hosts"][0]["ports"][0]["port"], 443)


if __name__ == "__main__":
    unittest.main()
