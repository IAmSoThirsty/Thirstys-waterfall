"""Tests for hardware and cloud firewall backend evidence."""

import unittest

from thirstys_waterfall.firewalls import CloudFirewall, HardwareFirewall


class FakeHardwareBackend:
    def __init__(self, allowed=True):
        self.allowed = allowed
        self.initialized = False
        self.rules = []
        self.removed_rules = []
        self.packets = []

    def initialize(self):
        self.initialized = True
        return True

    def add_rule(self, rule):
        self.rules.append(rule)

    def remove_rule(self, rule_id):
        self.removed_rules.append(rule_id)

    def inspect_packet(self, packet):
        self.packets.append(packet)
        return {"allowed": self.allowed}


class FakeCloudBackend:
    def __init__(self, allowed=True, threat=False):
        self.allowed = allowed
        self.threat = threat
        self.rules = []
        self.removed_rules = []
        self.packets = []

    def initialize_nodes(self):
        return [{"id": "edge-1", "region": "test", "active": True}]

    def add_rule(self, rule):
        self.rules.append(rule)

    def remove_rule(self, rule_id):
        self.removed_rules.append(rule_id)

    def evaluate_packet(self, packet):
        self.packets.append(packet)
        return {"allowed": self.allowed, "threat": self.threat}


class InvalidHardwareBackend:
    def initialize(self):
        return True

    def inspect_packet(self, packet):
        return {"status": "verified"}


class InvalidCloudBackend:
    def initialize_nodes(self):
        return [{"id": "edge-1", "region": "test", "active": True}]

    def evaluate_packet(self, packet):
        return "not-a-dict"


class TestHardwareFirewallBackendEvidence(unittest.TestCase):
    def test_hardware_firewall_without_backend_blocks(self):
        firewall = HardwareFirewall({"enabled": True})
        firewall.start()

        self.assertFalse(firewall.process_packet({"src_ip": "1.1.1.1"}))
        status = firewall.get_hardware_status()
        self.assertEqual(status["status"], "unavailable")
        self.assertFalse(status["backend_configured"])
        self.assertFalse(status["last_backend_result"]["allowed"])

    def test_hardware_firewall_uses_backend_evidence(self):
        backend = FakeHardwareBackend(allowed=True)
        firewall = HardwareFirewall(
            {"enabled": True, "hardware_backend": backend}
        )

        firewall.start()
        firewall.add_rule({"id": "allow-mac", "action": "allow"})
        self.assertTrue(firewall.process_packet({"src_ip": "1.1.1.1"}))
        firewall.remove_rule("allow-mac")

        status = firewall.get_hardware_status()
        self.assertTrue(backend.initialized)
        self.assertEqual(backend.rules[0]["id"], "allow-mac")
        self.assertEqual(backend.removed_rules, ["allow-mac"])
        self.assertEqual(status["status"], "ready")
        self.assertEqual(status["last_backend_result"]["backend"], "FakeHardwareBackend")

    def test_hardware_firewall_rejects_invalid_backend_result(self):
        firewall = HardwareFirewall(
            {"enabled": True, "hardware_backend": InvalidHardwareBackend()}
        )
        firewall.start()

        with self.assertRaisesRegex(RuntimeError, "returned invalid result"):
            firewall.process_packet({"src_ip": "1.1.1.1"})


class TestCloudFirewallBackendEvidence(unittest.TestCase):
    def test_cloud_firewall_without_backend_blocks(self):
        firewall = CloudFirewall({"enabled": True})
        firewall.start()

        self.assertFalse(firewall.process_packet({"src_ip": "1.1.1.1"}))
        status = firewall.get_cloud_status()
        self.assertEqual(status["status"], "unavailable")
        self.assertFalse(status["backend_configured"])
        self.assertEqual(status["nodes"], [])
        self.assertFalse(status["last_backend_result"]["allowed"])

    def test_cloud_firewall_uses_backend_evidence(self):
        backend = FakeCloudBackend(allowed=True)
        firewall = CloudFirewall({"enabled": True, "cloud_backend": backend})

        firewall.start()
        firewall.add_geo_rule("test", "allow")
        self.assertTrue(
            firewall.process_packet(
                {"src_ip": "1.1.1.1", "geo_info": {"region": "test"}}
            )
        )
        firewall.remove_rule("geo_test")

        status = firewall.get_cloud_status()
        self.assertEqual(status["status"], "ready")
        self.assertEqual(status["nodes"][0]["id"], "edge-1")
        self.assertEqual(status["last_backend_result"]["backend"], "FakeCloudBackend")
        self.assertEqual(backend.rules[0]["region"], "test")
        self.assertEqual(backend.removed_rules, ["geo_test"])

    def test_cloud_firewall_records_backend_threat_blocks(self):
        backend = FakeCloudBackend(allowed=False, threat=True)
        firewall = CloudFirewall({"enabled": True, "cloud_backend": backend})
        firewall.start()

        self.assertFalse(firewall.process_packet({"src_ip": "1.1.1.1"}))
        stats = firewall.get_statistics()
        self.assertEqual(stats["packets_blocked"], 1)
        self.assertEqual(stats["threats_detected"], 1)

    def test_cloud_firewall_rejects_invalid_backend_result(self):
        firewall = CloudFirewall(
            {"enabled": True, "cloud_backend": InvalidCloudBackend()}
        )
        firewall.start()

        with self.assertRaisesRegex(RuntimeError, "returned invalid result"):
            firewall.process_packet({"src_ip": "1.1.1.1"})


if __name__ == "__main__":
    unittest.main()
