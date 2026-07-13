"""Tests for packet-filtering firewall rule matching."""

import unittest

from thirstys_waterfall.firewalls import PacketFilteringFirewall


class TestPacketFilteringIpMatching(unittest.TestCase):
    def setUp(self):
        self.firewall = PacketFilteringFirewall(
            {"enabled": True, "default_policy": "deny"}
        )

    def test_exact_ip_match(self):
        self.assertTrue(self.firewall._match_ip("192.168.1.10", "192.168.1.10"))
        self.assertFalse(self.firewall._match_ip("192.168.1.11", "192.168.1.10"))

    def test_ipv4_cidr_match(self):
        self.assertTrue(self.firewall._match_ip("10.42.1.5", "10.0.0.0/8"))
        self.assertFalse(self.firewall._match_ip("11.42.1.5", "10.0.0.0/8"))

    def test_ipv6_cidr_match(self):
        self.assertTrue(self.firewall._match_ip("2001:db8::1", "2001:db8::/32"))
        self.assertFalse(self.firewall._match_ip("2001:db9::1", "2001:db8::/32"))

    def test_rule_list_match(self):
        self.assertTrue(
            self.firewall._match_ip(
                "172.16.0.10", ["192.168.0.0/16", "172.16.0.0/12"]
            )
        )

    def test_invalid_packet_ip_fails_closed(self):
        self.assertFalse(self.firewall._match_ip("not-an-ip", "10.0.0.0/8"))

    def test_missing_packet_ip_fails_closed(self):
        self.assertFalse(self.firewall._match_ip(None, "10.0.0.0/8"))

    def test_invalid_rule_ip_is_ignored(self):
        self.assertFalse(self.firewall._match_ip("10.1.2.3", "not-a-network"))


if __name__ == "__main__":
    unittest.main()
