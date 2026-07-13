"""Tests for VPNManager backend-driven connection behavior."""

import unittest
from unittest.mock import Mock, patch

from thirstys_waterfall.vpn.vpn_manager import VPNManager


class TestVPNManagerBackendConnections(unittest.TestCase):
    def make_manager(self):
        return VPNManager(
            {
                "enabled": True,
                "multi_hop": True,
                "protocol_fallback": ["wireguard", "openvpn"],
                "kill_switch": True,
                "dns_leak_protection": True,
                "ipv6_leak_protection": True,
            }
        )

    def make_backend(self, available=True, connected=True):
        backend = Mock()
        backend.check_availability.return_value = available
        backend.connect.return_value = connected
        backend.disconnect.return_value = True
        backend.get_status.return_value = {
            "backend": "wireguard",
            "connected": connected,
            "interface": "wg-test",
        }
        return backend

    @patch("thirstys_waterfall.vpn.vpn_manager.VPNBackendFactory.create_backend")
    def test_start_fails_closed_when_no_backend_available(self, mock_create_backend):
        unavailable_backend = self.make_backend(available=False)
        mock_create_backend.return_value = unavailable_backend
        manager = self.make_manager()

        with self.assertRaises(ConnectionError):
            manager.start()

        status = manager.get_status()
        self.assertFalse(status["active"])
        self.assertFalse(status["connected"])
        self.assertFalse(status["traffic_encrypted"])
        self.assertTrue(status["kill_switch"])
        self.assertIn("All VPN protocols failed", status["error"])
        unavailable_backend.connect.assert_not_called()

    @patch("thirstys_waterfall.vpn.vpn_manager.VPNBackendFactory.create_backend")
    def test_start_fails_closed_when_backend_connect_fails(self, mock_create_backend):
        failing_backend = self.make_backend(available=True, connected=False)
        mock_create_backend.return_value = failing_backend
        manager = self.make_manager()

        with self.assertRaises(ConnectionError):
            manager.start()

        status = manager.get_status()
        self.assertFalse(status["active"])
        self.assertFalse(status["connected"])
        self.assertFalse(status["traffic_encrypted"])
        self.assertIn("failed to connect", status["error"])

    @patch("thirstys_waterfall.vpn.vpn_manager.VPNBackendFactory.create_backend")
    def test_start_uses_backend_status_instead_of_synthetic_endpoint(
        self, mock_create_backend
    ):
        backend = self.make_backend(available=True, connected=True)
        mock_create_backend.return_value = backend
        manager = self.make_manager()

        manager.start()

        status = manager.get_status()
        self.assertTrue(status["active"])
        self.assertTrue(status["connected"])
        self.assertTrue(status["traffic_encrypted"])
        self.assertEqual(status["backend"]["backend"], "wireguard")
        self.assertEqual(status["route"], [backend.get_status.return_value])
        self.assertFalse(status["multi_hop_accepted"])
        self.assertNotIn("endpoint", status["route"][0])

    @patch("thirstys_waterfall.vpn.vpn_manager.VPNBackendFactory.create_backend")
    def test_stop_disconnects_active_backend(self, mock_create_backend):
        backend = self.make_backend(available=True, connected=True)
        mock_create_backend.return_value = backend
        manager = self.make_manager()

        manager.start()
        manager.stop()

        backend.disconnect.assert_called_once()
        status = manager.get_status()
        self.assertFalse(status["active"])
        self.assertFalse(status["connected"])
        self.assertFalse(status["backend_available"])

    def test_current_ip_fails_closed_for_non_string_endpoint(self):
        manager = self.make_manager()
        manager._current_route = [{"endpoint": 1234}]

        self.assertIsNone(manager.get_current_ip())


if __name__ == "__main__":
    unittest.main()
