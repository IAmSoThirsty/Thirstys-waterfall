"""Tests for secure tunnel backend gating."""

import unittest

from thirstys_waterfall.remote_access import SecureTunnel
from thirstys_waterfall.utils.god_tier_encryption import GodTierEncryption


class FakeVPNManager:
    def __init__(self, connected=True):
        self.connected = connected

    def is_connected(self):
        return self.connected

    def get_status(self):
        return {
            "active": self.connected,
            "connected": self.connected,
            "route": [{"protocol": "wireguard", "real_backend": True}],
        }


class FakeTunnelBackend:
    def __init__(self):
        self.establish_calls = []
        self.closed = False

    def establish(self, encrypted_vpn_status: bytes):
        self.establish_calls.append(encrypted_vpn_status)
        return {"status": "established", "transport_established": True}

    def close(self):
        self.closed = True


class InvalidTunnelBackend:
    def establish(self, **kwargs):
        return "not-a-dict"


class TestSecureTunnel(unittest.TestCase):
    def setUp(self):
        self.god_tier = GodTierEncryption()

    def test_disconnected_vpn_returns_unavailable(self):
        tunnel = SecureTunnel(self.god_tier, FakeVPNManager(connected=False))

        result = tunnel.establish()

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["error"], "VPN manager is not connected")
        self.assertFalse(tunnel.get_status()["active"])

    def test_without_backend_returns_unavailable_not_established(self):
        tunnel = SecureTunnel(self.god_tier, FakeVPNManager(connected=True))

        result = tunnel.establish()

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["error"], "Secure tunnel backend is not configured")
        self.assertFalse(tunnel.get_status()["active"])
        self.assertFalse(tunnel.get_status()["backend_configured"])

    def test_backend_receives_encrypted_vpn_status_and_establishes_tunnel(self):
        backend = FakeTunnelBackend()
        tunnel = SecureTunnel(
            self.god_tier,
            FakeVPNManager(connected=True),
            tunnel_backend=backend,
        )

        result = tunnel.establish()

        self.assertEqual(result["status"], "established")
        self.assertTrue(result["transport_established"])
        self.assertEqual(result["backend"], "FakeTunnelBackend")
        self.assertTrue(tunnel.get_status()["active"])
        self.assertEqual(len(backend.establish_calls), 1)
        encrypted_status = backend.establish_calls[0]
        self.assertIsInstance(encrypted_status, bytes)
        self.assertNotIn(b"wireguard", encrypted_status)

    def test_close_delegates_to_backend(self):
        backend = FakeTunnelBackend()
        tunnel = SecureTunnel(
            self.god_tier,
            FakeVPNManager(connected=True),
            tunnel_backend=backend,
        )
        tunnel.establish()

        tunnel.close()

        self.assertTrue(backend.closed)
        self.assertFalse(tunnel.get_status()["active"])

    def test_backend_result_must_be_mapping(self):
        tunnel = SecureTunnel(
            self.god_tier,
            FakeVPNManager(connected=True),
            tunnel_backend=InvalidTunnelBackend(),
        )

        with self.assertRaisesRegex(RuntimeError, "returned invalid result"):
            tunnel.establish()


if __name__ == "__main__":
    unittest.main()
