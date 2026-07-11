"""Tests for remote desktop backend gating."""

import unittest

from thirstys_waterfall.remote_access import RemoteDesktop
from thirstys_waterfall.utils.god_tier_encryption import GodTierEncryption


class FakeDesktopBackend:
    def __init__(self):
        self.started = False
        self.start_args = None
        self.connections = []
        self.disconnects = []
        self.stopped = False

    def start(self, host: str, port: int, resolution: str):
        self.started = True
        self.start_args = (host, port, resolution)

    def connect(
        self,
        connection_id: str,
        encrypted_client: bytes,
        encrypted_auth_token: bytes,
    ):
        self.connections.append(
            (connection_id, encrypted_client, encrypted_auth_token)
        )
        return {"status": "connected", "transport_connected": True}

    def disconnect(self, connection_id: str):
        self.disconnects.append(connection_id)

    def stop(self):
        self.stopped = True


class TestRemoteDesktop(unittest.TestCase):
    def setUp(self):
        self.god_tier = GodTierEncryption()
        self.config = {
            "remote_desktop_host": "127.0.0.1",
            "remote_desktop_port": 9001,
            "resolution": "1280x720",
        }

    def test_start_without_backend_fails_closed(self):
        remote = RemoteDesktop(self.config, self.god_tier)

        with self.assertRaisesRegex(
            RuntimeError, "Remote desktop backend is not configured"
        ):
            remote.start()

        self.assertFalse(remote.get_status()["active"])
        self.assertFalse(remote.get_status()["backend_configured"])

    def test_connect_delegates_encrypted_credentials_to_backend(self):
        backend = FakeDesktopBackend()
        remote = RemoteDesktop(self.config, self.god_tier, desktop_backend=backend)

        remote.start()
        result = remote.connect("client-1", "token-1")

        self.assertTrue(backend.started)
        self.assertEqual(backend.start_args, ("127.0.0.1", 9001, "1280x720"))
        self.assertEqual(result["status"], "connected")
        self.assertTrue(result["transport_connected"])
        self.assertEqual(result["backend"], "FakeDesktopBackend")
        self.assertEqual(len(backend.connections), 1)
        _, encrypted_client, encrypted_token = backend.connections[0]
        self.assertIsInstance(encrypted_client, bytes)
        self.assertIsInstance(encrypted_token, bytes)
        self.assertNotIn(b"client-1", encrypted_client)
        self.assertNotIn(b"token-1", encrypted_token)

    def test_stop_disconnects_backend(self):
        backend = FakeDesktopBackend()
        remote = RemoteDesktop(self.config, self.god_tier, desktop_backend=backend)
        remote.start()
        result = remote.connect("client-1", "token-1")

        remote.stop()

        self.assertEqual(backend.disconnects, [result["connection_id"]])
        self.assertTrue(backend.stopped)
        self.assertFalse(remote.get_status()["active"])


if __name__ == "__main__":
    unittest.main()
