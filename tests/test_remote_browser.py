"""Tests for remote browser backend gating."""

import unittest

from thirstys_waterfall.remote_access import RemoteBrowser
from thirstys_waterfall.utils.god_tier_encryption import GodTierEncryption


class FakeRemoteTransport:
    def __init__(self):
        self.started = False
        self.host = None
        self.port = None
        self.sessions = []
        self.commands = []
        self.stopped = False

    def start(self, host: str, port: int):
        self.started = True
        self.host = host
        self.port = port

    def create_session(self, session_id: str, encrypted_client_id: bytes):
        self.sessions.append((session_id, encrypted_client_id))
        return {"status": "active", "transport_connected": True}

    def send_command(self, session_id: str, encrypted_command: bytes):
        self.commands.append((session_id, encrypted_command))
        return {"status": "delivered"}

    def stop(self):
        self.stopped = True


class TestRemoteBrowser(unittest.TestCase):
    def setUp(self):
        self.god_tier = GodTierEncryption()
        self.config = {"remote_host": "127.0.0.1", "remote_port": 9000}

    def test_start_without_backend_fails_closed(self):
        remote = RemoteBrowser(self.config, self.god_tier)

        with self.assertRaisesRegex(
            RuntimeError, "Remote browser transport backend is not configured"
        ):
            remote.start()

        self.assertFalse(remote.get_status()["active"])
        self.assertFalse(remote.get_status()["backend_configured"])

    def test_session_and_command_delegate_to_backend(self):
        backend = FakeRemoteTransport()
        remote = RemoteBrowser(self.config, self.god_tier, transport_backend=backend)

        remote.start()
        session = remote.create_session("client-1")
        command = remote.send_command(session["session_id"], "navigate:https://test")

        self.assertTrue(backend.started)
        self.assertEqual((backend.host, backend.port), ("127.0.0.1", 9000))
        self.assertEqual(session["status"], "active")
        self.assertTrue(session["transport_connected"])
        self.assertEqual(session["backend"], "FakeRemoteTransport")
        self.assertEqual(command["status"], "delivered")
        self.assertEqual(command["backend"], "FakeRemoteTransport")
        self.assertEqual(len(backend.sessions), 1)
        self.assertEqual(len(backend.commands), 1)
        self.assertIsInstance(backend.sessions[0][1], bytes)
        self.assertIsInstance(backend.commands[0][1], bytes)
        self.assertNotIn(b"client-1", backend.sessions[0][1])
        self.assertNotIn(b"navigate:https://test", backend.commands[0][1])

    def test_stop_delegates_to_backend(self):
        backend = FakeRemoteTransport()
        remote = RemoteBrowser(self.config, self.god_tier, transport_backend=backend)
        remote.start()

        remote.stop()

        self.assertTrue(backend.stopped)
        self.assertFalse(remote.get_status()["active"])


if __name__ == "__main__":
    unittest.main()
