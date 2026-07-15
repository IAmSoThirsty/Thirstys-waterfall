"""Focused storage and resolver runtime tests."""

import unittest
from unittest.mock import patch

from cryptography.fernet import Fernet

from thirstys_waterfall.storage import EphemeralStorage, PrivacyVault
from thirstys_waterfall.utils import DoHResolver


class TestStorageRuntime(unittest.TestCase):
    def test_privacy_vault_encrypts_round_trip_and_wipes_on_stop(self):
        vault = PrivacyVault({"encrypted": True, "forensic_resistance": True})
        vault.start(encryption_key=Fernet.generate_key())

        vault.store("token", "sensitive-value")

        self.assertEqual(vault.retrieve("token"), "sensitive-value")
        self.assertNotIn(b"sensitive-value", vault._vault["token"])

        vault.stop()
        self.assertFalse(vault.is_active())
        self.assertEqual(vault.list_keys(), [])

    def test_ephemeral_storage_expires_entries_deterministically(self):
        storage = EphemeralStorage({"memory_only": True})
        storage.start()

        with patch("thirstys_waterfall.storage.ephemeral_storage.time.time") as now:
            now.return_value = 100.0
            storage.store("session", {"id": "one"}, ttl=5)
            now.return_value = 106.0
            storage.cleanup_expired()

        self.assertIsNone(storage.retrieve("session"))
        self.assertEqual(storage.get_statistics()["items_stored"], 0)

    def test_doh_resolver_fails_closed_without_network_backend(self):
        resolver = DoHResolver()

        self.assertIsNone(resolver.resolve("example.com"))
        resolver.start()
        self.assertIsNone(resolver.resolve("example.com"))
        self.assertTrue(resolver.is_active())


if __name__ == "__main__":
    unittest.main()
