"""Tests for settings encryption and import behavior."""

import unittest

from cryptography.fernet import Fernet

from thirstys_waterfall.settings import SettingsManager


class LocalEncryptionHelper:
    def __init__(self):
        self.cipher = Fernet(Fernet.generate_key())

    def encrypt_god_tier(self, data: bytes) -> bytes:
        return self.cipher.encrypt(data)

    def decrypt_god_tier(self, encrypted_data: bytes) -> bytes:
        return self.cipher.decrypt(encrypted_data)


class TestSettingsManagerEncryptionEvidence(unittest.TestCase):
    def test_export_settings_uses_encryption_helper_without_plaintext_leak(self):
        manager = SettingsManager(LocalEncryptionHelper())
        manager.set_setting("general", "theme", "solarized")

        exported = manager.export_settings()

        self.assertIsInstance(exported, bytes)
        self.assertNotIn(b"solarized", exported)
        self.assertNotIn(b"general", exported)

    def test_import_settings_restores_exported_values(self):
        helper = LocalEncryptionHelper()
        source = SettingsManager(helper)
        target = SettingsManager(helper)
        source.set_setting("general", "theme", "solarized")
        source.set_setting("browser", "no_history", False)

        target.import_settings(source.export_settings())

        self.assertEqual(target.get_setting("general", "theme"), "solarized")
        self.assertFalse(target.get_setting("browser", "no_history"))
        self.assertTrue(target.get_status()["modified"])

    def test_import_settings_rejects_unreadable_data_without_mutation(self):
        manager = SettingsManager(LocalEncryptionHelper())
        before = manager.get_all_settings()

        manager.import_settings(b"not valid encrypted settings")

        self.assertEqual(manager.get_all_settings(), before)
        self.assertFalse(manager.get_status()["modified"])

    def test_status_reports_unaccepted_local_helper_scope(self):
        status = SettingsManager(LocalEncryptionHelper()).get_status()

        self.assertTrue(status["local_helper_encrypted"])
        self.assertFalse(status["encryption_accepted"])
        self.assertIsNone(status["encryption_layers"])


if __name__ == "__main__":
    unittest.main()
