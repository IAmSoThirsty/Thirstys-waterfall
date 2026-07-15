"""Tests for settings encryption and import behavior."""

import unittest

from cryptography.fernet import Fernet

from thirstys_waterfall.settings import SettingsManager
from thirstys_waterfall.settings.qa_system import QASystem


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

    def test_import_settings_rejects_invalid_shape_atomically(self):
        helper = LocalEncryptionHelper()
        manager = SettingsManager(helper)
        before = manager.get_all_settings()
        invalid = helper.encrypt_god_tier(
            b'{"general":{"theme":"solarized"},"privacy":[]}'
        )

        manager.import_settings(invalid)

        self.assertEqual(manager.get_all_settings(), before)
        self.assertFalse(manager.get_status()["modified"])

    def test_import_settings_deep_merges_nested_values(self):
        helper = LocalEncryptionHelper()
        manager = SettingsManager(helper)
        imported = helper.encrypt_god_tier(
            b'{"ai_assistant":{"capabilities":{"text_generation":false}}}'
        )

        manager.import_settings(imported)

        capabilities = manager.get_setting("ai_assistant", "capabilities")
        self.assertFalse(capabilities["text_generation"])
        self.assertTrue(capabilities["code_assistance"])
        self.assertTrue(capabilities["privacy_analysis"])

    def test_reset_uses_isolated_default_snapshot(self):
        manager = SettingsManager(LocalEncryptionHelper())
        manager.set_setting("general", "theme", "solarized")
        manager.set_setting("ai_assistant", "capabilities", {"text_generation": False})

        manager.reset_category("general")
        manager.reset_category("ai_assistant")

        self.assertEqual(manager.get_setting("general", "theme"), "dark")
        capabilities = manager.get_setting("ai_assistant", "capabilities")
        self.assertTrue(capabilities["text_generation"])

    def test_returned_settings_snapshot_cannot_mutate_manager(self):
        manager = SettingsManager(LocalEncryptionHelper())
        snapshot = manager.get_all_settings()

        snapshot["general"]["theme"] = "solarized"
        snapshot["ai_assistant"]["capabilities"]["text_generation"] = False

        self.assertEqual(manager.get_setting("general", "theme"), "dark")
        capabilities = manager.get_setting("ai_assistant", "capabilities")
        self.assertTrue(capabilities["text_generation"])

    def test_status_reports_unaccepted_local_helper_scope(self):
        status = SettingsManager(LocalEncryptionHelper()).get_status()

        self.assertTrue(status["local_helper_encrypted"])
        self.assertFalse(status["encryption_accepted"])
        self.assertIsNone(status["encryption_layers"])


class TestQASystemClaimEvidence(unittest.TestCase):
    def test_security_answers_do_not_promise_unproven_backend_results(self):
        answers = " ".join(
            item["answer"] for item in QASystem(None).qa_database
        ).lower()

        self.assertNotIn("100% guaranteed", answers)
        self.assertNotIn("eliminates all", answers)
        self.assertIn("backend", answers)
        self.assertIn("evidence", answers)


if __name__ == "__main__":
    unittest.main()
