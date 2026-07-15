"""Focused acceptance tests for AI, setup, theme, and config helpers."""

import tempfile
from pathlib import Path
import unittest
from unittest import mock

from thirstys_waterfall.ai_assistant import ContextManager, GodTierAI
from thirstys_waterfall.config import ConfigValidator
from thirstys_waterfall.setup import SetupWizard
from thirstys_waterfall.themes import SystemThemeDetector, ThemeManager


class FakeEncryption:
    def encrypt_god_tier(self, data: bytes) -> bytes:
        return b"encrypted:" + data


class TestAIAssistantLifecycle(unittest.TestCase):
    def test_context_is_bounded_and_history_does_not_retain_queries(self):
        assistant = GodTierAI({"max_context": 1}, FakeEncryption())
        self.addCleanup(assistant.stop)
        assistant.start()

        privacy_response = assistant.ask("review privacy")
        code_response = assistant.ask("review code")

        self.assertTrue(privacy_response["processed_on_device"])
        self.assertFalse(privacy_response["encryption_accepted"])
        self.assertTrue(code_response["no_external_calls"])
        self.assertEqual(len(assistant._context), 1)
        history = assistant.get_conversation_history()
        self.assertEqual(len(history), 2)
        self.assertTrue(all("query" not in entry for entry in history))

    def test_stop_clears_ephemeral_state(self):
        assistant = GodTierAI({}, FakeEncryption())
        assistant.start()
        assistant.ask("general question")

        assistant.stop()

        self.assertEqual(assistant.get_conversation_history(), [])
        self.assertEqual(assistant.get_status()["context_size"], 0)
        self.assertFalse(assistant.get_status()["active"])

    def test_context_manager_returns_copy_and_enforces_limit(self):
        manager = ContextManager(FakeEncryption(), max_size=1)
        manager.add({"value": 1})
        manager.add({"value": 2})

        context = manager.get()
        context.clear()

        self.assertEqual(manager.get(), [{"value": 2}])


class TestSetupWizard(unittest.TestCase):
    def test_accepted_setup_completes_and_persists_marker(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = Path(temp_dir) / "setup-complete"
            wizard = SetupWizard(FakeEncryption())
            wizard.setup_file = str(marker)

            with mock.patch(
                "thirstys_waterfall.setup.notice_letter."
                "NoticeLetterManager.show_notice_and_get_acceptance",
                return_value=True,
            ), mock.patch(
                "thirstys_waterfall.setup.captcha_system."
                "AntiBotCaptchaSystem.verify_human",
                return_value={"verified": True},
            ), mock.patch(
                "thirstys_waterfall.setup.usage_tutorial."
                "UsageTutorial.show_interactive_tutorial"
            ) as tutorial:
                result = wizard.run_setup()

            self.assertEqual(result, {"setup_complete": True})
            self.assertEqual(marker.read_text(encoding="utf-8"), "complete")
            tutorial.assert_called_once_with()

    def test_rejected_notice_fails_closed_without_marker(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = Path(temp_dir) / "setup-complete"
            wizard = SetupWizard(FakeEncryption())
            wizard.setup_file = str(marker)

            with mock.patch(
                "thirstys_waterfall.setup.notice_letter."
                "NoticeLetterManager.show_notice_and_get_acceptance",
                return_value=False,
            ):
                result = wizard.run_setup()

            self.assertEqual(result, {"setup_complete": False})
            self.assertFalse(marker.exists())


class TestThemesAndConfig(unittest.TestCase):
    def test_theme_manager_uses_explicit_and_detected_themes(self):
        manager = ThemeManager()
        manager.set_theme("light")
        self.assertEqual(manager.get_theme_colors()["background"], "#FFFFFF")

        manager.set_theme("default")
        with mock.patch.object(
            SystemThemeDetector, "detect_system_theme", return_value="dark"
        ):
            self.assertEqual(manager.get_effective_theme(), "dark")

    def test_theme_detection_fails_closed_to_dark(self):
        detector = SystemThemeDetector()
        detector.os_name = "Windows"
        with mock.patch.object(detector, "_detect_windows", side_effect=OSError):
            self.assertEqual(detector.detect_system_theme(), "dark")

    def test_ip_validation_rejects_invalid_octets_and_accepts_compressed_ipv6(self):
        self.assertFalse(ConfigValidator.validate_ip_address("999.999.999.999"))
        self.assertFalse(ConfigValidator.validate_ip_address(None))
        self.assertFalse(ConfigValidator.validate_ip_address([]))
        self.assertTrue(ConfigValidator.validate_ip_address("192.0.2.10"))
        self.assertTrue(ConfigValidator.validate_ip_address("2001:db8::1"))


if __name__ == "__main__":
    unittest.main()
