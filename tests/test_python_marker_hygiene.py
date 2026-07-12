"""Regression tests for evidence-gated marker cleanup."""

import unittest
from datetime import datetime

from src.core.integrated_specs.canonical_bundle import (
    UnsafeCapabilityExceptionRecords,
)
from thirstys_waterfall.ai_assistant.ai_engine import GodTierAI
from thirstys_waterfall.privacy.anti_fingerprint import AntiFingerprintEngine


class FakeEncryptionHelper:
    def encrypt_god_tier(self, data: bytes) -> bytes:
        return b"encrypted-" + data


class TestPythonMarkerHygiene(unittest.TestCase):
    def test_ai_status_and_response_do_not_claim_accepted_encryption(self):
        ai = GodTierAI(config={}, god_tier_encryption=FakeEncryptionHelper())
        ai.start()

        response = ai.ask("privacy check")
        status = ai.get_status()
        history = ai.get_conversation_history()

        self.assertTrue(response["processed_on_device"])
        self.assertTrue(response["local_helper_encrypted"])
        self.assertFalse(response["encryption_accepted"])
        self.assertFalse(response["encryption_evidence"]["accepted_end_to_end"])
        self.assertIsNone(status["encryption_layers"])
        self.assertFalse(status["encryption_accepted"])
        self.assertTrue(history[0]["local_helper_encrypted"])
        self.assertFalse(history[0]["encryption_accepted"])

    def test_anti_fingerprint_status_matches_active_state(self):
        engine = AntiFingerprintEngine({})

        inactive = engine.get_protection_status()
        engine.start()
        active = engine.get_protection_status()

        self.assertFalse(inactive["active"])
        self.assertFalse(inactive["canvas_randomized"])
        self.assertFalse(inactive["webgl_blocked"])
        self.assertTrue(active["active"])
        self.assertTrue(active["canvas_randomized"])
        self.assertTrue(active["webgl_blocked"])

    def test_exception_duration_sets_future_expiration(self):
        records = UnsafeCapabilityExceptionRecords(
            records_id="unsafe-records", exceptions=[]
        )
        before = datetime.now()

        exception_id = records.grant_exception(
            capability="network-control",
            authorized_by="operator",
            authorized_for="agent",
            justification="test",
            duration=60,
        )

        exception = records.exceptions[0]
        self.assertEqual(exception.exception_id, exception_id)
        self.assertGreater(exception.expires_at, before)
        self.assertEqual(records.get_active_exceptions("agent"), [exception])


if __name__ == "__main__":
    unittest.main()
