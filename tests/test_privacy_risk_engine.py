"""Tests for privacy risk engine backend evidence."""

import unittest

from thirstys_waterfall.security.privacy_risk_engine import (
    PrivacyRiskEngine,
    RiskLevel,
    ThreatEvent,
    ThreatType,
)


class FakeRiskModelBackend:
    def __init__(self):
        self.classify_calls = []
        self.learn_calls = []

    def classify_event(self, **kwargs):
        self.classify_calls.append(kwargs)
        return ThreatEvent(
            timestamp=1.0,
            threat_type=ThreatType.NETWORK_ATTACK,
            risk_level=RiskLevel.HIGH,
            source=kwargs["source"],
            description="backend threat",
            metadata=kwargs["metadata"],
        )

    def learn_from_event(self, **kwargs):
        self.learn_calls.append(kwargs)
        return {"status": "learned"}


class FakeHardeningBackend:
    def __init__(self):
        self.calls = []

    def harden_layer(self, **kwargs):
        self.calls.append(kwargs)
        return {"status": "applied", "control_id": f"{kwargs['layer']}-1"}


class InvalidHardeningBackend:
    def harden_layer(self, **kwargs):
        return "not-a-dict"


class TestPrivacyRiskEngine(unittest.TestCase):
    def test_status_reports_heuristic_model_without_backend(self):
        engine = PrivacyRiskEngine()

        status = engine.get_detailed_status()

        self.assertFalse(status["ai_model"]["initialized"])
        self.assertEqual(status["ai_model"]["model_type"], "heuristic")
        self.assertFalse(status["ai_model"]["backend_configured"])
        self.assertFalse(status["hardening"]["backend_configured"])

    def test_report_event_handles_threat_without_deadlock(self):
        engine = PrivacyRiskEngine()

        engine.report_event(
            "request",
            "browser",
            {"data_size": 11 * 1024 * 1024},
        )
        summary = engine.get_threat_summary()

        self.assertEqual(summary["recent_threat_count"], 1)
        self.assertEqual(summary["threat_types"]["data_exfiltration"], 1)

    def test_hardening_without_backend_reports_unavailable(self):
        engine = PrivacyRiskEngine()

        result = engine._harden_network_layer()
        status = engine.get_detailed_status()

        self.assertEqual(result["status"], "unavailable")
        self.assertFalse(result["hardening_applied"])
        self.assertEqual(result["layer"], "network")
        self.assertEqual(status["hardening"]["last_results"], [result])

    def test_hardening_delegates_to_backend(self):
        backend = FakeHardeningBackend()
        engine = PrivacyRiskEngine(hardening_backend=backend)

        result = engine._harden_browser_layer()

        self.assertEqual(result["status"], "applied")
        self.assertTrue(result["hardening_applied"])
        self.assertEqual(result["backend"], "FakeHardeningBackend")
        self.assertEqual(backend.calls[0]["layer"], "browser")

    def test_invalid_hardening_backend_fails_loudly(self):
        engine = PrivacyRiskEngine(hardening_backend=InvalidHardeningBackend())

        with self.assertRaisesRegex(RuntimeError, "returned invalid result"):
            engine._harden_data_layer()

    def test_model_backend_classifies_and_learns(self):
        model = FakeRiskModelBackend()
        engine = PrivacyRiskEngine(model_backend=model)

        engine.report_event("request", "browser", {"data_size": 100})
        result = engine.learn_from_event("request", {"data_size": 100}, True)
        status = engine.get_detailed_status()

        self.assertEqual(result["status"], "learned")
        self.assertEqual(result["backend"], "FakeRiskModelBackend")
        self.assertEqual(len(model.classify_calls), 1)
        self.assertEqual(len(model.learn_calls), 1)
        self.assertEqual(status["ai_model"]["model_type"], "FakeRiskModelBackend")
        self.assertTrue(status["ai_model"]["backend_configured"])


if __name__ == "__main__":
    unittest.main()
