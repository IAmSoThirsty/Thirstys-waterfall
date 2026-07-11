"""Tests for evidence-gated orchestrator status reporting."""

import unittest

from thirstys_waterfall import ThirstysWaterfall


class TestOrchestratorStatus(unittest.TestCase):
    def test_status_does_not_report_unaccepted_encryption_as_complete(self):
        waterfall = ThirstysWaterfall()

        status = waterfall.get_status()

        self.assertEqual(status["standard_v3_status"], "in_progress")
        self.assertFalse(status["deployment_accepted"])
        self.assertFalse(status["everything_encrypted"])
        self.assertFalse(status["everything_encrypted_accepted"])
        self.assertEqual(status["encryption_tier"], "not_accepted")
        self.assertIsNone(status["encryption_layers"])
        self.assertFalse(status["encryption"]["accepted"])
        self.assertFalse(status["encryption"]["searches_encrypted"])
        self.assertFalse(status["encryption"]["sites_encrypted"])
        self.assertFalse(status["encryption"]["traffic_encrypted"])
        self.assertFalse(status["encryption"]["zero_knowledge"])
        self.assertIn("helper_strength", status["encryption"])

    def test_status_does_not_report_builtin_vpn_accepted_without_connection(self):
        waterfall = ThirstysWaterfall()

        status = waterfall.get_status()

        self.assertFalse(status["built_in_vpn"])
        self.assertFalse(status["built_in_vpn_accepted"])
        self.assertFalse(status["vpn"]["connected"])


if __name__ == "__main__":
    unittest.main()
