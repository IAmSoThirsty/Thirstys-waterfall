"""Focused tests for privacy engine runtime contracts."""

import unittest

from thirstys_waterfall.privacy import AntiMalwareEngine


class TestAntiMalwareEngine(unittest.TestCase):
    def setUp(self):
        self.engine = AntiMalwareEngine({})
        self.engine.start()

    def tearDown(self):
        self.engine.stop()

    def test_scan_file_accepts_absent_payload(self):
        self.assertTrue(self.engine.scan_file("unavailable.bin"))

    def test_suspicious_bytes_are_blocked_and_logged_as_text(self):
        with self.assertLogs(
            "thirstys_waterfall.privacy.anti_malware", level="WARNING"
        ) as logs:
            result = self.engine.scan_file("payload.bin", b"prefix eval( suffix")

        self.assertFalse(result)
        self.assertIn("Suspicious pattern detected: eval(", "\n".join(logs.output))
        self.assertNotIn("b'eval('", "\n".join(logs.output))


if __name__ == "__main__":
    unittest.main()
