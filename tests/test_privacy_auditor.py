"""Tests for privacy leak auditor backend evidence."""

import unittest

from thirstys_waterfall.privacy import PrivacyAuditor


class FakeLeakAuditBackend:
    def __init__(self, leak_detected=False):
        self.leak_detected = leak_detected
        self.calls = []

    def audit_dns_leak(self):
        self.calls.append("dns")
        return {"status": "verified", "leak_detected": self.leak_detected}

    def audit_ipv6_leak(self):
        self.calls.append("ipv6")
        return {"status": "verified", "leak_detected": self.leak_detected}

    def audit_webrtc_leak(self):
        self.calls.append("webrtc")
        return {"status": "verified", "leak_detected": self.leak_detected}


class InvalidLeakAuditBackend:
    def audit_dns_leak(self):
        return "not-a-dict"

    def audit_ipv6_leak(self):
        return "not-a-dict"

    def audit_webrtc_leak(self):
        return "not-a-dict"


class TestPrivacyAuditorLeakEvidence(unittest.TestCase):
    def test_audit_events_are_stored_encrypted(self):
        auditor = PrivacyAuditor({"session_auditing": True, "leak_auditing": False})
        auditor.start()
        probe_value = "privacy-audit-secret"

        auditor.log_event("data_access", {"probe": probe_value})

        encrypted_blob = b"\n".join(auditor.get_encrypted_audit_log())
        audit_log = auditor.get_audit_log()

        self.assertNotIn(probe_value.encode(), encrypted_blob)
        self.assertTrue(any(entry["details"].get("probe") == probe_value for entry in audit_log))
        self.assertEqual(auditor.run_full_audit()["audit_events_encrypted"], True)

    def test_privacy_violations_are_returned_from_encrypted_events(self):
        auditor = PrivacyAuditor({"session_auditing": True, "leak_auditing": False})
        auditor.start()

        auditor.log_event("cookie_stored", {"domain": "example.test"})

        violations = auditor.get_violations()
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["type"], "cookie_stored")
        self.assertEqual(violations[0]["details"]["domain"], "example.test")

    def test_leak_audits_without_backend_fail_closed(self):
        auditor = PrivacyAuditor({"session_auditing": True, "leak_auditing": True})
        auditor.start()

        self.assertFalse(auditor.audit_dns_leak())
        self.assertFalse(auditor.audit_ipv6_leak())
        self.assertFalse(auditor.audit_webrtc_leak())

        result = auditor.run_full_audit()
        self.assertFalse(result["dns_leak"])
        self.assertFalse(result["ipv6_leak"])
        self.assertFalse(result["webrtc_leak"])
        self.assertFalse(result["leak_audit_backend_configured"])
        self.assertEqual(result["leak_results"]["dns"]["status"], "unavailable")

    def test_leak_audits_delegate_to_backend(self):
        backend = FakeLeakAuditBackend(leak_detected=False)
        auditor = PrivacyAuditor(
            {
                "session_auditing": True,
                "leak_auditing": True,
                "leak_audit_backend": backend,
            }
        )
        auditor.start()

        result = auditor.run_full_audit()

        self.assertTrue(result["dns_leak"])
        self.assertTrue(result["ipv6_leak"])
        self.assertTrue(result["webrtc_leak"])
        self.assertTrue(result["leak_audit_backend_configured"])
        self.assertEqual(backend.calls, ["dns", "ipv6", "webrtc"])
        self.assertEqual(result["leak_results"]["dns"]["backend"], "FakeLeakAuditBackend")

    def test_detected_leaks_return_unprotected(self):
        backend = FakeLeakAuditBackend(leak_detected=True)
        auditor = PrivacyAuditor(
            {
                "session_auditing": True,
                "leak_auditing": True,
                "leak_audit_backend": backend,
            }
        )
        auditor.start()

        self.assertFalse(auditor.audit_dns_leak())
        self.assertFalse(auditor.audit_ipv6_leak())
        self.assertFalse(auditor.audit_webrtc_leak())

    def test_invalid_backend_results_fail_loudly(self):
        auditor = PrivacyAuditor(
            {
                "session_auditing": True,
                "leak_auditing": True,
                "leak_audit_backend": InvalidLeakAuditBackend(),
            }
        )
        auditor.start()

        with self.assertRaisesRegex(RuntimeError, "returned invalid result"):
            auditor.audit_dns_leak()


if __name__ == "__main__":
    unittest.main()
