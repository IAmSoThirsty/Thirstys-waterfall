"""Tests for VPN DNS and IPv6 leak protection backend evidence."""

import unittest

from thirstys_waterfall.vpn import DNSProtection


class FakeDNSBackend:
    def __init__(self):
        self.set_calls = []
        self.ipv6_block_calls = 0
        self.ipv6_restore_calls = 0

    def get_system_dns(self):
        return ["192.0.2.53"]

    def set_dns_servers(self, **kwargs):
        self.set_calls.append(kwargs)
        return {
            "status": "restored" if kwargs.get("restore") else "set",
            "dns_servers_set": True,
        }

    def block_ipv6(self):
        self.ipv6_block_calls += 1
        return {"status": "blocked", "ipv6_blocked": True}

    def restore_ipv6(self):
        self.ipv6_restore_calls += 1
        return {"status": "restored", "ipv6_restored": True}


class FakeLeakDetector:
    def __init__(self, leak_detected=False):
        self.leak_detected = leak_detected
        self.dns_checks = []
        self.ipv6_checks = 0

    def verify_dns_leak(self, **kwargs):
        self.dns_checks.append(kwargs)
        return {
            "status": "verified",
            "leak_detected": self.leak_detected,
        }

    def verify_ipv6_leak(self):
        self.ipv6_checks += 1
        return {
            "status": "verified",
            "leak_detected": self.leak_detected,
        }


class InvalidDNSBackend:
    def get_system_dns(self):
        return "not-a-list"

    def set_dns_servers(self, **kwargs):
        return "not-a-dict"

    def block_ipv6(self):
        return "not-a-dict"

    def restore_ipv6(self):
        return "not-a-dict"


class InvalidLeakDetector:
    def verify_dns_leak(self, **kwargs):
        return "not-a-dict"

    def verify_ipv6_leak(self):
        return "not-a-dict"


class TestDNSProtection(unittest.TestCase):
    def test_start_without_backend_reports_unavailable_not_active(self):
        protection = DNSProtection()

        result = protection.start()

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(
            result["error"],
            "VPN DNS protection backend is not configured",
        )
        self.assertFalse(result["dns_protected"])
        self.assertFalse(result["ipv6_protected"])
        self.assertFalse(protection.is_active())
        self.assertFalse(protection.get_status()["backend_configured"])

    def test_start_and_stop_delegate_to_backend(self):
        backend = FakeDNSBackend()
        protection = DNSProtection(dns_backend=backend)

        start_result = protection.start()

        self.assertTrue(protection.is_active())
        self.assertEqual(start_result["status"], "protected")
        self.assertTrue(start_result["dns_protected"])
        self.assertTrue(start_result["ipv6_protected"])
        self.assertEqual(start_result["original_dns"], ["192.0.2.53"])
        self.assertEqual(backend.ipv6_block_calls, 1)
        self.assertEqual(backend.set_calls[0]["servers"], ["10.200.200.1", "10.200.200.2"])

        stop_result = protection.stop()

        self.assertFalse(protection.is_active())
        self.assertEqual(stop_result["status"], "stopped")
        self.assertTrue(stop_result["dns_restored"])
        self.assertTrue(stop_result["ipv6_restored"])
        self.assertEqual(backend.ipv6_restore_calls, 1)
        self.assertEqual(backend.set_calls[1]["servers"], ["192.0.2.53"])
        self.assertTrue(backend.set_calls[1]["restore"])

    def test_verify_without_leak_detector_fails_closed(self):
        protection = DNSProtection()

        self.assertFalse(protection.verify_dns_leak())
        self.assertFalse(protection.verify_ipv6_leak())
        self.assertEqual(
            protection.get_status()["dns_leak_result"]["status"],
            "unavailable",
        )
        self.assertEqual(
            protection.get_status()["ipv6_leak_result"]["status"],
            "unavailable",
        )

    def test_verify_delegates_to_leak_detector(self):
        backend = FakeDNSBackend()
        detector = FakeLeakDetector(leak_detected=False)
        protection = DNSProtection(dns_backend=backend, leak_detector=detector)
        protection.start()

        self.assertTrue(protection.verify_dns_leak())
        self.assertTrue(protection.verify_ipv6_leak())
        self.assertEqual(detector.dns_checks[0]["dns_servers"], ["10.200.200.1", "10.200.200.2"])
        self.assertEqual(detector.ipv6_checks, 1)

    def test_detector_reports_leak_as_unprotected(self):
        detector = FakeLeakDetector(leak_detected=True)
        protection = DNSProtection(leak_detector=detector)

        self.assertFalse(protection.verify_dns_leak())
        self.assertFalse(protection.verify_ipv6_leak())

    def test_invalid_backend_results_fail_loudly(self):
        protection = DNSProtection(dns_backend=InvalidDNSBackend())

        with self.assertRaisesRegex(RuntimeError, "invalid DNS server list"):
            protection.start()

    def test_invalid_leak_detector_results_fail_loudly(self):
        protection = DNSProtection(leak_detector=InvalidLeakDetector())

        with self.assertRaisesRegex(RuntimeError, "returned invalid result"):
            protection.verify_dns_leak()

        with self.assertRaisesRegex(RuntimeError, "returned invalid result"):
            protection.verify_ipv6_leak()


if __name__ == "__main__":
    unittest.main()
