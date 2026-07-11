"""Tests for encrypted network payload handling."""

import unittest

from cryptography.fernet import Fernet

from thirstys_waterfall.utils.encrypted_network import EncryptedNetworkHandler


class TestEncryptedNetworkHandler(unittest.TestCase):
    def setUp(self):
        self.handler = EncryptedNetworkHandler(Fernet(Fernet.generate_key()))

    def test_inactive_request_fails_closed(self):
        self.assertEqual(self.handler.encrypt_request({"url": "https://example.test"}), b"")

    def test_encrypt_request_uses_structured_payload_without_plaintext(self):
        self.handler.start()

        encrypted = self.handler.encrypt_request(
            {"url": "https://example.test", "headers": {"x-test": "1"}}
        )
        decrypted = self.handler.decrypt_response(encrypted)

        self.assertIsInstance(encrypted, bytes)
        self.assertNotIn(b"https://example.test", encrypted)
        self.assertEqual(decrypted["url"], "https://example.test")
        self.assertEqual(decrypted["headers"], {"x-test": "1"})

    def test_decrypt_response_keeps_legacy_string_payload_compatible(self):
        self.handler.start()
        legacy_payload = self.handler._cipher.encrypt(
            b"{'url': 'https://legacy.example'}"
        )

        decrypted = self.handler.decrypt_response(legacy_payload)

        self.assertEqual(decrypted, {"data": "{'url': 'https://legacy.example'}"})

    def test_decrypt_packet_returns_structured_packet_and_compatibility_flag(self):
        self.handler.start()

        encrypted = self.handler.encrypt_packet({"src": "10.0.0.1", "port": 443})
        decrypted = self.handler.decrypt_packet(encrypted)

        self.assertEqual(decrypted["src"], "10.0.0.1")
        self.assertEqual(decrypted["port"], 443)
        self.assertTrue(decrypted["decrypted"])

    def test_status_does_not_claim_host_wide_interception(self):
        status = self.handler.get_status()

        self.assertEqual(status["handler_scope"], "explicit_payloads_only")
        self.assertFalse(status["host_wide_interception"])
        self.assertEqual(status["encryption_layers"], ["fernet"])


if __name__ == "__main__":
    unittest.main()
