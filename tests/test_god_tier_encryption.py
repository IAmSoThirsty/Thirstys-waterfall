"""Tests for cryptography capability evidence."""

import unittest

from thirstys_waterfall.utils.god_tier_encryption import (
    GodTierEncryption,
    QuantumResistantEncryption,
)


class FakePostQuantumBackend:
    def __init__(self):
        self.encrypted = []
        self.decrypted = []

    def encrypt(self, data: bytes) -> bytes:
        self.encrypted.append(data)
        return b"pq:" + data

    def decrypt(self, encrypted_data: bytes, salt=None) -> bytes:
        self.decrypted.append((encrypted_data, salt))
        if not encrypted_data.startswith(b"pq:"):
            raise ValueError("invalid ciphertext")
        return encrypted_data[3:]


class TestGodTierEncryptionEvidence(unittest.TestCase):
    def test_strength_does_not_claim_post_quantum_acceptance(self):
        strength = GodTierEncryption().get_encryption_strength()

        self.assertFalse(strength["quantum_resistant"])
        self.assertFalse(strength["post_quantum_backend_configured"])
        self.assertIn(
            "RSA-4096 (classical asymmetric key material)",
            strength["algorithms"],
        )

    def test_quantum_facade_fails_closed_without_backend(self):
        crypto = QuantumResistantEncryption()

        with self.assertRaisesRegex(RuntimeError, "backend is not configured"):
            crypto.encrypt_quantum_resistant(b"secret")

        with self.assertRaisesRegex(RuntimeError, "backend is not configured"):
            crypto.decrypt_quantum_resistant(b"ciphertext")

        self.assertFalse(crypto.get_status()["backend_configured"])
        self.assertFalse(crypto.get_status()["accepted_post_quantum"])

    def test_quantum_facade_delegates_to_configured_backend(self):
        backend = FakePostQuantumBackend()
        crypto = QuantumResistantEncryption(post_quantum_backend=backend)

        encrypted = crypto.encrypt_quantum_resistant(b"secret")
        decrypted = crypto.decrypt_quantum_resistant(encrypted, salt=b"salt")

        self.assertEqual(encrypted, b"pq:secret")
        self.assertEqual(decrypted, b"secret")
        self.assertEqual(backend.encrypted, [b"secret"])
        self.assertEqual(backend.decrypted, [(b"pq:secret", b"salt")])
        self.assertTrue(crypto.get_status()["backend_configured"])
        self.assertTrue(crypto.get_status()["accepted_post_quantum"])
        self.assertEqual(crypto.get_status()["backend"], "FakePostQuantumBackend")


if __name__ == "__main__":
    unittest.main()
