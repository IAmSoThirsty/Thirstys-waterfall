"""Tests for encrypted runtime log handling."""

import io
import logging
import tempfile
import unittest
from contextlib import redirect_stdout

from cryptography.fernet import Fernet

from thirstys_waterfall import ThirstysWaterfall
from thirstys_waterfall.utils.encrypted_logging import EncryptedLogger


class TestEncryptedLoggerEvidence(unittest.TestCase):
    def test_direct_logger_persists_encrypted_file_without_plaintext(self):
        probe_value = "plaintext-probe-value"
        cipher = Fernet(Fernet.generate_key())

        with tempfile.NamedTemporaryFile(delete=False) as log_file:
            log_path = log_file.name

        logger = EncryptedLogger(cipher, log_file=log_path)
        logger.start()

        logger.log("INFO", probe_value)

        with open(log_path, "rb") as persisted:
            persisted_bytes = persisted.read()

        encrypted_entries = logger.get_encrypted_logs()
        self.assertEqual(len(encrypted_entries), 1)
        self.assertNotIn(probe_value.encode(), persisted_bytes)
        self.assertNotIn(probe_value.encode(), encrypted_entries[0])
        self.assertIn(probe_value, logger.decrypt_log(encrypted_entries[0]))

        logger.stop()

    def test_package_runtime_logs_are_encrypted_and_not_written_to_stdout(self):
        stdout = io.StringIO()
        probe_value = "runtime-plaintext-probe"

        with redirect_stdout(stdout):
            waterfall = ThirstysWaterfall()
            logging.getLogger("thirstys_waterfall.runtime").info(probe_value)

        encrypted_entries = waterfall.encrypted_logger.get_encrypted_logs()
        encrypted_blob = b"\n".join(encrypted_entries)
        decrypted_entries = [
            waterfall.encrypted_logger.decrypt_log(entry)
            for entry in encrypted_entries
        ]

        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn(probe_value.encode(), encrypted_blob)
        self.assertTrue(any(probe_value in entry for entry in decrypted_entries))

        status = waterfall.get_status()["encryption"]
        self.assertTrue(status["logs_encrypted"])
        self.assertEqual(status["logs_encryption_scope"], "local_package_runtime_logs")
        self.assertFalse(status["logs_encryption_accepted"])


if __name__ == "__main__":
    unittest.main()
