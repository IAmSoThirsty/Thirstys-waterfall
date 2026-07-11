"""Tests for format converter backend gating."""

import unittest

from thirstys_waterfall.media_downloader import FormatConverter
from thirstys_waterfall.utils.god_tier_encryption import GodTierEncryption


class FakeConversionBackend:
    def __init__(self):
        self.calls = []

    def convert(self, input_file: str, encrypted_input_path: bytes, output_format: str):
        self.calls.append(
            {
                "input_file": input_file,
                "encrypted_input_path": encrypted_input_path,
                "output_format": output_format,
            }
        )
        return {
            "status": "completed",
            "output_file": input_file.rsplit(".", 1)[0] + "." + output_format,
        }


class InvalidConversionBackend:
    def convert(self, **kwargs):
        return "not-a-dict"


class TestFormatConverter(unittest.TestCase):
    def setUp(self):
        self.god_tier = GodTierEncryption()

    def test_without_backend_returns_unavailable_not_completed(self):
        converter = FormatConverter(self.god_tier)

        result = converter.convert("sample.wav", "mp3")

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["error"], "Media conversion backend is not configured")
        self.assertEqual(result["output_format"], "mp3")
        self.assertTrue(result["god_tier_encrypted"])
        self.assertNotIn("output_file", result)
        self.assertNotIn("encrypted_output_path", result)

    def test_backend_receives_encrypted_input_and_returns_encrypted_output_path(self):
        backend = FakeConversionBackend()
        converter = FormatConverter(self.god_tier, conversion_backend=backend)

        result = converter.convert("sample.wav", "flac")

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["output_file"], "sample.flac")
        self.assertEqual(result["output_format"], "flac")
        self.assertTrue(result["god_tier_encrypted"])
        self.assertIn("encrypted_output_path", result)
        self.assertEqual(len(backend.calls), 1)
        call = backend.calls[0]
        self.assertEqual(call["input_file"], "sample.wav")
        self.assertEqual(call["output_format"], "flac")
        self.assertIsInstance(call["encrypted_input_path"], bytes)
        self.assertNotIn(b"sample.wav", call["encrypted_input_path"])

    def test_backend_result_must_be_mapping(self):
        converter = FormatConverter(
            self.god_tier,
            conversion_backend=InvalidConversionBackend(),
        )

        with self.assertRaisesRegex(RuntimeError, "returned invalid result"):
            converter.convert("sample.wav", "mp3")


if __name__ == "__main__":
    unittest.main()
