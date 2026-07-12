"""Tests for media downloader backend gating."""

import os
import tempfile
import unittest

from thirstys_waterfall.media_downloader import MediaDownloader
from thirstys_waterfall.utils.god_tier_encryption import GodTierEncryption


class FakeDownloadBackend:
    def __init__(self):
        self.calls = []

    def download(
        self,
        url_hash: str,
        encrypted_url: bytes,
        mode: str,
        audio_format: str,
        video_format: str,
        download_directory: str,
    ):
        self.calls.append(
            {
                "url_hash": url_hash,
                "encrypted_url": encrypted_url,
                "mode": mode,
                "audio_format": audio_format,
                "video_format": video_format,
                "download_directory": download_directory,
            }
        )
        return {
            "status": "completed",
            "file_path": os.path.join(download_directory, f"{url_hash}.{video_format}"),
        }


class InvalidBackend:
    def download(self, **kwargs):
        return "not-a-dict"


class TestMediaDownloader(unittest.TestCase):
    def setUp(self):
        self.god_tier = GodTierEncryption()
        self.temp_dir = tempfile.TemporaryDirectory()
        self.config = {"download_directory": self.temp_dir.name}

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_without_backend_returns_unavailable_not_completed(self):
        downloader = MediaDownloader(self.config, self.god_tier)
        downloader.start()

        result = downloader.download("https://example.invalid/video")

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["error"], "Media download backend is not configured")
        self.assertNotIn("file_path", result)
        self.assertEqual(downloader.get_history()[0]["status"], "unavailable")
        self.assertFalse(downloader.get_status()["backend_configured"])

    def test_backend_receives_encrypted_url_and_returns_encrypted_path(self):
        backend = FakeDownloadBackend()
        downloader = MediaDownloader(
            self.config,
            self.god_tier,
            download_backend=backend,
        )
        downloader.start()

        result = downloader.download(
            "https://example.invalid/video",
            mode="video_only",
            video_format="webm",
            metadata={"title": "sample"},
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["mode"], "video_only")
        self.assertTrue(result["local_helper_encrypted"])
        self.assertFalse(result["encryption_accepted"])
        self.assertTrue(result["metadata_encrypted"])
        self.assertIn("encrypted_file_path", result)
        self.assertEqual(len(backend.calls), 1)
        call = backend.calls[0]
        self.assertEqual(call["mode"], "video_only")
        self.assertEqual(call["video_format"], "webm")
        self.assertIsInstance(call["encrypted_url"], bytes)
        self.assertNotIn(b"https://example.invalid/video", call["encrypted_url"])

    def test_backend_result_must_be_mapping(self):
        downloader = MediaDownloader(
            self.config,
            self.god_tier,
            download_backend=InvalidBackend(),
        )
        downloader.start()

        with self.assertRaisesRegex(RuntimeError, "returned invalid result"):
            downloader.download("https://example.invalid/video")


if __name__ == "__main__":
    unittest.main()
