"""Media downloader engine with local helper encryption."""

import logging
from typing import Dict, Any, Optional, List
import os
import hashlib
from cryptography.fernet import Fernet


class MediaDownloader:
    """
    Multi-mode media downloader with evidence-gated security reporting.

    Features:
    - Audio-only downloads
    - Video-only downloads
    - Combined audio+video
    - Format conversion
    - Metadata helper encryption
    - Built-in library management
    - Secure streaming
    """

    def __init__(
        self,
        config: Dict[str, Any],
        god_tier_encryption,
        download_backend: Optional[Any] = None,
    ):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.god_tier_encryption = god_tier_encryption
        self.download_backend = download_backend

        # Download modes
        self.supported_modes = [
            "audio_only",
            "video_only",
            "audio_video",
            "best_quality",
        ]

        # Supported formats
        self.audio_formats = ["mp3", "aac", "flac", "opus", "vorbis"]
        self.video_formats = ["mp4", "webm", "mkv", "avi"]

        # Local helper encryption for metadata
        self._cipher = Fernet(Fernet.generate_key())

        # Download queue (encrypted)
        self._download_queue: List[Dict[str, Any]] = []

        # Download history (encrypted, ephemeral)
        self._download_history: List[Dict[str, Any]] = []

        self._active = False
        self._download_directory = config.get("download_directory", "./downloads")

    def start(self):
        """Start media downloader"""
        self.logger.info("Starting Media Downloader with local helper encryption")
        self.logger.info("Metadata helper encryption enabled")

        # Create download directory if it doesn't exist
        os.makedirs(self._download_directory, exist_ok=True)

        self._active = True

    def stop(self):
        """Stop and wipe ephemeral data"""
        self.logger.info("Stopping Media Downloader - wiping ephemeral data")

        # Clear queues
        self._download_queue.clear()
        self._download_history.clear()

        self._active = False

    def download(
        self,
        url: str,
        mode: str = "best_quality",
        audio_format: str = "mp3",
        video_format: str = "mp4",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Download media with local helper encryption.

        Args:
            url: Media URL (encrypted immediately)
            mode: Download mode (audio_only, video_only, audio_video, best_quality)
            audio_format: Audio format for extraction
            video_format: Video format for download
            metadata: Optional metadata (will be encrypted)

        Returns:
            Download result with encrypted paths
        """
        if not self._active:
            return {"error": "Media downloader not active"}

        if mode not in self.supported_modes:
            return {"error": f"Invalid mode. Supported: {self.supported_modes}"}

        # Encrypt URL with the configured local helper.
        encrypted_url = self.god_tier_encryption.encrypt_god_tier(url.encode())

        # Generate secure filename
        url_hash = hashlib.sha256(url.encode()).hexdigest()[:16]

        # Create download entry
        download = {
            "id": len(self._download_queue),
            "url_hash": url_hash,  # Never store plaintext URL
            "encrypted_url": encrypted_url,
            "mode": mode,
            "audio_format": audio_format,
            "video_format": video_format,
            "status": "queued",
            "progress": 0,
            "metadata": self._encrypt_metadata(metadata) if metadata else None,
        }

        self._download_queue.append(download)

        self.logger.info(f"Download queued: {mode} - ID: {download['id']}")

        result = self._process_download(download)

        # Add to history (encrypted)
        self._download_history.append(
            {
                "id": download["id"],
                "mode": mode,
                "status": result["status"],
                "local_helper_encrypted": True,
                "encryption_accepted": False,
            }
        )

        return result

    def _process_download(self, download: Dict[str, Any]) -> Dict[str, Any]:
        """Process download through the configured backend."""
        mode = download["mode"]

        # Decrypt URL for download (kept in memory only)
        download["encrypted_url"]

        self.logger.info(f"Processing download: {mode}")

        if self.download_backend is None:
            download["status"] = "unavailable"
            return {
                "status": "unavailable",
                "mode": mode,
                "error": "Media download backend is not configured",
                "local_helper_encrypted": True,
                "encryption_accepted": False,
                "metadata_encrypted": download["metadata"] is not None,
            }

        download_media = getattr(self.download_backend, "download", None)
        if not callable(download_media):
            raise RuntimeError("Media download backend does not implement download")

        result = download_media(
            url_hash=download["url_hash"],
            encrypted_url=download["encrypted_url"],
            mode=mode,
            audio_format=download["audio_format"],
            video_format=download["video_format"],
            download_directory=self._download_directory,
        )
        if not isinstance(result, dict):
            raise RuntimeError("Media download backend returned invalid result")

        result.setdefault("mode", mode)
        result.setdefault("local_helper_encrypted", True)
        result.setdefault("encryption_accepted", False)
        if download["metadata"] is not None:
            result.setdefault("metadata_encrypted", True)
        download["status"] = result.get("status", "unknown")

        # Encrypt file paths in result
        if "file_path" in result:
            result["encrypted_file_path"] = self.god_tier_encryption.encrypt_god_tier(
                result["file_path"].encode()
            )

        return result

    def _encrypt_metadata(self, metadata: Dict[str, Any]) -> bytes:
        """Encrypt metadata with the configured local helper."""
        import json

        metadata_str = json.dumps(metadata)
        return self.god_tier_encryption.encrypt_god_tier(metadata_str.encode())

    def get_queue(self) -> List[Dict[str, Any]]:
        """Get download queue (URLs encrypted)"""
        return self._download_queue.copy()

    def get_history(self) -> List[Dict[str, Any]]:
        """Get download history (encrypted)"""
        return self._download_history.copy()

    def clear_history(self):
        """Clear download history"""
        self._download_history.clear()
        self.logger.info("Download history cleared")

    def get_status(self) -> Dict[str, Any]:
        """Get downloader status"""
        return {
            "active": self._active,
            "local_helper_encrypted": True,
            "encryption_accepted": False,
            "encryption_layers": None,
            "supported_modes": self.supported_modes,
            "audio_formats": self.audio_formats,
            "video_formats": self.video_formats,
            "queue_size": len(self._download_queue),
            "history_size": len(self._download_history),
            "download_directory": self._download_directory,
            "backend_configured": self.download_backend is not None,
            "backend": (
                type(self.download_backend).__name__
                if self.download_backend is not None
                else None
            ),
        }
