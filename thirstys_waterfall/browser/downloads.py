"""Encrypted browser download backend."""

from __future__ import annotations

import base64
import hashlib
import secrets
from pathlib import Path
from typing import Any
from urllib.parse import unquote_to_bytes, urlparse
from urllib.request import Request, urlopen

from cryptography.fernet import Fernet


class EncryptedDownloadBackend:
    """Store downloaded bytes as encrypted local artifacts."""

    def __init__(
        self,
        storage_path: str | Path,
        cipher: Fernet,
        *,
        allow_network: bool = False,
        timeout_seconds: float = 10.0,
        max_bytes: int = 1024 * 1024,
        user_agent: str = "ThirstysWaterfall/EncryptedDownload",
    ):
        self.storage_path = Path(storage_path)
        self.cipher = cipher
        self.allow_network = allow_network
        self.timeout_seconds = timeout_seconds
        self.max_bytes = max(1, int(max_bytes))
        self.user_agent = user_agent
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def download_file(
        self,
        *,
        url: str,
        tab_id: str,
        download_isolated: bool,
    ) -> dict[str, Any]:
        """Fetch and encrypt one URL into the configured storage path."""
        encrypted_url = self.cipher.encrypt(url.encode("utf-8"))
        try:
            content, content_type, final_url = self._fetch_bytes(url)
        except RuntimeError as exc:
            return {
                "status": "unavailable",
                "error": str(exc),
                "encrypted_url": encrypted_url,
                "url_encrypted": True,
                "tab_id": tab_id,
                "download_isolated": download_isolated,
                "content_encrypted": False,
            }

        encrypted_content = self.cipher.encrypt(content)
        download_id = secrets.token_hex(16)
        artifact_path = self.storage_path / f"{download_id}.twdownload"
        artifact_path.write_bytes(encrypted_content)
        return {
            "status": "completed",
            "download_id": download_id,
            "encrypted_artifact": str(artifact_path),
            "sha256_ciphertext": hashlib.sha256(encrypted_content).hexdigest(),
            "content_type": content_type,
            "plaintext_bytes": len(content),
            "ciphertext_bytes": len(encrypted_content),
            "encrypted_url": encrypted_url,
            "url_encrypted": True,
            "final_url_encrypted": self.cipher.encrypt(final_url.encode("utf-8")),
            "content_encrypted": True,
            "tab_id": tab_id,
            "download_isolated": download_isolated,
        }

    def read_encrypted_artifact(self, download_id: str) -> bytes:
        """Return the decrypted bytes for a stored download artifact."""
        if not download_id or not all(char in "0123456789abcdef" for char in download_id):
            raise ValueError("invalid download id")
        artifact_path = self.storage_path / f"{download_id}.twdownload"
        return self.cipher.decrypt(artifact_path.read_bytes())

    def _fetch_bytes(self, url: str) -> tuple[bytes, str, str]:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        if scheme == "data":
            return self._fetch_data_url(url)
        if scheme in {"http", "https"}:
            if not self.allow_network:
                raise RuntimeError("network downloads are disabled by policy")
            return self._fetch_network(url)
        raise RuntimeError(f"unsupported download URL scheme: {scheme or 'none'}")

    def _fetch_data_url(self, url: str) -> tuple[bytes, str, str]:
        header, separator, payload = url.partition(",")
        if not separator:
            raise RuntimeError("malformed data URL")

        metadata = header[5:]
        parts = metadata.split(";") if metadata else []
        content_type = parts[0] if parts and "/" in parts[0] else "text/plain"
        is_base64 = "base64" in parts
        content = base64.b64decode(payload) if is_base64 else unquote_to_bytes(payload)
        if len(content) > self.max_bytes:
            raise RuntimeError("download exceeds max_bytes policy")
        return content, content_type, url

    def _fetch_network(self, url: str) -> tuple[bytes, str, str]:
        request = Request(url, headers={"User-Agent": self.user_agent})
        with urlopen(request, timeout=self.timeout_seconds) as response:  # nosec B310
            content = response.read(self.max_bytes + 1)
            if len(content) > self.max_bytes:
                raise RuntimeError("download exceeds max_bytes policy")
            return (
                content,
                response.headers.get("content-type", "application/octet-stream"),
                response.geturl(),
            )
