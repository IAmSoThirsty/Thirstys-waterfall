"""Encrypted Navigation History - All visited sites encrypted"""

import logging
from typing import List, Dict, Any, Optional
from cryptography.fernet import Fernet
import time
import hashlib


class EncryptedNavigationHistory:
    """
    Encrypted navigation history that stores all visited URLs encrypted.
    Every site, every navigation is encrypted. Never stored in plaintext.
    """

    def __init__(self, cipher: Fernet, search_backend: Optional[Any] = None):
        self.logger = logging.getLogger(__name__)
        self._cipher = cipher
        self._search_backend = search_backend
        self._active = False

        # All URLs encrypted
        self._encrypted_history: List[Dict[str, Any]] = []

        # Encrypted bookmarks
        self._encrypted_bookmarks: Dict[str, bytes] = {}

    def start(self):
        """Start encrypted navigation history"""
        self.logger.info("Starting Encrypted Navigation - All sites encrypted")
        self._active = True

    def stop(self):
        """Stop and securely wipe all data"""
        self.logger.info("Stopping Encrypted Navigation - Wiping all data")
        self._encrypted_history.clear()
        self._encrypted_bookmarks.clear()
        self._active = False

    def record_navigation(self, url: str, tab_id: str):
        """
        Record navigation to URL.
        URL is encrypted immediately before storage.

        Args:
            url: URL to record (encrypted immediately)
            tab_id: Tab ID (also encrypted)
        """
        if not self._active:
            return

        # Encrypt URL immediately
        encrypted_url = self._cipher.encrypt(url.encode())
        encrypted_tab_id = self._cipher.encrypt(tab_id.encode())

        # Generate hash for logging (never log plaintext)
        url_hash = hashlib.sha256(encrypted_url).hexdigest()[:16]

        # Store encrypted entry
        entry = {
            "encrypted_url": encrypted_url,
            "encrypted_tab_id": encrypted_tab_id,
            "timestamp": time.time(),
            "hash": url_hash,
        }

        self._encrypted_history.append(entry)
        self.logger.debug(f"Recorded encrypted navigation: {url_hash}")

    def get_encrypted_history(self) -> List[Dict[str, Any]]:
        """
        Get encrypted history.
        Returns encrypted data only, never plaintext.
        """
        return self._encrypted_history.copy()

    def decrypt_url(self, encrypted_url: bytes) -> str:
        """
        Decrypt URL for display only.
        Only decrypted in memory when needed.
        """
        try:
            return self._cipher.decrypt(encrypted_url).decode()
        except Exception as e:
            self.logger.error(f"Failed to decrypt URL: {e}")
            return "encrypted_url"

    def add_encrypted_bookmark(self, name: str, url: str):
        """
        Add bookmark with encrypted URL.
        Both name and URL are encrypted.
        """
        encrypted_name = self._cipher.encrypt(name.encode())
        encrypted_url = self._cipher.encrypt(url.encode())

        # Use encrypted name as key
        name_hash = hashlib.sha256(encrypted_name).hexdigest()
        self._encrypted_bookmarks[name_hash] = encrypted_url

        self.logger.debug(f"Added encrypted bookmark: {name_hash[:16]}")

    def get_encrypted_bookmarks(self) -> Dict[str, bytes]:
        """Get all encrypted bookmarks"""
        return self._encrypted_bookmarks.copy()

    def clear_history(self):
        """Securely clear all encrypted navigation history"""
        self.logger.info("Clearing encrypted navigation history")
        self._encrypted_history.clear()

    def search_encrypted_history(self, encrypted_query: bytes) -> List[Dict[str, Any]]:
        """
        Search through encrypted history.
        Search must be performed by a configured encrypted-search backend.
        """
        if self._search_backend is None:
            raise RuntimeError(
                "Encrypted navigation search backend is not configured"
            )

        search = getattr(self._search_backend, "search_encrypted_history", None)
        if not callable(search):
            raise RuntimeError(
                "Encrypted navigation search backend does not implement "
                "search_encrypted_history"
            )

        results = search(encrypted_query, self.get_encrypted_history())
        if not isinstance(results, list):
            raise RuntimeError(
                "Encrypted navigation search backend returned invalid result"
            )

        return results
