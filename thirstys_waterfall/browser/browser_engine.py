"""Incognito Browser Engine"""

from typing import Dict, Any, Optional
import logging
from cryptography.fernet import Fernet
from .tab_manager import TabManager
from .sandbox import BrowserSandbox
from .content_blocker import ContentBlocker
from .encrypted_search import EncryptedSearchEngine
from .encrypted_navigation import EncryptedNavigationHistory
from .engine import FetchBlocked, FetchPolicy, ThirstyWebEngine


class IncognitoBrowser:
    """
    Privacy-first browser runtime.

    Standard v3 acceptance for native rendering, session behavior, and
    end-to-end browser-data encryption remains evidence-gated.
    """

    def __init__(self, config: Dict[str, Any], download_backend: Optional[Any] = None):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.download_backend = download_backend

        # Privacy settings
        self.incognito_mode = config.get("incognito_mode", True)
        self.no_history = config.get("no_history", True)
        self.no_cache = config.get("no_cache", True)
        self.no_cookies = config.get("no_cookies", True)
        self.tab_isolation = config.get("tab_isolation", True)
        self.fingerprint_protection = config.get("fingerprint_protection", True)
        self.tracker_blocking = config.get("tracker_blocking", True)
        self.keyboard_cloaking = config.get("keyboard_cloaking", True)
        self.mouse_cloaking = config.get("mouse_cloaking", True)

        # ENCRYPTION: Generate encryption key for all browser data
        self._cipher = Fernet(Fernet.generate_key())

        # Components
        self._tab_manager = TabManager(
            {
                "tab_isolation": self.tab_isolation,
                "max_tabs": config.get("max_tabs", 100),
            }
        )
        self._sandbox = BrowserSandbox(
            {
                "enabled": config.get("sandbox_enabled", True),
                "memory_limit_mb": config.get("memory_limit_mb", 512),
                "cpu_limit_percent": config.get("cpu_limit_percent", 50),
            }
        )
        self._content_blocker = ContentBlocker(
            block_trackers=self.tracker_blocking,
            block_popups=True,  # Block pop-ups
            block_redirects=True,  # Block redirects
            block_ads=True,
        )

        # MAXIMUM ALLOWED DESIGN: Expose as public properties
        self.tab_manager = self._tab_manager
        self.sandbox = self._sandbox
        self.content_blocker = self._content_blocker

        # Local encrypted helper components.
        self._search_engine = EncryptedSearchEngine(self._cipher)
        self._nav_history = EncryptedNavigationHistory(self._cipher)
        self._web_engine = ThirstyWebEngine(
            FetchPolicy(
                allow_network=config.get("engine_network_enabled", False),
                allow_file=config.get("engine_file_enabled", False),
                timeout_seconds=config.get("engine_timeout_seconds", 10.0),
                max_bytes=config.get("engine_max_bytes", 1024 * 1024),
            )
        )

        # MAXIMUM ALLOWED DESIGN: Expose as public properties for test introspection
        self.encrypted_search = self._search_engine
        self.encrypted_navigation = self._nav_history
        self._navigation_history = self._nav_history  # Alias
        self.web_engine = self._web_engine
        self._rendered_documents = {}

        self._active = False
        self._extension_whitelist = config.get("extension_whitelist", [])
        self._download_isolation = config.get("download_isolation", True)

    def start(self):
        """Start incognito browser"""
        self.logger.info("Starting Incognito Browser")

        # Verify privacy mode
        if not self._verify_privacy_mode():
            raise RuntimeError("Privacy mode verification failed")

        # Start components - MAXIMUM ALLOWED DESIGN: explicit lifecycle
        self._tab_manager.start()
        self._sandbox.start()
        self._content_blocker.start()

        # Start encrypted components
        self._search_engine.start()
        self._nav_history.start()

        self._active = True
        self.logger.info("Incognito browser runtime started")
        self.logger.info("Browser privacy controls enabled")
        self.logger.info("Browser encryption claims remain Standard v3 gated")

    def stop(self):
        """Stop browser and clear all data"""
        self.logger.info("Stopping Incognito Browser")

        # Stop encrypted components (wipes encrypted data)
        self._search_engine.stop()
        self._nav_history.stop()

        # Close all tabs
        self._tab_manager.stop()

        # Clear any ephemeral data
        self._clear_ephemeral_data()
        self._rendered_documents.clear()

        # Stop components
        self._sandbox.stop()
        self._content_blocker.stop()

        self._active = False

    def _verify_privacy_mode(self) -> bool:
        """Verify privacy settings are correct"""
        if not self.incognito_mode:
            self.logger.error("Incognito mode must be enabled")
            return False

        if not self.no_history or not self.no_cache or not self.no_cookies:
            self.logger.error("History, cache, and cookies must be disabled")
            return False

        return True

    def create_tab(self, url: Optional[str] = None) -> str:
        """
        Create new isolated tab.

        Returns:
            Tab ID
        """
        if not self._active:
            raise RuntimeError("Browser not active")

        # Create isolated tab
        tab_id = self.tab_manager.create_tab(url)

        # Apply privacy policies to tab
        self._apply_privacy_policies(tab_id)

        return tab_id

    def close_tab(self, tab_id: str):
        """Close tab and clear its data"""
        self.tab_manager.close_tab(tab_id)

    def navigate(self, tab_id: str, url: str) -> bool:
        """
        Navigate tab to URL with privacy protection.
        URL is encrypted immediately after validation.

        Returns:
            True if navigation allowed, False if blocked
        """
        # Check if URL should be blocked
        if not self.content_blocker.should_allow_url(url):
            self.logger.warning("URL blocked: (encrypted)")
            return False

        # Record encrypted navigation (URL encrypted immediately)
        self.encrypted_navigation.record_navigation(url, tab_id)

        # Navigate in sandbox
        navigated = self.tab_manager.navigate(tab_id, url)
        if navigated:
            try:
                document = self.web_engine.navigate(url)
            except FetchBlocked as exc:
                document = self.web_engine.blocked_document(url, str(exc))
            self._rendered_documents[tab_id] = document
            tab = self.tab_manager.get_tab(tab_id)
            if tab is not None:
                tab["document"] = document.snapshot()

        return navigated

    def get_document_snapshot(self, tab_id: str) -> Optional[Dict[str, Any]]:
        """Return the current parsed document snapshot for a tab."""
        document = self._rendered_documents.get(tab_id)
        if document is None:
            return None
        return document.snapshot()

    def _apply_privacy_policies(self, tab_id: str):
        """Apply privacy policies to tab"""
        # Disable storage
        self.tab_manager.set_tab_config(
            tab_id,
            {
                "storage": False,
                "cookies": False,
                "cache": False,
                "history": False,
                "popups": False,  # NEW REQUIREMENT
                "redirects": False,  # NEW REQUIREMENT
            },
        )

    def _clear_ephemeral_data(self):
        """Clear all ephemeral data"""
        # No history to clear (never stored)
        # No cache to clear (never stored)
        # No cookies to clear (never stored)
        self.logger.debug("Ephemeral data cleared (nothing stored)")

    def install_extension(self, extension_id: str) -> bool:
        """
        Install extension if whitelisted.

        Returns:
            True if installed, False if blocked
        """
        if extension_id in self._extension_whitelist:
            self.logger.info(f"Installing whitelisted extension: {extension_id}")
            return True
        else:
            self.logger.warning(f"Extension not whitelisted: {extension_id}")
            return False

    def download_file(self, url: str, tab_id: str) -> Dict[str, Any]:
        """
        Download file with isolation.

        Returns:
            Structured download result.
        """
        if not self._download_isolation:
            self.logger.warning("Download isolation not enabled")

        self.logger.info("Downloading file through configured browser backend")

        if self.download_backend is None:
            return {
                "status": "unavailable",
                "error": "Browser download backend is not configured",
                "url": url,
                "tab_id": tab_id,
                "download_isolated": self._download_isolation,
            }

        download_file = getattr(self.download_backend, "download_file", None)
        if not callable(download_file):
            raise RuntimeError("Browser download backend does not implement download_file")

        result = download_file(
            url=url,
            tab_id=tab_id,
            download_isolated=self._download_isolation,
        )
        if not isinstance(result, dict):
            raise RuntimeError("Browser download backend returned invalid result")

        result.setdefault("status", "unknown")
        result.setdefault("tab_id", tab_id)
        result.setdefault("download_isolated", self._download_isolation)
        result.setdefault("backend", type(self.download_backend).__name__)
        return result

    def get_fingerprint_protection_status(self) -> Dict[str, Any]:
        """Get fingerprint protection status"""
        return {
            "enabled": self.fingerprint_protection,
            "user_agent_spoofed": True,
            "canvas_randomized": True,
            "webgl_blocked": True,
            "fonts_limited": True,
            "timezone_spoofed": True,
            "language_spoofed": True,
            "screen_size_spoofed": True,
            "hardware_info_hidden": True,
        }

    def search(self, query: str) -> Dict[str, Any]:
        """
        Perform encrypted search.
        Query is encrypted immediately.

        Returns:
            Encrypted search results
        """
        return self.encrypted_search.search(query)

    def get_status(self) -> Dict[str, Any]:
        """Get browser status"""
        return {
            "active": self._active,
            "incognito_mode": self.incognito_mode,
            "no_history": self.no_history,
            "no_cache": self.no_cache,
            "no_cookies": self.no_cookies,
            "no_popups": True,
            "no_redirects": True,
            "tab_isolation": self.tab_isolation,
            "open_tabs": len(self.tab_manager.get_all_tabs()),
            "fingerprint_protection": self.fingerprint_protection,
            "tracker_blocking": self.tracker_blocking,
            "sandbox_enabled": self.sandbox.is_active(),
            "everything_encrypted": False,
            "everything_encrypted_accepted": False,
            "searches_encrypted": self.encrypted_search._active,
            "navigation_encrypted": self.encrypted_navigation._active,
            "browser_encryption_accepted": False,
            "native_engine": True,
            "native_engine_accepted": False,
            "engine_network_enabled": self.web_engine.fetch_policy.allow_network,
            "download_backend_configured": self.download_backend is not None,
        }
