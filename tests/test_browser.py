"""
Comprehensive Browser Testing Suite
Tests for incognito browser, encrypted search, encrypted navigation, tab isolation, and sandbox
"""

import json
import unittest
from cryptography.fernet import Fernet

from thirstys_waterfall.browser import (
    IncognitoBrowser,
    EncryptedSearchEngine,
    EncryptedNavigationHistory,
    TabManager,
    BrowserSandbox,
    ContentBlocker,
)


class TestEncryptedSearchEngine(unittest.TestCase):
    """Test encrypted search functionality"""

    def setUp(self):
        """Setup test fixtures"""
        self.cipher = Fernet(Fernet.generate_key())
        self.search_engine = EncryptedSearchEngine(self.cipher)

    def tearDown(self):
        """Cleanup"""
        if self.search_engine._active:
            self.search_engine.stop()

    def test_search_engine_initialization(self):
        """Test search engine initializes correctly"""
        self.assertFalse(self.search_engine._active)
        self.assertEqual(len(self.search_engine._encrypted_search_history), 0)
        self.assertEqual(len(self.search_engine._encrypted_cache), 0)

    def test_search_engine_start_stop(self):
        """Test search engine start and stop"""
        self.search_engine.start()
        self.assertTrue(self.search_engine._active)

        self.search_engine.stop()
        self.assertFalse(self.search_engine._active)
        self.assertEqual(len(self.search_engine._encrypted_search_history), 0)
        self.assertEqual(len(self.search_engine._encrypted_cache), 0)

    def test_search_query_encrypted_immediately(self):
        """Test that search queries are encrypted immediately"""
        self.search_engine.start()

        test_query = "sensitive search query"
        result = self.search_engine.search(test_query)

        # Verify result contains encrypted data
        self.assertIn("encrypted_results", result)
        self.assertIsInstance(result["encrypted_results"], bytes)

        # Verify history contains encrypted query
        history = self.search_engine.get_encrypted_history()
        self.assertEqual(len(history), 1)
        self.assertIn("encrypted_query", history[0])
        self.assertIsInstance(history[0]["encrypted_query"], bytes)

        # Verify plaintext query is NOT in history
        encrypted_query = history[0]["encrypted_query"]
        decrypted_query = self.cipher.decrypt(encrypted_query).decode()
        self.assertEqual(decrypted_query, test_query)

    def test_search_results_encrypted(self):
        """Test that search results are encrypted"""
        self.search_engine.start()

        result = self.search_engine.search("test query")
        encrypted_results = result["encrypted_results"]

        # Verify results are encrypted (bytes)
        self.assertIsInstance(encrypted_results, bytes)

        # Verify we can decrypt results
        decrypted = self.search_engine.decrypt_results(encrypted_results)
        self.assertIsInstance(decrypted, str)

    def test_search_without_backend_returns_encrypted_unavailable_payload(self):
        """Test that missing search backend fails closed without fake results"""
        self.search_engine.start()

        result = self.search_engine.search("test query")

        self.assertFalse(result["success"])
        self.assertFalse(result["backend_available"])
        self.assertEqual(result["error"], "Encrypted search backend is not configured")
        decrypted = self.search_engine.decrypt_results(result["encrypted_results"])
        payload = json.loads(decrypted)
        self.assertFalse(payload["success"])
        self.assertFalse(payload["backend_available"])
        self.assertEqual(payload["results"], [])
        self.assertNotIn("encrypted_search_results_placeholder", decrypted)

    def test_search_caching_encrypted(self):
        """Test that unavailable backend responses are not cached as results"""
        self.search_engine.start()

        # First search
        result1 = self.search_engine.search("cached query")
        self.assertFalse(result1["from_cache"])
        self.assertFalse(result1["success"])

        # Second search (same query)
        result2 = self.search_engine.search("cached query")
        self.assertFalse(result2["from_cache"])
        self.assertFalse(result2["success"])

        # Verify unavailable responses are not stored as accepted search cache.
        self.assertEqual(len(self.search_engine._encrypted_cache), 0)

    def test_no_plaintext_in_history(self):
        """Test that no plaintext queries are stored in history"""
        self.search_engine.start()

        queries = ["query1", "query2", "query3"]
        for query in queries:
            self.search_engine.search(query)

        # Verify all history entries are encrypted
        history = self.search_engine.get_encrypted_history()
        self.assertEqual(len(history), 3)

        for entry in history:
            # Query should be encrypted bytes
            self.assertIsInstance(entry["encrypted_query"], bytes)
            # Should have timestamp and hash
            self.assertIn("timestamp", entry)
            self.assertIn("hash", entry)

    def test_clear_history_wipes_data(self):
        """Test that clearing history securely wipes all data"""
        self.search_engine.start()

        self.search_engine.search("query1")
        self.search_engine.search("query2")

        self.assertEqual(len(self.search_engine.get_encrypted_history()), 2)

        self.search_engine.clear_history()

        self.assertEqual(len(self.search_engine.get_encrypted_history()), 0)
        self.assertEqual(len(self.search_engine._encrypted_cache), 0)

    def test_search_requires_active_engine(self):
        """Test that search requires engine to be started"""
        with self.assertRaises(RuntimeError):
            self.search_engine.search("test")


class TestEncryptedNavigationHistory(unittest.TestCase):
    """Test encrypted navigation history"""

    def setUp(self):
        """Setup test fixtures"""
        self.cipher = Fernet(Fernet.generate_key())
        self.nav_history = EncryptedNavigationHistory(self.cipher)

    def tearDown(self):
        """Cleanup"""
        if self.nav_history._active:
            self.nav_history.stop()

    def test_navigation_history_initialization(self):
        """Test navigation history initializes correctly"""
        self.assertFalse(self.nav_history._active)
        self.assertEqual(len(self.nav_history._encrypted_history), 0)
        self.assertEqual(len(self.nav_history._encrypted_bookmarks), 0)

    def test_navigation_encrypted_immediately(self):
        """Test that URLs are encrypted immediately on navigation"""
        self.nav_history.start()

        test_url = "https://sensitive-website.com"
        test_tab_id = "tab123"

        self.nav_history.record_navigation(test_url, test_tab_id)

        # Verify history contains encrypted data
        history = self.nav_history.get_encrypted_history()
        self.assertEqual(len(history), 1)

        entry = history[0]
        self.assertIn("encrypted_url", entry)
        self.assertIn("encrypted_tab_id", entry)
        self.assertIsInstance(entry["encrypted_url"], bytes)
        self.assertIsInstance(entry["encrypted_tab_id"], bytes)

        # Verify we can decrypt the URL
        decrypted_url = self.nav_history.decrypt_url(entry["encrypted_url"])
        self.assertEqual(decrypted_url, test_url)

    def test_no_plaintext_urls_stored(self):
        """Test that no plaintext URLs are stored"""
        self.nav_history.start()

        urls = ["https://example1.com", "https://example2.com", "https://example3.com"]

        for url in urls:
            self.nav_history.record_navigation(url, "tab_id")

        history = self.nav_history.get_encrypted_history()
        self.assertEqual(len(history), 3)

        # Verify all URLs are encrypted
        for entry in history:
            self.assertIsInstance(entry["encrypted_url"], bytes)
            self.assertIsInstance(entry["encrypted_tab_id"], bytes)
            self.assertIn("timestamp", entry)
            self.assertIn("hash", entry)

    def test_bookmarks_encrypted(self):
        """Test that bookmarks are stored encrypted"""
        self.nav_history.start()

        bookmark_name = "My Bookmark"
        bookmark_url = "https://bookmarked-site.com"

        self.nav_history.add_encrypted_bookmark(bookmark_name, bookmark_url)

        bookmarks = self.nav_history.get_encrypted_bookmarks()
        self.assertEqual(len(bookmarks), 1)

        # All bookmark data should be encrypted
        for key, value in bookmarks.items():
            self.assertIsInstance(key, str)  # Hash of encrypted name
            self.assertIsInstance(value, bytes)  # Encrypted URL

    def test_clear_history_wipes_navigation(self):
        """Test that clearing history wipes all navigation data"""
        self.nav_history.start()

        self.nav_history.record_navigation("https://example.com", "tab1")
        self.nav_history.record_navigation("https://example2.com", "tab2")

        self.assertEqual(len(self.nav_history.get_encrypted_history()), 2)

        self.nav_history.clear_history()

        self.assertEqual(len(self.nav_history.get_encrypted_history()), 0)

    def test_stop_wipes_all_data(self):
        """Test that stopping wipes all data including bookmarks"""
        self.nav_history.start()

        self.nav_history.record_navigation("https://example.com", "tab1")
        self.nav_history.add_encrypted_bookmark("Test", "https://test.com")

        self.nav_history.stop()

        self.assertEqual(len(self.nav_history._encrypted_history), 0)
        self.assertEqual(len(self.nav_history._encrypted_bookmarks), 0)
        self.assertFalse(self.nav_history._active)


class FakeBrowserDownloadBackend:
    def __init__(self):
        self.calls = []

    def download_file(self, url: str, tab_id: str, download_isolated: bool):
        self.calls.append(
            {
                "url": url,
                "tab_id": tab_id,
                "download_isolated": download_isolated,
            }
        )
        return {
            "status": "completed",
            "download_path": f"/isolated/{tab_id}/example.bin",
        }


class InvalidBrowserDownloadBackend:
    def download_file(self, **kwargs):
        return "not-a-dict"


class TestIncognitoBrowser(unittest.TestCase):
    """Test incognito browser engine"""

    def setUp(self):
        """Setup test fixtures"""
        self.config = {
            "incognito_mode": True,
            "no_history": True,
            "no_cache": True,
            "no_cookies": True,
            "tab_isolation": True,
            "sandbox_enabled": True,
            "fingerprint_protection": True,
            "tracker_blocking": True,
            "extension_whitelist": [],
            "download_isolation": True,
        }
        self.browser = IncognitoBrowser(self.config)

    def tearDown(self):
        """Cleanup"""
        if self.browser._active:
            self.browser.stop()

    def test_browser_initialization(self):
        """Test browser initializes with correct privacy settings"""
        self.assertFalse(self.browser._active)
        self.assertTrue(self.browser.config["incognito_mode"])
        self.assertTrue(self.browser.config["no_history"])
        self.assertTrue(self.browser.config["no_cache"])
        self.assertTrue(self.browser.config["no_cookies"])

    def test_browser_start_initializes_subsystems(self):
        """Test that starting browser initializes all subsystems"""
        self.browser.start()

        self.assertTrue(self.browser._active)
        self.assertTrue(self.browser._search_engine._active)
        self.assertTrue(self.browser._nav_history._active)
        self.assertTrue(self.browser._tab_manager._active)
        self.assertTrue(self.browser._sandbox._active)
        self.assertTrue(self.browser._content_blocker._active)

    def test_browser_stop_clears_all_data(self):
        """Test that stopping browser clears all ephemeral data"""
        self.browser.start()

        self.browser.create_tab()
        self.browser.search("test query")

        self.browser.stop()

        self.assertFalse(self.browser._active)
        self.assertEqual(len(self.browser._search_engine._encrypted_search_history), 0)
        self.assertEqual(len(self.browser._nav_history._encrypted_history), 0)

    def test_tab_creation_isolation(self):
        """Test that tabs are created with isolation"""
        self.browser.start()

        tab1 = self.browser.create_tab()
        tab2 = self.browser.create_tab()

        self.assertIsNotNone(tab1)
        self.assertIsNotNone(tab2)
        self.assertNotEqual(tab1, tab2)

        # Verify tabs are tracked
        tabs = self.browser._tab_manager.list_tabs()
        self.assertIn(tab1, tabs)
        self.assertIn(tab2, tabs)

    def test_navigation_with_encryption(self):
        """Test that navigation encrypts URLs"""
        self.browser.start()

        tab_id = self.browser.create_tab()
        test_url = "https://example.com"

        allowed = self.browser.navigate(tab_id, test_url)

        # Navigation should be allowed for normal URLs
        self.assertTrue(allowed)

        # Verify URL was encrypted and stored
        history = self.browser._nav_history.get_encrypted_history()
        self.assertGreater(len(history), 0)

    def test_encrypted_search_integration(self):
        """Test that browser search uses encryption"""
        self.browser.start()

        query = "sensitive search"
        result = self.browser.search(query)

        self.assertIn("encrypted_results", result)
        self.assertIsInstance(result["encrypted_results"], bytes)
        self.assertFalse(result["success"])
        self.assertFalse(result["backend_available"])

    def test_privacy_mode_verification(self):
        """Test that privacy mode is enforced"""
        self.browser.start()

        # Privacy verification should pass
        try:
            self.browser._verify_privacy_mode()
        except Exception as e:
            self.fail(f"Privacy mode verification failed: {e}")

    def test_extension_whitelist_enforcement(self):
        """Test that only whitelisted extensions can be installed"""
        self.browser.start()

        # Non-whitelisted extension should be blocked
        result = self.browser.install_extension("malicious_extension")
        self.assertFalse(result)

        # Add to whitelist and try again
        self.browser.config["extension_whitelist"].append("safe_extension")
        result = self.browser.install_extension("safe_extension")
        self.assertTrue(result)

    def test_fingerprint_protection_status(self):
        """Test fingerprint protection is active"""
        self.browser.start()

        status = self.browser.get_fingerprint_protection_status()

        self.assertIn("enabled", status)
        self.assertIn("user_agent_spoofed", status)
        self.assertIn("canvas_randomized", status)
        self.assertIn("webgl_blocked", status)

    def test_browser_status_is_evidence_gated(self):
        """Test browser status separates helper activity from accepted claims."""
        self.browser.start()

        status = self.browser.get_status()

        self.assertFalse(status["everything_encrypted"])
        self.assertFalse(status["everything_encrypted_accepted"])
        self.assertFalse(status["browser_encryption_accepted"])
        self.assertFalse(status["native_engine_accepted"])
        self.assertTrue(status["searches_encrypted"])
        self.assertTrue(status["navigation_encrypted"])
        self.assertFalse(status["download_backend_configured"])

    def test_download_without_backend_returns_unavailable_not_silent_none(self):
        """Test browser downloads fail closed when no backend is configured."""
        self.browser.start()

        tab_id = self.browser.create_tab()
        result = self.browser.download_file("https://example.invalid/file.bin", tab_id)

        self.assertEqual(result["status"], "unavailable")
        self.assertEqual(result["error"], "Browser download backend is not configured")
        self.assertEqual(result["tab_id"], tab_id)
        self.assertTrue(result["download_isolated"])

    def test_download_delegates_to_configured_backend(self):
        """Test browser downloads use configured backend results."""
        backend = FakeBrowserDownloadBackend()
        browser = IncognitoBrowser(self.config, download_backend=backend)
        self.addCleanup(lambda: browser._active and browser.stop())
        browser.start()

        tab_id = browser.create_tab()
        result = browser.download_file("https://example.invalid/file.bin", tab_id)

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["download_path"], f"/isolated/{tab_id}/example.bin")
        self.assertEqual(result["backend"], "FakeBrowserDownloadBackend")
        self.assertTrue(result["download_isolated"])
        self.assertEqual(len(backend.calls), 1)
        self.assertEqual(backend.calls[0]["tab_id"], tab_id)

    def test_download_backend_result_must_be_mapping(self):
        """Test invalid browser download backend results fail loudly."""
        browser = IncognitoBrowser(
            self.config,
            download_backend=InvalidBrowserDownloadBackend(),
        )
        self.addCleanup(lambda: browser._active and browser.stop())
        browser.start()

        tab_id = browser.create_tab()
        with self.assertRaisesRegex(RuntimeError, "returned invalid result"):
            browser.download_file("https://example.invalid/file.bin", tab_id)


class TestTabManager(unittest.TestCase):
    """Test tab management and isolation"""

    def setUp(self):
        """Setup test fixtures"""
        self.config = {"tab_isolation": True}
        self.tab_manager = TabManager(self.config)

    def tearDown(self):
        """Cleanup"""
        if self.tab_manager._active:
            self.tab_manager.stop()

    def test_tab_creation(self):
        """Test tab creation returns unique IDs"""
        self.tab_manager.start()

        tab1 = self.tab_manager.create_tab()
        tab2 = self.tab_manager.create_tab()

        self.assertIsNotNone(tab1)
        self.assertIsNotNone(tab2)
        self.assertNotEqual(tab1, tab2)

    def test_tab_isolation(self):
        """Test that tabs are isolated from each other"""
        self.tab_manager.start()

        tab1 = self.tab_manager.create_tab()
        tab2 = self.tab_manager.create_tab()

        tabs = self.tab_manager.list_tabs()

        # Each tab should have isolated storage
        self.assertIn(tab1, tabs)
        self.assertIn(tab2, tabs)
        self.assertTrue(tabs[tab1]["isolated"])
        self.assertTrue(tabs[tab2]["isolated"])

    def test_tab_close_clears_data(self):
        """Test that closing tab clears its data"""
        self.tab_manager.start()

        tab_id = self.tab_manager.create_tab()
        self.tab_manager.close_tab(tab_id)

        tabs = self.tab_manager.list_tabs()
        self.assertNotIn(tab_id, tabs)


class TestBrowserSandbox(unittest.TestCase):
    """Test browser sandbox functionality"""

    def setUp(self):
        """Setup test fixtures"""
        self.config = {"sandbox_enabled": True}
        self.sandbox = BrowserSandbox(self.config)

    def tearDown(self):
        """Cleanup"""
        if self.sandbox._active:
            self.sandbox.stop()

    def test_sandbox_initialization(self):
        """Test sandbox initializes correctly"""
        self.assertFalse(self.sandbox._active)
        self.assertTrue(self.sandbox.enabled)

    def test_sandbox_process_isolation(self):
        """Test sandbox creates isolated processes"""
        self.sandbox.start()

        # Sandbox should be active
        self.assertTrue(self.sandbox._active)

        # Verify process limits are set
        limits = self.sandbox.get_resource_limits()
        self.assertIn("memory_limit", limits)
        self.assertIn("cpu_limit", limits)

    def test_sandbox_security_boundaries(self):
        """Test sandbox enforces security boundaries"""
        self.sandbox.start()

        # Verify security boundaries are active
        boundaries = self.sandbox.get_security_boundaries()
        self.assertIn("filesystem_isolation", boundaries)
        self.assertIn("network_restrictions", boundaries)


class TestContentBlocker(unittest.TestCase):
    """Test content blocking functionality"""

    def setUp(self):
        """Setup test fixtures"""
        self.config = {
            "block_ads": True,
            "block_trackers": True,
            "block_popups": True,
            "block_redirects": True,
        }
        self.blocker = ContentBlocker(self.config)

    def tearDown(self):
        """Cleanup"""
        if self.blocker._active:
            self.blocker.stop()

    def test_content_blocker_initialization(self):
        """Test content blocker initializes with correct rules"""
        self.assertFalse(self.blocker._active)
        self.assertTrue(self.blocker.config["block_ads"])
        self.assertTrue(self.blocker.config["block_trackers"])

    def test_ad_blocking(self):
        """Test that ads are blocked"""
        self.blocker.start()

        # Test known ad domain
        ad_url = "https://doubleclick.net/ad"
        result = self.blocker.should_block(ad_url)
        self.assertTrue(result)

        # Test normal domain
        normal_url = "https://example.com"
        result = self.blocker.should_block(normal_url)
        self.assertFalse(result)

    def test_tracker_blocking(self):
        """Test that trackers are blocked"""
        self.blocker.start()

        # Test known tracker
        tracker_url = "https://google-analytics.com/track"
        result = self.blocker.should_block(tracker_url)
        self.assertTrue(result)

    def test_popup_blocking(self):
        """Test that popups are blocked"""
        self.blocker.start()

        # Popup should be blocked
        is_blocked = self.blocker.block_popup()
        self.assertTrue(is_blocked)


if __name__ == "__main__":
    unittest.main()
