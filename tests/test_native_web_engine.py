"""Tests for the native Thirstys web engine."""

import unittest

from thirstys_waterfall.browser import FetchBlocked, FetchPolicy, IncognitoBrowser, ThirstyWebEngine


class TestThirstyWebEngine(unittest.TestCase):
    def test_render_html_builds_dom_snapshot(self):
        engine = ThirstyWebEngine()

        document = engine.render_html(
            """
            <html>
              <head><title>Example Page</title></head>
              <body>
                <h1>Hello Thirsty</h1>
                <a href="/next">Next</a>
              </body>
            </html>
            """,
            url="https://example.local",
        )

        snapshot = document.snapshot()

        self.assertEqual(snapshot["title"], "Example Page")
        self.assertIn("Hello Thirsty", snapshot["text"])
        self.assertEqual(snapshot["links"], ["/next"])
        self.assertEqual(snapshot["script_count"], 0)
        self.assertFalse(snapshot["script_execution_enabled"])
        self.assertEqual(snapshot["layout"]["tag_name"], "document")
        self.assertGreater(snapshot["layout"]["height"], 0)

    def test_layout_snapshot_records_visible_boxes_only(self):
        engine = ThirstyWebEngine()

        document = engine.render_html(
            """
            <html>
              <head><title>Hidden Title</title><script>ignored()</script></head>
              <body><main><h1>Visible</h1><p>First paragraph</p></main></body>
            </html>
            """
        )

        layout = document.layout_snapshot(viewport_width=320)
        layout_text = str(layout)

        self.assertIn("Visible", layout_text)
        self.assertIn("First paragraph", layout_text)
        self.assertNotIn("Hidden Title", layout_text)
        self.assertNotIn("ignored", layout_text)

    def test_scripts_are_parsed_but_not_executed(self):
        engine = ThirstyWebEngine()

        document = engine.render_html(
            "<html><head><script>window.open('https://tracker.local')</script></head><body>Safe text</body></html>"
        )

        snapshot = document.snapshot()

        self.assertEqual(snapshot["script_count"], 1)
        self.assertFalse(snapshot["script_execution_enabled"])
        self.assertIn("Safe text", snapshot["text"])

    def test_data_url_navigation_renders_without_network(self):
        engine = ThirstyWebEngine(FetchPolicy(allow_network=False))

        document = engine.navigate("data:text/html,%3Ctitle%3Dbad%3E%3C/title%3E<p>Local%20document</p>")

        self.assertEqual(document.status_code, 200)
        self.assertIn("Local document", document.text)

    def test_http_navigation_is_policy_blocked_by_default(self):
        engine = ThirstyWebEngine()

        with self.assertRaises(FetchBlocked):
            engine.navigate("https://example.com")


class TestIncognitoBrowserNativeEngine(unittest.TestCase):
    def setUp(self):
        self.browser = IncognitoBrowser(
            {
                "incognito_mode": True,
                "no_history": True,
                "no_cache": True,
                "no_cookies": True,
                "tab_isolation": True,
                "sandbox_enabled": True,
                "fingerprint_protection": True,
                "tracker_blocking": True,
            }
        )

    def tearDown(self):
        if self.browser._active:
            self.browser.stop()

    def test_navigation_keeps_bool_contract_and_records_engine_snapshot(self):
        self.browser.start()
        tab_id = self.browser.create_tab()

        allowed = self.browser.navigate(tab_id, "https://example.com")

        self.assertTrue(allowed)
        snapshot = self.browser.get_document_snapshot(tab_id)
        session = self.browser.get_session_snapshot(tab_id)
        self.assertIsNotNone(snapshot)
        self.assertIsNotNone(session)
        self.assertEqual(snapshot["load_status"], "blocked")
        self.assertEqual(snapshot["load_error"], "network loading is disabled by policy")
        self.assertFalse(snapshot["script_execution_enabled"])
        self.assertEqual(session["last_load_status"], "blocked")
        self.assertEqual(session["documents_rendered"], 1)
        self.assertFalse(session["history_retained"])
        self.assertTrue(session["document_available"])

    def test_status_exposes_native_engine(self):
        self.browser.start()

        status = self.browser.get_status()

        self.assertTrue(status["native_engine"])
        self.assertTrue(status["native_layout_snapshots"])
        self.assertTrue(status["ephemeral_session_snapshots"])
        self.assertFalse(status["engine_network_enabled"])

    def test_session_snapshot_is_removed_when_tab_closes(self):
        self.browser.start()
        tab_id = self.browser.create_tab()

        self.assertIsNotNone(self.browser.get_session_snapshot(tab_id))
        self.browser.close_tab(tab_id)

        self.assertIsNone(self.browser.get_session_snapshot(tab_id))
        self.assertIsNone(self.browser.get_document_snapshot(tab_id))


if __name__ == "__main__":
    unittest.main()
