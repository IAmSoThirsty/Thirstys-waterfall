"""Native web engine entry point."""

from typing import Dict, Optional

from .document import BrowserDocument, ElementNode
from .fetcher import FetchBlocked, FetchPolicy, URLFetcher
from .html_parser import parse_html


class ThirstyWebEngine:
    """
    Minimal native web engine.

    This first layer owns URL loading policy, HTML parsing, DOM snapshots, and
    fail-closed script handling. It intentionally does not execute JavaScript.
    """

    def __init__(self, fetch_policy: Optional[FetchPolicy] = None):
        self.fetch_policy = fetch_policy or FetchPolicy()
        self.fetcher = URLFetcher(self.fetch_policy)

    def navigate(self, url: str) -> BrowserDocument:
        result = self.fetcher.fetch(url)
        if "html" not in result.content_type:
            raise FetchBlocked("content type is not renderable HTML: {0}".format(result.content_type))
        return self.render_html(
            result.body,
            url=result.url,
            content_type=result.content_type,
            status_code=result.status_code,
        )

    def render_html(
        self,
        source: str,
        url: str = "about:blank",
        content_type: str = "text/html",
        status_code: Optional[int] = 200,
    ) -> BrowserDocument:
        return parse_html(source, url=url, content_type=content_type, status_code=status_code)

    def blocked_document(self, url: str, reason: str) -> BrowserDocument:
        return BrowserDocument(
            url=url,
            root=ElementNode("document"),
            content_type="text/html",
            status_code=None,
            script_execution_enabled=False,
            load_status="blocked",
            load_error=reason,
        )

    def snapshot(self, document: BrowserDocument) -> Dict[str, object]:
        return document.snapshot()
