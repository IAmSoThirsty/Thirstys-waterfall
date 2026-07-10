"""Fetch policy and URL loading for the native Thirstys web engine."""

from dataclasses import dataclass
from typing import Optional
from urllib.parse import unquote_to_bytes, urlparse
from urllib.request import Request, urlopen
import base64


class FetchBlocked(RuntimeError):
    """Raised when fetch policy blocks a URL load."""


@dataclass
class FetchPolicy:
    allow_network: bool = False
    allow_file: bool = False
    timeout_seconds: float = 10.0
    max_bytes: int = 1024 * 1024
    user_agent: str = "ThirstysWaterfall/NativeEngine"


@dataclass
class FetchResult:
    url: str
    body: str
    content_type: str
    status_code: Optional[int] = None


class URLFetcher:
    """Policy-gated URL fetcher."""

    def __init__(self, policy: FetchPolicy = None):
        self.policy = policy or FetchPolicy()

    def fetch(self, url: str) -> FetchResult:
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()

        if url == "about:blank":
            return FetchResult(url=url, body="", content_type="text/html", status_code=200)

        if scheme == "data":
            return self._fetch_data_url(url)

        if scheme == "file":
            if not self.policy.allow_file:
                raise FetchBlocked("file URL loading is disabled by policy")
            raise FetchBlocked("file URL loading is not implemented")

        if scheme in {"http", "https"}:
            if not self.policy.allow_network:
                raise FetchBlocked("network loading is disabled by policy")
            return self._fetch_network(url)

        raise FetchBlocked("unsupported URL scheme: {0}".format(scheme or "none"))

    def _fetch_data_url(self, url: str) -> FetchResult:
        header, separator, payload = url.partition(",")
        if not separator:
            raise FetchBlocked("malformed data URL")

        metadata = header[5:]
        parts = metadata.split(";") if metadata else []
        content_type = parts[0] if parts and "/" in parts[0] else "text/plain"
        is_base64 = "base64" in parts

        raw = base64.b64decode(payload) if is_base64 else unquote_to_bytes(payload)
        if len(raw) > self.policy.max_bytes:
            raise FetchBlocked("data URL exceeds max_bytes policy")

        return FetchResult(
            url=url,
            body=raw.decode("utf-8", errors="replace"),
            content_type=content_type,
            status_code=200,
        )

    def _fetch_network(self, url: str) -> FetchResult:
        scheme = urlparse(url).scheme.lower()
        if scheme not in {"http", "https"}:
            raise FetchBlocked("network fetch requires http or https URL")

        request = Request(url, headers={"User-Agent": self.policy.user_agent})
        with urlopen(request, timeout=self.policy.timeout_seconds) as response:  # nosec B310
            raw = response.read(self.policy.max_bytes + 1)
            if len(raw) > self.policy.max_bytes:
                raise FetchBlocked("response exceeds max_bytes policy")

            content_type = response.headers.get("content-type", "text/html")
            charset = response.headers.get_content_charset() or "utf-8"
            return FetchResult(
                url=response.geturl(),
                body=raw.decode(charset, errors="replace"),
                content_type=content_type,
                status_code=response.status,
            )
