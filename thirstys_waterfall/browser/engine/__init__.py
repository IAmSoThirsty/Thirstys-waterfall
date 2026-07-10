"""Native Thirstys web engine primitives."""

from .document import BrowserDocument, ElementNode, TextNode
from .engine import ThirstyWebEngine
from .fetcher import FetchBlocked, FetchPolicy, FetchResult

__all__ = [
    "BrowserDocument",
    "ElementNode",
    "TextNode",
    "ThirstyWebEngine",
    "FetchBlocked",
    "FetchPolicy",
    "FetchResult",
]
