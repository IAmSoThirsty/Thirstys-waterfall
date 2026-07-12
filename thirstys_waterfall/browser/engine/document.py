"""DOM document model for the native Thirstys web engine."""

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional


@dataclass
class TextNode:
    """Text node in a parsed document tree."""

    text: str
    parent: Optional["ElementNode"] = None

    def text_content(self) -> str:
        return self.text


@dataclass
class ElementNode:
    """Element node in a parsed document tree."""

    tag_name: str
    attributes: Dict[str, str] = field(default_factory=dict)
    children: List[object] = field(default_factory=list)
    parent: Optional["ElementNode"] = None

    def append_child(self, node: object) -> None:
        if isinstance(node, (ElementNode, TextNode)):
            node.parent = self
        self.children.append(node)

    def find_all(self, tag_name: str) -> List["ElementNode"]:
        normalized = tag_name.lower()
        matches: List[ElementNode] = []
        for node in self.walk_elements():
            if node.tag_name == normalized:
                matches.append(node)
        return matches

    def get_attribute(self, name: str, default: Optional[str] = None) -> Optional[str]:
        return self.attributes.get(name.lower(), default)

    def text_content(self) -> str:
        parts: List[str] = []
        for child in self.children:
            if isinstance(child, TextNode):
                parts.append(child.text_content())
            elif isinstance(child, ElementNode):
                parts.append(child.text_content())
        return "".join(parts)

    def walk_elements(self) -> Iterable["ElementNode"]:
        yield self
        for child in self.children:
            if isinstance(child, ElementNode):
                yield from child.walk_elements()


@dataclass
class BrowserDocument:
    """Parsed browser document produced by the native engine."""

    url: str
    root: ElementNode
    content_type: str = "text/html"
    status_code: Optional[int] = None
    script_execution_enabled: bool = False
    load_status: str = "loaded"
    load_error: Optional[str] = None

    @property
    def title(self) -> str:
        titles = self.root.find_all("title")
        if not titles:
            return ""
        return " ".join(titles[0].text_content().split())

    @property
    def text(self) -> str:
        return " ".join(self.root.text_content().split())

    @property
    def links(self) -> List[str]:
        links: List[str] = []
        for node in self.root.find_all("a"):
            href = node.get_attribute("href")
            if href:
                links.append(href)
        return links

    @property
    def script_count(self) -> int:
        return len(self.root.find_all("script"))

    def snapshot(self) -> Dict[str, object]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "load_status": self.load_status,
            "load_error": self.load_error,
            "title": self.title,
            "text": self.text,
            "links": list(self.links),
            "script_count": self.script_count,
            "script_execution_enabled": self.script_execution_enabled,
            "layout": self.layout_snapshot(),
        }

    def layout_snapshot(self, viewport_width: int = 800) -> Dict[str, object]:
        from .layout import layout_document

        return layout_document(self, viewport_width=viewport_width).snapshot()
