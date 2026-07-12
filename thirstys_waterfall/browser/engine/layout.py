"""Deterministic layout snapshots for the native browser engine."""

from dataclasses import dataclass, field
from typing import Dict, Iterable, List

from .document import BrowserDocument, ElementNode, TextNode


BLOCK_TAGS = {
    "article",
    "aside",
    "body",
    "div",
    "document",
    "footer",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "html",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "section",
    "ul",
}
HIDDEN_TAGS = {"head", "meta", "script", "style", "title", "link"}
LINE_HEIGHT = 18
BLOCK_GAP = 8
CHAR_WIDTH = 8


@dataclass
class LayoutBox:
    """A render-tree box with stable geometry for acceptance tests."""

    node_type: str
    tag_name: str = ""
    text: str = ""
    x: int = 0
    y: int = 0
    width: int = 0
    height: int = 0
    children: List["LayoutBox"] = field(default_factory=list)

    def snapshot(self) -> Dict[str, object]:
        return {
            "node_type": self.node_type,
            "tag_name": self.tag_name,
            "text": self.text,
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "children": [child.snapshot() for child in self.children],
        }


def layout_document(document: BrowserDocument, viewport_width: int = 800) -> LayoutBox:
    """Create a deterministic block layout tree for a parsed document."""

    width = max(1, int(viewport_width))
    return _layout_element(document.root, x=0, y=0, width=width)


def _layout_element(element: ElementNode, x: int, y: int, width: int) -> LayoutBox:
    box = LayoutBox(
        node_type="element",
        tag_name=element.tag_name,
        x=x,
        y=y,
        width=width,
        height=0,
    )
    cursor_y = y
    for child in _visible_children(element.children):
        if isinstance(child, TextNode):
            text_box = _layout_text(child, x=x, y=cursor_y, width=width)
            if text_box.height:
                box.children.append(text_box)
                cursor_y += text_box.height + BLOCK_GAP
        elif isinstance(child, ElementNode):
            child_x = x + _indent_for(child)
            child_width = max(1, width - (child_x - x))
            child_box = _layout_element(child, x=child_x, y=cursor_y, width=child_width)
            if child_box.height or child_box.children or child.tag_name in BLOCK_TAGS:
                box.children.append(child_box)
                cursor_y += child_box.height + BLOCK_GAP

    content_height = max(0, cursor_y - y - (BLOCK_GAP if box.children else 0))
    box.height = max(LINE_HEIGHT if element.tag_name in BLOCK_TAGS and not box.children else 0, content_height)
    return box


def _visible_children(children: Iterable[object]) -> Iterable[object]:
    for child in children:
        if isinstance(child, ElementNode) and child.tag_name in HIDDEN_TAGS:
            continue
        yield child


def _layout_text(node: TextNode, x: int, y: int, width: int) -> LayoutBox:
    normalized = " ".join(node.text.split())
    if not normalized:
        return LayoutBox(node_type="text", text="", x=x, y=y, width=width, height=0)

    chars_per_line = max(1, width // CHAR_WIDTH)
    line_count = max(1, (len(normalized) + chars_per_line - 1) // chars_per_line)
    return LayoutBox(
        node_type="text",
        text=normalized,
        x=x,
        y=y,
        width=width,
        height=line_count * LINE_HEIGHT,
    )


def _indent_for(element: ElementNode) -> int:
    if element.tag_name == "li":
        return 16
    return 0
