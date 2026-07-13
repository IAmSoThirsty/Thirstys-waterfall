"""HTML parser for the native Thirstys web engine."""

from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple

from .document import BrowserDocument, ElementNode, TextNode


VOID_ELEMENTS = {
    "area",
    "base",
    "br",
    "col",
    "embed",
    "hr",
    "img",
    "input",
    "link",
    "meta",
    "param",
    "source",
    "track",
    "wbr",
}


class NativeHTMLParser(HTMLParser):
    """Builds a small DOM tree from HTML using the Python standard parser."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.root = ElementNode("document")
        self._stack: List[ElementNode] = [self.root]

    def handle_starttag(
        self, tag: str, attrs: List[Tuple[str, Optional[str]]]
    ) -> None:
        tag_name = tag.lower()
        attributes: Dict[str, str] = {}
        for key, value in attrs:
            attributes[key.lower()] = value if value is not None else ""

        element = ElementNode(tag_name=tag_name, attributes=attributes)
        self._stack[-1].append_child(element)
        if tag_name not in VOID_ELEMENTS:
            self._stack.append(element)

    def handle_endtag(self, tag: str) -> None:
        tag_name = tag.lower()
        for index in range(len(self._stack) - 1, 0, -1):
            if self._stack[index].tag_name == tag_name:
                del self._stack[index:]
                return

    def handle_data(self, data: str) -> None:
        if data:
            self._stack[-1].append_child(TextNode(data))


def parse_html(
    source: str,
    url: str,
    content_type: str = "text/html",
    status_code: Optional[int] = None,
) -> BrowserDocument:
    parser = NativeHTMLParser()
    parser.feed(source)
    parser.close()
    return BrowserDocument(
        url=url,
        root=parser.root,
        content_type=content_type,
        status_code=status_code,
        script_execution_enabled=False,
        load_status="loaded",
    )
