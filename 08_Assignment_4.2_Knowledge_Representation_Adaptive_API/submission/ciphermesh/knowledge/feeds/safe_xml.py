"""Defensive XML/RSS parsing.

Author: Kumar Waibhav Akshat (RA2212704010027)
Course: 21CSE525T Agent Technology - Assignment 4.2

RSS feeds are untrusted input. A document type declaration enables entity
expansion ("billion laughs") and external entities (XXE, OWASP), so any document
that contains a DTD, an ENTITY declaration or an external reference is refused
before parsing. The expat handlers are also wired to raise, as a second layer.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from xml.parsers import expat
from dataclasses import dataclass, field

_FORBIDDEN = re.compile(rb"<!\s*(?:DOCTYPE|ENTITY|ELEMENT|ATTLIST)", re.IGNORECASE)
MAX_XML_BYTES = 4 * 1024 * 1024
MAX_ITEMS = 500


class UnsafeXMLError(ValueError):
    """The document uses XML features that are refused (DTD, entities, oversize)."""


@dataclass
class RssItem:
    title: str = ""
    description: str = ""
    link: str = ""
    guid: str = ""
    pub_date: str = ""
    extra: dict = field(default_factory=dict)


def _refuse(*_args, **_kwargs):
    raise UnsafeXMLError("DTD / entity declarations are not accepted")


def parse_xml(body: bytes) -> ET.Element:
    if len(body) > MAX_XML_BYTES:
        raise UnsafeXMLError(f"XML document larger than {MAX_XML_BYTES} bytes")
    if _FORBIDDEN.search(body):
        raise UnsafeXMLError("XML document contains a DTD or entity declaration; refused")
    guard = expat.ParserCreate()            # pass 1: raw expat with refusing handlers
    guard.StartDoctypeDeclHandler = _refuse
    guard.EntityDeclHandler = _refuse
    guard.UnparsedEntityDeclHandler = _refuse
    guard.ExternalEntityRefHandler = _refuse
    try:
        guard.Parse(body, True)
        return ET.fromstring(body)          # pass 2: build the tree (no DTD present)
    except (expat.ExpatError, ET.ParseError) as exc:
        raise ValueError(f"malformed XML: {exc}") from exc


def _text(el: ET.Element | None) -> str:
    return "".join(el.itertext()).strip() if el is not None else ""


def parse_rss(body: bytes) -> tuple[str, list[RssItem]]:
    """Return (channel title, items). Supports RSS 2.0 and Atom entries."""
    root = parse_xml(body)
    atom = "{http://www.w3.org/2005/Atom}"
    items: list[RssItem] = []
    channel = root.find("channel")
    title = _text(channel.find("title")) if channel is not None else _text(root.find(f"{atom}title"))
    for el in root.iter("item"):
        items.append(RssItem(title=_text(el.find("title")), description=_text(el.find("description")),
                             link=_text(el.find("link")), guid=_text(el.find("guid")),
                             pub_date=_text(el.find("pubDate"))))
        if len(items) >= MAX_ITEMS:
            break
    for el in root.iter(f"{atom}entry"):
        link = el.find(f"{atom}link")
        items.append(RssItem(title=_text(el.find(f"{atom}title")),
                             description=_text(el.find(f"{atom}summary")) or _text(el.find(f"{atom}content")),
                             link=link.get("href", "") if link is not None else "",
                             guid=_text(el.find(f"{atom}id")), pub_date=_text(el.find(f"{atom}updated"))))
        if len(items) >= MAX_ITEMS:
            break
    return title, items
