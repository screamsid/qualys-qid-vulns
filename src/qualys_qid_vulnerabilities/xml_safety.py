"""Small, dependency-free guards around the standard XML parser."""

from __future__ import annotations

from xml.etree import ElementTree


MAX_XML_BYTES = 10 * 1024 * 1024


def fromstring(payload: bytes) -> ElementTree.Element:
    """Parse an API document while rejecting entity-based XML attacks."""
    document = payload.strip()
    if len(document) > MAX_XML_BYTES:
        raise ValueError("XML response exceeded the maximum permitted size")
    upper = document.upper()
    # Qualys legitimately includes a DOCTYPE in some responses. ElementTree
    # does not fetch external DTDs, so permit that declaration but reject
    # entity definitions, which enable expansion attacks.
    if b"<!ENTITY" in upper:
        raise ValueError("XML response contained a prohibited entity declaration")
    return ElementTree.fromstring(document)
