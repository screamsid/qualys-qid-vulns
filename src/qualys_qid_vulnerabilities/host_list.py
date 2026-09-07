"""Parser for the read-only Qualys Host List response used for asset search."""

from __future__ import annotations

from dataclasses import dataclass
from xml.etree import ElementTree

from qualys_qid_vulnerabilities.errors import QualysResponseError
from qualys_qid_vulnerabilities.xml_safety import fromstring


@dataclass(frozen=True, slots=True)
class HostAsset:
    asset_id: str
    ip_address: str | None
    hostnames: tuple[str, ...]


def parse_host_list(payload: bytes) -> tuple[HostAsset, ...]:
    if not payload.strip():
        return ()
    try:
        root = fromstring(payload)
    except ValueError as exc:
        raise QualysResponseError("Qualys host list XML was unsafe") from exc
    except ElementTree.ParseError as exc:
        raise QualysResponseError("Qualys host list response was not valid XML") from exc

    # Qualys has returned this XML with different element casing across API
    # versions/tenants. XML names are case-sensitive, so do not assume the
    # upper-case spelling used by some older examples and fixtures.
    response = _find_child(root, "response")
    if response is None:
        raise QualysResponseError("Qualys host list response did not include RESPONSE")
    host_list = _find_child(response, "host_list")
    if host_list is None:
        return ()

    assets: list[HostAsset] = []
    for host in _find_children(host_list, "host"):
        asset_id = _text(host, "asset_id")
        if not asset_id:
            raise QualysResponseError("Qualys host list record did not include an asset ID")
        dns_data = _find_child(host, "dns_data")
        hostnames = tuple(
            value
            for value in (
                _text(host, "dns"),
                _text(dns_data, "hostname"),
                _text(dns_data, "fqdn"),
            )
            if value
        )
        assets.append(HostAsset(asset_id, _text(host, "ip"), hostnames))
    return tuple(assets)


def _text(parent: ElementTree.Element | None, name: str) -> str | None:
    if parent is None:
        return None
    child = _find_child(parent, name)
    value = child.text if child is not None else None
    return value.strip() if value and value.strip() else None


def _find_child(parent: ElementTree.Element, name: str) -> ElementTree.Element | None:
    expected = name.casefold()
    return next(
        (child for child in parent if _local_name(child.tag).casefold() == expected),
        None,
    )


def _find_children(parent: ElementTree.Element, name: str) -> tuple[ElementTree.Element, ...]:
    expected = name.casefold()
    return tuple(child for child in parent if _local_name(child.tag).casefold() == expected)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]
