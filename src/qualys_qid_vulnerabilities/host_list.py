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

    response = root.find("RESPONSE")
    if response is None:
        raise QualysResponseError("Qualys host list response did not include RESPONSE")
    host_list = response.find("HOST_LIST")
    if host_list is None:
        return ()

    assets: list[HostAsset] = []
    for host in host_list.findall("HOST"):
        asset_id = _text(host, "ASSET_ID")
        if not asset_id:
            raise QualysResponseError("Qualys host list record did not include an asset ID")
        hostnames = tuple(
            value
            for value in (
                _text(host, "DNS"),
                _text(host.find("DNS_DATA"), "HOSTNAME") if host.find("DNS_DATA") is not None else None,
                _text(host.find("DNS_DATA"), "FQDN") if host.find("DNS_DATA") is not None else None,
            )
            if value
        )
        assets.append(HostAsset(asset_id, _text(host, "IP"), hostnames))
    return tuple(assets)


def _text(parent: ElementTree.Element | None, name: str) -> str | None:
    if parent is None:
        return None
    value = parent.findtext(name)
    return value.strip() if value and value.strip() else None
