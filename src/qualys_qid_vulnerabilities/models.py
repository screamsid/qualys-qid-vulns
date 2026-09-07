"""Response models for Qualys host vulnerability detections."""

from __future__ import annotations

from dataclasses import dataclass
from xml.etree import ElementTree

from qualys_qid_vulnerabilities.errors import QualysResponseError
from qualys_qid_vulnerabilities.xml_safety import fromstring


@dataclass(frozen=True, slots=True)
class QidVulnerabilityRecord:
    """One vulnerability detection for one Qualys asset."""

    asset_id: str
    ip_address: str
    dns_hostname: str | None
    qid: int
    status: str
    vulnerability_id: str | None
    ignored: bool | None = None

    @property
    def ignored_state(self) -> str:
        """Return the evidence-backed display state for ``IS_IGNORED``."""

        if self.ignored is True:
            return "ignored"
        if self.ignored is False:
            return "not ignored"
        return "unknown"


@dataclass(frozen=True, slots=True)
class QidMatchedAsset:
    """One asset returned by the Host Detection list response."""

    asset_id: str
    ip_address: str
    dns_hostname: str | None


@dataclass(frozen=True, slots=True)
class QidVulnerabilityListing:
    """All host vulnerability detections returned for a QID."""

    vulnerabilities: tuple[QidVulnerabilityRecord, ...]
    matched_asset_ids: tuple[str, ...] = ()
    matched_assets: tuple[QidMatchedAsset, ...] = ()

    @property
    def matched_asset_count(self) -> int:
        matched_ids = set(self.matched_asset_ids)
        matched_ids.update(asset.asset_id for asset in self.matched_assets)
        matched_ids.update(record.asset_id for record in self.vulnerabilities)
        return len(matched_ids)

    @property
    def affected_asset_count(self) -> int:
        return len({record.asset_id for record in self.vulnerabilities})

    @property
    def confirmed_ignored_asset_count(self) -> int:
        return sum(state == "ignored" for state in self._asset_ignore_states())

    @property
    def not_ignored_asset_count(self) -> int:
        return sum(state == "not ignored" for state in self._asset_ignore_states())

    @property
    def unknown_ignore_state_asset_count(self) -> int:
        return sum(state == "unknown" for state in self._asset_ignore_states())

    @property
    def assets_without_requested_qid(self) -> tuple[QidMatchedAsset, ...]:
        affected_ids = {record.asset_id for record in self.vulnerabilities}
        return tuple(
            asset for asset in self.matched_assets if asset.asset_id not in affected_ids
        )

    def ignored_only(self) -> "QidVulnerabilityListing":
        """Return only detections Qualys explicitly reports as ignored."""

        vulnerabilities = tuple(
            record for record in self.vulnerabilities if record.ignored is True
        )
        asset_ids = {record.asset_id for record in vulnerabilities}
        return QidVulnerabilityListing(
            vulnerabilities=vulnerabilities,
            matched_asset_ids=tuple(
                asset_id for asset_id in self.matched_asset_ids if asset_id in asset_ids
            ),
            matched_assets=tuple(
                asset for asset in self.matched_assets if asset.asset_id in asset_ids
            ),
        )

    def _asset_ignore_states(self) -> tuple[str, ...]:
        """Classify unique assets without overstating partial detection evidence."""

        by_asset: dict[str, list[bool | None]] = {}
        for record in self.vulnerabilities:
            by_asset.setdefault(record.asset_id, []).append(record.ignored)

        states: list[str] = []
        for ignored_values in by_asset.values():
            if False in ignored_values:
                states.append("not ignored")
            elif None in ignored_values:
                states.append("unknown")
            else:
                states.append("ignored")
        return tuple(states)

    @classmethod
    def from_api_xml(
        cls,
        payload: bytes,
        *,
        requested_qid: int | None,
    ) -> "QidVulnerabilityListing":
        try:
            root = fromstring(payload)
        except ValueError as exc:
            raise QualysResponseError("Qualys host vulnerability XML was unsafe") from exc
        except ElementTree.ParseError as exc:
            raise QualysResponseError(
                "Qualys host vulnerability response was not valid XML"
            ) from exc

        response = root.find("RESPONSE")
        if response is None:
            raise QualysResponseError(
                "Qualys host vulnerability response did not include RESPONSE"
            )

        host_list = response.find("HOST_LIST")
        if host_list is None:
            error_code = _optional_text(response, "CODE")
            error_text = _optional_text(response, "TEXT")
            if error_code or error_text:
                detail = ": ".join(
                    value for value in (error_code, error_text) if value
                )
                raise QualysResponseError(
                    f"Qualys host vulnerability request failed: {detail}"
                )
            return cls(vulnerabilities=())

        records: list[QidVulnerabilityRecord] = []
        matched_asset_ids: list[str] = []
        matched_assets: list[QidMatchedAsset] = []
        for host in host_list.findall("HOST"):
            asset_id = _required_text(host, "ASSET_ID", "asset ID")
            matched_asset_ids.append(asset_id)
            ip_address = _required_text(host, "IP", "IP address")
            host_name = _host_name(host)
            matched_assets.append(
                QidMatchedAsset(
                    asset_id=asset_id,
                    ip_address=ip_address,
                    dns_hostname=host_name,
                )
            )
            detection_list = host.find("DETECTION_LIST")
            if detection_list is None:
                continue

            for detection in detection_list.findall("DETECTION"):
                qid_text = _required_text(detection, "QID", "QID")
                try:
                    qid = int(qid_text)
                except ValueError as exc:
                    raise QualysResponseError(
                        "Qualys host vulnerability QID was not a valid integer"
                    ) from exc
                if requested_qid is not None and qid != requested_qid:
                    continue

                records.append(
                    QidVulnerabilityRecord(
                        asset_id=asset_id,
                        ip_address=ip_address,
                        dns_hostname=_optional_text(detection, "FQDN") or host_name,
                        qid=qid,
                        status=_required_text(detection, "STATUS", "status"),
                        vulnerability_id=_optional_text(
                            detection, "UNIQUE_VULN_ID"
                        ),
                        ignored=_ignored_state(detection),
                    )
                )

        return cls(
            vulnerabilities=tuple(records),
            matched_asset_ids=tuple(dict.fromkeys(matched_asset_ids)),
            matched_assets=tuple(matched_assets),
        )


@dataclass(frozen=True, slots=True)
class IgnoredVulnerabilityRecord:
    """One ignored vulnerability record confirmed by Qualys."""

    ticket_number: str
    qid: int
    ip_address: str
    dns_hostname: str | None


@dataclass(frozen=True, slots=True)
class IgnoreVulnerabilityResult:
    """Confirmed result of one Qualys ignore operation."""

    message: str
    ignored: tuple[IgnoredVulnerabilityRecord, ...]

    @property
    def affected_ip_count(self) -> int:
        return len({record.ip_address for record in self.ignored})

    @classmethod
    def from_api_xml(
        cls,
        payload: bytes,
        *,
        requested_qid: int,
        requested_ips: tuple[str, ...],
    ) -> "IgnoreVulnerabilityResult":
        try:
            root = fromstring(payload)
        except ValueError as exc:
            raise QualysResponseError("Qualys ignore vulnerability XML was unsafe") from exc
        except ElementTree.ParseError as exc:
            raise QualysResponseError(
                "Qualys ignore vulnerability response was not valid XML"
            ) from exc

        response = root.find("RESPONSE")
        if response is None:
            raise QualysResponseError(
                "Qualys ignore vulnerability response did not include RESPONSE"
            )

        status = (response.get("status") or "").strip().upper()
        message = _optional_text(response, "MESSAGE") or "No response message"
        if status != "SUCCESS":
            detail = _optional_text(response, "TEXT") or message
            raise QualysResponseError(
                f"Qualys ignore vulnerability request was not successful"
                f" ({status or 'UNKNOWN'}): {detail}. The outcome may be partial; "
                "verify Qualys before retrying"
            )

        requested_ip_set = set(requested_ips)
        ignored: list[IgnoredVulnerabilityRecord] = []
        ignored_list = response.find("IGNORED_LIST")
        if ignored_list is not None:
            for record in ignored_list.findall("IGNORED"):
                qid_text = _required_ignore_text(record, "QID", "QID")
                try:
                    qid = int(qid_text)
                except ValueError as exc:
                    raise QualysResponseError(
                        "Qualys ignored vulnerability QID was not a valid integer"
                    ) from exc
                if qid != requested_qid:
                    raise QualysResponseError(
                        "Qualys ignore response included an unexpected QID"
                    )

                ip_address = _required_ignore_text(record, "IP", "IP address")
                if ip_address not in requested_ip_set:
                    raise QualysResponseError(
                        "Qualys ignore response included an unexpected IP address"
                    )
                ignored.append(
                    IgnoredVulnerabilityRecord(
                        ticket_number=_required_ignore_text(
                            record, "TICKET_NUMBER", "ticket number"
                        ),
                        qid=qid,
                        ip_address=ip_address,
                        dns_hostname=_optional_text(record, "DNS"),
                    )
                )

        return cls(message=message, ignored=tuple(ignored))


def _host_name(host: ElementTree.Element) -> str | None:
    dns_data = host.find("DNS_DATA")
    if dns_data is not None:
        fqdn = _optional_text(dns_data, "FQDN")
        if fqdn:
            return fqdn
        hostname = _optional_text(dns_data, "HOSTNAME")
        if hostname:
            return hostname
    return _optional_text(host, "DNS")


def _ignored_state(detection: ElementTree.Element) -> bool | None:
    """Parse the documented detection-level ``IS_IGNORED`` value."""

    value = _optional_text(detection, "IS_IGNORED")
    if value == "1":
        return True
    if value == "0":
        return False
    return None


def _required_text(
    element: ElementTree.Element,
    tag_name: str,
    field_name: str,
) -> str:
    value = _optional_text(element, tag_name)
    if value is None:
        raise QualysResponseError(
            f"Qualys host vulnerability {field_name} was missing from XML response"
        )
    return value


def _required_ignore_text(
    element: ElementTree.Element,
    tag_name: str,
    field_name: str,
) -> str:
    value = _optional_text(element, tag_name)
    if value is None:
        raise QualysResponseError(
            f"Qualys ignored vulnerability {field_name} was missing from XML response"
        )
    return value


def _optional_text(element: ElementTree.Element, tag_name: str) -> str | None:
    child = element.find(tag_name)
    if child is None or child.text is None:
        return None
    value = child.text.strip()
    return value or None
