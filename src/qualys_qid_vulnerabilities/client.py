"""Qualys Host Detection client with one explicitly scoped ignore write."""

from __future__ import annotations

import logging

from qualys_qid_vulnerabilities.config import AppConfig
from qualys_qid_vulnerabilities.asset_search import AssetSearch
from qualys_qid_vulnerabilities.ignore import IgnoreVulnerabilityRequest
from qualys_qid_vulnerabilities.ip_filter import IpFilter
from qualys_qid_vulnerabilities.host_list import HostAsset, parse_host_list
from qualys_qid_vulnerabilities.models import (
    IgnoreVulnerabilityResult,
    QidVulnerabilityListing,
)
from qualys_qid_vulnerabilities.transport import QualysTransport


HOST_VULNERABILITY_DETECTION_PATH = "/api/5.0/fo/asset/host/vm/detection/"
HOST_LIST_PATH = "/api/5.0/fo/asset/host/"
IGNORE_VULNERABILITY_PATH = "/api/2.0/fo/ignore_vuln/index.php"
LOGGER = logging.getLogger("qualys_qid_vulnerabilities.client")


class QidVulnerabilityClient(QualysTransport):
    """Authenticated Qualys client owned by the standalone QID tool."""

    @classmethod
    def from_config(cls, config: AppConfig) -> "QidVulnerabilityClient":
        config.validate()
        return cls(
            base_url=config.qualys.base_url,
            auth_model=config.qualys.auth_model,
            timeout_seconds=config.qualys.timeout_seconds,
            verify_ssl=config.qualys.verify_ssl,
            username=config.secrets.username,
            password=config.secrets.password,
            access_token=config.secrets.access_token,
        )

    def get_vulnerabilities_for_qid(
        self,
        qid: int | None,
        *,
        ip_filter: IpFilter | None = None,
        include_ignored: bool = False,
    ) -> QidVulnerabilityListing:
        if qid is not None and qid <= 0:
            raise ValueError("QID must be a positive integer")

        form: dict[str, str] = {
            "action": "list",
            "show_asset_id": "1",
            "truncation_limit": "0",
        }
        if qid is not None:
            form["qids"] = str(qid)
        if ip_filter is not None:
            form["ips"] = ip_filter.qualys_value
        if include_ignored:
            form["include_ignored"] = "1"

        LOGGER.info(
            "Looking up %s detections%s",
            f"QID {qid}" if qid is not None else "all QID",
            " including ignored state" if include_ignored else "",
        )

        payload = self._post_form(
            base_url=self._api_server_base_url(),
            path=HOST_VULNERABILITY_DETECTION_PATH,
            form=form,
            accept="application/xml",
            headers=self._vmdr_api_headers(),
        )
        return QidVulnerabilityListing.from_api_xml(
            payload,
            requested_qid=qid,
        )

    def search_assets(self, search: AssetSearch) -> tuple[HostAsset, ...]:
        """Find assets by exact Asset ID or DNS/hostname in Qualys Host List."""
        LOGGER.info("Searching Qualys Host List for selected assets")
        payload = self._post_form(
            base_url=self._api_server_base_url(),
            path=HOST_LIST_PATH,
            form={
                "action": "list",
                "details": "Basic",
                "show_asset_id": "1",
                "truncation_limit": "0",
            },
            accept="application/xml",
            headers=self._vmdr_api_headers(),
        )
        return tuple(
            asset for asset in parse_host_list(payload)
            if search.matches(asset_id=asset.asset_id, hostnames=asset.hostnames)
        )

    def ignore_vulnerabilities(
        self,
        request: IgnoreVulnerabilityRequest,
    ) -> IgnoreVulnerabilityResult:
        """Ignore one QID only on the request's exact validated asset IPs."""

        LOGGER.info(
            "Submitting confirmed ignore for QID %s to %d exact IP address(es)",
            request.qid,
            len(request.ip_addresses),
        )

        form = {
            "action": "ignore",
            "qids": str(request.qid),
            "ips": request.qualys_ips_value,
            "comments": request.comments,
        }
        if request.reopen_ignored_days is not None:
            form["reopen_ignored_days"] = str(request.reopen_ignored_days)

        payload = self._post_form(
            base_url=self._api_server_base_url(),
            path=IGNORE_VULNERABILITY_PATH,
            form=form,
            accept="application/xml",
            headers=self._vmdr_api_headers(),
        )
        return IgnoreVulnerabilityResult.from_api_xml(
            payload,
            requested_qid=request.qid,
            requested_ips=request.ip_addresses,
        )
