"""Private authenticated HTTP transport copied for standalone QID use."""

from __future__ import annotations

import base64
import logging
import ssl
import time
from typing import Any
from urllib import error, parse, request

from qualys_qid_vulnerabilities.config import AppConfig
from qualys_qid_vulnerabilities.errors import (
    ConfigurationValidationError,
    QualysAuthenticationError,
    QualysHTTPError,
    QualysTransportError,
)


USER_AGENT = "qualys_qid_vulnerabilities/0.1"
MAX_RESPONSE_BYTES = 10 * 1024 * 1024
LOGGER = logging.getLogger("qualys_qid_vulnerabilities.transport")


class QualysTransport:
    """Minimal authenticated Qualys transport used only by the QID tool."""

    def __init__(
        self,
        *,
        base_url: str,
        auth_model: str,
        timeout_seconds: int,
        verify_ssl: bool,
        ca_bundle: str | None = None,
        username: str | None = None,
        password: str | None = None,
        access_token: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth_model = auth_model
        self.timeout_seconds = timeout_seconds
        self.verify_ssl = verify_ssl
        self.ca_bundle = ca_bundle
        self.username = username
        self.password = password
        self.access_token = access_token
        self._bearer_token: str | None = None

    @classmethod
    def from_config(cls, config: AppConfig) -> "QualysTransport":
        config.validate()
        return cls(
            base_url=config.qualys.base_url,
            auth_model=config.qualys.auth_model,
            timeout_seconds=config.qualys.timeout_seconds,
            verify_ssl=config.qualys.verify_ssl,
            ca_bundle=config.qualys.ca_bundle,
            username=config.secrets.username,
            password=config.secrets.password,
            access_token=config.secrets.access_token,
        )

    def post_form(
        self,
        *,
        path: str,
        form: dict[str, str],
        accept: str,
        headers: dict[str, str],
    ) -> bytes:
        data = parse.urlencode(form).encode("utf-8")
        req = request.Request(
            url=f"{self._api_server_base_url()}{path}",
            data=data,
            headers={
                **headers,
                "Accept": accept,
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )
        return self._perform_request(req)

    def _post_form(
        self,
        *,
        base_url: str,
        path: str,
        form: dict[str, str],
        accept: str,
        headers: dict[str, str],
    ) -> bytes:
        """Compatibility seam kept local for the QID client's request tests."""
        data = parse.urlencode(form).encode("utf-8")
        req = request.Request(
            url=f"{base_url.rstrip('/')}{path}",
            data=data,
            headers={
                **headers,
                "Accept": accept,
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": USER_AGENT,
            },
            method="POST",
        )
        return self._perform_request(req)

    def api_headers(self) -> dict[str, str]:
        headers = {"X-Requested-With": USER_AGENT}
        if self.auth_model == "basic":
            if not self.username or not self.password:
                raise ConfigurationValidationError(
                    "Basic Qualys auth requires both username and password"
                )
            token = base64.b64encode(
                f"{self.username}:{self.password}".encode("utf-8")
            ).decode("ascii")
            headers["Authorization"] = f"Basic {token}"
            return headers
        if self.auth_model == "token":
            if not self.access_token:
                raise ConfigurationValidationError(
                    "Token Qualys auth requires QUALYS_ACCESS_TOKEN"
                )
            headers["Authorization"] = f"Bearer {self.access_token}"
            return headers
        raise ConfigurationValidationError(
            f"Unsupported qualys.auth_model for live API calls: {self.auth_model}"
        )

    def _vmdr_api_headers(self) -> dict[str, str]:
        return self.api_headers()

    def _api_server_base_url(self) -> str:
        parsed = parse.urlparse(self.base_url)
        host = parsed.hostname or ""
        if host.startswith("gateway."):
            host = f"qualysapi.{host.removeprefix('gateway.')}"
        return parse.urlunparse((parsed.scheme, host, "", "", "", ""))

    def _perform_request(
        self,
        req: request.Request,
        *,
        expected_status_codes: set[int] | None = None,
    ) -> bytes:
        kwargs: dict[str, Any] = {"timeout": self.timeout_seconds}
        if self.verify_ssl and self.ca_bundle:
            kwargs["context"] = ssl.create_default_context(cafile=self.ca_bundle)
        elif not self.verify_ssl:
            kwargs["context"] = ssl._create_unverified_context()
        started = time.monotonic()
        LOGGER.info(
            "POST %s (request body omitted)",
            req.full_url,
        )
        try:
            with request.urlopen(req, **kwargs) as response:
                status_code = getattr(response, "status", None) or response.getcode()
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise QualysTransportError(
                        "Qualys API response exceeded the 10 MiB safety limit"
                    )
        except error.HTTPError as exc:
            LOGGER.warning(
                "Request failed with HTTP %s from %s after %.2fs",
                exc.code,
                req.full_url,
                time.monotonic() - started,
            )
            if exc.code in {401, 403}:
                raise QualysAuthenticationError(
                    status_code=exc.code,
                    reason=exc.reason,
                    method=req.get_method(),
                    url=req.full_url,
                ) from exc
            raise QualysHTTPError(
                status_code=exc.code,
                reason=exc.reason,
                method=req.get_method(),
                url=req.full_url,
            ) from exc
        except error.URLError as exc:
            LOGGER.warning(
                "Request could not reach %s after %.2fs",
                req.full_url,
                time.monotonic() - started,
            )
            raise QualysTransportError(
                f"Unable to reach Qualys API at {req.full_url}: {exc.reason}"
            ) from exc
        if status_code not in (expected_status_codes or {200}):
            LOGGER.warning(
                "Request returned unexpected HTTP %s from %s after %.2fs",
                status_code,
                req.full_url,
                time.monotonic() - started,
            )
            raise QualysHTTPError(
                status_code=status_code,
                reason="unexpected status",
                method=req.get_method(),
                url=req.full_url,
            )
        LOGGER.info(
            "Response %s from %s in %.2fs (%d bytes)",
            status_code,
            req.full_url,
            time.monotonic() - started,
            len(body),
        )
        return body
