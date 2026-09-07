"""Qualys CSAM gateway base URL validation helpers."""

from __future__ import annotations

from urllib import parse

from qualys_qid_vulnerabilities.errors import ConfigurationValidationError


CONFIGURED_QUALYS_GATEWAY_EXAMPLE = "https://gateway.<platform>.example"
QUALYS_GATEWAY_HOST_PREFIX = "gateway."
QUALYS_UI_HOST_PREFIX = "qualysguard."


def validate_live_qualys_base_url(base_url: str) -> None:
    """Enforce the validated CSAM gateway contract for live API operations."""
    parsed = parse.urlparse(base_url)
    host = (parsed.hostname or "").lower()

    if parsed.scheme.lower() != "https":
        raise ConfigurationValidationError(
            "qualys.base_url must use https:// for live Qualys CSAM API calls "
            f"and target a gateway host such as {CONFIGURED_QUALYS_GATEWAY_EXAMPLE}"
        )

    if not host:
        raise ConfigurationValidationError(
            "qualys.base_url must include a gateway host for live Qualys CSAM API calls "
            f"such as {CONFIGURED_QUALYS_GATEWAY_EXAMPLE}"
        )

    if host.startswith(QUALYS_UI_HOST_PREFIX):
        raise ConfigurationValidationError(
            f"qualys.base_url points to the Qualys UI host '{host}'. "
            "Qualys CSAM API calls must target the gateway host instead, "
            f"for example {CONFIGURED_QUALYS_GATEWAY_EXAMPLE}"
        )

    if not host.startswith(QUALYS_GATEWAY_HOST_PREFIX):
        raise ConfigurationValidationError(
            "qualys.base_url must target a gateway-style host for live Qualys CSAM API calls, "
            f"for example {CONFIGURED_QUALYS_GATEWAY_EXAMPLE}"
        )


def validate_live_qualys_operation_config(*, base_url: str, auth_model: str) -> None:
    """Validate live-operation config before any Qualys network call is attempted."""
    validate_live_qualys_base_url(base_url)
    if auth_model == "unset":
        raise ConfigurationValidationError(
            "qualys.auth_model must be 'basic' or 'token' for live Qualys API calls"
        )
