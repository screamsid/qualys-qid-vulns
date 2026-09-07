"""Validated request scope for explicitly confirmed Qualys ignore writes."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address


MAX_IGNORE_IPS_LENGTH = 512
MAX_IGNORE_COMMENT_LENGTH = 255
MIN_REOPEN_IGNORED_DAYS = 1
MAX_REOPEN_IGNORED_DAYS = 730


class IgnoreRequestError(ValueError):
    """Raised when an ignore request cannot be scoped safely."""


@dataclass(frozen=True, slots=True)
class IgnoreVulnerabilityRequest:
    """One QID ignore request constrained to exact returned asset IPs."""

    qid: int
    ip_addresses: tuple[str, ...]
    comments: str
    reopen_ignored_days: int | None = None

    @property
    def qualys_ips_value(self) -> str:
        return ",".join(self.ip_addresses)

    @classmethod
    def create(
        cls,
        *,
        qid: int,
        ip_addresses: tuple[str, ...],
        comments: str,
        reopen_ignored_days: int | None = None,
    ) -> "IgnoreVulnerabilityRequest":
        normalized_ips, normalized_comments = _normalize_ignore_scope(
            qid=qid,
            ip_addresses=ip_addresses,
            comments=comments,
            reopen_ignored_days=reopen_ignored_days,
        )

        ips_value = ",".join(normalized_ips)
        if len(ips_value.encode("ascii")) > MAX_IGNORE_IPS_LENGTH:
            raise IgnoreRequestError(
                "Exact matched asset IPs exceed Qualys' 512-character ignore limit; "
                "no ignore request was sent"
            )

        return cls(
            qid=qid,
            ip_addresses=tuple(normalized_ips),
            comments=normalized_comments,
            reopen_ignored_days=reopen_ignored_days,
        )


def create_ignore_request_batches(
    *,
    qid: int,
    ip_addresses: tuple[str, ...],
    comments: str,
    reopen_ignored_days: int | None = None,
) -> tuple[IgnoreVulnerabilityRequest, ...]:
    """Split one confirmed exact-IP scope into Qualys-safe request batches."""

    normalized_ips, normalized_comments = _normalize_ignore_scope(
        qid=qid,
        ip_addresses=ip_addresses,
        comments=comments,
        reopen_ignored_days=reopen_ignored_days,
    )
    batches: list[IgnoreVulnerabilityRequest] = []
    current_batch: list[str] = []
    current_length = 0
    for ip_address in normalized_ips:
        added_length = len(ip_address) + (1 if current_batch else 0)
        if current_batch and current_length + added_length > MAX_IGNORE_IPS_LENGTH:
            batches.append(
                IgnoreVulnerabilityRequest(
                    qid=qid,
                    ip_addresses=tuple(current_batch),
                    comments=normalized_comments,
                    reopen_ignored_days=reopen_ignored_days,
                )
            )
            current_batch = []
            current_length = 0
            added_length = len(ip_address)
        current_batch.append(ip_address)
        current_length += added_length

    batches.append(
        IgnoreVulnerabilityRequest(
            qid=qid,
            ip_addresses=tuple(current_batch),
            comments=normalized_comments,
            reopen_ignored_days=reopen_ignored_days,
        )
    )
    return tuple(batches)


def _normalize_ignore_scope(
    *,
    qid: int,
    ip_addresses: tuple[str, ...],
    comments: str,
    reopen_ignored_days: int | None,
) -> tuple[list[str], str]:
    if qid <= 0:
        raise IgnoreRequestError("QID must be a positive integer")

    normalized_comments = validate_ignore_comment(comments)
    if reopen_ignored_days is not None and not (
        MIN_REOPEN_IGNORED_DAYS
        <= reopen_ignored_days
        <= MAX_REOPEN_IGNORED_DAYS
    ):
        raise IgnoreRequestError(
            "reopen ignored days must be between 1 and 730"
        )
    normalized_ips: list[str] = []
    seen_ips: set[str] = set()
    for raw_ip in ip_addresses:
        try:
            normalized_ip = str(IPv4Address(raw_ip))
        except AddressValueError as exc:
            raise IgnoreRequestError(
                f"Cannot ignore QID on invalid returned IPv4 address: {raw_ip!r}"
            ) from exc
        if normalized_ip not in seen_ips:
            seen_ips.add(normalized_ip)
            normalized_ips.append(normalized_ip)

    if not normalized_ips:
        raise IgnoreRequestError(
            "Cannot ignore a QID without matching vulnerability asset IPs"
        )
    return normalized_ips, normalized_comments


def validate_ignore_comment(value: str) -> str:
    """Validate the required operator audit comment before any API request."""

    comment = value.strip()
    if not comment:
        raise IgnoreRequestError("--comment must not be empty when --ignore is used")
    if len(comment) > MAX_IGNORE_COMMENT_LENGTH:
        raise IgnoreRequestError("--comment must not exceed 255 characters")
    return comment
