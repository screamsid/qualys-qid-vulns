"""Validated Qualys IPv4 host filter values."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import AddressValueError, IPv4Address


class IpFilterError(ValueError):
    """Raised when an operator-supplied IP filter is invalid."""


@dataclass(frozen=True, slots=True)
class IpFilter:
    """A normalized, non-expanded list of IPv4 addresses and ranges."""

    entries: tuple[str, ...]

    @property
    def qualys_value(self) -> str:
        """Return the validated value expected by Qualys' ``ips`` filter."""

        return ",".join(self.entries)

    @property
    def requested_count(self) -> int:
        """Return the number of requested addresses or ranges."""

        return len(self.entries)

    def entry_matches(self, entry: str, ip_address: str) -> bool:
        """Return whether a returned IPv4 address falls within one entry."""

        candidate = IPv4Address(ip_address)
        if "-" not in entry:
            return candidate == IPv4Address(entry)
        start, end = (IPv4Address(value) for value in entry.split("-", maxsplit=1))
        return start <= candidate <= end

    @classmethod
    def parse(cls, value: str) -> "IpFilter":
        """Validate and normalize a comma-separated IPv4 filter."""

        if not value.strip():
            raise IpFilterError("IP filter must not be empty")

        normalized: list[str] = []
        for position, raw_entry in enumerate(value.split(","), start=1):
            entry = raw_entry.strip()
            if not entry:
                raise IpFilterError(f"IP filter entry {position} must not be empty")
            normalized.append(_normalize_entry(entry, position=position))

        return cls(entries=tuple(normalized))


def _normalize_entry(entry: str, *, position: int) -> str:
    if "-" not in entry:
        return str(_parse_ipv4(entry, position=position))

    parts = entry.split("-")
    if len(parts) != 2:
        raise IpFilterError(
            f"IP filter entry {position} contains an invalid IPv4 address or "
            f"range: {entry!r}"
        )
    if not parts[0].strip() or not parts[1].strip():
        raise IpFilterError(
            f"IP filter entry {position} is an incomplete IPv4 range: {entry!r}"
        )

    start = _parse_ipv4(parts[0].strip(), position=position)
    end = _parse_ipv4(parts[1].strip(), position=position)
    if end < start:
        raise IpFilterError(
            f"IP filter entry {position} has an ending address lower than its "
            f"starting address: {entry!r}"
        )
    return f"{start}-{end}"


def _parse_ipv4(value: str, *, position: int) -> IPv4Address:
    try:
        return IPv4Address(value)
    except AddressValueError as exc:
        raise IpFilterError(
            f"IP filter entry {position} contains an invalid IPv4 address: {value!r}"
        ) from exc
