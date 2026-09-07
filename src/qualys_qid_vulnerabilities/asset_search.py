"""Validated local selectors for the read-only Qualys Host List lookup."""

from __future__ import annotations

from dataclasses import dataclass


class AssetSearchError(ValueError):
    """Raised when an Asset ID or DNS/hostname selector is invalid."""


@dataclass(frozen=True, slots=True)
class AssetSearch:
    """Exact, case-insensitive selectors applied to Qualys Host List data."""

    asset_ids: tuple[str, ...] = ()
    hostnames: tuple[str, ...] = ()

    @classmethod
    def parse(cls, *, asset_ids: str | None, hostnames: str | None) -> "AssetSearch":
        ids = _values(asset_ids, "Asset ID")
        names = tuple(_normalize_hostname(value) for value in _values(hostnames, "DNS/Hostname"))
        if not ids and not names:
            raise AssetSearchError("one Asset ID or DNS/Hostname selector is required")
        return cls(asset_ids=ids, hostnames=names)

    def matches(self, *, asset_id: str, hostnames: tuple[str, ...]) -> bool:
        if self.asset_ids and asset_id in self.asset_ids:
            return True
        normalized = {_normalize_hostname(value) for value in hostnames if value.strip()}
        return bool(set(self.hostnames).intersection(normalized))


def _values(raw: str | None, label: str) -> tuple[str, ...]:
    if raw is None:
        return ()
    values = tuple(value.strip() for value in raw.split(",") if value.strip())
    if not values:
        raise AssetSearchError(f"{label} selector must not be empty")
    return tuple(dict.fromkeys(values))


def _normalize_hostname(value: str) -> str:
    return value.strip().rstrip(".").casefold()
