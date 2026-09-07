"""Safe, terminal-aware rendering for QID command results."""

from __future__ import annotations

import os
import csv
import io
import json
import shutil
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

from .ip_filter import IpFilter
from .models import QidVulnerabilityListing

HEADERS = ("Asset ID", "IP Address", "DNS/Hostname", "QID", "Status", "Host Vulnerability ID")
VERIFICATION_HEADERS = ("Asset ID", "IP Address", "DNS/Hostname", "QID", "Detection Status", "Ignored State", "Host Vulnerability ID")
_RESET, _CYAN, _GREEN, _YELLOW, _RED = "\033[0m", "\033[36m", "\033[32m", "\033[33m", "\033[31m"


def safe_output(value: str) -> str:
    """Prevent API-provided control characters from reaching the terminal."""
    return "".join(char if char in "\n\t" or ord(char) >= 32 else f"\\x{ord(char):02x}" for char in value).replace("\n", "\\x0a").replace("\r", "\\x0d")


def safe_log_output(value: str) -> str:
    """Display stored logs without replaying control characters."""
    return "".join(char if char in "\n\t" or ord(char) >= 32 else f"\\x{ord(char):02x}" for char in value).replace("\r", "\\x0d")


def format_table(listing: QidVulnerabilityListing) -> str:
    rows = [(safe_output(r.asset_id), r.ip_address, safe_output(r.dns_hostname or "-"), str(r.qid), safe_output(r.status), safe_output(r.vulnerability_id or "-")) for r in listing.vulnerabilities]
    return format_responsive_table(HEADERS, rows)


def listing_rows(listing: QidVulnerabilityListing) -> list[dict[str, object]]:
    return [{
        "asset_id": record.asset_id,
        "ip_address": record.ip_address,
        "dns_hostname": record.dns_hostname,
        "qid": record.qid,
        "status": record.status,
        "vulnerability_id": record.vulnerability_id,
        "ignored": record.ignored,
        "ignored_state": record.ignored_state,
    } for record in listing.vulnerabilities]


def summary_rows(listing: QidVulnerabilityListing, group_by: str | None) -> list[dict[str, object]]:
    rows = listing_rows(listing)
    if not group_by:
        return [{"assets_matched": listing.matched_asset_count,
                 "assets_affected": listing.affected_asset_count,
                 "detections": len(listing.vulnerabilities),
                 "ignored_assets": listing.confirmed_ignored_asset_count,
                 "not_ignored_assets": listing.not_ignored_asset_count,
                 "unknown_ignore_assets": listing.unknown_ignore_state_asset_count}]
    values = {"qid": lambda row: row["qid"], "status": lambda row: row["status"],
              "asset": lambda row: row["asset_id"], "ignored": lambda row: row["ignored_state"]}
    grouped: dict[object, list[dict[str, object]]] = {}
    for row in rows:
        grouped.setdefault(values[group_by](row), []).append(row)
    return [{"group": key, "detections": len(items),
             "assets": len({item["asset_id"] for item in items})}
            for key, items in sorted(grouped.items(), key=lambda item: str(item[0]))]


def format_json(listing: QidVulnerabilityListing, *, summary: bool = False, group_by: str | None = None) -> str:
    payload = summary_rows(listing, group_by) if summary else listing_rows(listing)
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def format_csv(listing: QidVulnerabilityListing, *, summary: bool = False, group_by: str | None = None) -> str:
    rows = summary_rows(listing, group_by) if summary else listing_rows(listing)
    if not rows:
        return "\n"
    stream = io.StringIO()
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]), extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue()


def evidence_payload(listing: QidVulnerabilityListing, *, qid: int | None, scope: str) -> dict[str, object]:
    return {"schema_version": 1, "verified_at": datetime.now(timezone.utc).isoformat(),
            "qid": qid, "scope": scope, "matched_assets": listing.matched_asset_count,
            "affected_assets": listing.affected_asset_count, "detections": listing_rows(listing)}


def write_text(path: str, content: str) -> None:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as stream:
            descriptor = -1
            stream.write(content)
        if descriptor != -1:
            os.close(descriptor)
    except BaseException:
        if descriptor != -1:
            os.close(descriptor)
        raise


def write_evidence(path: str, payload: dict[str, object]) -> None:
    write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def evidence_is_stale(path: str, days: int) -> bool:
    payload = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    verified_at = datetime.fromisoformat(str(payload["verified_at"]).replace("Z", "+00:00"))
    return (datetime.now(timezone.utc) - verified_at).total_seconds() > days * 86400


def print_verification(qid: int | None, ip_filter: IpFilter | None, listing: QidVulnerabilityListing) -> None:
    scope = "all assets" if ip_filter is None else "the supplied IP filter"
    qid_label = f"QID {qid}" if qid is not None else "QIDs"
    if listing.matched_asset_count == 0:
        print(f"No asset or QID detection was returned for {scope}. This endpoint cannot distinguish an unmatched asset from an asset with no matching QID when no HOST record is returned.")
    elif not listing.vulnerabilities:
        print(f"Assets were returned for {scope}, but no detection for {qid_label} was returned.")
    elif listing.confirmed_ignored_asset_count == listing.affected_asset_count:
        print("Every asset with returned QID detections is confirmed ignored.")
    else:
        print("Returned QID detections have mixed or incomplete ignored-state evidence.")
    print(); print(format_verification_table(listing))
    if qid is not None and listing.assets_without_requested_qid:
        print(); print(f"Assets matched with no returned detection for {qid_label}:")
        for asset in listing.assets_without_requested_qid:
            print(f"- {safe_output(asset.asset_id)} | {asset.ip_address} | {safe_output(asset.dns_hostname or '-')}")
    if ip_filter is not None:
        print(); print("Requested IP/range response coverage:")
        returned_ips = tuple(asset.ip_address for asset in listing.matched_assets)
        for entry in ip_filter.entries:
            outcome = "asset returned" if any(ip_filter.entry_matches(entry, address) for address in returned_ips) else "no asset/detection returned; Host Detection cannot establish whether no asset matched or the asset had no matching QID"
            print(f"- {entry}: {outcome}")
    print()
    print(f"Total IP addresses or ranges requested: {ip_filter.requested_count}" if ip_filter is not None else "Total scope: all assets returned by Qualys")
    print(f"Total assets matched: {listing.matched_asset_count}")
    print(f"Total assets with {'the QID' if qid is not None else 'QIDs'}: {listing.affected_asset_count}")
    print(f"Total assets confirmed ignored: {listing.confirmed_ignored_asset_count}")
    print(f"Total assets not ignored: {listing.not_ignored_asset_count}")
    print(f"Total assets with unknown ignore state: {listing.unknown_ignore_state_asset_count}")
    print(f"Total vulnerability detections returned: {len(listing.vulnerabilities)}")
    print(); print(format_notification_card(("Verification confirms only the detection-level ignored state returned by", "Qualys; this response cannot verify the stored exception comment, ticket", "number, or ignore date.")))


def format_verification_table(listing: QidVulnerabilityListing) -> str:
    rows = [(safe_output(r.asset_id), r.ip_address, safe_output(r.dns_hostname or "-"), str(r.qid), safe_output(r.status), r.ignored_state, safe_output(r.vulnerability_id or "-")) for r in listing.vulnerabilities]
    return format_responsive_table(VERIFICATION_HEADERS, rows)


def format_notification_card(lines: tuple[str, ...]) -> str:
    inner_width = max(len("NOTICE"), *(len(line) for line in lines))
    border = "+" + "-" * (inner_width + 4) + "+"
    return "\n".join([border, f"|  {'NOTICE'.ljust(inner_width)}  |"] + [f"|  {line.ljust(inner_width)}  |" for line in lines] + [border])


def terminal_width() -> int:
    return shutil.get_terminal_size((100, 24)).columns


def format_responsive_table(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> str:
    widths = responsive_column_widths(headers, rows)
    def wrapped_row(row: tuple[str, ...]) -> list[str]:
        cells = [textwrap.wrap(value, width=widths[i], break_long_words=True, break_on_hyphens=False) or [""] for i, value in enumerate(row)]
        return [" | ".join(colour_table_cell(headers[i], cells[i][line].ljust(widths[i]) if line < len(cells[i]) else " " * widths[i]) for i in range(len(headers))) for line in range(max(map(len, cells)))]
    output = ["-+-".join("-" * width for width in widths)]
    output = wrapped_row(headers) + output
    output.extend(line for row in rows for line in wrapped_row(row))
    return "\n".join(output)


def responsive_column_widths(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> list[int]:
    widths = [max((len(header), *(len(row[i]) for row in rows))) for i, header in enumerate(headers)]
    available = max(20, terminal_width()) - 3 * (len(headers) - 1)
    minimums = [8, 10, 9, 5, 10, 10, 10]
    while sum(widths) > available:
        widest = max((i for i, width in enumerate(widths) if width > minimums[i]), key=widths.__getitem__, default=None)
        if widest is None:
            break
        widths[widest] -= 1
    return widths


def responsive_table_width(headers: tuple[str, ...], rows: list[tuple[str, ...]]) -> int:
    return sum(responsive_column_widths(headers, rows)) + 3 * (len(headers) - 1)


def colour_cli_value(value: str, colour: str) -> str:
    if sys.stdout.isatty() and not os.environ.get("NO_COLOR"):
        return f"{colour}{value}{_RESET}"
    return value


def colour_table_cell(header: str, value: str) -> str:
    if header in {"Status", "Detection Status"}:
        return colour_cli_value(value, _YELLOW if value.strip() == "New" else _GREEN)
    if header == "Ignored State":
        return colour_cli_value(value, _GREEN if value.strip() == "ignored" else _RED)
    return value
