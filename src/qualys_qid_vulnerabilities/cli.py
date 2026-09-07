"""CLI for QID discovery and explicitly confirmed vulnerability ignores."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap

from qualys_qid_vulnerabilities.config import AppConfig
from qualys_qid_vulnerabilities.asset_search import AssetSearch, AssetSearchError
from qualys_qid_vulnerabilities.errors import ConfigurationError, QualysClientError
from qualys_qid_vulnerabilities.client import QidVulnerabilityClient
from qualys_qid_vulnerabilities.ignore import (
    IgnoreRequestError,
    IgnoreVulnerabilityRequest,
    create_ignore_request_batches,
    validate_ignore_comment,
)
from qualys_qid_vulnerabilities.ip_filter import IpFilter, IpFilterError
from qualys_qid_vulnerabilities.models import (
    IgnoreVulnerabilityResult,
    QidVulnerabilityListing,
)
from qualys_qid_vulnerabilities.progress import ProgressDisplay
from qualys_qid_vulnerabilities.logging_setup import configure_logging


LOGGER = logging.getLogger("qualys_qid_vulnerabilities.cli")


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Keep option descriptions in one stable column."""

    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=34)


HEADERS = (
    "Asset ID",
    "IP Address",
    "DNS/Hostname",
    "QID",
    "Status",
    "Host Vulnerability ID",
)
_RESET = "\033[0m"
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
VERIFICATION_HEADERS = (
    "Asset ID",
    "IP Address",
    "DNS/Hostname",
    "QID",
    "Detection Status",
    "Ignored State",
    "Host Vulnerability ID",
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qid",
        usage="qid QID [OPTIONS]",
        formatter_class=_HelpFormatter,
        description=(
            "Look up one Qualys QID across all assets or a selected scope.\n"
            "Read-only by default; --ignore requires explicit confirmation."
        ),
        epilog=textwrap.dedent(
            """
            examples:
              qid 12345
              qid 12345 --ips "192.0.2.10-192.0.2.20"
              qid 12345 --hostname "server-one.example.test" --verify-ignored
              qid 12345 --asset-id 100001 --ignore --comment "Approved exception"

            notes:
              Selectors are mutually exclusive. Asset IDs and hostnames are
              matched against Qualys Host List data; local DNS is not queried.
              Run `qid QID --ignore ...` only after reviewing the preflight.
              Use `qid --help` or `qid ?` to show this help.

            manual:
              Open directly with: qid --man
              From a source checkout: man ./man/qualys-qid-vulnerabilities.1
              Default install: man -l ~/.local/share/qualys-qid-vulnerabilities/man/qualys-qid-vulnerabilities.1
            """
        ).strip(),
    )
    parser.add_argument(
        "qid",
        metavar="QID",
        type=_positive_qid,
        help="Positive Qualys QID to retrieve",
    )

    selector = parser.add_argument_group("target scope (choose at most one)")
    selector = selector.add_mutually_exclusive_group()
    selector.add_argument(
        "--ips",
        type=_ip_filter,
        metavar="IP_FILTER",
        help="IPv4 addresses/ranges (comma-separated); alias: --ip",
    )
    selector.add_argument(
        "--ip",
        dest="ips",
        type=_ip_filter,
        metavar="IP_FILTER",
        help=argparse.SUPPRESS,
    )
    selector.add_argument(
        "--asset-ids",
        metavar="ASSET_IDS",
        help="Exact Asset IDs (comma-separated); alias: --asset-id",
    )
    selector.add_argument(
        "--asset-id",
        dest="asset_ids",
        metavar="ASSET_IDS",
        help=argparse.SUPPRESS,
    )
    selector.add_argument(
        "--dns-hostnames",
        metavar="HOSTNAMES",
        help=(
            "Exact DNS names/hostnames (comma-separated); aliases: "
            "--dns-hostname, --hostname"
        ),
    )
    selector.add_argument(
        "--dns-hostname",
        dest="dns_hostnames",
        metavar="HOSTNAMES",
        help=argparse.SUPPRESS,
    )
    selector.add_argument(
        "--hostname",
        dest="dns_hostnames",
        metavar="HOSTNAMES",
        help=argparse.SUPPRESS,
    )

    modes = parser.add_argument_group("read-only modes")
    modes.add_argument(
        "--verify-ignored",
        action="store_true",
        help="Include Qualys ignored-state evidence in the results",
    )
    modes.add_argument(
        "--ignored-only",
        action="store_true",
        help="With --verify-ignored, show only currently ignored detections",
    )

    ignore = parser.add_argument_group("ignore workflow (changes Qualys state)")
    ignore.add_argument(
        "--ignore",
        action="store_true",
        help="Submit an ignore request after preflight and confirmation",
    )
    ignore.add_argument(
        "--comment",
        type=_ignore_comment,
        metavar="COMMENT",
        help="Required audit comment for --ignore (max 255 characters)",
    )
    ignore.add_argument(
        "--reopen-after-days",
        type=_reopen_after_days,
        metavar="DAYS",
        help="Reopen after 1-730 days; valid only with --ignore",
    )

    runtime = parser.add_argument_group("configuration and diagnostics")
    runtime.add_argument(
        "--man",
        action="store_true",
        help="Open the bundled manual page",
    )
    runtime.add_argument(
        "--config-file",
        metavar="PATH",
        help="Use an alternate runtime TOML file",
    )
    runtime.add_argument(
        "--env-file",
        metavar="PATH",
        help="Use an alternate local environment file",
    )
    runtime.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Show request and response diagnostics on stderr",
    )
    runtime.add_argument(
        "--log-file",
        metavar="PATH",
        help="Write diagnostics to PATH (rotates at 5 MiB; 3 backups)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["?"]:
        parser.print_help()
        return 0
    if arguments == ["--man"]:
        return _open_manual()
    try:
        args = parser.parse_args(arguments)
    except KeyboardInterrupt:
        print("Interrupted; no Qualys changes were made.", file=sys.stderr)
        return 130
    configure_logging(verbose=args.verbose, log_file=args.log_file)
    mode = (
        "verify-ignored"
        if args.verify_ignored
        else "ignore"
        if args.ignore
        else "lookup"
    )
    LOGGER.info("BEGIN COMMAND | qid=%s | mode=%s", args.qid, mode)
    search = None
    if args.asset_ids or args.dns_hostnames:
        try:
            search = AssetSearch.parse(asset_ids=args.asset_ids, hostnames=args.dns_hostnames)
        except AssetSearchError as exc:
            parser.error(str(exc))
    if args.ignore and args.verify_ignored:
        parser.error("--verify-ignored may not be combined with --ignore")
    if args.ignored_only and not args.verify_ignored:
        parser.error("--ignored-only requires --verify-ignored")
    if args.ignore and args.comment is None:
        parser.error("--comment is required when --ignore is used")
    if args.ignore and not (args.ips or args.asset_ids or args.dns_hostnames):
        parser.error("--ignore requires an explicit IP, Asset ID, or DNS/hostname selector")
    if args.comment is not None and not args.ignore:
        parser.error("--comment may only be used with --ignore")
    if args.reopen_after_days is not None and not args.ignore:
        parser.error("--reopen-after-days may only be used with --ignore")
    # Verbose diagnostics also use stderr. Keep progress as discrete lines so
    # log records cannot be appended to or overwrite the current status line.
    # Let ProgressDisplay detect whether stderr is a terminal. Verbose mode
    # always uses discrete lines so diagnostics cannot overwrite progress.
    progress = ProgressDisplay(interactive=None if not args.verbose else False)
    try:
        with progress.step("Loading and validating runtime configuration"):
            config = AppConfig.load(
                config_file=args.config_file,
                env_file=args.env_file,
            )
            client = QidVulnerabilityClient.from_config(config)
        if search is not None:
            with progress.step("Searching Qualys Host List for selected assets"):
                matched_assets = client.search_assets(search)
            resolved_ips = tuple(asset.ip_address for asset in matched_assets if asset.ip_address)
            if not resolved_ips:
                print("No matching assets with an IP address were returned by Qualys.")
                return 0
            lookup_filter = IpFilter.parse(",".join(resolved_ips))
        else:
            lookup_filter = args.ips
        all_assets = lookup_filter is None
        lookup_description = (
            f"Verifying ignored state for QID {args.qid} in Qualys"
            if args.verify_ignored
            else f"Querying Qualys for QID {args.qid} detections"
        )
        with progress.step(lookup_description):
            if args.verify_ignored:
                listing = client.get_vulnerabilities_for_qid(
                    args.qid,
                    ip_filter=lookup_filter,
                    include_ignored=True,
                )
            else:
                listing = client.get_vulnerabilities_for_qid(
                    args.qid,
                    ip_filter=lookup_filter,
                )
            if args.ignored_only:
                listing = listing.ignored_only()
    except (ConfigurationError, QualysClientError) as exc:
        LOGGER.error("QID command failed: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        LOGGER.warning(
            "COMMAND INTERRUPTED | qid=%s | mode=%s | no Qualys changes were made",
            args.qid,
            mode,
        )
        print("Interrupted; no Qualys changes were made.", file=sys.stderr)
        return 130

    if args.verify_ignored:
        _print_verification(args.qid, lookup_filter, listing)
        return 0

    selector_label = (
        "all assets"
        if all_assets
        else "asset selector"
        if search is not None
        else "IP filter"
    )
    if listing.matched_asset_count == 0:
        if all_assets:
            print(f"No assets with QID {args.qid} detections were returned.")
        else:
            print(f"No assets matched the supplied {selector_label}.")
    elif not listing.vulnerabilities:
        print(
            f"Assets matched the supplied {selector_label}, but QID {args.qid} "
            "was not found."
        )
    else:
        print("Matching vulnerability detections were found.")

    print()
    print(_format_table(listing))
    print()
    if lookup_filter is not None:
        print(f"Total IPs or ranges requested: {lookup_filter.requested_count}")
    else:
        print("Total scope: all assets returned by Qualys")
    print(f"Total assets matched: {listing.matched_asset_count}")
    print(f"Total assets affected: {listing.affected_asset_count}")
    print(f"Total vulnerabilities found: {len(listing.vulnerabilities)}")
    if not args.ignore:
        return 0

    if not listing.vulnerabilities:
        print()
        print("No ignore request sent because no matching detections were found.")
        return 0

    try:
        ignore_requests = create_ignore_request_batches(
            qid=args.qid,
            ip_addresses=tuple(
                record.ip_address for record in listing.vulnerabilities
            ),
            comments=args.comment,
            reopen_ignored_days=args.reopen_after_days,
        )
    except IgnoreRequestError as exc:
        LOGGER.error("Could not prepare ignore request: %s", exc)
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if not _confirm_ignore(ignore_requests):
        print("Ignore cancelled; no Qualys changes were made.", file=sys.stderr)
        return 1

    results: list[IgnoreVulnerabilityResult] = []
    for batch_number, ignore_request in enumerate(ignore_requests, start=1):
        try:
            batch_detail = (
                f" batch {batch_number}/{len(ignore_requests)}"
                if len(ignore_requests) > 1
                else ""
            )
            with progress.step(
                f"Submitting confirmed ignore{batch_detail} for QID {args.qid} "
                "to Qualys"
            ):
                results.append(client.ignore_vulnerabilities(ignore_request))
        except QualysClientError as exc:
            LOGGER.error(
                "Ignore request failed after %d successful batch(es): %s",
                len(results),
                exc,
            )
            print(
                "Error: Ignore outcome is unconfirmed and may have been partially "
                "applied. Verify Qualys before retrying. "
                f"Completed batches: {len(results)}/{len(ignore_requests)}. {exc}",
                file=sys.stderr,
            )
            return 1
        except KeyboardInterrupt:
            LOGGER.warning(
                "COMMAND INTERRUPTED | qid=%s | mode=ignore | ignore outcome "
                "is unconfirmed; verify Qualys before retrying",
                args.qid,
            )
            print(
                "Interrupted; ignore outcome is unconfirmed. Verify Qualys "
                "before retrying.",
                file=sys.stderr,
            )
            return 130

    print()
    if len(results) == 1:
        print(f"Qualys response: {results[0].message}")
    else:
        print(f"Qualys responses: {len(results)} successful batches")
    print(
        "Total asset IPs confirmed ignored: "
        f"{sum(result.affected_ip_count for result in results)}"
    )
    print(
        "Total ignore records returned: "
        f"{sum(len(result.ignored) for result in results)}"
    )
    return 0


def _open_manual() -> int:
    project_root = Path(
        os.environ.get("QID_PROJECT_ROOT", Path(__file__).resolve().parents[2])
    ).expanduser()
    manual = project_root / "man" / "qualys-qid-vulnerabilities.1"
    if not manual.is_file():
        print(f"Error: bundled manual page not found at {manual}", file=sys.stderr)
        return 1
    try:
        result = subprocess.run(["man", "-l", str(manual)], check=False)
    except KeyboardInterrupt:
        print("Interrupted while opening the manual page.", file=sys.stderr)
        return 130
    except OSError as exc:
        print(f"Error: could not open the manual page: {exc}", file=sys.stderr)
        return 1
    return result.returncode


def _positive_qid(value: str) -> int:
    try:
        qid = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("QID must be a positive integer") from exc
    if qid <= 0:
        raise argparse.ArgumentTypeError("QID must be a positive integer")
    return qid


def _ip_filter(value: str) -> IpFilter:
    try:
        return IpFilter.parse(value)
    except IpFilterError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _ignore_comment(value: str) -> str:
    try:
        return validate_ignore_comment(value)
    except IgnoreRequestError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def _reopen_after_days(value: str) -> int:
    try:
        days = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(
            "--reopen-after-days must be an integer from 1 to 730"
        ) from exc
    if not 1 <= days <= 730:
        raise argparse.ArgumentTypeError(
            "--reopen-after-days must be an integer from 1 to 730"
        )
    return days


def _confirm_ignore(requests: tuple[IgnoreVulnerabilityRequest, ...]) -> bool:
    confirmation = f"IGNORE QID {requests[0].qid}"
    target_count = sum(len(request.ip_addresses) for request in requests)
    print()
    print(
        "WARNING: This will change Qualys and may close or create remediation "
        "tickets."
    )
    print(
        f"The write is limited to {target_count} exact matched asset "
        "IP address(es)."
    )
    print(
        f"Qualys API requests required: {len(requests)} "
        "(each limited to 512 characters of exact IPs)."
    )
    if requests[0].reopen_ignored_days is None:
        print("Automatic reopen: not set (ignore remains until restored).")
    else:
        print(
            "Automatic reopen: "
            f"{requests[0].reopen_ignored_days} day(s) after the ignore."
        )
    try:
        response = input(f"Type {confirmation!r} to continue: ")
    except KeyboardInterrupt:
        LOGGER.warning(
            "COMMAND INTERRUPTED | qid=%s | mode=ignore | confirmation "
            "cancelled; no Qualys changes were made",
            requests[0].qid,
        )
        return False
    except EOFError:
        return False
    return response == confirmation


def _format_table(listing: QidVulnerabilityListing) -> str:
    rows = [
        (
            record.asset_id,
            record.ip_address,
            record.dns_hostname or "-",
            str(record.qid),
            record.status,
            record.vulnerability_id or "-",
        )
        for record in listing.vulnerabilities
    ]
    return _format_responsive_table(HEADERS, rows)


def _print_verification(
    qid: int,
    ip_filter: IpFilter | None,
    listing: QidVulnerabilityListing,
) -> None:
    scope_label = "all assets" if ip_filter is None else "the supplied IP filter"
    if listing.matched_asset_count == 0:
        print(
            f"No asset or QID detection was returned for {scope_label}. "
            "This endpoint cannot distinguish an unmatched asset from an asset "
            "with no matching QID when no HOST record is returned."
        )
    elif not listing.vulnerabilities:
        print(
            f"Assets were returned for {scope_label}, but no detection "
            f"for QID {qid} was returned."
        )
    elif listing.confirmed_ignored_asset_count == listing.affected_asset_count:
        print("Every asset with returned QID detections is confirmed ignored.")
    else:
        print(
            "Returned QID detections have mixed or incomplete ignored-state "
            "evidence."
        )

    print()
    print(_format_verification_table(listing))

    if listing.assets_without_requested_qid:
        print()
        print(f"Assets matched with no returned detection for QID {qid}:")
        for asset in listing.assets_without_requested_qid:
            print(
                f"- {asset.asset_id} | {asset.ip_address} | "
                f"{asset.dns_hostname or '-'}"
            )

    if ip_filter is not None:
        print()
        print("Requested IP/range response coverage:")
        returned_ips = tuple(asset.ip_address for asset in listing.matched_assets)
        for entry in ip_filter.entries:
            if any(ip_filter.entry_matches(entry, address) for address in returned_ips):
                outcome = "asset returned"
            else:
                outcome = (
                    "no asset/detection returned; Host Detection cannot establish "
                    "whether no asset matched or the asset had no matching QID"
                )
            print(f"- {entry}: {outcome}")

    print()
    if ip_filter is not None:
        print(f"Total IP addresses or ranges requested: {ip_filter.requested_count}")
    else:
        print("Total scope: all assets returned by Qualys")
    print(f"Total assets matched: {listing.matched_asset_count}")
    print(f"Total assets with the QID: {listing.affected_asset_count}")
    print(
        "Total assets confirmed ignored: "
        f"{listing.confirmed_ignored_asset_count}"
    )
    print(f"Total assets not ignored: {listing.not_ignored_asset_count}")
    print(
        "Total assets with unknown ignore state: "
        f"{listing.unknown_ignore_state_asset_count}"
    )
    print(
        "Total vulnerability detections returned: "
        f"{len(listing.vulnerabilities)}"
    )
    print()
    verification_note = (
        "Verification confirms only the detection-level ignored state returned by",
        "Qualys; this response cannot verify the stored exception comment, ticket",
        "number, or ignore date.",
    )
    print(_format_notification_card(verification_note))


def _format_notification_card(lines: tuple[str, ...]) -> str:
    """Render deliberately split notification text without terminal wrapping."""

    inner_width = max(len("NOTICE"), *(len(line) for line in lines))
    border = "+" + "-" * (inner_width + 4) + "+"
    return "\n".join(
        [border, f"|  {'NOTICE'.ljust(inner_width)}  |"]
        + [f"|  {line.ljust(inner_width)}  |" for line in lines]
        + [border]
    )


def _verification_rows(listing: QidVulnerabilityListing) -> list[tuple[str, ...]]:
    return [
        (
            record.asset_id,
            record.ip_address,
            record.dns_hostname or "-",
            str(record.qid),
            record.status,
            record.ignored_state,
            record.vulnerability_id or "-",
        )
        for record in listing.vulnerabilities
    ]


def _format_verification_table(listing: QidVulnerabilityListing) -> str:
    return _format_responsive_table(VERIFICATION_HEADERS, _verification_rows(listing))


def _terminal_width() -> int:
    return shutil.get_terminal_size((100, 24)).columns


def _colour_cli_value(value: str, colour: str) -> str:
    if sys.stdout.isatty() and not os.environ.get("NO_COLOR"):
        return f"{colour}{value}{_RESET}"
    return value


def _format_responsive_table(
    headers: tuple[str, ...],
    rows: list[tuple[str, ...]],
) -> str:
    """Keep the compact table while wrapping cells to the terminal width."""

    widths = _responsive_column_widths(headers, rows)

    def wrapped_row(row: tuple[str, ...]) -> list[str]:
        cells = [
            textwrap.wrap(
                value,
                width=widths[index],
                break_long_words=True,
                break_on_hyphens=False,
            ) or [""]
            for index, value in enumerate(row)
        ]
        return [
            " | ".join(
                _colour_table_cell(
                    headers[index],
                    cells[index][line].ljust(widths[index])
                    if line < len(cells[index])
                    else " " * widths[index],
                )
                for index in range(len(headers))
            )
            for line in range(max(map(len, cells)))
        ]

    output = ["-+-".join("-" * width for width in widths)]
    output = wrapped_row(headers) + output
    output.extend(line for row in rows for line in wrapped_row(row))
    return "\n".join(output)


def _responsive_column_widths(
    headers: tuple[str, ...],
    rows: list[tuple[str, ...]],
) -> list[int]:
    widths = [
        max(len(header), *(len(row[index]) for row in rows))
        for index, header in enumerate(headers)
    ]
    available = max(20, _terminal_width()) - 3 * (len(headers) - 1)
    # Preserve the useful identifying fields (especially the five-digit QID)
    # while allowing descriptive headers and hostnames to wrap.
    minimums = [8, 10, 9, 5, 10, 10, 10]
    while sum(widths) > available:
        widest = max(
            (index for index, width in enumerate(widths) if width > minimums[index]),
            key=widths.__getitem__,
            default=None,
        )
        if widest is None:
            break
        widths[widest] -= 1
    return widths


def _responsive_table_width(
    headers: tuple[str, ...],
    rows: list[tuple[str, ...]],
) -> int:
    widths = _responsive_column_widths(headers, rows)
    return sum(widths) + 3 * (len(headers) - 1)


def _colour_table_cell(header: str, value: str) -> str:
    if header in {"Status", "Detection Status"}:
        return _colour_cli_value(value, _YELLOW if value.strip() == "New" else _GREEN)
    if header == "Ignored State":
        return _colour_cli_value(
            value, _GREEN if value.strip() == "ignored" else _RED
        )
    return value


if __name__ == "__main__":
    raise SystemExit(main())
