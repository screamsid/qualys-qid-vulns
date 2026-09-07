"""Argument parsing and command-line value validation."""

from __future__ import annotations

import argparse
import textwrap

from .asset_search import AssetSearch, AssetSearchError
from .ignore import IgnoreRequestError, validate_ignore_comment
from .ip_filter import IpFilter, IpFilterError


class _HelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Keep option descriptions in one stable column."""

    def __init__(self, prog: str) -> None:
        super().__init__(prog, max_help_position=34)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qid",
        usage="qid [QID] [OPTIONS]",
        formatter_class=_HelpFormatter,
        description=(
            "Look up one QID, or all QIDs for a selected device.\n"
            "Read-only by default; --ignore requires explicit confirmation."
        ),
        epilog=textwrap.dedent(
            """
            examples:
              qid 12345
              qid --ip 192.0.2.10
              qid --asset-id 100001
              qid --hostname "server-one.example.test"
              qid 12345 --ips "192.0.2.10-192.0.2.20"
              qid 12345 --hostname "server-one.example.test" --verify-ignored
              qid 12345 --asset-id 100001 --ignore --comment "Approved exception"
              qid logs
              qid update

            notes:
              Omit QID to list all returned QIDs for a selected device; an
              IP, Asset ID, or DNS/hostname selector is required in that mode.
              Selectors are mutually exclusive. Asset IDs and hostnames are
              matched against Qualys Host List data; local DNS is not queried.
              Run `qid QID --ignore ...` only after reviewing the preflight.
              Use `qid --help` or `qid ?` to show this help.
              Use `qid logs` to display the private command log.
              Use `qid update` to explicitly update a pipx installation;
              standalone installs are updated by rerunning install.sh.

            manual:
              Open directly with: qid --man
              From a source checkout: man ./man/qualys-qid-vulnerabilities.1
              Default install: man -l ~/.local/share/qualys-qid-vulnerabilities/man/qualys-qid-vulnerabilities.1
            """
        ).strip(),
    )
    parser.add_argument("qid", metavar="QID", type=_positive_qid, nargs="?",
                        help="Positive Qualys QID to retrieve; omit to list all QIDs for a selector")
    selector = parser.add_argument_group("target scope (choose at most one)").add_mutually_exclusive_group()
    selector.add_argument("--ips", type=_ip_filter, metavar="IP_FILTER", help="IPv4 addresses/ranges (comma-separated); alias: --ip")
    selector.add_argument("--ip", dest="ips", type=_ip_filter, metavar="IP_FILTER", help=argparse.SUPPRESS)
    selector.add_argument("--asset-ids", metavar="ASSET_IDS", help="Exact Asset IDs (comma-separated); alias: --asset-id")
    selector.add_argument("--asset-id", dest="asset_ids", metavar="ASSET_IDS", help=argparse.SUPPRESS)
    selector.add_argument("--dns-hostnames", metavar="HOSTNAMES", help="Exact DNS names/hostnames (comma-separated); aliases: --dns-hostname, --hostname, --host")
    for alias in ("--dns-hostname", "--hostname", "--host"):
        selector.add_argument(alias, dest="dns_hostnames", metavar="HOSTNAMES", help=argparse.SUPPRESS)
    modes = parser.add_argument_group("read-only modes")
    modes.add_argument("--verify-ignored", action="store_true", help="Include Qualys ignored-state evidence in the results")
    modes.add_argument("--ignored-only", action="store_true", help="With --verify-ignored, show only currently ignored detections")
    ignore = parser.add_argument_group("ignore workflow (changes Qualys state)")
    ignore.add_argument("--ignore", action="store_true", help="Submit an ignore request after preflight and confirmation")
    ignore.add_argument("--comment", type=_ignore_comment, metavar="COMMENT", help="Required audit comment for --ignore (max 255 characters)")
    ignore.add_argument("--reopen-after-days", type=_reopen_after_days, metavar="DAYS", help="Reopen after 1-730 days; valid only with --ignore")
    runtime = parser.add_argument_group("configuration and diagnostics")
    runtime.add_argument("--man", action="store_true", help="Open the bundled manual page")
    runtime.add_argument("--config-file", metavar="PATH", help="Use an alternate runtime TOML file")
    runtime.add_argument("--env-file", metavar="PATH", help="Use an alternate local environment file")
    runtime.add_argument("-v", "--verbose", action="store_true", help="Show request and response diagnostics on stderr")
    runtime.add_argument("--log-file", metavar="PATH", help="Write diagnostics to PATH (rotates at 5 MiB; 3 backups)")
    output = parser.add_argument_group("automation and reporting")
    output.add_argument("--format", choices=("table", "json", "csv"), default="table", help="Output format (default: table)")
    output.add_argument("--output", metavar="PATH", help="Write machine-readable output or evidence to PATH")
    output.add_argument("--evidence-file", metavar="PATH", help="Write a redacted JSON evidence record to PATH")
    output.add_argument("--summary", action="store_true", help="Show grouped counts instead of detailed rows")
    output.add_argument("--group-by", choices=("qid", "status", "asset", "ignored"), help="Group summary rows by this field")
    output.add_argument("--plan", action="store_true", help="Show an ignore plan without prompting or changing Qualys")
    output.add_argument("--verify-after-ignore", action="store_true", help="Verify ignored state after a successful ignore request")
    output.add_argument("--fail-if-found", action="store_true", help="Return exit code 2 when findings are returned")
    output.add_argument("--fail-if-not-ignored", action="store_true", help="Return exit code 2 when any returned detection is not ignored")
    output.add_argument("--stale-after-days", type=_positive_days, metavar="DAYS", help="Flag evidence files older than DAYS when reviewing exported evidence")
    batch = parser.add_argument_group("batch input")
    batch.add_argument("--qids-file", metavar="PATH", help="Read one positive QID per line")
    batch.add_argument("--ips-file", metavar="PATH", help="Read comma-separated IP filters from a file")
    batch.add_argument("--asset-ids-file", metavar="PATH", help="Read comma-separated Asset IDs from a file")
    batch.add_argument("--dns-hostnames-file", metavar="PATH", help="Read comma-separated DNS names/hostnames from a file")
    return parser


def validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> AssetSearch | None:
    search = None
    if args.asset_ids or args.dns_hostnames:
        try:
            search = AssetSearch.parse(asset_ids=args.asset_ids, hostnames=args.dns_hostnames)
        except AssetSearchError as exc:
            parser.error(str(exc))
    if args.qid is None and not (args.ips or args.asset_ids or args.dns_hostnames):
        parser.error("omitting QID requires an explicit IP, Asset ID, or DNS/hostname selector")
    if args.ignore and args.verify_ignored:
        parser.error("--verify-ignored may not be combined with --ignore")
    if args.ignored_only and not args.verify_ignored:
        parser.error("--ignored-only requires --verify-ignored")
    if args.ignore and args.comment is None:
        parser.error("--comment is required when --ignore is used")
    if args.ignore and not (args.ips or args.asset_ids or args.dns_hostnames):
        parser.error("--ignore requires an explicit IP, Asset ID, or DNS/hostname selector")
    if args.ignore and args.qid is None:
        parser.error("--ignore requires a QID")
    if args.comment is not None and not args.ignore:
        parser.error("--comment may only be used with --ignore")
    if args.reopen_after_days is not None and not args.ignore:
        parser.error("--reopen-after-days may only be used with --ignore")
    if args.plan and not args.ignore:
        parser.error("--plan requires --ignore")
    if args.fail_if_not_ignored and not args.verify_ignored:
        parser.error("--fail-if-not-ignored requires --verify-ignored")
    if args.fail_if_found and args.ignore:
        parser.error("--fail-if-found cannot be combined with --ignore")
    if args.group_by and not args.summary:
        parser.error("--group-by requires --summary")
    if args.stale_after_days is not None and not args.evidence_file:
        parser.error("--stale-after-days requires --evidence-file")
    if args.output and args.evidence_file:
        parser.error("--output and --evidence-file may not be combined")
    if args.ignore and args.format != "table" and not args.output:
        parser.error("machine-readable ignore output requires --output PATH")
    file_selectors = [args.ips_file, args.asset_ids_file, args.dns_hostnames_file]
    if sum(value is not None for value in file_selectors) > 1:
        parser.error("batch selector files are mutually exclusive")
    if any(file_selectors) and any((args.ips, args.asset_ids, args.dns_hostnames)):
        parser.error("a batch selector file may not be combined with a selector option")
    if args.qids_file and args.qid is not None:
        parser.error("--qids-file may not be combined with a positional QID")
    if args.qids_file and args.ignore:
        parser.error("--qids-file cannot be used with --ignore; review and ignore one QID at a time")
    return search


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
        raise argparse.ArgumentTypeError("--reopen-after-days must be an integer from 1 to 730") from exc
    if not 1 <= days <= 730:
        raise argparse.ArgumentTypeError("--reopen-after-days must be an integer from 1 to 730")
    return days


def _positive_days(value: str) -> int:
    try:
        days = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("days must be a positive integer") from exc
    if days <= 0:
        raise argparse.ArgumentTypeError("days must be a positive integer")
    return days
