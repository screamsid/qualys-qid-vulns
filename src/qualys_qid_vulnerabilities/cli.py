"""Thin command-line entry point for QID discovery and ignores."""

from __future__ import annotations

import logging
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

from . import logging_setup
from .client import QidVulnerabilityClient
from .commands import _ip_in_filter, confirm_ignore, run
from .config import AppConfig
from .diagnostics import open_manual, show_logs
from .ignore import IgnoreVulnerabilityRequest
from .ip_filter import IpFilter
from .output import (
    HEADERS,
    VERIFICATION_HEADERS,
    colour_cli_value,
    colour_table_cell,
    format_notification_card,
    format_responsive_table,
    format_table,
    format_verification_table,
    print_verification,
    responsive_column_widths,
    responsive_table_width,
    safe_log_output,
    safe_output,
    terminal_width,
)
from .parser import build_parser, validate_args

LOGGER = logging.getLogger("qualys_qid_vulnerabilities.cli")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["?"]:
        parser.print_help()
        return 0
    if arguments == ["--man"]:
        return open_manual(run=subprocess.run)
    if arguments and arguments[0] == "logs":
        return show_logs(arguments[1:])
    try:
        args = parser.parse_args(arguments)
    except KeyboardInterrupt:
        print("Interrupted; no Qualys changes were made.", file=sys.stderr)
        return 130
    try:
        _load_batch_files(args, parser)
    except ValueError as exc:
        parser.error(str(exc))
    # Validation remains before configuration loading or any Qualys request.
    args.asset_search = validate_args(parser, args)
    from .logging_setup import configure_logging
    configure_logging(verbose=args.verbose, log_file=args.log_file)
    qids = _read_qids(args.qids_file) if args.qids_file else [args.qid]
    if len(qids) > 1 and (args.output or args.evidence_file or args.format != "table"):
        parser.error("multiple QIDs require the default table format and cannot use --output/--evidence-file")
    result = 0
    for qid in qids:
        args.qid = qid
        result = max(result, run(
            args,
            parser=parser,
            config_loader=AppConfig.load,
            client_factory=QidVulnerabilityClient.from_config,
            confirmation=_confirm_ignore,
        ))
    return result


def _read_lines(path: str) -> list[str]:
    try:
        lines = Path(path).expanduser().read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"cannot read batch file {path!r}: {exc}") from exc
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def _read_qids(path: str) -> list[int]:
    qids: list[int] = []
    for line in _read_lines(path):
        try:
            qid = int(line)
        except ValueError as exc:
            raise ValueError(f"invalid QID in {path!r}: {line!r}") from exc
        if qid <= 0:
            raise ValueError(f"invalid positive QID in {path!r}: {line!r}")
        qids.append(qid)
    if not qids:
        raise ValueError(f"batch file {path!r} did not contain any QIDs")
    return qids


def _load_batch_files(args, parser) -> None:
    if args.ips_file:
        values = _read_lines(args.ips_file)
        if not values:
            raise ValueError(f"batch file {args.ips_file!r} did not contain an IP filter")
        try:
            args.ips = IpFilter.parse(",".join(values))
        except ValueError as exc:
            raise ValueError(f"invalid IP filter in {args.ips_file!r}: {exc}") from exc
    if args.asset_ids_file:
        values = _read_lines(args.asset_ids_file)
        if not values:
            raise ValueError(f"batch file {args.asset_ids_file!r} did not contain Asset IDs")
        args.asset_ids = ",".join(values)
    if args.dns_hostnames_file:
        values = _read_lines(args.dns_hostnames_file)
        if not values:
            raise ValueError(f"batch file {args.dns_hostnames_file!r} did not contain hostnames")


# Backwards-compatible private names used by the existing test suite and by
# small operator scripts. New code should import these from their modules.
_confirm_ignore = confirm_ignore
_format_table = format_table
_print_verification = print_verification
_format_notification_card = format_notification_card
_format_verification_table = format_verification_table
_terminal_width = terminal_width
_colour_cli_value = colour_cli_value
_format_responsive_table = format_responsive_table
_responsive_column_widths = responsive_column_widths
_responsive_table_width = responsive_table_width
_colour_table_cell = colour_table_cell
_safe_output = safe_output
_safe_log_output = safe_log_output
_ip_in_filter = _ip_in_filter


if __name__ == "__main__":
    raise SystemExit(main())
