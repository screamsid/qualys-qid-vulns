"""Thin command-line entry point for QID discovery and ignores."""

from __future__ import annotations

import logging
import subprocess
import sys
from collections.abc import Sequence

from . import logging_setup
from .client import QidVulnerabilityClient
from .commands import _ip_in_filter, confirm_ignore, run
from .config import AppConfig
from .diagnostics import open_manual, show_logs
from .ignore import IgnoreVulnerabilityRequest
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
    # Validation remains before configuration loading or any Qualys request.
    args.asset_search = validate_args(parser, args)
    from .logging_setup import configure_logging
    configure_logging(verbose=args.verbose, log_file=args.log_file)
    return run(
        args,
        parser=parser,
        config_loader=AppConfig.load,
        client_factory=QidVulnerabilityClient.from_config,
        confirmation=_confirm_ignore,
    )


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
