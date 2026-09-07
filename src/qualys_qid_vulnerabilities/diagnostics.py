"""Standalone diagnostic subcommands."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

from . import logging_setup


def open_manual(*, run=subprocess.run) -> int:
    project_root = Path(os.environ.get("QID_PROJECT_ROOT", Path(__file__).resolve().parents[2])).expanduser()
    manual = project_root / "man" / "qualys-qid-vulnerabilities.1"
    if not manual.is_file():
        print(f"Error: bundled manual page not found at {manual}", file=sys.stderr)
        return 1
    try:
        result = run(["man", "-l", str(manual)], check=False)
    except KeyboardInterrupt:
        print("Interrupted while opening the manual page.", file=sys.stderr)
        return 130
    except OSError as exc:
        print(f"Error: could not open the manual page: {exc}", file=sys.stderr)
        return 1
    return result.returncode


def show_logs(arguments: tuple[str, ...] | list[str]) -> int:
    parser = argparse.ArgumentParser(prog="qid logs", description="Display the QID command log.")
    parser.add_argument("--log-file", metavar="PATH", help="Display PATH instead of the default private log")
    args = parser.parse_args(arguments)
    log_path = Path(args.log_file).expanduser() if args.log_file else logging_setup.DEFAULT_LOG_FILE
    try:
        contents = log_path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"Error: could not read log file {log_path}: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(_safe_log_output(contents))
    if contents and not contents.endswith("\n"):
        sys.stdout.write("\n")
    return 0


def _safe_log_output(value: str) -> str:
    return "".join(char if char in "\n\t" or ord(char) >= 32 else f"\\x{ord(char):02x}" for char in value).replace("\r", "\\x0d")
