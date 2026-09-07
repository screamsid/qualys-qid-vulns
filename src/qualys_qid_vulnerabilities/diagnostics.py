"""Standalone diagnostic subcommands."""

from __future__ import annotations

import argparse
from importlib import metadata
import os
from pathlib import Path
import shutil
import subprocess
import sys

from . import logging_setup

PACKAGE_NAME = "qualys-qid-vulnerabilities"


def open_manual(*, run=subprocess.run) -> int:
    project_root = Path(os.environ.get("QID_PROJECT_ROOT", Path(__file__).resolve().parents[2])).expanduser()
    relative_manual = Path("man") / "qualys-qid-vulnerabilities.1"
    candidates = (
        project_root / relative_manual,
        Path(sys.prefix) / relative_manual,
        Path(sys.prefix) / "share" / "man" / "man1" / "qualys-qid-vulnerabilities.1",
    )
    manual = next((candidate for candidate in candidates if candidate.is_file()), None)
    if manual is None:
        searched = ", ".join(str(candidate) for candidate in candidates)
        print(f"Error: bundled manual page not found; searched: {searched}", file=sys.stderr)
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


def update(*, arguments: tuple[str, ...] | list[str], run=subprocess.run,
           which=shutil.which, input_fn=input) -> int:
    """Explicitly update a pipx installation through its configured source."""

    parser = argparse.ArgumentParser(
        prog="qid update",
        description="Update a pipx installation from its configured package source.",
    )
    parser.add_argument("--yes", action="store_true", help="Confirm the update without prompting")
    args = parser.parse_args(arguments)
    pipx = which("pipx")
    if pipx is None:
        print("Error: pipx was not found. For a standalone install, rerun install.sh from the source checkout.", file=sys.stderr)
        return 1
    if "pipx" not in Path(sys.prefix).parts:
        print("Error: this is not a pipx installation. Rerun install.sh from the source checkout to update it.", file=sys.stderr)
        return 1
    current = _installed_version()
    if not args.yes:
        try:
            response = input_fn(f"Update {PACKAGE_NAME} (currently {current}) using pipx? [y/N] ")
        except (EOFError, KeyboardInterrupt):
            print("Update cancelled; no changes were made.", file=sys.stderr)
            return 1
        if response.strip().lower() not in {"y", "yes"}:
            print("Update cancelled; no changes were made.", file=sys.stderr)
            return 1
    print(f"Updating {PACKAGE_NAME} (currently {current})...")
    result = run([pipx, "upgrade", PACKAGE_NAME], check=False)
    if result.returncode != 0:
        print("Error: pipx could not update the package. No automatic fallback was attempted.", file=sys.stderr)
        return result.returncode or 1
    updated = _installed_version()
    if updated == current:
        print(f"{PACKAGE_NAME} is already up to date ({updated}).")
    else:
        print(f"Updated {PACKAGE_NAME} from {current} to {updated}.")
    return 0


def _installed_version() -> str:
    try:
        return metadata.version(PACKAGE_NAME)
    except metadata.PackageNotFoundError:
        return "unknown"


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
