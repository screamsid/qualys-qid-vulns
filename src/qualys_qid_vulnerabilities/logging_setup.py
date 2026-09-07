"""Bounded, operator-friendly logging for the QID command."""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import shutil
import sys
import textwrap


LOGGER_NAME = "qualys_qid_vulnerabilities"
MAX_LOG_BYTES = 5 * 1024 * 1024
LOG_BACKUP_COUNT = 3
PROJECT_ROOT = Path(
    os.environ.get("QID_PROJECT_ROOT", Path(__file__).resolve().parents[2])
).expanduser().resolve()
DEFAULT_LOG_DIR = PROJECT_ROOT / "logs"
DEFAULT_LOG_FILE = DEFAULT_LOG_DIR / "qid.log"
_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"
_RESET = "\033[0m"
_LEVEL_COLOURS = {
    logging.DEBUG: "\033[2m",
    logging.INFO: "\033[36m",
    logging.WARNING: "\033[33m",
    logging.ERROR: "\033[31m",
    logging.CRITICAL: "\033[1;31m",
}


class TerminalFormatter(logging.Formatter):
    """Colour and wrap diagnostic records for a terminal without ANSI in files."""

    def __init__(self, *, colour: bool, width: int, compact_logger: bool = False) -> None:
        super().__init__(_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
        self._colour = colour
        # Honour the actual terminal width. A minimum of 1 keeps the
        # formatter safe for unusual or mocked terminal-size values.
        self._width = max(1, width)
        self._compact_logger = compact_logger

    def format(self, record: logging.LogRecord) -> str:
        logger_name = (
            record.name.rsplit(".", 1)[-1]
            if self._compact_logger
            else record.name
        )
        prefix = (
            f"{self.formatTime(record, self.datefmt)} "
            f"{record.levelname:<8} {logger_name}: "
        )
        message = record.getMessage()
        if record.exc_info:
            message = f"{message}\n{self.formatException(record.exc_info)}"
        wrapped = textwrap.wrap(
            message,
            width=self._width,
            initial_indent=prefix,
            subsequent_indent=" " * len(prefix),
            break_long_words=True,
            break_on_hyphens=False,
        ) or [prefix]
        output = "\n".join(wrapped)
        if not self._colour:
            return output
        colour = _LEVEL_COLOURS.get(record.levelno, "")
        return f"{colour}{output}{_RESET}" if colour else output


class FileFormatter(logging.Formatter):
    """Keep records compact and separate each command invocation visibly."""

    def format(self, record: logging.LogRecord) -> str:
        timestamp = self.formatTime(record, "%Y-%m-%d %H:%M:%S")
        level = record.levelname
        component = record.name.rsplit(".", 1)[-1]
        message = record.getMessage()
        if record.exc_info:
            message = f"{message}\n{self.formatException(record.exc_info)}"
        # A traceback is useful in the file, but embedded newlines in a
        # record should not make the next record look like a new event.
        message = message.replace("\n", "\\n")
        line = f"{timestamp} | {level:<8} | {component:<9} | {message}"
        return f"\n{line}" if message.startswith("BEGIN COMMAND |") else line

def _default_log_file() -> Path:
    """Return the project log path independently of the current directory."""

    return DEFAULT_LOG_FILE


def configure_logging(*, verbose: bool = False, log_file: str | None = None) -> logging.Logger:
    """Configure readable stderr logging and a bounded rotating log file.

    Request bodies and credentials are deliberately never logged by the
    application. A private project-local log is enabled for every invocation;
    ``log_file`` overrides that location. Reconfiguration is supported because
    tests and embedding callers may invoke the CLI more than once in one process.
    """

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()

    terminal = sys.stderr.isatty() and not os.environ.get("NO_COLOR")
    terminal_formatter = TerminalFormatter(
        colour=terminal,
        width=shutil.get_terminal_size((100, 24)).columns,
        compact_logger=terminal,
    )
    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.setFormatter(terminal_formatter)
    logger.addHandler(console)

    log_path = Path(log_file).expanduser() if log_file else _default_log_file()
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=MAX_LOG_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        os.chmod(log_path, 0o600)
    except OSError as exc:
        logger.warning("Could not open log file %s: %s", log_path, exc)
    else:
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(FileFormatter())
        logger.addHandler(file_handler)

    return logger
