"""Small dependency-free elapsed-time progress display for the operator CLI."""

from __future__ import annotations

from contextlib import contextmanager
import sys
from threading import Event, Thread
import time
from typing import Iterator, TextIO


class ProgressDisplay:
    """Show the current operation, refreshing its elapsed time on terminals."""

    def __init__(
        self,
        *,
        stream: TextIO | None = None,
        refresh_seconds: float = 0.2,
        interactive: bool | None = None,
    ) -> None:
        self._stream = stream or sys.stderr
        self._refresh_seconds = refresh_seconds
        self._interactive = interactive

    @contextmanager
    def step(self, description: str) -> Iterator[None]:
        """Display one safe, operator-facing operation until it completes."""

        started = time.monotonic()
        stopped = Event()
        interactive = (
            self._stream.isatty()
            if self._interactive is None
            else self._interactive
        )
        self._write_status(description, started, interactive=interactive)
        refresher: Thread | None = None
        if interactive:
            refresher = Thread(
                target=self._refresh,
                args=(description, started, stopped),
                daemon=True,
            )
            refresher.start()

        outcome = "done"
        try:
            yield
        except BaseException:
            outcome = "failed"
            raise
        finally:
            stopped.set()
            if refresher is not None:
                refresher.join()
            elapsed = time.monotonic() - started
            if interactive:
                self._stream.write("\r\033[2K")
            self._stream.write(
                f"[{_format_elapsed(elapsed)}] {outcome}: {description}\n"
            )
            self._stream.flush()

    def _refresh(self, description: str, started: float, stopped: Event) -> None:
        while not stopped.wait(self._refresh_seconds):
            self._write_status(description, started, interactive=True)

    def _write_status(
        self,
        description: str,
        started: float,
        *,
        interactive: bool,
    ) -> None:
        prefix = "\r\033[2K" if interactive else ""
        suffix = "" if interactive else "\n"
        elapsed = time.monotonic() - started
        self._stream.write(
            f"{prefix}[{_format_elapsed(elapsed)}] {description}...{suffix}"
        )
        self._stream.flush()


def _format_elapsed(elapsed_seconds: float) -> str:
    total_seconds = max(0, int(elapsed_seconds))
    minutes, seconds = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    if hours:
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    return f"{minutes:02d}:{seconds:02d}"
