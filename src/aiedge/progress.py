"""Real-time pipeline progress display for SCOUT CLI.

Renders stage-by-stage progress to stderr during pipeline execution.
Supports TTY (colorized, overwriting) and pipe (plain text) modes.
"""

from __future__ import annotations

import os
import sys
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .stage import StageResult

# ---------------------------------------------------------------------------
# ANSI constants (duplicated to avoid circular import with cli_common)
# ---------------------------------------------------------------------------
_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"
_GREEN = "\x1b[32m"
_YELLOW = "\x1b[33m"
_RED = "\x1b[31m"
_CYAN = "\x1b[36m"
_CLEAR_LINE = "\x1b[K"


def _stderr_color_supported() -> bool:
    no_color = os.environ.get("NO_COLOR")
    if no_color:
        return False
    force = os.environ.get("FORCE_COLOR") or os.environ.get("CLICOLOR_FORCE")
    if force and force != "0":
        return True
    if os.environ.get("TERM", "dumb").lower() == "dumb":
        return False
    if os.environ.get("CLICOLOR") == "0":
        return False
    return bool(sys.stderr.isatty())


def _format_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = int(seconds) // 60
    secs = int(seconds) % 60
    if minutes < 60:
        return f"{minutes}m{secs:02d}s"
    hours = minutes // 60
    mins = minutes % 60
    return f"{hours}h{mins:02d}m"


def _dots_pad(name: str, *, width: int = 36) -> str:
    dots_needed = max(2, width - len(name))
    return name + " " + "." * dots_needed


def _color(text: str, code: str, *, enabled: bool) -> str:
    if not enabled:
        return text
    return code + text + _RESET


class ProgressTracker:
    """Tracks and renders pipeline stage progress to stderr.

    Supports two output modes:

    * **idx-ordered** (default): stages are indexed against their position in
      the batch and rendered with a ``[idx/total]`` prefix. Assumes ``on_end``
      is called in strict batch order.
    * **out-of-order** (``out_of_order=True``): stages are rendered in
      completion order without relying on the incoming ``idx`` parameter.
      Used by :func:`aiedge.stage.run_stages_parallel` where the DAG runner
      emits events as threads finish rather than in batch order.
    """

    def __init__(self, *, file: object = None, out_of_order: bool = False) -> None:
        # ``_file`` is a duck-typed text-stream (must support ``write`` /
        # ``flush`` / ``isatty``). Typing as ``Any`` avoids requiring a
        # specific ``IO[str]`` instance while preserving runtime behaviour.
        self._file: Any = file or sys.stderr
        self._is_tty = hasattr(self._file, "isatty") and bool(self._file.isatty())
        self._color = _stderr_color_supported()
        self._batch_label = ""
        self._running = False
        self._out_of_order = bool(out_of_order)
        self._completion_counter = 0
        self._batch_size = 0

    def register_batch(self, label: str, size: int) -> None:
        self._batch_label = label
        self._batch_size = int(size)
        self._completion_counter = 0
        header = f"[SCOUT] {label}: {size} stages"
        if self._color:
            header = (
                f"{_BOLD}{_CYAN}[SCOUT]{_RESET} {label}: {_BOLD}{size}{_RESET} stages"
            )
        self._write(header + "\n")

    def on_start(self, index: int, total: int, name: str) -> None:
        if self._out_of_order:
            # Out-of-order mode does not render a pre-start line; the stage
            # name only appears when it completes so the rendered stream stays
            # monotonic in wall-clock time.
            return
        if self._is_tty:
            idx_str = f"[{index + 1:3d}/{total}]"
            line = f"  {idx_str} {_dots_pad(name)} "
            status = "running..."
            if self._color:
                line = f"  {idx_str} {_color(_dots_pad(name), _CYAN, enabled=True)} "
                status = _color("running...", _BOLD, enabled=True)
            self._write(line + status)
            self._running = True

    def on_end(self, index: int, total: int, name: str, result: "StageResult") -> None:
        status = result.status
        duration = _format_duration(result.duration_s)
        status_display = self._format_status(status)

        if self._out_of_order:
            self._completion_counter += 1
            batch_total = self._batch_size or total
            idx_str = f"[{self._completion_counter:3d}/{batch_total}]"
            line = f"  {idx_str} {name}: {status_display} ({duration})"
            self._write(line + "\n")
            if status == "failed" and result.error:
                reason = _color(
                    f"         -> {result.error}", _RED, enabled=self._color
                )
                self._write(reason + "\n")
            elif status == "failed" and result.limitations:
                reason = _color(
                    f"         -> {result.limitations[0]}",
                    _RED,
                    enabled=self._color,
                )
                self._write(reason + "\n")
            return

        idx_str = f"[{index + 1:3d}/{total}]"

        if self._is_tty and self._running:
            self._write("\r" + _CLEAR_LINE if self._color else "\r")
            self._running = False

        if self._is_tty:
            line = f"  {idx_str} {_dots_pad(name)} {status_display:8s} ({duration})"
        else:
            line = f"  {idx_str} {name}: {status} ({duration})"

        self._write(line + "\n")

        # Print failure reason
        if status == "failed" and result.error:
            reason = _color(f"         -> {result.error}", _RED, enabled=self._color)
            self._write(reason + "\n")
        elif status == "failed" and result.limitations:
            reason = _color(
                f"         -> {result.limitations[0]}", _RED, enabled=self._color
            )
            self._write(reason + "\n")

    def _format_status(self, status: str) -> str:
        color_map = {
            "ok": _GREEN,
            "partial": _YELLOW,
            "failed": _RED,
            "skipped": _DIM,
        }
        code = color_map.get(status, "")
        if self._color and code:
            return code + status + _RESET
        return status

    def _write(self, text: str) -> None:
        try:
            self._file.write(text)
            self._file.flush()
        except OSError:
            pass
