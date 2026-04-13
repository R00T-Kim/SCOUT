"""TUI entry points: interactive and non-interactive dashboard modes."""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any, cast

from .cli_common import _tui_ansi_supported
from .cli_tui_data import _build_tui_snapshot
from .cli_tui_render import (
    _build_tui_color_theme,
    _build_tui_snapshot_lines,
    _draw_interactive_tui_frame,
)


def _run_tui_interactive(*, run_dir: Path, limit: int, interval_s: float) -> int:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Interactive mode requires a TTY (stdin/stdout).", file=sys.stderr)
        return 20

    try:
        import curses
    except Exception as e:
        print(f"Interactive mode unavailable: {e}", file=sys.stderr)
        return 20

    refresh_interval = max(0.3, float(interval_s))

    def _curses_main(stdscr: object) -> int:
        # ``curses._CursesWindow`` is a private attribute that pyright
        # cannot resolve; fall back to ``Any`` to preserve runtime duck
        # typing without exposing the private name.
        win = cast(Any, stdscr)
        win.nodelay(True)
        win.keypad(True)
        try:
            curses.curs_set(0)
        except Exception:
            pass
        theme = _build_tui_color_theme(curses_mod=curses)

        selected_index = 0
        detail_mode = "candidate"
        snapshot = _build_tui_snapshot(run_dir=run_dir)
        last_refresh = time.monotonic()
        force_refresh = False

        while True:
            now = time.monotonic()
            if force_refresh or (now - last_refresh) >= refresh_interval:
                snapshot = _build_tui_snapshot(run_dir=run_dir)
                candidate_groups_now = cast(
                    list[dict[str, object]], snapshot.get("candidate_groups", [])
                )
                if candidate_groups_now:
                    selected_index = min(
                        selected_index, min(limit, len(candidate_groups_now)) - 1
                    )
                else:
                    selected_index = 0
                last_refresh = now
                force_refresh = False

            candidates = cast(list[dict[str, object]], snapshot.get("candidates", []))
            candidate_groups = cast(
                list[dict[str, object]], snapshot.get("candidate_groups", [])
            )
            _draw_interactive_tui_frame(
                stdscr=win,
                run_dir=run_dir,
                snapshot=snapshot,
                candidates=candidates,
                candidate_groups=candidate_groups,
                selected_index=selected_index,
                list_limit=limit,
                detail_mode=detail_mode,
                theme=theme,
            )

            key = win.getch()
            if key == -1:
                time.sleep(0.05)
                continue
            if key in (ord("q"), ord("Q")):
                return 0
            selectable_count = min(limit, len(candidate_groups))
            if key in (ord("j"), curses.KEY_DOWN):
                if candidate_groups and selectable_count > 0:
                    selected_index = min(selected_index + 1, selectable_count - 1)
                continue
            if key in (ord("k"), curses.KEY_UP):
                if candidate_groups:
                    selected_index = max(0, selected_index - 1)
                continue
            if key in (ord("g"),):
                selected_index = 0
                continue
            if key in (ord("G"),):
                if candidate_groups:
                    selected_index = selectable_count - 1
                continue
            if key in (ord("r"), ord("R")):
                force_refresh = True
                continue
            if key in (ord("t"), ord("T")):
                detail_mode = "threat"
                continue
            if key in (ord("m"), ord("M")):
                detail_mode = "runtime"
                continue
            if key in (ord("a"), ord("A")):
                detail_mode = "asset"
                continue
            if key in (ord("c"), ord("C")):
                detail_mode = "candidate"
                continue

    try:
        return int(curses.wrapper(_curses_main))
    except KeyboardInterrupt:
        print("")
        return 0


def _run_tui(
    *,
    run_dir_path: str,
    limit: int,
    mode: str,
    interval_s: float,
    # kept for compatibility with old CLI usage; mode is authoritative.
    watch: bool,
    interactive: bool,
) -> int:
    run_dir = Path(run_dir_path).expanduser().resolve()
    if not run_dir.is_dir():
        print(f"Run directory not found: {run_dir}", file=sys.stderr)
        return 20
    if limit <= 0:
        print("Invalid --limit value: must be > 0", file=sys.stderr)
        return 20
    if interval_s <= 0:
        print("Invalid --interval-s value: must be > 0", file=sys.stderr)
        return 20
    effective_mode = mode
    if interactive and watch:
        print(
            "Invalid flags: --interactive and --watch cannot be combined",
            file=sys.stderr,
        )
        return 20
    if interactive:
        effective_mode = "interactive"
    elif watch:
        effective_mode = "watch"
    elif mode not in ("auto", "once", "watch", "interactive"):
        print("Invalid --mode value", file=sys.stderr)
        return 20

    if effective_mode == "auto":
        effective_mode = (
            "interactive" if sys.stdin.isatty() and sys.stdout.isatty() else "once"
        )

    if effective_mode == "interactive":
        return _run_tui_interactive(run_dir=run_dir, limit=limit, interval_s=interval_s)

    supports_ansi = _tui_ansi_supported()

    def render_once() -> int:
        lines = _build_tui_snapshot_lines(run_dir=run_dir, limit=limit)
        print("\n".join(lines))
        return 0

    if effective_mode != "watch":
        return render_once()

    watch_clear = bool(
        supports_ansi
        and sys.stdout.isatty()
        and os.environ.get("TERM", "dumb").lower() != "dumb"
    )
    last_snapshot: str | None = None

    try:
        while True:
            lines = _build_tui_snapshot_lines(run_dir=run_dir, limit=limit)
            snapshot = "\n".join(lines)
            if snapshot != last_snapshot:
                if watch_clear:
                    # ANSI clear+home for lightweight terminal dashboard refresh.
                    print("\x1b[2J\x1b[H" + snapshot, end="", flush=True)
                else:
                    if last_snapshot is not None:
                        print("\n" + ("-" * 88))
                    print(snapshot, flush=True)
                last_snapshot = snapshot
            time.sleep(float(interval_s))
    except KeyboardInterrupt:
        print("")
        return 0
