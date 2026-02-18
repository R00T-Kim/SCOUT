"""Module entrypoint.

Allows: python -m aiedge
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import importlib
import json
import os
import sys
import textwrap
import time
from collections.abc import Sequence
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from types import ModuleType
from typing import Callable, Protocol, cast

from . import __version__
from .corpus import (
    CorpusValidationError,
    corpus_summary,
    format_summary,
    load_corpus_manifest,
)
from .codex_probe import resolve_llm_gate_input
from .quality_metrics import (
    QualityMetricsError,
    build_quality_delta_report,
    evaluate_quality_metrics_harness,
    format_quality_metrics,
    write_quality_metrics,
)
from .quality_policy import (
    QUALITY_GATE_INVALID_METRICS,
    QUALITY_GATE_INVALID_REPORT,
    QUALITY_GATE_LLM_REQUIRED,
    QualityGateError,
    evaluate_quality_gate,
    format_quality_gate,
    load_json_object,
    write_quality_gate,
)
from .schema import JsonValue


class _RunInfo(Protocol):
    run_dir: Path


class _RunReport(Protocol):
    status: str


_CANONICAL_8MB_SHA256 = (
    "387d97fd925125471691d5c565fcc0ff009e111bdbdfd2ddb057f9212a939c8a"
)
_CANONICAL_8MB_SIZE_BYTES = 8_388_608


def _serve_report_directory(
    *,
    run_dir_path: str,
    host: str,
    port: int,
    once: bool,
    duration_s: float | None,
) -> int:
    run_dir = Path(run_dir_path).expanduser().resolve()
    report_dir = run_dir / "report"
    viewer_path = report_dir / "viewer.html"

    if not run_dir.is_dir():
        print(f"Run directory not found: {run_dir}", file=sys.stderr)
        return 20
    if not report_dir.is_dir():
        print(f"Report directory not found: {report_dir}", file=sys.stderr)
        return 20
    if not viewer_path.is_file():
        print(
            f"Viewer file not found: {viewer_path} (run analyze first)",
            file=sys.stderr,
        )
        return 20

    if port < 0 or port > 65535:
        print("Invalid --port value: must be in range 0..65535", file=sys.stderr)
        return 20

    if duration_s is not None and duration_s <= 0:
        print("Invalid --duration-s value: must be > 0", file=sys.stderr)
        return 20

    handler = functools.partial(SimpleHTTPRequestHandler, directory=str(report_dir))
    try:
        httpd = HTTPServer((host, int(port)), handler)
    except OSError as e:
        print(f"Failed to start report server: {e}", file=sys.stderr)
        return 20

    with httpd:
        bound_host = cast(str, httpd.server_address[0])
        bound_port = int(httpd.server_address[1])
        print(
            f"http://{bound_host}:{bound_port}/viewer.html",
            flush=True,
        )
        try:
            if once:
                httpd.handle_request()
                return 0
            if duration_s is not None:
                deadline = time.monotonic() + float(duration_s)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0.0:
                        break
                    httpd.timeout = min(1.0, max(0.05, remaining))
                    httpd.handle_request()
                return 0
            httpd.serve_forever()
        except KeyboardInterrupt:
            return 0

    return 0


def _safe_load_json_object(path: Path) -> dict[str, object]:
    if not path.is_file():
        return {}
    try:
        obj_any = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception:
        return {}
    if not isinstance(obj_any, dict):
        return {}
    return cast(dict[str, object], obj_any)


def _as_int(value: object, *, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return int(value)
    return default


def _as_float(value: object, *, default: float = 0.0) -> float:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return float(value)
    return default


def _short_text(value: object, *, max_len: int = 96) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    if len(text) <= max_len:
        return text
    if max_len <= 3:
        return text[:max_len]
    return text[: max_len - 3] + "..."


def _short_path(value: object, *, max_len: int = 120) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    if len(text) <= max_len:
        return text
    if max_len <= 7:
        return text[:max_len]
    keep = max_len - 3
    head = int(keep * 0.55)
    tail = keep - head
    return text[:head] + "..." + text[-tail:]


def _path_tail(value: object, *, max_segments: int = 4, max_len: int = 84) -> str:
    if not isinstance(value, str):
        return ""
    text = " ".join(value.split())
    if not text:
        return ""
    parts = [p for p in text.split("/") if p]
    if not parts:
        return _short_path(text, max_len=max_len)
    tail = "/".join(parts[-max_segments:])
    if len(parts) > max_segments:
        tail = ".../" + tail
    return _short_path(tail, max_len=max_len)


def _count_bar(label: str, *, count: int, max_count: int, width: int = 24) -> str:
    if width <= 0:
        width = 24
    denom = max(1, max_count)
    filled = int(round((max(0, count) / float(denom)) * float(width)))
    filled = max(0, min(width, filled))
    bar = ("#" * filled) + ("-" * (width - filled))
    return f"{label:<6} |{bar}| {count}"


def _build_tui_snapshot(*, run_dir: Path) -> dict[str, object]:
    manifest = _safe_load_json_object(run_dir / "manifest.json")
    report = _safe_load_json_object(run_dir / "report" / "report.json")
    digest = _safe_load_json_object(run_dir / "report" / "analyst_digest.json")
    candidates_payload = _safe_load_json_object(
        run_dir / "stages" / "findings" / "exploit_candidates.json"
    )

    profile_any = manifest.get("profile")
    profile = profile_any if isinstance(profile_any, str) and profile_any else "unknown"

    report_completeness_any = report.get("report_completeness")
    report_completeness = (
        cast(dict[str, object], report_completeness_any)
        if isinstance(report_completeness_any, dict)
        else {}
    )
    report_status = _short_text(report_completeness.get("status")) or "unknown"
    gate_passed = report_completeness.get("gate_passed")
    gate_passed_text = (
        "true" if gate_passed is True else "false" if gate_passed is False else "unknown"
    )

    llm_any = report.get("llm")
    llm = cast(dict[str, object], llm_any) if isinstance(llm_any, dict) else {}
    llm_status = _short_text(llm.get("status")) or "unknown"

    verdict_any = digest.get("exploitability_verdict")
    verdict = (
        cast(dict[str, object], verdict_any) if isinstance(verdict_any, dict) else {}
    )
    verdict_state = _short_text(verdict.get("state")) or "unknown"
    reason_codes_any = verdict.get("reason_codes")
    reason_codes = (
        [x for x in cast(list[object], reason_codes_any) if isinstance(x, str)]
        if isinstance(reason_codes_any, list)
        else []
    )

    summary_any = candidates_payload.get("summary")
    summary = cast(dict[str, object], summary_any) if isinstance(summary_any, dict) else {}
    high = _as_int(summary.get("high"))
    medium = _as_int(summary.get("medium"))
    low = _as_int(summary.get("low"))
    chain_backed = _as_int(summary.get("chain_backed"))
    candidate_count = _as_int(summary.get("candidate_count"))
    max_bucket = max(high, medium, low, 1)

    candidates_any = candidates_payload.get("candidates")
    candidates = (
        cast(list[dict[str, object]], candidates_any)
        if isinstance(candidates_any, list)
        else []
    )

    return {
        "profile": profile,
        "report_status": report_status,
        "gate_passed_text": gate_passed_text,
        "llm_status": llm_status,
        "verdict_state": verdict_state,
        "reason_codes": reason_codes,
        "schema_version": _short_text(candidates_payload.get("schema_version")) or "unknown",
        "high": high,
        "medium": medium,
        "low": low,
        "chain_backed": chain_backed,
        "candidate_count": candidate_count,
        "max_bucket": max_bucket,
        "candidates": candidates,
    }


def _build_tui_snapshot_lines(*, run_dir: Path, limit: int) -> list[str]:
    snapshot = _build_tui_snapshot(run_dir=run_dir)
    profile = _short_text(snapshot.get("profile"), max_len=40) or "unknown"
    report_status = _short_text(snapshot.get("report_status"), max_len=40) or "unknown"
    gate_passed_text = (
        _short_text(snapshot.get("gate_passed_text"), max_len=16) or "unknown"
    )
    llm_status = _short_text(snapshot.get("llm_status"), max_len=40) or "unknown"
    verdict_state = _short_text(snapshot.get("verdict_state"), max_len=48) or "unknown"
    reason_codes = cast(list[str], snapshot.get("reason_codes", []))
    candidate_count = _as_int(snapshot.get("candidate_count"))
    chain_backed = _as_int(snapshot.get("chain_backed"))
    high = _as_int(snapshot.get("high"))
    medium = _as_int(snapshot.get("medium"))
    low = _as_int(snapshot.get("low"))
    max_bucket = _as_int(snapshot.get("max_bucket"), default=1)
    schema_version = _short_text(snapshot.get("schema_version"), max_len=48) or "unknown"

    lines: list[str] = []
    lines.append(f"AIEdge TUI :: {run_dir}")
    lines.append("=" * 88)
    lines.append(
        f"profile={profile} | report_completeness={report_status} (gate_passed={gate_passed_text}) | llm={llm_status}"
    )
    lines.append(f"verdict={verdict_state}")
    if reason_codes:
        lines.append("reason_codes=" + ", ".join(reason_codes[:5]))
    lines.append("")
    lines.append("Exploit Candidate Map")
    lines.append("-" * 88)
    lines.append(
        f"candidate_count={candidate_count} | chain_backed={chain_backed} | schema={schema_version}"
    )
    lines.append(_count_bar("HIGH", count=high, max_count=max_bucket))
    lines.append(_count_bar("MEDIUM", count=medium, max_count=max_bucket))
    lines.append(_count_bar("LOW", count=low, max_count=max_bucket))

    candidates = cast(list[dict[str, object]], snapshot.get("candidates", []))
    if not candidates:
        lines.append("")
        lines.append("(no candidates)")
        return lines

    lines.append("")
    lines.append(f"Top {min(limit, len(candidates))} candidate(s) [compact]")
    lines.append("-" * 88)
    hypothesis_groups: dict[
        tuple[str, str, str, str],
        dict[str, object],
    ] = {}
    for idx, item in enumerate(candidates[:limit], start=1):
        pr = _short_text(item.get("priority"), max_len=16) or "unknown"
        pr_tag = pr[:1].upper() if pr else "?"
        source = _short_text(item.get("source"), max_len=16) or "unknown"
        score = _as_float(item.get("score"))
        path = _path_tail(item.get("path"), max_segments=5, max_len=72) or "(none)"
        families_any = item.get("families")
        families = (
            [x for x in cast(list[object], families_any) if isinstance(x, str)]
            if isinstance(families_any, list)
            else []
        )
        family_text = ",".join(families[:3]) if families else "unknown"
        hypothesis = _short_text(item.get("attack_hypothesis"), max_len=140)
        impacts_any = item.get("expected_impact")
        impacts = (
            [x for x in cast(list[object], impacts_any) if isinstance(x, str)]
            if isinstance(impacts_any, list)
            else []
        )
        impact = _short_text(impacts[0], max_len=140) if impacts else ""
        plan_any = item.get("validation_plan")
        if isinstance(plan_any, list):
            plans = [x for x in cast(list[object], plan_any) if isinstance(x, str)]
        else:
            fallback_any = item.get("analyst_next_steps")
            plans = (
                [x for x in cast(list[object], fallback_any) if isinstance(x, str)]
                if isinstance(fallback_any, list)
                else []
            )
        next_step = _short_text(plans[0], max_len=140) if plans else ""

        lines.append(
            f"{idx:02d} [{pr_tag}] {score:.3f} {family_text} | {path}"
        )

        group_key = (pr, family_text, hypothesis, impact)
        group = hypothesis_groups.get(group_key)
        if group is None:
            group = {
                "priority": pr,
                "family": family_text,
                "hypothesis": hypothesis,
                "impact": impact,
                "next_step": next_step,
                "source": source,
                "count": 0,
                "sample_paths": [],
                "max_score": score,
            }
            hypothesis_groups[group_key] = group

        group["count"] = _as_int(group.get("count")) + 1
        sample_paths = cast(list[str], group.get("sample_paths"))
        if len(sample_paths) < 3:
            sample_paths.append(path)
        current_max_score = _as_float(group.get("max_score"))
        if score > current_max_score:
            group["max_score"] = score
        if next_step and not _short_text(group.get("next_step")):
            group["next_step"] = next_step

    grouped_items = sorted(
        cast(list[dict[str, object]], list(hypothesis_groups.values())),
        key=lambda g: (-_as_int(g.get("count")), -_as_float(g.get("max_score"))),
    )

    lines.append("")
    lines.append(f"Hypothesis groups: {len(grouped_items)} unique")
    lines.append("-" * 88)
    for idx, group in enumerate(grouped_items[: min(limit, len(grouped_items))], start=1):
        priority = _short_text(group.get("priority"), max_len=12) or "unknown"
        priority_tag = priority[:1].upper() if priority else "?"
        family = _short_text(group.get("family"), max_len=28) or "unknown"
        count = _as_int(group.get("count"))
        max_score = _as_float(group.get("max_score"))
        source = _short_text(group.get("source"), max_len=16) or "unknown"
        lines.append(
            f"G{idx:02d} [{priority_tag}] family={family} source={source} count={count} max_score={max_score:.3f}"
        )
        hypothesis = _short_text(group.get("hypothesis"), max_len=140)
        impact = _short_text(group.get("impact"), max_len=140)
        next_step = _short_text(group.get("next_step"), max_len=140)
        if hypothesis:
            lines.append(f"    attack: {hypothesis}")
        if impact:
            lines.append(f"    impact: {impact}")
        if next_step:
            lines.append(f"    next: {next_step}")
        sample_paths = cast(list[str], group.get("sample_paths"))
        if sample_paths:
            lines.append("    sample_paths:")
            for sample in sample_paths:
                lines.append(f"      - {sample}")

    return lines


def _candidate_family_text(item: dict[str, object]) -> str:
    families_any = item.get("families")
    if isinstance(families_any, list):
        families = [x for x in cast(list[object], families_any) if isinstance(x, str)]
    else:
        families = []
    return ",".join(families[:3]) if families else "unknown"


def _candidate_next_step_text(item: dict[str, object]) -> str:
    plan_any = item.get("validation_plan")
    plans = (
        [x for x in cast(list[object], plan_any) if isinstance(x, str)]
        if isinstance(plan_any, list)
        else []
    )
    if not plans:
        fallback_any = item.get("analyst_next_steps")
        plans = (
            [x for x in cast(list[object], fallback_any) if isinstance(x, str)]
            if isinstance(fallback_any, list)
            else []
        )
    return _short_text(plans[0], max_len=220) if plans else ""


def _safe_curses_addstr(
    window: object,
    *,
    y: int,
    x: int,
    text: str,
    attr: int = 0,
) -> None:
    win = cast("curses._CursesWindow", window)
    max_y, max_x = win.getmaxyx()
    if y < 0 or y >= max_y or x >= max_x:
        return
    allowed = max(0, max_x - x - 1)
    if allowed <= 0:
        return
    snippet = text[:allowed]
    try:
        if attr:
            win.addstr(y, x, snippet, attr)
        else:
            win.addstr(y, x, snippet)
    except Exception:
        return


def _draw_interactive_tui_frame(
    *,
    stdscr: object,
    run_dir: Path,
    snapshot: dict[str, object],
    candidates: list[dict[str, object]],
    selected_index: int,
    list_limit: int,
) -> None:
    import curses

    win = cast("curses._CursesWindow", stdscr)
    win.erase()
    max_y, max_x = win.getmaxyx()
    if max_y < 12 or max_x < 72:
        _safe_curses_addstr(
            win,
            y=0,
            x=0,
            text="Terminal too small (need >=72x12). Resize and retry.",
        )
        win.refresh()
        return

    profile = _short_text(snapshot.get("profile"), max_len=24) or "unknown"
    report_status = _short_text(snapshot.get("report_status"), max_len=20) or "unknown"
    gate_passed_text = (
        _short_text(snapshot.get("gate_passed_text"), max_len=16) or "unknown"
    )
    llm_status = _short_text(snapshot.get("llm_status"), max_len=20) or "unknown"
    verdict_state = _short_text(snapshot.get("verdict_state"), max_len=40) or "unknown"
    reason_codes = cast(list[str], snapshot.get("reason_codes", []))
    high = _as_int(snapshot.get("high"))
    medium = _as_int(snapshot.get("medium"))
    low = _as_int(snapshot.get("low"))
    chain_backed = _as_int(snapshot.get("chain_backed"))
    candidate_count = _as_int(snapshot.get("candidate_count"))

    _safe_curses_addstr(win, y=0, x=0, text=f"AIEdge Interactive TUI :: {run_dir.name}")
    _safe_curses_addstr(
        win,
        y=1,
        x=0,
        text=(
            f"profile={profile} | report={report_status}(gate={gate_passed_text}) | "
            f"llm={llm_status}"
        ),
    )
    _safe_curses_addstr(win, y=2, x=0, text=f"verdict={verdict_state}")
    if reason_codes:
        _safe_curses_addstr(
            win,
            y=3,
            x=0,
            text="reason_codes=" + ", ".join(reason_codes[:3]),
        )
    _safe_curses_addstr(
        win,
        y=4,
        x=0,
        text=(
            f"candidates={candidate_count} (H={high}, M={medium}, L={low}, "
            f"chain_backed={chain_backed})"
        ),
    )

    list_top = 6
    status_row = max_y - 1
    list_height = max(3, status_row - list_top)
    left_width = max(42, int(max_x * 0.52))
    left_width = min(left_width, max_x - 24)
    right_x = left_width + 2

    _safe_curses_addstr(
        win,
        y=list_top - 1,
        x=0,
        text=f"[Candidates] showing {min(list_limit, len(candidates))}/{len(candidates)}",
    )
    _safe_curses_addstr(win, y=list_top - 1, x=right_x, text="[Details]")

    shown_candidates = candidates[:list_limit]
    if not shown_candidates:
        _safe_curses_addstr(win, y=list_top, x=0, text="(no candidates)")
    else:
        selected_index = max(0, min(selected_index, len(shown_candidates) - 1))
        if selected_index < list_height // 2:
            start = 0
        else:
            start = selected_index - (list_height // 2)
        max_start = max(0, len(shown_candidates) - list_height)
        start = min(start, max_start)
        stop = min(len(shown_candidates), start + list_height)

        for row, idx in enumerate(range(start, stop)):
            item = shown_candidates[idx]
            pr = _short_text(item.get("priority"), max_len=12) or "unknown"
            pr_tag = pr[:1].upper() if pr else "?"
            score = _as_float(item.get("score"))
            family = _short_text(_candidate_family_text(item), max_len=24) or "unknown"
            path = _path_tail(item.get("path"), max_segments=4, max_len=max(22, left_width - 30))
            line = f"{idx + 1:02d} [{pr_tag}] {score:.3f} {family} | {path or '(none)'}"
            attr = curses.A_REVERSE if idx == selected_index else 0
            _safe_curses_addstr(win, y=list_top + row, x=0, text=line, attr=attr)

        selected = shown_candidates[selected_index]
        details: list[str] = []
        details.append(
            f"id: {_short_text(selected.get('candidate_id'), max_len=max(20, max_x - right_x - 4))}"
        )
        details.append(
            f"priority/source: {_short_text(selected.get('priority'), max_len=10)} / "
            f"{_short_text(selected.get('source'), max_len=16)}"
        )
        details.append(f"score: {_as_float(selected.get('score')):.3f}")
        details.append(
            f"family: {_short_text(_candidate_family_text(selected), max_len=max(20, max_x - right_x - 4))}"
        )
        details.append(
            f"path: {_path_tail(selected.get('path'), max_segments=6, max_len=max(24, max_x - right_x - 4)) or '(none)'}"
        )
        details.append(
            f"attack: {_short_text(selected.get('attack_hypothesis'), max_len=max(24, max_x - right_x - 10)) or '(none)'}"
        )
        impacts_any = selected.get("expected_impact")
        if isinstance(impacts_any, list):
            impacts = [x for x in cast(list[object], impacts_any) if isinstance(x, str)]
        else:
            impacts = []
        details.append(
            f"impact: {_short_text(impacts[0], max_len=max(24, max_x - right_x - 10)) if impacts else '(none)'}"
        )
        details.append(
            f"next: {_candidate_next_step_text(selected) or '(none)'}"
        )

        refs_any = selected.get("evidence_refs")
        refs = (
            [x for x in cast(list[object], refs_any) if isinstance(x, str)]
            if isinstance(refs_any, list)
            else []
        )
        details.append("evidence_refs:")
        for ref in refs[:3]:
            details.append("  - " + _short_text(ref, max_len=max(16, max_x - right_x - 4)))

        for i, line in enumerate(details[:list_height]):
            _safe_curses_addstr(win, y=list_top + i, x=right_x, text=line)

    _safe_curses_addstr(
        win,
        y=status_row,
        x=0,
        text="j/k or ↑/↓ move | g/G top/bottom | r refresh | q quit",
    )
    win.refresh()


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
        win = cast("curses._CursesWindow", stdscr)
        win.nodelay(True)
        win.keypad(True)
        try:
            curses.curs_set(0)
        except Exception:
            pass

        selected_index = 0
        snapshot = _build_tui_snapshot(run_dir=run_dir)
        last_refresh = time.monotonic()
        force_refresh = False

        while True:
            now = time.monotonic()
            if force_refresh or (now - last_refresh) >= refresh_interval:
                snapshot = _build_tui_snapshot(run_dir=run_dir)
                candidates_now = cast(
                    list[dict[str, object]], snapshot.get("candidates", [])
                )[:limit]
                if candidates_now:
                    selected_index = min(selected_index, len(candidates_now) - 1)
                else:
                    selected_index = 0
                last_refresh = now
                force_refresh = False

            candidates = cast(list[dict[str, object]], snapshot.get("candidates", []))
            _draw_interactive_tui_frame(
                stdscr=win,
                run_dir=run_dir,
                snapshot=snapshot,
                candidates=candidates,
                selected_index=selected_index,
                list_limit=limit,
            )

            key = win.getch()
            if key == -1:
                time.sleep(0.05)
                continue
            if key in (ord("q"), ord("Q")):
                return 0
            if key in (ord("j"), curses.KEY_DOWN):
                if candidates:
                    selected_index = min(selected_index + 1, min(limit, len(candidates)) - 1)
                continue
            if key in (ord("k"), curses.KEY_UP):
                if candidates:
                    selected_index = max(0, selected_index - 1)
                continue
            if key in (ord("g"),):
                selected_index = 0
                continue
            if key in (ord("G"),):
                if candidates:
                    selected_index = min(limit, len(candidates)) - 1
                continue
            if key in (ord("r"), ord("R")):
                force_refresh = True
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
    watch: bool,
    interval_s: float,
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
    if interactive and watch:
        print("Invalid flags: --interactive and --watch cannot be combined", file=sys.stderr)
        return 20

    if interactive:
        return _run_tui_interactive(run_dir=run_dir, limit=limit, interval_s=interval_s)

    def render_once() -> int:
        lines = _build_tui_snapshot_lines(run_dir=run_dir, limit=limit)
        print("\n".join(lines))
        return 0

    if not watch:
        return render_once()

    supports_ansi = bool(
        sys.stdout.isatty() and os.environ.get("TERM", "dumb").lower() != "dumb"
    )
    last_snapshot: str | None = None

    try:
        while True:
            lines = _build_tui_snapshot_lines(run_dir=run_dir, limit=limit)
            snapshot = "\n".join(lines)
            if snapshot != last_snapshot:
                if supports_ansi:
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

def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_manifest_track_marker(manifest_path: Path) -> None:
    obj_any = cast(object, json.loads(manifest_path.read_text(encoding="utf-8")))
    if not isinstance(obj_any, dict):
        raise ValueError("manifest.json is not an object")
    obj = cast(dict[str, object], obj_any)
    obj["track"] = {
        "track_id": "8mb",
        "canonical_sha256_prefix": _CANONICAL_8MB_SHA256[:12],
        "canonical_size_bytes": _CANONICAL_8MB_SIZE_BYTES,
    }
    _ = manifest_path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _write_manifest_profile_marker(
    manifest_path: Path,
    *,
    profile: str,
    exploit_gate: dict[str, str] | None,
) -> None:
    obj_any = cast(object, json.loads(manifest_path.read_text(encoding="utf-8")))
    if not isinstance(obj_any, dict):
        raise ValueError("manifest.json is not an object")
    obj = cast(dict[str, object], obj_any)
    obj["profile"] = profile
    if exploit_gate is not None:
        obj["exploit_gate"] = dict(exploit_gate)
    _ = manifest_path.write_text(
        json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _build_parser() -> argparse.ArgumentParser:
    epilog = textwrap.dedent(
        """\
        Exit codes:
          0   Success
          10  Partial success
          20  Fatal error
          30  Policy violation
        """
    )

    parser = argparse.ArgumentParser(
        prog="aiedge",
        description="Internal aiedge v1 scaffold",
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _ = parser.add_argument(
        "--version",
        action="version",
        version=f"aiedge {__version__}",
        help="Print version and exit.",
    )
    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser(
        "analyze",
        help="Create a run directory for a firmware analysis (best-effort extraction).",
    )
    _ = analyze.add_argument(
        "input_firmware",
        help="Path to firmware binary to analyze.",
    )
    _ = analyze.add_argument(
        "--case-id",
        required=True,
        help="Case identifier recorded into the run manifest.",
    )
    _ = analyze.add_argument(
        "--ack-authorization",
        action="store_true",
        help="Acknowledge you are authorized to analyze this firmware.",
    )
    _ = analyze.add_argument(
        "--time-budget-s",
        type=int,
        default=3600,
        help="Overall pipeline time budget in seconds (default: 3600).",
    )
    _ = analyze.add_argument(
        "--open-egress",
        action="store_true",
        help="Record an override allowing full internet egress for this run.",
    )
    _ = analyze.add_argument(
        "--egress-allow",
        action="append",
        default=[],
        metavar="HOST",
        help="Add an allowed internet egress host; may be repeated.",
    )
    _ = analyze.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM probing and record deterministic skipped LLM report fields.",
    )
    _ = analyze.add_argument(
        "--profile",
        choices=["analysis", "exploit"],
        default="analysis",
        help="Execution profile (default: analysis).",
    )
    _ = analyze.add_argument(
        "--exploit-flag",
        default="",
        help="Exploit profile gate flag (required for --profile exploit).",
    )
    _ = analyze.add_argument(
        "--exploit-attestation",
        default="",
        help="Exploit profile attestation (required for --profile exploit).",
    )
    _ = analyze.add_argument(
        "--exploit-scope",
        default="",
        help="Exploit profile explicit scope string (required for --profile exploit).",
    )
    _ = analyze.add_argument(
        "--stages",
        default=None,
        help=("Comma-separated subset of stages to run (example: tooling,structure)."),
    )
    _ = analyze.add_argument(
        "--ref-md",
        default=None,
        metavar="PATH",
        help="Path to governed reference markdown context file.",
    )
    _ = analyze.add_argument(
        "--require-ref-md",
        action="store_true",
        help="Fail closed if --ref-md is missing or unreadable.",
    )
    _ = analyze.add_argument(
        "--force-retriage",
        action="store_true",
        help=(
            "Operator override: reopen duplicate-suppressed findings for retriage "
            "and emit deterministic duplicate-gate audit events."
        ),
    )

    analyze_8mb = sub.add_parser(
        "analyze-8mb",
        help=(
            "Analyze only the canonical 8MB firmware snapshot (sha256-locked); writes runs under aiedge-8mb-runs/."
        ),
    )
    _ = analyze_8mb.add_argument(
        "input_firmware",
        help=(
            "Path to firmware binary to analyze (must match canonical 8MB snapshot by sha256/size)."
        ),
    )
    _ = analyze_8mb.add_argument(
        "--case-id",
        required=True,
        help="Case identifier recorded into the run manifest.",
    )
    _ = analyze_8mb.add_argument(
        "--ack-authorization",
        action="store_true",
        help="Acknowledge you are authorized to analyze this firmware.",
    )
    _ = analyze_8mb.add_argument(
        "--time-budget-s",
        type=int,
        default=3600,
        help="Overall pipeline time budget in seconds (default: 3600).",
    )
    _ = analyze_8mb.add_argument(
        "--open-egress",
        action="store_true",
        help="Record an override allowing full internet egress for this run.",
    )
    _ = analyze_8mb.add_argument(
        "--egress-allow",
        action="append",
        default=[],
        metavar="HOST",
        help="Add an allowed internet egress host; may be repeated.",
    )
    _ = analyze_8mb.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM probing and record deterministic skipped LLM report fields.",
    )
    _ = analyze_8mb.add_argument(
        "--profile",
        choices=["analysis", "exploit"],
        default="analysis",
        help="Execution profile (default: analysis).",
    )
    _ = analyze_8mb.add_argument(
        "--exploit-flag",
        default="",
        help="Exploit profile gate flag (required for --profile exploit).",
    )
    _ = analyze_8mb.add_argument(
        "--exploit-attestation",
        default="",
        help="Exploit profile attestation (required for --profile exploit).",
    )
    _ = analyze_8mb.add_argument(
        "--exploit-scope",
        default="",
        help="Exploit profile explicit scope string (required for --profile exploit).",
    )
    _ = analyze_8mb.add_argument(
        "--stages",
        default=None,
        help=("Comma-separated subset of stages to run (example: tooling,structure)."),
    )
    _ = analyze_8mb.add_argument(
        "--ref-md",
        default=None,
        metavar="PATH",
        help="Path to governed reference markdown context file.",
    )
    _ = analyze_8mb.add_argument(
        "--require-ref-md",
        action="store_true",
        help="Fail closed if --ref-md is missing or unreadable.",
    )
    _ = analyze_8mb.add_argument(
        "--force-retriage",
        action="store_true",
        help=(
            "Operator override: reopen duplicate-suppressed findings for retriage "
            "and emit deterministic duplicate-gate audit events."
        ),
    )

    stages = sub.add_parser(
        "stages",
        help="Run a stage subset against an existing run directory.",
    )
    _ = stages.add_argument(
        "run_dir",
        help="Path to an existing run directory.",
    )
    _ = stages.add_argument(
        "--stages",
        required=True,
        help=("Comma-separated subset of stages to run (example: tooling,structure)."),
    )
    _ = stages.add_argument(
        "--time-budget-s",
        type=int,
        default=3600,
        help="Overall pipeline time budget in seconds (default: 3600).",
    )
    _ = stages.add_argument(
        "--no-llm",
        action="store_true",
        help="Skip LLM probing and record deterministic skipped LLM report fields.",
    )

    corpus_validate = sub.add_parser(
        "corpus-validate",
        help="Validate corpus manifest and print deterministic split summary.",
    )
    _ = corpus_validate.add_argument(
        "--manifest",
        default="benchmarks/corpus/manifest.json",
        metavar="PATH",
        help="Path to corpus manifest JSON (default: benchmarks/corpus/manifest.json).",
    )

    quality_metrics = sub.add_parser(
        "quality-metrics",
        help=(
            "Evaluate corpus labels with deterministic quality metrics and optional baseline delta output."
        ),
    )
    _ = quality_metrics.add_argument(
        "--manifest",
        default="benchmarks/corpus/manifest.json",
        metavar="PATH",
        help="Path to corpus manifest JSON (default: benchmarks/corpus/manifest.json).",
    )
    _ = quality_metrics.add_argument(
        "--baseline",
        default=None,
        metavar="PATH",
        help="Optional baseline metrics JSON for deterministic delta comparison.",
    )
    _ = quality_metrics.add_argument(
        "--out",
        default="metrics.json",
        metavar="PATH",
        help="Path for metrics report JSON output (default: metrics.json).",
    )
    _ = quality_metrics.add_argument(
        "--delta-out",
        default="metrics.delta.json",
        metavar="PATH",
        help="Path for baseline delta JSON output when --baseline is set (default: metrics.delta.json).",
    )
    _ = quality_metrics.add_argument(
        "--max-regression",
        type=float,
        default=0.01,
        metavar="FLOAT",
        help=(
            "Maximum allowed metric regression before flagging (default: 0.01). "
            "Regression is baseline-current for precision/recall/f1, and current-baseline for fpr/fnr."
        ),
    )

    quality_gate = sub.add_parser(
        "quality-gate",
        help=(
            "Enforce release-quality thresholds against metrics.json and emit a deterministic verdict artifact."
        ),
    )
    _ = quality_gate.add_argument(
        "--metrics",
        default="metrics.json",
        metavar="PATH",
        help="Path to quality metrics JSON (default: metrics.json).",
    )
    _ = quality_gate.add_argument(
        "--report",
        default=None,
        metavar="PATH",
        help="Optional report JSON for additive release-mode confirmed high/critical constraint.",
    )
    _ = quality_gate.add_argument(
        "--release-mode",
        action="store_true",
        help="Enable additive release constraint checks that consider report findings.",
    )
    _ = quality_gate.add_argument(
        "--llm-primary",
        action="store_true",
        help="Enable LLM-primary gating policy checks.",
    )
    _ = quality_gate.add_argument(
        "--llm-fixture",
        default=None,
        metavar="PATH",
        help=(
            "Optional LLM gate fixture JSON path; when omitted in llm-primary mode, "
            "a verdict is derived from report.llm.status."
        ),
    )
    _ = quality_gate.add_argument(
        "--out",
        default="quality_gate.json",
        metavar="PATH",
        help="Path for gate verdict JSON output artifact (default: quality_gate.json).",
    )

    release_quality_gate = sub.add_parser(
        "release-quality-gate",
        help=(
            "Alias for quality-gate with release-mode enabled by default for release CI policy checks."
        ),
    )
    _ = release_quality_gate.add_argument(
        "--metrics",
        default="metrics.json",
        metavar="PATH",
        help="Path to quality metrics JSON (default: metrics.json).",
    )
    _ = release_quality_gate.add_argument(
        "--report",
        default=None,
        metavar="PATH",
        help="Optional report JSON for additive release-mode confirmed high/critical constraint.",
    )
    _ = release_quality_gate.add_argument(
        "--llm-primary",
        action="store_true",
        help="Enable LLM-primary gating policy checks (release-quality-gate enables this by default).",
    )
    _ = release_quality_gate.add_argument(
        "--llm-fixture",
        default=None,
        metavar="PATH",
        help=(
            "Optional LLM gate fixture JSON path; when omitted in llm-primary mode, "
            "a verdict is derived from report.llm.status."
        ),
    )
    _ = release_quality_gate.add_argument(
        "--out",
        default="quality_gate.json",
        metavar="PATH",
        help="Path for gate verdict JSON output artifact (default: quality_gate.json).",
    )

    serve = sub.add_parser(
        "serve",
        help=(
            "Serve an existing run report directory over local HTTP and print the viewer URL."
        ),
    )
    _ = serve.add_argument(
        "run_dir",
        help="Path to an existing run directory (must contain report/viewer.html).",
    )
    _ = serve.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host interface to bind (default: 127.0.0.1).",
    )
    _ = serve.add_argument(
        "--port",
        type=int,
        default=8000,
        help="TCP port to bind (default: 8000, use 0 for auto-assign).",
    )
    _ = serve.add_argument(
        "--once",
        action="store_true",
        help="Serve a single request and exit (useful for automation/tests).",
    )
    _ = serve.add_argument(
        "--duration-s",
        type=float,
        default=None,
        metavar="SECONDS",
        help="Optional max runtime in seconds before auto-stop.",
    )

    tui = sub.add_parser(
        "tui",
        help="Render an analyst-focused terminal dashboard for an existing run directory.",
    )
    _ = tui.add_argument(
        "run_dir",
        help="Path to an existing run directory.",
    )
    _ = tui.add_argument(
        "--limit",
        type=int,
        default=12,
        help="Maximum number of exploit candidates to print (default: 12).",
    )
    _ = tui.add_argument(
        "--watch",
        action="store_true",
        help="Refresh dashboard continuously until Ctrl+C.",
    )
    _ = tui.add_argument(
        "--interactive",
        action="store_true",
        help="Launch interactive terminal UI (keyboard navigation).",
    )
    _ = tui.add_argument(
        "--interval-s",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="Refresh interval for --watch mode (default: 2.0).",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    parser = _build_parser()
    try:
        args = parser.parse_args(list(argv))
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 20

    command = cast(str | None, getattr(args, "command", None))
    if command is None:
        parser.print_help()
        return 0

    def parse_stage_names(stages_raw: str | None) -> list[str] | None:
        if stages_raw is None:
            return None
        stage_names_local = [
            part.strip() for part in stages_raw.split(",") if part.strip()
        ]
        if not stage_names_local:
            print(
                "Invalid --stages value: provide at least one non-empty stage name.",
                file=sys.stderr,
            )
            return []
        return stage_names_local

    if command in ("analyze", "analyze-8mb"):
        input_firmware = cast(str, getattr(args, "input_firmware"))
        case_id = cast(str, getattr(args, "case_id"))
        ack_authorization = bool(getattr(args, "ack_authorization", False))
        time_budget_s = cast(int, getattr(args, "time_budget_s"))
        open_egress = bool(getattr(args, "open_egress", False))
        egress_allow = cast(list[str], getattr(args, "egress_allow", []))
        no_llm = bool(getattr(args, "no_llm", False))
        stages_raw = cast(str | None, getattr(args, "stages", None))
        ref_md = cast(str | None, getattr(args, "ref_md", None))
        require_ref_md = bool(getattr(args, "require_ref_md", False))
        force_retriage = bool(getattr(args, "force_retriage", False))
        profile = cast(str, getattr(args, "profile", "analysis"))
        exploit_flag = cast(str, getattr(args, "exploit_flag", ""))
        exploit_att = cast(str, getattr(args, "exploit_attestation", ""))
        exploit_scope = cast(str, getattr(args, "exploit_scope", ""))

        enforce_canonical_8mb = command == "analyze-8mb"
        if enforce_canonical_8mb:
            src = Path(input_firmware)
            if not src.is_file():
                print(f"Input firmware not found: {input_firmware}", file=sys.stderr)
                return 20
            if src.stat().st_size != _CANONICAL_8MB_SIZE_BYTES:
                print(
                    "8MB track requires the canonical snapshot (size mismatch)",
                    file=sys.stderr,
                )
                return 30
            if _sha256_file(src) != _CANONICAL_8MB_SHA256:
                print(
                    "8MB track requires the canonical snapshot (sha256 mismatch)",
                    file=sys.stderr,
                )
                return 30

        if not ack_authorization:
            print(
                "Missing required acknowledgement: --ack-authorization",
                file=sys.stderr,
            )
            return 30

        exploit_gate: dict[str, str] | None = None
        if profile == "exploit":
            if not (exploit_flag and exploit_att and exploit_scope):
                print(
                    "Exploit profile requires --exploit-flag, --exploit-attestation, and --exploit-scope",
                    file=sys.stderr,
                )
                return 30
            exploit_gate = {
                "flag": exploit_flag,
                "attestation": exploit_att,
                "scope": exploit_scope,
            }

        run_mod: ModuleType = importlib.import_module("aiedge.run")
        create_run = cast(Callable[..., object], getattr(run_mod, "create_run"))
        analyze_run = cast(
            Callable[..., object] | None, getattr(run_mod, "analyze_run", None)
        )
        run_subset = cast(
            Callable[..., object] | None, getattr(run_mod, "run_subset", None)
        )
        policy_exc = cast(
            type[BaseException],
            getattr(run_mod, "AIEdgePolicyViolation", RuntimeError),
        )

        stage_names = parse_stage_names(stages_raw)
        if stage_names == []:
            return 20

        try:
            info = create_run(
                input_firmware,
                case_id=case_id,
                ack_authorization=ack_authorization,
                open_egress=open_egress,
                egress_allowlist=egress_allow,
                ref_md_path=ref_md,
                require_ref_md=require_ref_md,
                runs_root=(Path.cwd() / "aiedge-8mb-runs")
                if enforce_canonical_8mb
                else None,
            )

            if enforce_canonical_8mb:
                info_obj = info
                manifest_path_any = getattr(info_obj, "manifest_path", None)
                if not isinstance(manifest_path_any, Path):
                    raise RuntimeError("create_run did not return a manifest_path")
                _write_manifest_profile_marker(
                    manifest_path_any,
                    profile=profile,
                    exploit_gate=exploit_gate,
                )
                _write_manifest_track_marker(manifest_path_any)
            else:
                info_obj = info
                manifest_path_any = getattr(info_obj, "manifest_path", None)
                if isinstance(manifest_path_any, Path):
                    _write_manifest_profile_marker(
                        manifest_path_any,
                        profile=profile,
                        exploit_gate=exploit_gate,
                    )

            stage_status: str | None = None
            if stage_names is not None:
                if not callable(run_subset):
                    raise RuntimeError("run_subset is unavailable in aiedge.run")
                rep = cast(
                    _RunReport,
                    run_subset(
                        info,
                        stage_names,
                        time_budget_s=time_budget_s,
                        no_llm=no_llm,
                    ),
                )
                stage_status = rep.status
            elif callable(analyze_run):
                stage_status = cast(
                    str,
                    analyze_run(
                        info,
                        time_budget_s=time_budget_s,
                        no_llm=no_llm,
                        force_retriage=force_retriage,
                    ),
                )
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 20
        except policy_exc as e:
            print(str(e), file=sys.stderr)
            return 30
        except FileNotFoundError:
            print(f"Input firmware not found: {input_firmware}", file=sys.stderr)
            return 20
        except Exception as e:
            print(f"Fatal error: {e}", file=sys.stderr)
            return 20

        info_typed = cast(_RunInfo, info)
        print(str(info_typed.run_dir))
        if stage_status in ("partial", "failed"):
            return 10
        return 0

    if command == "stages":
        run_dir = cast(str, getattr(args, "run_dir"))
        time_budget_s = cast(int, getattr(args, "time_budget_s"))
        no_llm = bool(getattr(args, "no_llm", False))
        stages_raw = cast(str, getattr(args, "stages"))

        stage_names = parse_stage_names(stages_raw)
        if stage_names in (None, []):
            return 20

        run_mod_existing: ModuleType = importlib.import_module("aiedge.run")
        load_existing_run = cast(
            Callable[..., object] | None,
            getattr(run_mod_existing, "load_existing_run", None),
        )
        run_subset = cast(
            Callable[..., object] | None,
            getattr(run_mod_existing, "run_subset", None),
        )
        policy_exc = cast(
            type[BaseException],
            getattr(run_mod_existing, "AIEdgePolicyViolation", RuntimeError),
        )

        try:
            if not callable(load_existing_run):
                raise RuntimeError("load_existing_run is unavailable in aiedge.run")
            if not callable(run_subset):
                raise RuntimeError("run_subset is unavailable in aiedge.run")

            info = load_existing_run(run_dir)
            rep = cast(
                _RunReport,
                run_subset(
                    info,
                    stage_names,
                    time_budget_s=time_budget_s,
                    no_llm=no_llm,
                ),
            )
        except ValueError as e:
            print(str(e), file=sys.stderr)
            return 20
        except policy_exc as e:
            print(str(e), file=sys.stderr)
            return 30
        except Exception as e:
            print(f"Fatal error: {e}", file=sys.stderr)
            return 20

        info_typed = cast(_RunInfo, info)
        print(str(info_typed.run_dir))
        if rep.status in ("partial", "failed"):
            return 10
        return 0

    if command == "serve":
        run_dir = cast(str, getattr(args, "run_dir"))
        host = cast(str, getattr(args, "host"))
        port = cast(int, getattr(args, "port"))
        once = bool(getattr(args, "once", False))
        duration_s = cast(float | None, getattr(args, "duration_s", None))

        try:
            return _serve_report_directory(
                run_dir_path=run_dir,
                host=host,
                port=port,
                once=once,
                duration_s=duration_s,
            )
        except Exception as e:
            print(f"Fatal error: {e}", file=sys.stderr)
            return 20

    if command == "tui":
        run_dir = cast(str, getattr(args, "run_dir"))
        limit = cast(int, getattr(args, "limit"))
        watch = bool(getattr(args, "watch", False))
        interactive = bool(getattr(args, "interactive", False))
        interval_s = cast(float, getattr(args, "interval_s"))

        try:
            return _run_tui(
                run_dir_path=run_dir,
                limit=limit,
                watch=watch,
                interval_s=interval_s,
                interactive=interactive,
            )
        except Exception as e:
            print(f"Fatal error: {e}", file=sys.stderr)
            return 20

    if command == "corpus-validate":
        manifest_raw = cast(str, getattr(args, "manifest"))
        manifest_path = Path(manifest_raw)

        try:
            payload = load_corpus_manifest(manifest_path)
            summary = corpus_summary(payload)
        except FileNotFoundError:
            err = {
                "error_token": "CORPUS_INVALID_SAMPLE",
                "message": f"manifest file not found: {manifest_raw}",
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except json.JSONDecodeError as e:
            err = {
                "error_token": "CORPUS_INVALID_SAMPLE",
                "message": f"manifest is not valid JSON: {e.msg}",
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except CorpusValidationError as e:
            err = {
                "error_token": e.token,
                "message": str(e),
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20

        print(format_summary(summary), end="")
        return 0

    if command == "quality-metrics":
        manifest_raw = cast(str, getattr(args, "manifest"))
        baseline_raw = cast(str | None, getattr(args, "baseline", None))
        out_raw = cast(str, getattr(args, "out"))
        delta_out_raw = cast(str, getattr(args, "delta_out"))
        max_regression = cast(float, getattr(args, "max_regression"))
        manifest_path = Path(manifest_raw)
        baseline_path = Path(baseline_raw) if baseline_raw is not None else None
        out_path = Path(out_raw)
        delta_out_path = Path(delta_out_raw)

        try:
            if max_regression < 0.0:
                raise QualityMetricsError(
                    "QUALITY_METRICS_INVALID_THRESHOLD",
                    "max regression threshold must be >= 0.0",
                )

            payload, baseline_payload = evaluate_quality_metrics_harness(
                manifest_path=manifest_path,
                baseline_path=baseline_path,
            )
            write_quality_metrics(out_path, payload)

            if baseline_path is not None:
                if baseline_payload is None:
                    raise QualityMetricsError(
                        "QUALITY_METRICS_INVALID_BASELINE",
                        "baseline payload is required",
                    )
                delta_payload = build_quality_delta_report(
                    current_metrics=payload,
                    baseline_metrics=baseline_payload,
                    manifest_path=str(manifest_path),
                    baseline_path=str(baseline_path),
                    max_regression=max_regression,
                )
                write_quality_metrics(delta_out_path, delta_payload)
        except FileNotFoundError as e:
            missing_any = cast(object, getattr(e, "filename", None))
            missing = str(missing_any) if isinstance(missing_any, str) else manifest_raw
            err = {
                "error_token": "QUALITY_METRICS_INPUT_NOT_FOUND",
                "message": f"required input file not found: {missing}",
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except json.JSONDecodeError as e:
            err = {
                "error_token": "QUALITY_METRICS_INVALID_BASELINE",
                "message": f"input JSON is invalid: {e.msg}",
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except CorpusValidationError as e:
            err = {
                "error_token": e.token,
                "message": str(e),
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20
        except QualityMetricsError as e:
            err = {
                "error_token": e.token,
                "message": str(e),
            }
            print(
                json.dumps(err, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
            return 20

        print(format_quality_metrics(payload), end="")
        return 0

    if command in ("quality-gate", "release-quality-gate"):
        metrics_raw = cast(str, getattr(args, "metrics"))
        report_raw = cast(str | None, getattr(args, "report", None))
        llm_fixture_raw = cast(str | None, getattr(args, "llm_fixture", None))
        out_raw = cast(str, getattr(args, "out"))
        release_mode = command == "release-quality-gate" or bool(
            getattr(args, "release_mode", False)
        )
        llm_primary = command == "release-quality-gate" or bool(
            getattr(args, "llm_primary", False)
        )

        metrics_path = Path(metrics_raw)
        out_path = Path(out_raw)
        report_path = Path(report_raw) if report_raw is not None else None
        llm_fixture_path = (
            Path(llm_fixture_raw) if llm_fixture_raw is not None else None
        )

        verdict: dict[str, object]
        exit_code = 0
        try:
            metrics_payload = load_json_object(
                metrics_path,
                error_token=QUALITY_GATE_INVALID_METRICS,
                object_name="metrics",
            )
            report_payload: dict[str, object] | None = None
            if report_path is not None:
                report_payload = load_json_object(
                    report_path,
                    error_token=QUALITY_GATE_INVALID_REPORT,
                    object_name="report",
                )

            llm_gate_payload: dict[str, object] | None = None
            llm_gate_path: str | None = None
            if llm_primary:
                if report_payload is None:
                    raise QualityGateError(
                        QUALITY_GATE_LLM_REQUIRED,
                        "llm-primary policy requires --report",
                    )
                if llm_fixture_path is not None:
                    llm_gate_payload, llm_gate_path = resolve_llm_gate_input(
                        fixture_path=llm_fixture_path,
                        run_dir=Path.cwd(),
                        report=cast(dict[str, JsonValue], report_payload),
                    )
                else:
                    llm_status: str | None = None
                    llm_any = report_payload.get("llm")
                    if isinstance(llm_any, dict):
                        llm_status_any = cast(dict[str, object], llm_any).get("status")
                        if isinstance(llm_status_any, str):
                            llm_status = llm_status_any
                    llm_gate_payload = {
                        "verdict": "pass" if llm_status == "ok" else "fail"
                    }
                    llm_gate_path = "report.llm"

            verdict = evaluate_quality_gate(
                metrics_payload=metrics_payload,
                metrics_path=str(metrics_path),
                report_payload=report_payload,
                report_path=str(report_path) if report_path is not None else None,
                release_mode=release_mode,
                llm_primary=llm_primary,
                llm_gate_payload=llm_gate_payload,
                llm_gate_path=llm_gate_path,
            )
            if not bool(verdict.get("passed", False)):
                exit_code = 30
        except FileNotFoundError as e:
            missing_any = cast(object, getattr(e, "filename", None))
            missing = str(missing_any) if isinstance(missing_any, str) else metrics_raw
            err = {
                "error_token": "QUALITY_GATE_INPUT_NOT_FOUND",
                "message": f"required input file not found: {missing}",
            }
            verdict = {
                "schema_version": 1,
                "verdict": "fail",
                "passed": False,
                "metrics_path": str(metrics_path),
                "report_path": str(report_path) if report_path is not None else None,
                "errors": [err],
            }
            exit_code = 20
        except QualityGateError as e:
            err = {
                "error_token": e.token,
                "message": str(e),
            }
            verdict = {
                "schema_version": 1,
                "verdict": "fail",
                "passed": False,
                "metrics_path": str(metrics_path),
                "report_path": str(report_path) if report_path is not None else None,
                "errors": [err],
            }
            exit_code = 20

        write_quality_gate(out_path, verdict)
        if not bool(verdict.get("passed", False)):
            errors_any = verdict.get("errors")
            if isinstance(errors_any, list):
                for err_any in cast(list[object], errors_any):
                    if isinstance(err_any, dict):
                        print(
                            json.dumps(err_any, sort_keys=True, ensure_ascii=True),
                            file=sys.stderr,
                        )
        print(format_quality_gate(verdict), end="")
        return exit_code

    print(f"Unknown command: {command}", file=sys.stderr)
    return 20


if __name__ == "__main__":
    raise SystemExit(main())
