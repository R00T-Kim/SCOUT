#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import csv
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from aiedge.pair_eval import PairSpec, load_pairs_manifest


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _status_rank(status: str) -> int:
    return {"success": 4, "partial": 3, "fatal": 2, "error": 1}.get(status or "", 0)


def _wall_timeout(time_budget_s: int) -> int:
    return max(300, int(time_budget_s) + 900)


def _tail_lines(path: Path, n: int) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    lines = text.splitlines()
    return lines[-n:] if len(lines) > n else lines


def _guess_run_dir_from_stdout(stdout_tail: list[str]) -> str:
    for line in reversed(stdout_tail):
        candidate = line.strip()
        if "aiedge-runs/" not in candidate:
            continue
        for tok in reversed(candidate.split()):
            if "aiedge-runs/" in tok:
                return tok.strip().rstrip(",.;:")
    return ""


def _last_stage_info(run_dir_guess: str) -> tuple[str, str]:
    if not run_dir_guess:
        return "", ""
    stages_dir = Path(run_dir_guess) / "stages"
    if not stages_dir.is_dir():
        return "", ""
    try:
        stage_dirs = sorted(
            (p for p in stages_dir.iterdir() if p.is_dir()),
            key=lambda p: p.stat().st_mtime,
        )
    except OSError:
        return "", ""
    if not stage_dirs:
        return "", ""
    last_dir = stage_dirs[-1]
    last_name = last_dir.name
    stage_json = last_dir / "stage.json"
    if not stage_json.is_file():
        return last_name, ""
    try:
        payload_any = json.loads(stage_json.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return last_name, ""
    if not isinstance(payload_any, dict):
        return last_name, ""
    status_val = payload_any.get("status")
    if isinstance(status_val, str):
        return last_name, status_val
    return last_name, ""


def _dump_timeout_diagnostic(
    *,
    side_root: Path,
    pair: PairSpec,
    side: str,
    stdout_path: Path,
    stderr_path: Path,
    wall_timeout_s: int,
) -> None:
    stdout_tail = _tail_lines(stdout_path, 50)
    stderr_tail = _tail_lines(stderr_path, 200)
    run_dir_guess = _guess_run_dir_from_stdout(stdout_tail)
    last_stage, last_stage_status = _last_stage_info(run_dir_guess)
    diagnostic: dict[str, Any] = {
        "pair_id": pair.pair_id,
        "side": side,
        "wall_timeout_s": wall_timeout_s,
        "stdout_tail_count": len(stdout_tail),
        "stderr_tail_count": len(stderr_tail),
        "stdout_tail": stdout_tail,
        "stderr_tail": stderr_tail,
        "run_dir_guess": run_dir_guess,
        "last_stage": last_stage,
        "last_stage_status": last_stage_status,
    }
    _write_json(side_root / "timeout_diagnostic.json", diagnostic)


def _run_one(
    pair: PairSpec,
    side: str,
    firmware_path: str,
    results_root: Path,
    time_budget_s: int,
    driver: str,
) -> dict[str, Any]:
    side_root = results_root / "runs" / pair.pair_id / side
    side_root.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["AIEDGE_LLM_DRIVER"] = driver
    cmd = [
        "./scout",
        "analyze",
        firmware_path,
        "--ack-authorization",
        "--profile",
        "analysis",
        "--time-budget-s",
        str(time_budget_s),
    ]
    _write_json(
        side_root / "started.json",
        {
            "pair_id": pair.pair_id,
            "side": side,
            "driver": driver,
            "firmware_path": firmware_path,
            "cmd": cmd,
            "started_at": time.time(),
            "wall_timeout_s": _wall_timeout(time_budget_s),
        },
    )
    stdout_path = side_root / "stdout.txt"
    stderr_path = side_root / "stderr.txt"
    start = time.time()
    status = "fatal"
    run_dir = ""
    returncode = 20
    timed_out = False
    try:
        with stdout_path.open("wb") as fh_out, stderr_path.open("wb") as fh_err:
            proc = subprocess.run(
                cmd,
                cwd=Path.cwd(),
                env=env,
                stdout=fh_out,
                stderr=fh_err,
                timeout=_wall_timeout(time_budget_s),
                check=False,
            )
        returncode = int(proc.returncode)
        status = (
            "success"
            if returncode == 0
            else ("partial" if returncode == 10 else "fatal")
        )
    except subprocess.TimeoutExpired:
        timed_out = True
        returncode = 124
        status = "fatal"
        try:
            _dump_timeout_diagnostic(
                side_root=side_root,
                pair=pair,
                side=side,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                wall_timeout_s=_wall_timeout(time_budget_s),
            )
        except Exception:
            pass
    duration_s = round(time.time() - start, 3)
    try:
        stdout_text = stdout_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        stdout_text = ""
    stdout_lines = [line.strip() for line in stdout_text.splitlines() if line.strip()]
    run_dir = stdout_lines[-1] if stdout_lines else ""
    result = {
        "pair_id": pair.pair_id,
        "vendor": pair.vendor,
        "model": pair.model,
        "cve_id": pair.cve_id,
        "side": side,
        "firmware_path": firmware_path,
        "returncode": returncode,
        "duration_s": duration_s,
        "run_dir": run_dir,
        "status": status,
        "timed_out": timed_out,
        "driver": driver,
        "wall_timeout_s": _wall_timeout(time_budget_s),
    }
    _write_json(side_root / "last_run.json", result)
    if run_dir:
        link = side_root / "latest"
        if link.exists() or link.is_symlink():
            link.unlink()
        try:
            link.symlink_to(Path(run_dir).resolve())
        except Exception:
            pass
    return result


def _build_rows_from_summaries(
    pairs: list[PairSpec], summary_paths: list[Path], results_root: Path
) -> list[dict[str, Any]]:
    candidates: dict[tuple[str, str], tuple[tuple[int, int], dict[str, Any]]] = {}
    for idx, summary_path in enumerate(summary_paths, start=1):
        with summary_path.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        for row in rows:
            key = (row.get("vendor") or "", row.get("firmware") or "")
            rank = (_status_rank(row.get("status") or ""), idx)
            if key not in candidates or rank > candidates[key][0]:
                candidates[key] = (rank, row)

    out: list[dict[str, Any]] = []
    for pair in pairs:
        for side, side_spec in (
            ("vulnerable", pair.vulnerable),
            ("patched", pair.patched),
        ):
            firmware_name = Path(side_spec.firmware_path).name
            row = candidates.get((pair.vendor, firmware_name), (None, {}))[1]
            run_dir = row.get("run_dir") or ""
            side_root = results_root / "runs" / pair.pair_id / side
            side_root.mkdir(parents=True, exist_ok=True)
            if run_dir:
                link = side_root / "latest"
                if link.exists() or link.is_symlink():
                    link.unlink()
                try:
                    link.symlink_to(Path(run_dir).resolve())
                except Exception:
                    pass
            record = {
                "pair_id": pair.pair_id,
                "vendor": pair.vendor,
                "model": pair.model,
                "cve_id": pair.cve_id,
                "side": side,
                "firmware_path": side_spec.firmware_path,
                "returncode": int(row.get("exit_code") or 0) if row else 0,
                "duration_s": float(row.get("duration_s") or 0) if row else 0,
                "run_dir": run_dir,
                "status": row.get("status") or "missing",
                "source_summary": str(summary_paths[0]) if row else "",
                "driver": "summary-reuse",
                "timed_out": False,
            }
            _write_json(side_root / "last_run.json", record)
            out.append(record)
    return out


def _write_run_index(
    results_root: Path, *, driver: str, time_budget_s: int, rows: list[dict[str, Any]]
) -> None:
    ordered = sorted(rows, key=lambda r: (r["pair_id"], r["side"]))
    _write_json(
        results_root / "run_index.json",
        {
            "driver": driver,
            "time_budget_s": time_budget_s,
            "rows": ordered,
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the pair-eval corpus.")
    parser.add_argument("--pairs", default="benchmarks/pair-eval/pairs.json")
    parser.add_argument("--results-dir", default="benchmark-results/pair-eval")
    parser.add_argument("--driver", default="codex")
    parser.add_argument("--parallel", type=int, default=2)
    parser.add_argument("--time-budget-s", type=int, default=3600)
    parser.add_argument("--source-summary", nargs="*", default=[])
    args = parser.parse_args()

    results_root = Path(args.results_dir).resolve()
    results_root.mkdir(parents=True, exist_ok=True)
    pairs = load_pairs_manifest(Path(args.pairs).resolve())

    if args.source_summary:
        rows = _build_rows_from_summaries(
            pairs, [Path(p).resolve() for p in args.source_summary], results_root
        )
        _write_run_index(
            results_root,
            driver="summary-reuse",
            time_budget_s=args.time_budget_s,
            rows=rows,
        )
        return 0

    tasks: list[tuple[PairSpec, str, str]] = []
    for pair in pairs:
        tasks.append((pair, "vulnerable", pair.vulnerable.firmware_path))
        tasks.append((pair, "patched", pair.patched.firmware_path))

    rows: list[dict[str, Any]] = []
    _write_run_index(
        results_root, driver=args.driver, time_budget_s=args.time_budget_s, rows=rows
    )
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max(1, args.parallel)
    ) as pool:
        futs = [
            pool.submit(
                _run_one,
                pair,
                side,
                firmware,
                results_root,
                args.time_budget_s,
                args.driver,
            )
            for pair, side, firmware in tasks
        ]
        for fut in concurrent.futures.as_completed(futs):
            row = fut.result()
            rows.append(row)
            _write_run_index(
                results_root,
                driver=args.driver,
                time_budget_s=args.time_budget_s,
                rows=rows,
            )
            print(
                json.dumps(
                    {
                        k: row[k]
                        for k in [
                            "pair_id",
                            "side",
                            "status",
                            "returncode",
                            "run_dir",
                            "timed_out",
                        ]
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
    _write_run_index(
        results_root, driver=args.driver, time_budget_s=args.time_budget_s, rows=rows
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
