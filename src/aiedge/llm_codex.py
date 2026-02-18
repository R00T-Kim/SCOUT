from __future__ import annotations

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from .quality_policy import (
    QUALITY_GATE_LLM_INVALID,
    QUALITY_GATE_LLM_REQUIRED,
    QUALITY_GATE_LLM_VERDICT_MISS,
    QualityGateError,
)
from .schema import JsonValue

PROMPT_TEMPLATE_VERSION = "aiedge-codex-summary-v1"
INPUT_REDACTION_SUMMARY = {
    "included": [
        "overview metadata",
        "extraction.summary",
        "inventory.summary",
        "emulation status and reason",
        "findings list (id, title, severity, confidence, disposition)",
        "evidence paths only",
    ],
    "excluded": [
        "raw firmware bytes",
        "file contents",
        "full stage logs",
        "evidence snippets and snippet hashes",
    ],
}

_LLM_GATE_ALLOWED_KEYS = frozenset({"verdict", "confidence", "tokens", "evidence_refs"})


def _is_run_relative_path(path_s: str) -> bool:
    if not path_s:
        return False
    if path_s.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:\\\\", path_s):
        return False
    parts = Path(path_s).parts
    if any(part == ".." for part in parts):
        return False
    return True


def load_llm_gate_fixture(path: Path) -> dict[str, object]:
    try:
        fixture_any = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except FileNotFoundError as exc:
        raise QualityGateError(
            QUALITY_GATE_LLM_REQUIRED,
            f"llm gate fixture file not found: {path}",
        ) from exc
    except json.JSONDecodeError as exc:
        raise QualityGateError(
            QUALITY_GATE_LLM_INVALID,
            f"llm gate fixture JSON is invalid: {exc.msg}",
        ) from exc

    if not isinstance(fixture_any, dict):
        raise QualityGateError(
            QUALITY_GATE_LLM_INVALID,
            "llm gate fixture payload must be a JSON object",
        )
    fixture = cast(dict[str, object], fixture_any)

    extra_keys = sorted(set(fixture.keys()) - _LLM_GATE_ALLOWED_KEYS)
    if extra_keys:
        raise QualityGateError(
            QUALITY_GATE_LLM_INVALID,
            f"llm gate fixture contains unsupported key: {extra_keys[0]}",
        )

    if "verdict" not in fixture:
        raise QualityGateError(
            QUALITY_GATE_LLM_VERDICT_MISS,
            "llm gate fixture verdict is missing",
        )

    verdict = fixture.get("verdict")
    if verdict not in {"pass", "fail"}:
        raise QualityGateError(
            QUALITY_GATE_LLM_INVALID,
            "llm gate fixture verdict must be 'pass' or 'fail'",
        )

    if "confidence" in fixture:
        confidence = fixture.get("confidence")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise QualityGateError(
                QUALITY_GATE_LLM_INVALID,
                "llm gate fixture confidence must be numeric in 0..1",
            )
        confidence_f = float(confidence)
        if confidence_f < 0.0 or confidence_f > 1.0:
            raise QualityGateError(
                QUALITY_GATE_LLM_INVALID,
                "llm gate fixture confidence must be numeric in 0..1",
            )

    if "tokens" in fixture:
        tokens = fixture.get("tokens")
        if isinstance(tokens, bool) or not isinstance(tokens, int) or tokens < 0:
            raise QualityGateError(
                QUALITY_GATE_LLM_INVALID,
                "llm gate fixture tokens must be a non-negative integer",
            )

    if "evidence_refs" in fixture:
        refs_any = fixture.get("evidence_refs")
        if not isinstance(refs_any, list):
            raise QualityGateError(
                QUALITY_GATE_LLM_INVALID,
                "llm gate fixture evidence_refs must be a list",
            )
        refs = cast(list[object], refs_any)
        for idx, ref_any in enumerate(refs):
            if not isinstance(ref_any, str) or not _is_run_relative_path(ref_any):
                raise QualityGateError(
                    QUALITY_GATE_LLM_INVALID,
                    f"llm gate fixture evidence_refs[{idx}] must be run-relative path",
                )

    payload: dict[str, object] = {"verdict": cast(str, verdict)}
    if "confidence" in fixture:
        payload["confidence"] = cast(
            object, float(cast(int | float, fixture["confidence"]))
        )
    if "tokens" in fixture:
        payload["tokens"] = cast(object, int(cast(int, fixture["tokens"])))
    if "evidence_refs" in fixture:
        payload["evidence_refs"] = cast(
            object, list(cast(list[object], fixture["evidence_refs"]))
        )
    return payload


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _truncate_text(value: str, *, limit: int = 8000) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 18] + "\n...[truncated]..."


def _safe_dict(value: object) -> dict[str, object]:
    if isinstance(value, dict):
        return cast(dict[str, object], value)
    return {}


def _safe_json_dict(value: object) -> dict[str, JsonValue]:
    if isinstance(value, dict):
        return cast(dict[str, JsonValue], value)
    return {}


def _evidence_paths_only(value: object) -> list[str]:
    out: list[str] = []
    if not isinstance(value, list):
        return out
    for item in cast(list[object], value):
        if isinstance(item, dict):
            path_s = cast(dict[str, object], item).get("path")
            if isinstance(path_s, str) and path_s:
                out.append(path_s)
        elif isinstance(item, str) and item:
            out.append(item)
    return out


def build_sanitized_payload(report: dict[str, JsonValue]) -> dict[str, JsonValue]:
    overview = _safe_json_dict(report.get("overview"))
    extraction = _safe_dict(report.get("extraction"))
    inventory = _safe_dict(report.get("inventory"))
    emulation = _safe_dict(report.get("emulation"))
    emulation_status = emulation.get("status", "unknown")
    if (
        not isinstance(emulation_status, (str, int, float, bool))
        and emulation_status is not None
    ):
        emulation_status = "unknown"
    emulation_reason = emulation.get("reason", "")
    if (
        not isinstance(emulation_reason, (str, int, float, bool))
        and emulation_reason is not None
    ):
        emulation_reason = ""

    out_findings: list[JsonValue] = []
    findings_any = report.get("findings")
    if isinstance(findings_any, list):
        for item_any in cast(list[object], findings_any):
            if not isinstance(item_any, dict):
                continue
            item = cast(dict[str, object], item_any)
            finding: dict[str, JsonValue] = {}
            for k in ("id", "title", "severity", "confidence", "disposition"):
                v = item.get(k)
                if isinstance(v, (str, int, float, bool)) or v is None:
                    finding[k] = cast(JsonValue, v)
            finding["evidence_paths"] = cast(
                JsonValue, _evidence_paths_only(item.get("evidence"))
            )
            out_findings.append(finding)

    return {
        "overview": cast(JsonValue, overview),
        "extraction_summary": cast(
            JsonValue, _safe_json_dict(extraction.get("summary"))
        ),
        "inventory_summary": cast(JsonValue, _safe_json_dict(inventory.get("summary"))),
        "emulation": {
            "status": cast(JsonValue, emulation_status),
            "reason": cast(JsonValue, emulation_reason),
        },
        "findings": out_findings,
    }


def _build_prompt(payload: dict[str, JsonValue]) -> str:
    payload_json = json.dumps(payload, indent=2, sort_keys=True)
    return (
        "You are assisting with an internal firmware triage run. "
        "Write a concise analyst-facing summary with key risks, confidence caveats, "
        "and 3-5 prioritized next steps. Use only the provided sanitized input.\n\n"
        f"prompt_template_version: {PROMPT_TEMPLATE_VERSION}\n"
        "sanitized_input_json:\n"
        f"{payload_json}\n"
    )


def run_codex_exec_summary(
    *, run_dir: Path, report: dict[str, JsonValue], timeout_s: float = 60.0
) -> dict[str, JsonValue]:
    stage_dir = run_dir / "stages" / "llm"
    stage_dir.mkdir(parents=True, exist_ok=True)
    log_path = stage_dir / "llm.log"

    payload = build_sanitized_payload(report)
    prompt = _build_prompt(payload)
    effective_timeout = max(1.0, min(float(timeout_s), 60.0))

    base_argv: list[str] = [
        "codex",
        "exec",
        "--ephemeral",
        "-s",
        "read-only",
        "-C",
        str(run_dir),
    ]
    argv = base_argv + [prompt]

    log_obj: dict[str, JsonValue] = {
        "timestamp": _iso_utc_now(),
        "prompt_template_version": PROMPT_TEMPLATE_VERSION,
        "input_redaction_summary": cast(JsonValue, dict(INPUT_REDACTION_SUMMARY)),
        "executed_argv": cast(JsonValue, list(argv)),
        "input_preview": payload,
    }

    attempts: list[dict[str, JsonValue]] = []

    def run_once(argv_i: list[str]) -> subprocess.CompletedProcess[str]:
        proc_i = subprocess.run(
            argv_i,
            check=False,
            capture_output=True,
            text=True,
            timeout=effective_timeout,
            stdin=subprocess.DEVNULL,
        )
        attempts.append(
            {
                "argv": cast(JsonValue, list(argv_i)),
                "exit_code": cast(JsonValue, proc_i.returncode),
                "stdout": _truncate_text(proc_i.stdout or ""),
                "stderr": _truncate_text(proc_i.stderr or ""),
            }
        )
        return proc_i

    try:
        proc = run_once(argv)
    except FileNotFoundError:
        log_obj["exit_code"] = None
        log_obj["stdout"] = ""
        log_obj["stderr"] = "codex executable not found in PATH"
        _ = log_path.write_text(json.dumps(log_obj, indent=2, sort_keys=True) + "\n")
        return {
            "status": "skipped",
            "reason": "Codex CLI executable missing during `codex exec` attempt",
            "log": {"path": "stages/llm/llm.log"},
        }
    except subprocess.TimeoutExpired as exc:
        stdout_s = _truncate_text(
            (exc.stdout or "") if isinstance(exc.stdout, str) else ""
        )
        stderr_s = _truncate_text(
            (exc.stderr or "") if isinstance(exc.stderr, str) else ""
        )
        log_obj["exit_code"] = None
        log_obj["stdout"] = stdout_s
        log_obj["stderr"] = stderr_s
        log_obj["timeout_s"] = effective_timeout
        _ = log_path.write_text(json.dumps(log_obj, indent=2, sort_keys=True) + "\n")
        return {
            "status": "failed",
            "reason": f"Codex summary timed out after {effective_timeout:.1f}s",
            "log": {"path": "stages/llm/llm.log"},
        }

    stderr_lc0 = (proc.stderr or "").lower()
    if proc.returncode != 0 and "skip-git-repo-check" in stderr_lc0:
        proc = run_once(base_argv + ["--skip-git-repo-check", prompt])

    stdout_s2 = _truncate_text(proc.stdout or "")
    stderr_s2 = _truncate_text(proc.stderr or "")
    log_obj["exit_code"] = proc.returncode
    log_obj["stdout"] = stdout_s2
    log_obj["stderr"] = stderr_s2
    log_obj["attempts"] = cast(JsonValue, attempts)
    if attempts:
        last_argv = attempts[-1].get("argv")
        if isinstance(last_argv, list):
            log_obj["executed_argv"] = cast(JsonValue, list(last_argv))
    _ = log_path.write_text(json.dumps(log_obj, indent=2, sort_keys=True) + "\n")

    if proc.returncode == 0:
        out: dict[str, JsonValue] = {
            "status": "ok",
            "reason": "Codex summary completed",
            "log": {"path": "stages/llm/llm.log"},
        }
        if stdout_s2:
            summary_path = stage_dir / "summary.md"
            _ = summary_path.write_text(stdout_s2, encoding="utf-8")
            out["summary"] = {
                "path": "stages/llm/summary.md",
                "chars": len(stdout_s2),
            }
        return out

    stderr_lc = (proc.stderr or "").lower()
    if "login" in stderr_lc or "auth" in stderr_lc:
        return {
            "status": "skipped",
            "reason": "Codex CLI is not logged in for `codex exec`; run `codex login`.",
            "log": {"path": "stages/llm/llm.log"},
        }

    return {
        "status": "failed",
        "reason": f"Codex summary failed with exit code {proc.returncode}",
        "log": {"path": "stages/llm/llm.log"},
    }
