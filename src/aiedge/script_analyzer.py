from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus

_MAX_FINDINGS = 500
_MAX_LINE_CHARS = 240


@dataclass(frozen=True)
class _DangerousPattern:
    pattern_id: str
    regex: re.Pattern[str]
    title: str
    severity: str
    confidence: str
    rationale: str


_DANGEROUS_PATTERNS: tuple[_DangerousPattern, ...] = (
    _DangerousPattern(
        pattern_id="shell.eval.variable",
        regex=re.compile(r"\beval\b[^#\n]*\$"),
        title="eval uses variable-controlled content",
        severity="high",
        confidence="medium",
        rationale="eval reparses expanded shell text and can turn variable content into commands.",
    ),
    _DangerousPattern(
        pattern_id="shell.backtick.variable",
        regex=re.compile(r"`[^`\n]*\$[^`\n]*`"),
        title="backtick command substitution uses variables",
        severity="high",
        confidence="medium",
        rationale="backtick substitution can execute commands assembled from variable content.",
    ),
    _DangerousPattern(
        pattern_id="shell.command_substitution.variable",
        regex=re.compile(r"\$\([^\n)]*\$[^\n)]*\)"),
        title="command substitution uses variables",
        severity="high",
        confidence="medium",
        rationale="command substitution can execute commands assembled from variable content.",
    ),
    _DangerousPattern(
        pattern_id="shell.unquoted_variable",
        regex=re.compile(r"(?<![\"'])\$\{?[A-Za-z_][A-Za-z0-9_]*\}?"),
        title="unquoted variable expansion",
        severity="medium",
        confidence="low",
        rationale="unquoted expansion may enable word splitting, globbing, or argument injection.",
    ),
)


def _load_inventory(run_dir: Path) -> tuple[dict[str, object] | None, list[str]]:
    inventory_path = run_dir / "stages" / "inventory" / "inventory.json"
    if not inventory_path.is_file():
        return None, ["inventory_missing:stages/inventory/inventory.json"]
    try:
        raw = json.loads(inventory_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return None, [f"inventory_parse_failed:{type(exc).__name__}"]
    if not isinstance(raw, dict):
        return None, ["inventory_invalid_shape:expected_object"]
    return cast(dict[str, object], raw), []


def _inventory_scripts(inventory: dict[str, object]) -> tuple[list[str], list[str]]:
    scripts_any = inventory.get("scripts")
    if scripts_any is None:
        return [], ["inventory_schema_missing:scripts"]
    if not isinstance(scripts_any, list):
        return [], ["inventory_schema_invalid:scripts_not_list"]
    scripts = [item for item in scripts_any if isinstance(item, str) and item.strip()]
    dropped = len(scripts_any) - len(scripts)
    limitations = [f"inventory_schema_dropped_non_string_scripts:{dropped}"] if dropped else []
    return scripts, limitations


def _resolve_run_relative(run_dir: Path, rel_path: str) -> Path | None:
    if Path(rel_path).is_absolute():
        return None
    try:
        run_resolved = run_dir.resolve()
        candidate = (run_dir / rel_path).resolve()
    except OSError:
        return None
    if not candidate.is_relative_to(run_resolved):
        return None
    return candidate


def _truncate_line(line: str) -> str:
    stripped = line.strip()
    if len(stripped) <= _MAX_LINE_CHARS:
        return stripped
    return stripped[: _MAX_LINE_CHARS - 1] + "…"


def _finding(script_path: str, line_no: int, line: str, pattern: _DangerousPattern) -> dict[str, JsonValue]:
    return {
        "id": f"script_analysis.{pattern.pattern_id}:{script_path}:{line_no}",
        "file": script_path,
        "line": int(line_no),
        "content": _truncate_line(line),
        "title": pattern.title,
        "description": pattern.title,
        "severity": pattern.severity,
        "confidence": pattern.confidence,
        "source": "script_analysis",
        "source_type": "shell_script",
        "evidence": {
            "path": script_path,
            "line": int(line_no),
            "snippet": _truncate_line(line),
        },
        "rationale": pattern.rationale,
        "limitations": [
            "heuristic shell pattern only; no source-to-sink provenance or reachability proof"
        ],
    }


class ScriptAnalyzer:
    """Heuristic shell-script vulnerability stage backed by inventory.scripts."""

    def __init__(self, firmware_dest: Path | str | None = None) -> None:
        self.firmware_dest = Path(firmware_dest) if firmware_dest is not None else None
        self.dangerous_patterns = _DANGEROUS_PATTERNS

    @property
    def name(self) -> str:
        return "script_analysis"

    def run(self, ctx: StageContext) -> StageOutcome:
        limitations: list[str] = []
        inventory, inventory_limits = _load_inventory(ctx.run_dir)
        limitations.extend(inventory_limits)
        if inventory is None:
            return StageOutcome(
                status="partial",
                details={
                    "findings": [],
                    "scripts_discovered": 0,
                    "scripts_analyzed": 0,
                    "scripts_missing": 0,
                    "scripts_read_failed": 0,
                    "findings_truncated": False,
                    "max_findings": int(_MAX_FINDINGS),
                },
                limitations=limitations,
            )

        scripts, script_limits = _inventory_scripts(inventory)
        limitations.extend(script_limits)

        findings: list[JsonValue] = []
        scripts_analyzed = 0
        scripts_missing = 0
        scripts_read_failed = 0
        findings_truncated = False

        for script_path in scripts:
            full_path = _resolve_run_relative(ctx.run_dir, script_path)
            if full_path is None:
                scripts_missing += 1
                continue
            if not full_path.is_file():
                scripts_missing += 1
                continue

            try:
                content = full_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                scripts_read_failed += 1
                continue

            scripts_analyzed += 1
            for line_no, line in enumerate(content.splitlines(), start=1):
                for pattern in self.dangerous_patterns:
                    if not pattern.regex.search(line):
                        continue
                    if len(findings) >= _MAX_FINDINGS:
                        findings_truncated = True
                        break
                    findings.append(_finding(script_path, line_no, line, pattern))
                if findings_truncated:
                    break
            if findings_truncated:
                break

        if scripts_missing:
            limitations.append(f"script_path_miss_count:{scripts_missing}")
        if scripts_read_failed:
            limitations.append(f"script_open_failed_count:{scripts_read_failed}")
        if findings_truncated:
            limitations.append(f"script_findings_truncated:max_findings={_MAX_FINDINGS}")

        status: StageStatus = "partial" if limitations else "ok"
        return StageOutcome(
            status=status,
            details={
                "findings": findings,
                "scripts_discovered": int(len(scripts)),
                "scripts_analyzed": int(scripts_analyzed),
                "scripts_missing": int(scripts_missing),
                "scripts_read_failed": int(scripts_read_failed),
                "findings_truncated": bool(findings_truncated),
                "max_findings": int(_MAX_FINDINGS),
                "analysis_model": "heuristic_shell_patterns_v1",
            },
            limitations=limitations,
        )
