from __future__ import annotations

"""PoC refinement stage.

Generates and iteratively refines proof-of-concept exploits from fuzzing
crash seeds and confirmed taint paths.  Uses LLM for PoC generation with
optional emulation-based validation.  Skips under ``--no-llm`` or when
no fuzzing/taint data is available.
"""

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from ._typing_helpers import safe_float
from .llm_driver import resolve_driver
from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus

_SCHEMA_VERSION = "poc-refinement-v1"
_LLM_TIMEOUT_S = 180.0
_LLM_MAX_ATTEMPTS = 3
_MAX_REFINEMENT_ATTEMPTS = 5
_RETRYABLE_TOKENS: tuple[str, ...] = (
    "stream disconnected",
    "error sending request",
    "connection reset",
    "connection refused",
    "timed out",
    "timeout",
    "temporary failure",
    "503",
    "502",
    "429",
)

_SCOUT_MARKER = "SCOUT_MARKER"


def _load_json_file(path: Path) -> object | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _truncate_text(text: str, *, max_chars: int = 4000) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def _build_poc_prompt(
    crash_input_hex: str,
    taint_path: dict[str, object],
    vuln_type: str,
) -> str:
    taint_json = json.dumps(taint_path, indent=2, ensure_ascii=True)
    return (
        "You are a firmware exploit developer.\n"
        f"Generate a proof-of-concept exploit for a {vuln_type} vulnerability.\n\n"
        "## Crash Input (hex)\n"
        f"```\n{_truncate_text(crash_input_hex)}\n```\n\n"
        "## Taint Path\n"
        f"{taint_json}\n\n"
        "## Requirements\n"
        "- Generate a Python script that reproduces the crash\n"
        "- The script should send the crafted input to the target\n"
        "- Include a marker string 'SCOUT_MARKER' in output on success\n"
        "- Keep the script self-contained (stdlib only)\n"
        "- Include comments explaining the exploit logic\n\n"
        "## Output Format\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        "{\n"
        '  "poc_script": "<full Python script>",\n'
        '  "vuln_type": "<vulnerability type>",\n'
        '  "description": "<what the PoC does>",\n'
        '  "target_binary": "<binary name>",\n'
        '  "expected_outcome": "crash"|"code_execution"|"info_leak"\n'
        "}\n"
    )


def _build_refinement_prompt(
    original_poc: str,
    crash_log: str,
    attempt: int,
) -> str:
    return (
        "You are a firmware exploit developer.\n"
        f"The previous PoC attempt #{attempt} failed. Refine it.\n\n"
        "## Previous PoC\n"
        f"```python\n{_truncate_text(original_poc)}\n```\n\n"
        "## Crash/Error Log\n"
        f"```\n{_truncate_text(crash_log, max_chars=2000)}\n```\n\n"
        "## Requirements\n"
        "- Fix the issue indicated by the error log\n"
        "- Keep using stdlib-only Python\n"
        "- Include 'SCOUT_MARKER' in output on success\n\n"
        "## Output Format\n"
        "Return ONLY a JSON object (no markdown fences):\n"
        "{\n"
        '  "poc_script": "<refined Python script>",\n'
        '  "changes_made": "<what was changed>",\n'
        '  "expected_outcome": "crash"|"code_execution"|"info_leak"\n'
        "}\n"
    )


def _parse_json_response(stdout: str) -> dict[str, object] | None:
    from .llm_driver import parse_json_from_llm_output

    return parse_json_from_llm_output(stdout)


def _try_execute_poc(poc_path: Path, *, timeout_s: float = 30.0) -> dict[str, object]:
    """Attempt to execute a PoC script and check for SCOUT_MARKER or crash."""
    result: dict[str, object] = {
        "executed": False,
        "success": False,
        "stdout": "",
        "stderr": "",
        "returncode": -1,
    }
    try:
        cp = subprocess.run(
            ["python3", str(poc_path)],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
            stdin=subprocess.DEVNULL,
        )
        result["executed"] = True
        result["stdout"] = (cp.stdout or "")[:2000]
        result["stderr"] = (cp.stderr or "")[:2000]
        result["returncode"] = cp.returncode

        stdout_str = cp.stdout or ""
        stderr_str = cp.stderr or ""
        if _SCOUT_MARKER in stdout_str or _SCOUT_MARKER in stderr_str:
            result["success"] = True
        elif cp.returncode != 0:
            # Non-zero exit may indicate a crash was triggered
            result["crash_detected"] = True
    except subprocess.TimeoutExpired:
        result["executed"] = True
        result["timeout"] = True
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    return result


@dataclass(frozen=True)
class PoCRefinementStage:
    """Iterative PoC generation from fuzzing seeds."""

    no_llm: bool = False

    @property
    def name(self) -> str:
        return "poc_refinement"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "poc_refinement"
        out_json = stage_dir / "poc_results.json"
        pocs_dir = stage_dir / "pocs"

        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        assert_under_dir(run_dir, out_json)
        assert_under_dir(run_dir, pocs_dir)
        pocs_dir.mkdir(parents=True, exist_ok=True)

        limitations: list[str] = []

        # --- Skip under --no-llm ---
        if self.no_llm:
            payload: dict[str, JsonValue] = {
                "schema_version": _SCHEMA_VERSION,
                "status": "skipped",
                "reason": "no_llm_mode",
                "poc_results": [],
            }
            out_json.write_text(
                json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="skipped",
                details=cast(dict[str, JsonValue], {"reason": "no_llm_mode"}),
                limitations=["no_llm_mode"],
            )

        # --- Load crash inputs from fuzzing stage ---
        fuzzing_dir = run_dir / "stages" / "fuzzing"
        crashes: list[dict[str, object]] = []

        fuzz_stage = _load_json_file(fuzzing_dir / "stage.json")
        if isinstance(fuzz_stage, dict):
            crashes_any = cast(dict[str, object], fuzz_stage).get("crashes")
            if isinstance(crashes_any, list):
                for c in cast(list[object], crashes_any):
                    if isinstance(c, dict):
                        crashes.append(cast(dict[str, object], c))

        # Also scan for crash files in fuzzing output
        crash_files_dir = fuzzing_dir / "crashes"
        if crash_files_dir.is_dir():
            for crash_file in sorted(crash_files_dir.iterdir()):
                if crash_file.is_file() and crash_file.stat().st_size > 0:
                    try:
                        crash_hex = crash_file.read_bytes().hex()
                        crashes.append(
                            {
                                "file": str(crash_file.name),
                                "hex": crash_hex,
                                "size": crash_file.stat().st_size,
                            }
                        )
                    except Exception:
                        pass
                    if len(crashes) >= 20:
                        break

        # --- Load taint alerts ---
        taint_alerts: list[dict[str, object]] = []

        # Primary: taint_propagation alerts
        taint_path = run_dir / "stages" / "taint_propagation" / "alerts.json"
        taint_data = _load_json_file(taint_path)
        if isinstance(taint_data, dict):
            alerts_any = cast(dict[str, object], taint_data).get("alerts")
            if isinstance(alerts_any, list):
                for a in cast(list[object], alerts_any):
                    if isinstance(a, dict):
                        taint_alerts.append(cast(dict[str, object], a))

        # Fallback 1: fp_verification verified alerts
        if not taint_alerts:
            fp_path = run_dir / "stages" / "fp_verification" / "verified_alerts.json"
            fp_data = _load_json_file(fp_path)
            if isinstance(fp_data, dict):
                fp_any = cast(dict[str, object], fp_data).get("verified_alerts")
                if isinstance(fp_any, list):
                    for a in cast(list[object], fp_any):
                        if isinstance(a, dict):
                            taint_alerts.append(cast(dict[str, object], a))

        # Fallback 2: exploit_candidates.json
        if not taint_alerts and not crashes:
            ec_path = run_dir / "stages" / "findings" / "exploit_candidates.json"
            ec_data = _load_json_file(ec_path)
            if isinstance(ec_data, dict):
                ec_cands = cast(dict[str, object], ec_data).get("candidates")
                if isinstance(ec_cands, list):
                    for c_any in cast(list[object], ec_cands):
                        if not isinstance(c_any, dict):
                            continue
                        c = cast(dict[str, object], c_any)
                        families = c.get("families", [])
                        family_str = ""
                        if isinstance(families, list) and families:
                            family_str = str(families[0])
                        cand_path = str(c.get("path", ""))
                        # Determine sink_symbol from family
                        sink_sym = "system"
                        if "buffer" in family_str.lower():
                            sink_sym = "strcpy"
                        elif "credential" in family_str.lower():
                            sink_sym = "credential_exposure"
                        taint_alerts.append(
                            {
                                "source_api": "external_input",
                                "source_binary": cand_path,
                                "source_address": "0x0",
                                "sink_symbol": sink_sym,
                                "confidence": 0.45,
                                "path_description": (
                                    f"Exploit candidate: {family_str} in "
                                    f"{cand_path}"
                                ),
                                "method": "exploit_candidate_fallback",
                                "attack_hypothesis": str(
                                    c.get("attack_hypothesis", "")
                                ),
                            }
                        )
                    if taint_alerts:
                        limitations.append(
                            "Using exploit_candidates for PoC generation "
                            "(no fuzzing crashes or taint alerts available)"
                        )

        # Fallback 3: pattern_scan findings
        if not taint_alerts and not crashes:
            ps_path = run_dir / "stages" / "findings" / "pattern_scan.json"
            ps_data = _load_json_file(ps_path)
            if isinstance(ps_data, dict):
                ps_findings = cast(dict[str, object], ps_data).get("findings")
                if isinstance(ps_findings, list):
                    for f_any in cast(list[object], ps_findings):
                        if not isinstance(f_any, dict):
                            continue
                        f = cast(dict[str, object], f_any)
                        family = str(f.get("family", ""))
                        conf = f.get("confidence", "low")
                        # Only use medium/high confidence findings
                        if conf not in ("medium", "high"):
                            continue
                        ev_list = f.get("evidence", [])
                        bin_path = ""
                        if isinstance(ev_list, list) and ev_list:
                            first_ev = ev_list[0]
                            if isinstance(first_ev, dict):
                                bin_path = str(
                                    cast(dict[str, object], first_ev).get("path", "")
                                )
                        sink_sym = "system"
                        if "buffer" in family.lower():
                            sink_sym = "strcpy"
                        elif "format" in family.lower():
                            sink_sym = "sprintf"
                        taint_alerts.append(
                            {
                                "source_api": "external_input",
                                "source_binary": bin_path,
                                "source_address": "0x0",
                                "sink_symbol": sink_sym,
                                "confidence": 0.40,
                                "path_description": (
                                    f"Pattern scan finding: {family} in " f"{bin_path}"
                                ),
                                "method": "pattern_scan_fallback",
                            }
                        )
                    if taint_alerts:
                        limitations.append(
                            "Using pattern_scan findings for PoC generation "
                            "(no fuzzing crashes or taint alerts available)"
                        )

        # Fallback 4: enhanced_source sources (synthesize taint-like entries)
        if not taint_alerts and not crashes:
            es_path = run_dir / "stages" / "enhanced_source" / "sources.json"
            es_data = _load_json_file(es_path)
            if isinstance(es_data, dict):
                es_sources = cast(dict[str, object], es_data).get("sources")
                if isinstance(es_sources, list):
                    for s_any in cast(list[object], es_sources):
                        if not isinstance(s_any, dict):
                            continue
                        s = cast(dict[str, object], s_any)
                        sink_apis = s.get("matched_sink_apis")
                        if not isinstance(sink_apis, list) or not sink_apis:
                            continue
                        # Create a taint-like alert for PoC generation
                        for sink_api in cast(list[object], sink_apis):
                            if not isinstance(sink_api, str):
                                continue
                            taint_alerts.append(
                                {
                                    "source_api": str(s.get("api", "")),
                                    "source_binary": str(s.get("binary", "")),
                                    "source_address": str(s.get("address", "0x0")),
                                    "sink_symbol": sink_api,
                                    "confidence": safe_float(
                                        s.get("confidence"), default=0.4
                                    ),
                                    "path_description": (
                                        f"Static source: {s.get('binary', '')} "
                                        f"imports {s.get('api', '')}() and "
                                        f"{sink_api}()"
                                    ),
                                    "method": "enhanced_source_fallback",
                                }
                            )
                    if taint_alerts:
                        limitations.append(
                            "Using enhanced_source data for PoC generation "
                            "(no fuzzing crashes or taint alerts available)"
                        )

        if not crashes and not taint_alerts:
            limitations.append(
                "No fuzzing crashes, taint alerts, or source data "
                "available for PoC generation"
            )
            payload = {
                "schema_version": _SCHEMA_VERSION,
                "status": "skipped",
                "reason": "no_input_data",
                "poc_results": [],
                "limitations": cast(list[JsonValue], cast(list[object], limitations)),
            }
            out_json.write_text(
                json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="skipped",
                details=cast(dict[str, JsonValue], {"reason": "no_input_data"}),
                limitations=limitations,
            )

        # --- Check LLM budget ---
        budget_str = os.environ.get("AIEDGE_LLM_BUDGET_USD", "")
        has_budget_limit = bool(budget_str.strip())

        # --- Generate PoCs ---
        driver = resolve_driver()
        poc_results: list[dict[str, JsonValue]] = []

        if not driver.available():
            limitations.append("LLM driver not available for PoC generation")
        else:
            # Pair crashes with taint alerts
            pairs: list[tuple[dict[str, object], dict[str, object]]] = []
            for crash in crashes[:5]:
                if taint_alerts:
                    for alert in taint_alerts[:3]:
                        pairs.append((crash, alert))
                else:
                    pairs.append((crash, {}))

            # If no crashes but taint alerts exist, use alerts alone
            if not crashes:
                for alert in taint_alerts[:5]:
                    pairs.append(({}, alert))

            for pair_idx, (crash, taint_alert) in enumerate(pairs[:10]):
                crash_hex = str(crash.get("hex", ""))
                if not crash_hex and crash.get("file"):
                    crash_hex = f"(crash file: {crash.get('file')})"

                vuln_type = str(taint_alert.get("sink_symbol", "buffer_overflow"))
                if vuln_type in ("system", "popen", "execve"):
                    vuln_type = "command_injection"
                elif vuln_type in ("strcpy", "sprintf", "gets"):
                    vuln_type = "buffer_overflow"

                prompt = _build_poc_prompt(crash_hex, taint_alert, vuln_type)
                result = driver.execute(
                    prompt=prompt,
                    run_dir=run_dir,
                    timeout_s=_LLM_TIMEOUT_S,
                    max_attempts=_LLM_MAX_ATTEMPTS,
                    retryable_tokens=_RETRYABLE_TOKENS,
                    model_tier="sonnet",
                )

                poc_entry: dict[str, JsonValue] = {
                    "pair_index": pair_idx,
                    "vuln_type": vuln_type,
                    "status": "failed",
                    "attempts": 0,
                }

                if result.status == "ok":
                    parsed = _parse_json_response(result.stdout)
                    if parsed is not None:
                        poc_script = str(parsed.get("poc_script", ""))
                        if poc_script:
                            poc_file = pocs_dir / f"poc_{pair_idx}.py"
                            assert_under_dir(run_dir, poc_file)
                            poc_file.write_text(poc_script, encoding="utf-8")

                            poc_entry["status"] = "generated"
                            poc_entry["poc_file"] = f"pocs/poc_{pair_idx}.py"
                            poc_entry["description"] = str(
                                parsed.get("description", "")
                            )
                            poc_entry["target_binary"] = str(
                                parsed.get("target_binary", "")
                            )
                            poc_entry["attempts"] = 1

                            # Refinement loop (if budget allows)
                            if not has_budget_limit:
                                current_poc = poc_script
                                for attempt in range(2, _MAX_REFINEMENT_ATTEMPTS + 1):
                                    exec_result = _try_execute_poc(poc_file)
                                    if exec_result.get("success"):
                                        poc_entry["status"] = "validated"
                                        poc_entry["validation"] = cast(
                                            dict[str, JsonValue],
                                            exec_result,
                                        )
                                        break

                                    if not exec_result.get("executed"):
                                        break

                                    # Refine
                                    crash_log = (
                                        str(exec_result.get("stderr", ""))
                                        + "\n"
                                        + str(exec_result.get("stdout", ""))
                                    )
                                    refine_prompt = _build_refinement_prompt(
                                        current_poc, crash_log, attempt
                                    )
                                    refine_result = driver.execute(
                                        prompt=refine_prompt,
                                        run_dir=run_dir,
                                        timeout_s=_LLM_TIMEOUT_S,
                                        max_attempts=2,
                                        retryable_tokens=_RETRYABLE_TOKENS,
                                        model_tier="sonnet",
                                    )
                                    if refine_result.status == "ok":
                                        refine_parsed = _parse_json_response(
                                            refine_result.stdout
                                        )
                                        if refine_parsed is not None:
                                            new_script = str(
                                                refine_parsed.get("poc_script", "")
                                            )
                                            if new_script:
                                                current_poc = new_script
                                                poc_file.write_text(
                                                    new_script,
                                                    encoding="utf-8",
                                                )
                                                poc_entry["attempts"] = attempt
                                    else:
                                        break
                        else:
                            limitations.append(
                                "PoC refinement loop skipped due to LLM budget limit"
                            )

                poc_results.append(poc_entry)

        status: StageStatus = "ok"
        generated = sum(
            1
            for p in poc_results
            if cast(str, p.get("status")) in ("generated", "validated")
        )
        validated = sum(
            1 for p in poc_results if cast(str, p.get("status")) == "validated"
        )
        if not poc_results or generated == 0:
            status = "partial"

        payload = {
            "schema_version": _SCHEMA_VERSION,
            "status": status,
            "poc_results": cast(list[JsonValue], cast(list[object], poc_results)),
            "summary": {
                "total_pairs": len(poc_results),
                "generated": generated,
                "validated": validated,
            },
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limitations)))
            ),
        }
        out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        details: dict[str, JsonValue] = {
            "generated": generated,
            "validated": validated,
            "total_pairs": len(poc_results),
        }
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
