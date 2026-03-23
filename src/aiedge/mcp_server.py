"""mcp_server.py — MCP (Model Context Protocol) stdio server for SCOUT.

Exposes SCOUT firmware analysis capabilities as MCP tools so any
MCP-compatible AI agent (Claude Code, Claude Desktop, etc.) can drive
firmware analysis without shell access.

Transport: newline-delimited JSON over stdin/stdout (JSON-RPC 2.0).
Errors are written to stderr; stdout is the exclusive MCP channel.

Usage::

    python -m aiedge.mcp_server
    # or via ./scout mcp-server (if wired in __main__.py)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from .path_safety import assert_under_dir
from .policy import AIEdgePolicyViolation

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SERVER_NAME = "scout"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSION = "2024-11-05"

_MAX_OUTPUT_BYTES = int(os.environ.get("AIEDGE_MCP_MAX_OUTPUT_KB", "30")) * 1024

# Root of the SCOUT project (two levels up from src/aiedge/)
_SRC_DIR = Path(__file__).parent          # src/aiedge/
_PROJECT_ROOT = _SRC_DIR.parent.parent    # SCOUT/
_RUNS_DIR = _PROJECT_ROOT / "aiedge-runs"

# ---------------------------------------------------------------------------
# Tool definitions (schema only — implementation below)
# ---------------------------------------------------------------------------

TOOLS: list[dict[str, Any]] = [
    {
        "name": "scout_list_runs",
        "description": "List available SCOUT analysis run directories.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "scout_stage_status",
        "description": (
            "Get status of stages in a run. "
            "Returns stage name, status (ok/partial/failed/skipped), "
            "duration, and limitations."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {
                    "type": "string",
                    "description": "Run directory name (e.g. 20250101_120000_abc123)",
                },
                "stage": {
                    "type": "string",
                    "description": "Optional: specific stage name to inspect",
                },
            },
            "required": ["run_id"],
        },
    },
    {
        "name": "scout_read_artifact",
        "description": "Read a stage artifact file (JSON or text, max 30 KB).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "path": {
                    "type": "string",
                    "description": (
                        "Relative path within run dir, "
                        "e.g. stages/inventory/inventory.json"
                    ),
                },
            },
            "required": ["run_id", "path"],
        },
    },
    {
        "name": "scout_list_findings",
        "description": (
            "List security findings from a run, "
            "optionally filtered by severity and minimum confidence."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                    "description": "Filter to this severity level only",
                },
                "min_confidence": {
                    "type": "number",
                    "description": "Minimum confidence score (0.0–1.0)",
                },
            },
            "required": ["run_id"],
        },
    },
    {
        "name": "scout_sbom",
        "description": "Get CycloneDX SBOM (Software Bill of Materials) from a run.",
        "inputSchema": {
            "type": "object",
            "properties": {"run_id": {"type": "string"}},
            "required": ["run_id"],
        },
    },
    {
        "name": "scout_cve_lookup",
        "description": "Look up CVE matches for firmware components.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "component": {
                    "type": "string",
                    "description": "Optional: filter by component name substring",
                },
            },
            "required": ["run_id"],
        },
    },
    {
        "name": "scout_binary_info",
        "description": (
            "Get binary analysis info including hardening status "
            "(NX, PIE, RELRO, Canary)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "binary_path": {
                    "type": "string",
                    "description": "Optional: filter by specific binary path substring",
                },
            },
            "required": ["run_id"],
        },
    },
    {
        "name": "scout_attack_surface",
        "description": "Get attack surface analysis summary.",
        "inputSchema": {
            "type": "object",
            "properties": {"run_id": {"type": "string"}},
            "required": ["run_id"],
        },
    },
    {
        "name": "scout_graph",
        "description": (
            "Get communication graph showing service relationships "
            "and IPC channels."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {"run_id": {"type": "string"}},
            "required": ["run_id"],
        },
    },
    {
        "name": "scout_run_stage",
        "description": "Re-run specific stages on an existing analysis run.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "run_id": {"type": "string"},
                "stages": {
                    "type": "string",
                    "description": "Comma-separated stage names, e.g. inventory,sbom",
                },
            },
            "required": ["run_id", "stages"],
        },
    },
    {
        "name": "scout_analyze",
        "description": "Start a new firmware analysis (launches in background).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "firmware_path": {
                    "type": "string",
                    "description": "Absolute path to the firmware file",
                },
                "case_id": {
                    "type": "string",
                    "description": "Case identifier for this analysis",
                },
                "no_llm": {
                    "type": "boolean",
                    "description": "Disable LLM calls (default: true)",
                    "default": True,
                },
            },
            "required": ["firmware_path", "case_id"],
        },
    },
    {
        "name": "scout_cert_analysis",
        "description": "Get X.509 certificate analysis results.",
        "inputSchema": {
            "type": "object",
            "properties": {"run_id": {"type": "string"}},
            "required": ["run_id"],
        },
    },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _err(msg: str) -> None:
    """Write a message to stderr (never stdout)."""
    print(f"[scout-mcp] {msg}", file=sys.stderr, flush=True)


def _truncate(text: str, max_bytes: int = _MAX_OUTPUT_BYTES) -> str:
    """Truncate *text* to *max_bytes* UTF-8 bytes, appending a notice."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= max_bytes:
        return text
    truncated = encoded[:max_bytes].decode("utf-8", errors="replace")
    return truncated + f"\n\n[TRUNCATED: output exceeded {max_bytes // 1024} KB limit]"


def _truncate_json(obj: Any, max_bytes: int = _MAX_OUTPUT_BYTES) -> str:
    """Serialize JSON, truncating large arrays to stay within *max_bytes*."""
    text = json.dumps(obj, indent=2, sort_keys=True)
    if len(text.encode("utf-8", errors="replace")) <= max_bytes:
        return text
    if not isinstance(obj, dict):
        return json.dumps({"_truncated": "object too large", "_type": str(type(obj).__name__)})
    # Iteratively trim largest lists until it fits
    trimmed: dict[str, Any] = {}
    for k, v in obj.items():
        trimmed[k] = v
    for _ in range(10):
        list_keys = [(k, len(v)) for k, v in trimmed.items() if isinstance(v, list) and len(v) > 3]
        if not list_keys:
            break
        list_keys.sort(key=lambda x: -x[1])
        key, length = list_keys[0]
        keep = max(3, length // 4)
        original = trimmed[key]
        trimmed[key] = original[:keep] + [{"_truncated": f"{length - keep} of {length} items omitted"}]
        text = json.dumps(trimmed, indent=2, sort_keys=True)
        if len(text.encode("utf-8", errors="replace")) <= max_bytes:
            return text
    # Final: strip all lists to max 2 items
    minimal: dict[str, Any] = {}
    for k, v in trimmed.items():
        if isinstance(v, list) and len(v) > 2:
            minimal[k] = v[:2] + [{"_truncated": f"{len(v) - 2} more items"}]
        elif isinstance(v, dict) and len(json.dumps(v, default=str)) > 2000:
            minimal[k] = {"_truncated": "object too large"}
        else:
            minimal[k] = v
    return json.dumps(minimal, indent=2, sort_keys=True, default=str)


def _text_result(text: str) -> list[dict[str, str]]:
    """Wrap a string as an MCP content block."""
    return [{"type": "text", "text": _truncate(text)}]


def _json_result(obj: Any) -> list[dict[str, str]]:
    """Serialize *obj* as deterministic JSON and wrap as MCP content block."""
    return [{"type": "text", "text": _truncate_json(obj)}]


def _resolve_run_dir(run_id: str) -> Path:
    """Return the validated run directory for *run_id*.

    Raises:
        AIEdgePolicyViolation: if path escapes aiedge-runs/.
        FileNotFoundError: if the directory does not exist.
    """
    runs_base = _RUNS_DIR.resolve()
    candidate = (runs_base / run_id).resolve()
    # Path containment check — assert_under_dir works on files; do it manually
    # for directories so we can raise a friendlier error.
    if not str(candidate).startswith(str(runs_base)):
        raise AIEdgePolicyViolation(
            f"run_id escapes runs directory: {run_id!r}"
        )
    if not candidate.is_dir():
        raise FileNotFoundError(f"Run directory not found: {candidate}")
    return candidate


def _read_json(path: Path) -> Any:
    """Read and parse a JSON file."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        return json.load(fh)


def _read_stage_json(run_dir: Path, stage: str) -> dict[str, Any]:
    """Read the stage.json for a named stage within *run_dir*."""
    stage_json = run_dir / "stages" / stage / "stage.json"
    assert_under_dir(run_dir, stage_json)
    if not stage_json.is_file():
        raise FileNotFoundError(f"stage.json not found for stage {stage!r}")
    return _read_json(stage_json)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def _tool_list_runs() -> list[dict[str, str]]:
    if not _RUNS_DIR.is_dir():
        return _text_result("No aiedge-runs directory found.")
    runs = sorted(
        (d.name for d in _RUNS_DIR.iterdir() if d.is_dir()),
        reverse=True,
    )
    if not runs:
        return _text_result("No runs found in aiedge-runs/.")
    return _text_result("\n".join(runs))


def _tool_stage_status(args: dict[str, Any]) -> list[dict[str, str]]:
    run_id: str = args["run_id"]
    stage_filter: str | None = args.get("stage")

    run_dir = _resolve_run_dir(run_id)
    stages_dir = run_dir / "stages"

    if not stages_dir.is_dir():
        return _text_result(f"No stages directory found in run {run_id!r}.")

    results: list[dict[str, Any]] = []
    stage_dirs = sorted(d for d in stages_dir.iterdir() if d.is_dir())

    for stage_dir in stage_dirs:
        stage_name = stage_dir.name
        if stage_filter and stage_name != stage_filter:
            continue
        stage_json_path = stage_dir / "stage.json"
        assert_under_dir(run_dir, stage_json_path)
        if not stage_json_path.is_file():
            results.append({"stage": stage_name, "status": "missing_stage_json"})
            continue
        try:
            data = _read_json(stage_json_path)
            results.append(
                {
                    "stage": stage_name,
                    "status": data.get("status", "unknown"),
                    "duration_s": data.get("duration_s"),
                    "started_at": data.get("started_at"),
                    "finished_at": data.get("finished_at"),
                    "limitations": data.get("limitations", []),
                    "error": data.get("error"),
                }
            )
        except Exception as exc:
            results.append({"stage": stage_name, "error": str(exc)})

    if not results:
        msg = (
            f"Stage {stage_filter!r} not found in run {run_id!r}."
            if stage_filter
            else f"No stage directories found in run {run_id!r}."
        )
        return _text_result(msg)

    return _json_result(results)


def _tool_read_artifact(args: dict[str, Any]) -> list[dict[str, str]]:
    run_id: str = args["run_id"]
    rel_path: str = args["path"]

    run_dir = _resolve_run_dir(run_id)
    target = (run_dir / rel_path).resolve()
    assert_under_dir(run_dir, target)

    if not target.is_file():
        return _text_result(f"Artifact not found: {rel_path!r} in run {run_id!r}.")

    raw = target.read_bytes()
    # Attempt JSON parse for pretty output; fall back to raw text.
    try:
        parsed = json.loads(raw)
        return _json_result(parsed)
    except json.JSONDecodeError:
        return _text_result(raw.decode("utf-8", errors="replace"))


def _tool_list_findings(args: dict[str, Any]) -> list[dict[str, str]]:
    run_id: str = args["run_id"]
    severity_filter: str | None = args.get("severity")
    min_confidence: float | None = args.get("min_confidence")

    run_dir = _resolve_run_dir(run_id)

    # Findings live in stages/findings/findings.json (array) or
    # stages/findings/*.json depending on version.
    candidates = [
        run_dir / "stages" / "findings" / "findings.json",
        run_dir / "stages" / "llm_triage" / "findings.json",
    ]

    findings: list[Any] = []
    loaded = False
    for candidate in candidates:
        if candidate.is_file():
            assert_under_dir(run_dir, candidate)
            try:
                data = _read_json(candidate)
                if isinstance(data, list):
                    findings = data
                elif isinstance(data, dict) and "findings" in data:
                    findings = data["findings"]
                loaded = True
                break
            except Exception as exc:
                _err(f"Failed to read {candidate}: {exc}")

    if not loaded:
        return _text_result(
            f"No findings artifact found in run {run_id!r}. "
            "Ensure the findings stage has completed."
        )

    # Apply filters
    if severity_filter:
        findings = [
            f for f in findings
            if isinstance(f, dict)
            and f.get("severity", "").lower() == severity_filter.lower()
        ]
    if min_confidence is not None:
        findings = [
            f for f in findings
            if isinstance(f, dict)
            and float(f.get("confidence", 0.0)) >= min_confidence
        ]

    summary = {
        "total": len(findings),
        "filters_applied": {
            "severity": severity_filter,
            "min_confidence": min_confidence,
        },
        "findings": findings,
    }
    return _json_result(summary)


def _tool_sbom(args: dict[str, Any]) -> list[dict[str, str]]:
    run_id: str = args["run_id"]
    run_dir = _resolve_run_dir(run_id)

    sbom_path = run_dir / "stages" / "sbom" / "sbom.json"
    assert_under_dir(run_dir, sbom_path)

    if not sbom_path.is_file():
        return _text_result(
            f"SBOM artifact not found in run {run_id!r}. "
            "Ensure the sbom stage has completed."
        )
    try:
        data = _read_json(sbom_path)
        return _json_result(data)
    except Exception as exc:
        return _text_result(f"Failed to read SBOM: {exc}")


def _tool_cve_lookup(args: dict[str, Any]) -> list[dict[str, str]]:
    run_id: str = args["run_id"]
    component_filter: str | None = args.get("component")
    run_dir = _resolve_run_dir(run_id)

    cve_path = run_dir / "stages" / "cve_scan" / "cve_matches.json"
    assert_under_dir(run_dir, cve_path)

    if not cve_path.is_file():
        return _text_result(
            f"CVE scan artifact not found in run {run_id!r}. "
            "Ensure the cve_scan stage has completed."
        )
    try:
        data = _read_json(cve_path)
        matches: list[Any] = data if isinstance(data, list) else data.get("matches", [])
        if component_filter:
            component_lower = component_filter.lower()
            matches = [
                m for m in matches
                if isinstance(m, dict)
                and component_lower in str(m.get("component", "")).lower()
            ]
        result = {"total_matches": len(matches), "matches": matches}
        return _json_result(result)
    except Exception as exc:
        return _text_result(f"Failed to read CVE matches: {exc}")


def _tool_binary_info(args: dict[str, Any]) -> list[dict[str, str]]:
    run_id: str = args["run_id"]
    binary_filter: str | None = args.get("binary_path")
    run_dir = _resolve_run_dir(run_id)

    # Binary hardening info is typically in the inventory stage.
    candidates = [
        run_dir / "stages" / "inventory" / "binaries.json",
        run_dir / "stages" / "inventory" / "inventory.json",
    ]

    for candidate in candidates:
        if not candidate.is_file():
            continue
        assert_under_dir(run_dir, candidate)
        try:
            data = _read_json(candidate)
            # Normalise: if top-level has a "binaries" key, pull it out.
            binaries: list[Any]
            if isinstance(data, list):
                binaries = data
            elif isinstance(data, dict):
                binaries = data.get("binaries", [data])
            else:
                binaries = []

            if binary_filter:
                flt = binary_filter.lower()
                binaries = [
                    b for b in binaries
                    if isinstance(b, dict)
                    and flt in str(b.get("path", "")).lower()
                ]

            result = {"total": len(binaries), "binaries": binaries}
            return _json_result(result)
        except Exception as exc:
            return _text_result(f"Failed to read binary info: {exc}")

    return _text_result(
        f"Binary info not found in run {run_id!r}. "
        "Ensure the inventory stage has completed."
    )


def _tool_attack_surface(args: dict[str, Any]) -> list[dict[str, str]]:
    run_id: str = args["run_id"]
    run_dir = _resolve_run_dir(run_id)

    candidates = [
        run_dir / "stages" / "attack_surface" / "attack_surface.json",
        run_dir / "stages" / "surfaces" / "surfaces.json",
    ]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        assert_under_dir(run_dir, candidate)
        try:
            return _json_result(_read_json(candidate))
        except Exception as exc:
            return _text_result(f"Failed to read attack surface: {exc}")

    return _text_result(
        f"Attack surface artifact not found in run {run_id!r}. "
        "Ensure the attack_surface or surfaces stage has completed."
    )


def _tool_graph(args: dict[str, Any]) -> list[dict[str, str]]:
    run_id: str = args["run_id"]
    run_dir = _resolve_run_dir(run_id)

    graph_path = run_dir / "stages" / "graph" / "communication_graph.json"
    assert_under_dir(run_dir, graph_path)

    if not graph_path.is_file():
        return _text_result(
            f"Communication graph not found in run {run_id!r}. "
            "Ensure the graph stage has completed."
        )
    try:
        return _json_result(_read_json(graph_path))
    except Exception as exc:
        return _text_result(f"Failed to read graph: {exc}")


def _tool_run_stage(args: dict[str, Any]) -> list[dict[str, str]]:
    run_id: str = args["run_id"]
    stages: str = args["stages"]

    # Validate run_id resolves to a real directory.
    run_dir = _resolve_run_dir(run_id)

    scout_bin = _PROJECT_ROOT / "scout"
    if not scout_bin.is_file():
        return _text_result(
            f"./scout binary not found at {scout_bin}. "
            "Cannot re-run stages."
        )

    cmd = [
        str(scout_bin),
        "stages",
        str(run_dir),
        "--no-llm",
        "--stages",
        stages,
    ]
    _err(f"Executing: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=3600,
        )
        output = {
            "returncode": result.returncode,
            "stdout": result.stdout[-8000:] if result.stdout else "",
            "stderr": result.stderr[-4000:] if result.stderr else "",
        }
        return _json_result(output)
    except subprocess.TimeoutExpired:
        return _text_result("Stage re-run timed out after 3600 seconds.")
    except Exception as exc:
        return _text_result(f"Failed to run stage: {exc}")


def _tool_analyze(args: dict[str, Any]) -> list[dict[str, str]]:
    firmware_path: str = args["firmware_path"]
    case_id: str = args["case_id"]
    no_llm: bool = args.get("no_llm", True)

    fw = Path(firmware_path)
    if not fw.is_file():
        return _text_result(f"Firmware file not found: {firmware_path!r}")

    scout_bin = _PROJECT_ROOT / "scout"
    if not scout_bin.is_file():
        return _text_result(f"./scout binary not found at {scout_bin}.")

    cmd = [
        str(scout_bin),
        "analyze",
        str(fw),
        "--ack-authorization",
        "--case-id",
        case_id,
    ]
    if no_llm:
        cmd.append("--no-llm")

    _err(f"Launching background analysis: {' '.join(cmd)}")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return _text_result(
            f"Analysis started in background (PID {proc.pid}).\n"
            f"Firmware: {firmware_path}\n"
            f"Case ID: {case_id}\n"
            f"LLM: {'disabled' if no_llm else 'enabled'}\n\n"
            "Use scout_list_runs to find the run directory once complete, "
            "then scout_stage_status to track progress."
        )
    except Exception as exc:
        return _text_result(f"Failed to launch analysis: {exc}")


def _tool_cert_analysis(args: dict[str, Any]) -> list[dict[str, str]]:
    run_id: str = args["run_id"]
    run_dir = _resolve_run_dir(run_id)

    # cert_analysis writes into the findings stage area; check common locations.
    candidates = [
        run_dir / "stages" / "findings" / "cert_analysis.json",
        run_dir / "stages" / "inventory" / "cert_analysis.json",
        run_dir / "stages" / "cert_analysis" / "cert_analysis.json",
    ]
    for candidate in candidates:
        if not candidate.is_file():
            continue
        assert_under_dir(run_dir, candidate)
        try:
            return _json_result(_read_json(candidate))
        except Exception as exc:
            return _text_result(f"Failed to read cert analysis: {exc}")

    return _text_result(
        f"Certificate analysis artifact not found in run {run_id!r}. "
        "Ensure the findings stage has completed (cert analysis runs as part of findings)."
    )


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

_TOOL_HANDLERS: dict[str, Any] = {
    "scout_list_runs": lambda _args: _tool_list_runs(),
    "scout_stage_status": _tool_stage_status,
    "scout_read_artifact": _tool_read_artifact,
    "scout_list_findings": _tool_list_findings,
    "scout_sbom": _tool_sbom,
    "scout_cve_lookup": _tool_cve_lookup,
    "scout_binary_info": _tool_binary_info,
    "scout_attack_surface": _tool_attack_surface,
    "scout_graph": _tool_graph,
    "scout_run_stage": _tool_run_stage,
    "scout_analyze": _tool_analyze,
    "scout_cert_analysis": _tool_cert_analysis,
}

# ---------------------------------------------------------------------------
# JSON-RPC helpers
# ---------------------------------------------------------------------------


def _rpc_result(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _rpc_error(
    request_id: Any,
    code: int,
    message: str,
    data: Any = None,
) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": err}


# JSON-RPC 2.0 error codes
_ERR_PARSE = -32700
_ERR_INVALID_REQUEST = -32600
_ERR_METHOD_NOT_FOUND = -32601
_ERR_INVALID_PARAMS = -32602
_ERR_INTERNAL = -32603


# ---------------------------------------------------------------------------
# Request handling
# ---------------------------------------------------------------------------


def _handle_initialize(request_id: Any, _params: Any) -> dict[str, Any]:
    return _rpc_result(
        request_id,
        {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        },
    )


def _handle_tools_list(request_id: Any, _params: Any) -> dict[str, Any]:
    return _rpc_result(request_id, {"tools": TOOLS})


def _handle_tools_call(request_id: Any, params: Any) -> dict[str, Any]:
    if not isinstance(params, dict):
        return _rpc_error(request_id, _ERR_INVALID_PARAMS, "params must be an object")

    tool_name: str = params.get("name", "")
    arguments: dict[str, Any] = params.get("arguments", {})

    if not tool_name:
        return _rpc_error(request_id, _ERR_INVALID_PARAMS, "missing tool name")

    handler = _TOOL_HANDLERS.get(tool_name)
    if handler is None:
        return _rpc_error(
            request_id,
            _ERR_METHOD_NOT_FOUND,
            f"Unknown tool: {tool_name!r}",
        )

    try:
        content = handler(arguments)
        return _rpc_result(request_id, {"content": content})
    except AIEdgePolicyViolation as exc:
        _err(f"Policy violation in {tool_name}: {exc}")
        return _rpc_result(
            request_id,
            {
                "content": _text_result(f"Policy violation: {exc}"),
                "isError": True,
            },
        )
    except FileNotFoundError as exc:
        return _rpc_result(
            request_id,
            {
                "content": _text_result(f"Not found: {exc}"),
                "isError": True,
            },
        )
    except Exception as exc:
        _err(f"Unhandled error in {tool_name}: {exc}")
        return _rpc_result(
            request_id,
            {
                "content": _text_result(f"Internal error: {exc}"),
                "isError": True,
            },
        )


def handle_request(request: Any, project_id: str | None = None) -> dict[str, Any] | None:
    """Route a single JSON-RPC request to the appropriate handler.

    Returns None for notifications (no response expected).

    Args:
        request: Parsed JSON object from stdin.
        project_id: Optional project identifier passed at server startup.

    Returns:
        A JSON-RPC response dict, or None if the request is a notification.
    """
    if not isinstance(request, dict):
        return _rpc_error(None, _ERR_INVALID_REQUEST, "Request must be a JSON object")

    method: str = request.get("method", "")
    params: Any = request.get("params")
    request_id: Any = request.get("id")  # None for notifications

    # Notifications have no "id" — do not send a response.
    is_notification = "id" not in request

    if method == "initialize":
        return _handle_initialize(request_id, params)

    if method == "notifications/initialized":
        # Client confirms initialisation — no response.
        return None

    if is_notification:
        # Unknown notification — silently ignore.
        return None

    if method == "tools/list":
        return _handle_tools_list(request_id, params)

    if method == "tools/call":
        return _handle_tools_call(request_id, params)

    # Ping / keep-alive
    if method == "ping":
        return _rpc_result(request_id, {})

    return _rpc_error(
        request_id,
        _ERR_METHOD_NOT_FOUND,
        f"Method not found: {method!r}",
    )


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------


def main(project_id: str | None = None) -> int:
    """MCP stdio server main loop.

    Reads newline-delimited JSON from stdin, writes responses to stdout.
    Errors go to stderr (never stdout — that's the MCP channel).

    Args:
        project_id: Optional project identifier (forwarded to handlers).

    Returns:
        Exit code (always 0 on clean EOF).
    """
    _err(f"SCOUT MCP server v{SERVER_VERSION} starting (protocol {PROTOCOL_VERSION})")

    while True:
        try:
            line = sys.stdin.readline()
        except (KeyboardInterrupt, EOFError):
            break

        if not line:
            # Clean EOF — client disconnected.
            break

        line = line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            _err(f"JSON parse error: {exc} — input: {line[:200]!r}")
            # Respond with a parse error (no id available).
            error_response = _rpc_error(None, _ERR_PARSE, f"Parse error: {exc}")
            sys.stdout.write(json.dumps(error_response, sort_keys=True) + "\n")
            sys.stdout.flush()
            continue

        try:
            response = handle_request(request, project_id)
        except Exception as exc:
            _err(f"Unexpected error handling request: {exc}")
            req_id = request.get("id") if isinstance(request, dict) else None
            response = _rpc_error(req_id, _ERR_INTERNAL, f"Internal server error: {exc}")

        if response is not None:
            try:
                sys.stdout.write(json.dumps(response, sort_keys=True) + "\n")
                sys.stdout.flush()
            except Exception as exc:
                _err(f"Failed to write response: {exc}")
                break

    _err("SCOUT MCP server exiting.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
