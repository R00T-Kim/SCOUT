"""Web UI content analysis stage -- scans HTML/JS assets for security patterns."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .path_safety import assert_under_dir
from .schema import JsonValue
from .stage import StageContext, StageOutcome

_WEB_CONTENT_DIRS: tuple[str, ...] = (
    "www", "htdocs", "webroot", "html", "web", "cgi-bin",
    "webman", "webapi", "public_html",
)

_JS_SECURITY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("fetch_call", re.compile(r"\bfetch\s*\(")),
    ("axios_call", re.compile(r"\baxios\.\w+")),
    ("xmlhttprequest", re.compile(r"\bXMLHttpRequest\b")),
    ("jquery_ajax", re.compile(r"\$\.ajax\s*\(")),
    ("dangerous_js_eval", re.compile(r"\beval\s*\(")),
    ("innerhtml_assign", re.compile(r"\.innerHTML\s*=")),
    ("document_write", re.compile(r"\bdocument\.write\s*\(")),
    ("websocket_create", re.compile(r"\bnew\s+WebSocket\s*\(", re.IGNORECASE)),
    ("postmessage_call", re.compile(r"\.postMessage\s*\(")),
)

_HTML_SECURITY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("form_action", re.compile(r"<form[^>]+action\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)),
    ("script_src", re.compile(r"<script[^>]+src\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)),
    ("iframe_src", re.compile(r"<iframe[^>]+src\s*=\s*[\"']([^\"']*)[\"']", re.IGNORECASE)),
    ("inline_event_handler", re.compile(r"\bon\w+\s*=\s*[\"']", re.IGNORECASE)),
)

_API_SPEC_FILENAMES: frozenset[str] = frozenset({
    "swagger.json", "swagger.yaml", "swagger.yml",
    "openapi.json", "openapi.yaml", "openapi.yml",
    "api-docs.json",
})

_WEB_FILE_EXTENSIONS: frozenset[str] = frozenset({
    ".html", ".htm", ".js", ".mjs", ".cjs", ".jsx",
    ".php", ".asp", ".aspx", ".jsp",
})

_JS_EXTENSIONS: frozenset[str] = frozenset({".js", ".mjs", ".cjs", ".jsx"})
_HTML_EXTENSIONS: frozenset[str] = frozenset({".html", ".htm", ".php", ".asp", ".aspx", ".jsp"})



def _rel_to_run_dir(run_dir: Path, path: Path) -> str:
    try:
        resolved = path.resolve()
        run_resolved = run_dir.resolve()
        if not resolved.is_relative_to(run_resolved):
            return "<outside_run_dir>"
        return str(resolved.relative_to(run_resolved))
    except Exception:
        return "<outside_run_dir>"


def _safe_load_json_object(path: Path) -> dict[str, object]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        if isinstance(raw, dict):
            return raw
    except Exception:
        pass
    return {}


def _find_web_content_roots(
    run_dir: Path,
) -> tuple[list[Path], list[str]]:
    """Locate web content directories from inventory roots."""
    roots: list[Path] = []
    limitations: list[str] = []

    # Load inventory to find extraction roots
    inv_path = run_dir / "stages" / "inventory" / "inventory.json"
    if not inv_path.is_file():
        limitations.append("inventory.json not found; web content root discovery limited")
        # Fallback: scan extraction directory directly (with circular symlink guard)
        extraction_dir = run_dir / "stages" / "extraction"
        if extraction_dir.is_dir():
            seen_dirs: set[str] = set()
            for d in sorted(extraction_dir.rglob("*")):
                if not d.is_dir():
                    continue
                try:
                    resolved = d.resolve()
                    rkey = str(resolved)
                    if rkey in seen_dirs:
                        continue
                    seen_dirs.add(rkey)
                    if not resolved.is_relative_to(run_dir.resolve()):
                        continue
                    if d.name.lower() in _WEB_CONTENT_DIRS:
                        roots.append(d)
                except OSError:
                    pass
        return roots, limitations

    inv = _safe_load_json_object(inv_path)

    # Collect scan roots from inventory
    scan_roots: list[Path] = []
    entries_any = inv.get("entries")
    if isinstance(entries_any, list):
        for entry in entries_any:
            if isinstance(entry, dict):
                p = entry.get("path")
                if isinstance(p, str) and not p.startswith("<"):
                    full = run_dir / p
                    if full.is_dir():
                        scan_roots.append(full)
    # Also try "roots" field
    roots_any = inv.get("roots")
    if isinstance(roots_any, list):
        for root_entry in roots_any:
            if isinstance(root_entry, dict):
                p = root_entry.get("path")
                if isinstance(p, str):
                    full = run_dir / p
                    if full.is_dir():
                        scan_roots.append(full)
            elif isinstance(root_entry, str):
                full = run_dir / root_entry
                if full.is_dir():
                    scan_roots.append(full)
    if not scan_roots:
        # Use extraction dir as fallback
        extraction_dir = run_dir / "stages" / "extraction"
        if extraction_dir.is_dir():
            scan_roots.append(extraction_dir)

    # Find web content directories (with circular symlink guard)
    seen: set[str] = set()
    for scan_root in scan_roots:
        try:
            for d in sorted(scan_root.rglob("*")):
                if not d.is_dir():
                    continue
                try:
                    resolved = d.resolve()
                    rkey = str(resolved)
                    if rkey in seen:
                        continue
                    seen.add(rkey)
                    if not resolved.is_relative_to(run_dir.resolve()):
                        continue
                    if d.name.lower() in _WEB_CONTENT_DIRS:
                        roots.append(d)
                except OSError:
                    pass
        except OSError:
            limitations.append(f"Error scanning {_rel_to_run_dir(run_dir, scan_root)}")

    if not roots:
        limitations.append("No web content directories found")

    return roots, limitations


def _iter_web_files(
    roots: list[Path],
    *,
    run_dir: Path,
    max_files: int = 2000,
) -> list[Path]:
    """Walk roots and collect web-related files."""
    out: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        try:
            for p in sorted(root.rglob("*")):
                if len(out) >= max_files:
                    break
                if p.is_symlink():
                    try:
                        resolved = p.resolve()
                        if not resolved.is_relative_to(run_dir.resolve()):
                            continue
                    except OSError:
                        continue
                    if not p.is_file():
                        continue
                else:
                    if not p.is_file():
                        continue
                suffix = p.suffix.lower()
                if suffix not in _WEB_FILE_EXTENSIONS:
                    continue
                key = str(p.resolve())
                if key in seen:
                    continue
                seen.add(key)
                out.append(p)
        except OSError:
            pass
    return out


def _scan_js_file(
    path: Path,
    *,
    run_dir: Path,
    max_bytes: int = 256 * 1024,
) -> list[dict[str, JsonValue]]:
    """Scan a JS file for security-relevant patterns."""
    hits: list[dict[str, JsonValue]] = []
    try:
        raw = path.read_bytes()[:max_bytes]
        text = raw.decode("utf-8", errors="replace")
    except OSError:
        return hits

    rel_path = _rel_to_run_dir(run_dir, path)
    for pattern_name, regex in _JS_SECURITY_PATTERNS:
        for match in regex.finditer(text):
            line_num = text[:match.start()].count("\n") + 1
            hits.append({
                "pattern": pattern_name,
                "file": rel_path,
                "line": int(line_num),
                "match": text[match.start():match.end()][:80],
            })
    return hits


def _scan_html_file(
    path: Path,
    *,
    run_dir: Path,
    max_bytes: int = 256 * 1024,
) -> list[dict[str, JsonValue]]:
    """Scan an HTML file for security-relevant patterns."""
    hits: list[dict[str, JsonValue]] = []
    try:
        raw = path.read_bytes()[:max_bytes]
        text = raw.decode("utf-8", errors="replace")
    except OSError:
        return hits

    rel_path = _rel_to_run_dir(run_dir, path)
    for pattern_name, regex in _HTML_SECURITY_PATTERNS:
        for match in regex.finditer(text):
            line_num = text[:match.start()].count("\n") + 1
            hit: dict[str, JsonValue] = {
                "pattern": pattern_name,
                "file": rel_path,
                "line": int(line_num),
            }
            # Extract captured group if present (e.g. form action URL)
            if match.lastindex and match.lastindex >= 1:
                hit["value"] = match.group(1)[:200]
            else:
                hit["match"] = text[match.start():match.end()][:80]
            hits.append(hit)
    return hits


def _find_api_spec_files(
    roots: list[Path],
    *,
    run_dir: Path,
) -> list[dict[str, JsonValue]]:
    """Find API specification files (swagger, openapi)."""
    specs: list[dict[str, JsonValue]] = []
    seen: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        try:
            for p in sorted(root.rglob("*")):
                if not p.is_file():
                    continue
                if p.name.lower() in _API_SPEC_FILENAMES:
                    key = str(p.resolve())
                    if key in seen:
                        continue
                    seen.add(key)
                    specs.append({
                        "name": p.name,
                        "path": _rel_to_run_dir(run_dir, p),
                    })
        except OSError:
            pass
    return specs


@dataclass(frozen=True)
class WebUiStage:
    """Scans web UI assets (HTML/JS) for security-relevant patterns."""

    max_files: int = 2000
    max_bytes_per_file: int = 256 * 1024

    @property
    def name(self) -> str:
        return "web_ui"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "web_ui"
        assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        out_json = stage_dir / "web_ui.json"

        limitations: list[str] = []

        roots, root_limits = _find_web_content_roots(run_dir)
        limitations.extend(root_limits)

        if not roots:
            payload: dict[str, JsonValue] = {
                "status": "partial",
                "summary": cast(dict[str, JsonValue], {
                    "web_roots_found": 0,
                    "js_files_scanned": 0,
                    "html_files_scanned": 0,
                    "js_hits": 0,
                    "html_hits": 0,
                    "api_specs_found": 0,
                }),
                "js_security_patterns": cast(list[JsonValue], []),
                "html_security_patterns": cast(list[JsonValue], []),
                "api_spec_files": cast(list[JsonValue], []),
                "web_content_roots": cast(list[JsonValue], []),
                "limitations": cast(list[JsonValue], cast(list[object], sorted(set(limitations)))),
            }
            out_json.write_text(
                json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="partial",
                details=cast(dict[str, JsonValue], payload),
                limitations=limitations,
            )

        web_files = _iter_web_files(roots, run_dir=run_dir, max_files=self.max_files)

        js_hits: list[dict[str, JsonValue]] = []
        html_hits: list[dict[str, JsonValue]] = []
        js_count = 0
        html_count = 0

        for f in web_files:
            suffix = f.suffix.lower()
            if suffix in _JS_EXTENSIONS:
                js_count += 1
                js_hits.extend(_scan_js_file(f, run_dir=run_dir, max_bytes=self.max_bytes_per_file))
            elif suffix in _HTML_EXTENSIONS:
                html_count += 1
                html_hits.extend(_scan_html_file(f, run_dir=run_dir, max_bytes=self.max_bytes_per_file))

        api_specs = _find_api_spec_files(roots, run_dir=run_dir)

        status = "ok"
        if js_count == 0 and html_count == 0:
            status = "partial"
            limitations.append("No web files found in web content directories")

        payload = {
            "status": status,
            "summary": cast(dict[str, JsonValue], {
                "web_roots_found": int(len(roots)),
                "js_files_scanned": int(js_count),
                "html_files_scanned": int(html_count),
                "js_hits": int(len(js_hits)),
                "html_hits": int(len(html_hits)),
                "api_specs_found": int(len(api_specs)),
            }),
            "js_security_patterns": cast(list[JsonValue], cast(list[object], js_hits)),
            "html_security_patterns": cast(list[JsonValue], cast(list[object], html_hits)),
            "api_spec_files": cast(list[JsonValue], cast(list[object], api_specs)),
            "web_content_roots": cast(list[JsonValue], cast(list[object], [
                _rel_to_run_dir(run_dir, r) for r in roots
            ])),
            "limitations": cast(list[JsonValue], cast(list[object], sorted(set(limitations)))),
        }

        out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        return StageOutcome(
            status=status,
            details=cast(dict[str, JsonValue], payload),
            limitations=limitations,
        )
