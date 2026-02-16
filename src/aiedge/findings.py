from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from . import __version__ as AIEDGE_VERSION
from .policy import AIEdgePolicyViolation
from .exploit_tiering import (
    default_exploitability_tier,
    exploitability_tier_rank,
    is_valid_exploitability_tier,
)
from .schema import JsonValue
from .stage import StageContext


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _assert_under_dir(base_dir: Path, target: Path) -> None:
    base = base_dir.resolve()
    resolved = target.resolve()
    if not resolved.is_relative_to(base):
        raise AIEdgePolicyViolation(
            f"Refusing to write outside run dir: target={resolved} base={base}"
        )


def _rel_to_run_dir(run_dir: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(run_dir.resolve()))
    except Exception:
        return str(path)


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _run_relative_posix(run_dir: Path, path: Path) -> str:
    rel = path.resolve().relative_to(run_dir.resolve())
    return rel.as_posix()


def _firmware_id(run_dir: Path) -> tuple[str, list[str]]:
    firmware_path = run_dir / "input" / "firmware.bin"
    if not firmware_path.exists() or not firmware_path.is_file():
        return (
            "firmware:unknown",
            ["firmware.bin missing at run_dir/input; using firmware:unknown"],
        )
    try:
        return f"firmware:{_sha256_file(firmware_path)}", []
    except Exception:
        return (
            "firmware:unknown",
            ["firmware.bin unreadable at run_dir/input; using firmware:unknown"],
        )


def _contains_absolute_path_value(obj: object) -> bool:
    if isinstance(obj, dict):
        for value in cast(dict[str, object], obj).values():
            if _contains_absolute_path_value(value):
                return True
        return False
    if isinstance(obj, list):
        return any(_contains_absolute_path_value(v) for v in cast(list[object], obj))
    if isinstance(obj, str):
        v = obj.strip()
        return v.startswith("/") or bool(re.match(r"^[A-Za-z]:\\\\", v))
    return False


def _safe_ascii_text(text: str, *, max_len: int | None = None) -> str:
    out_chars: list[str] = []
    for ch in text:
        code = ord(ch)
        if 32 <= code <= 126:
            out_chars.append(ch)
        elif ch in "\r\n\t":
            out_chars.append(" ")
        else:
            out_chars.append("?")
    cleaned = "".join(out_chars).strip()
    if max_len is not None and max_len > 0 and len(cleaned) > max_len:
        cleaned = cleaned[:max_len]
    return cleaned or "n/a"


def _is_key_like_path(path_s: str) -> bool:
    p = path_s.lower()
    name = p.rsplit("/", 1)[-1]
    if name in {
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "ssh_host_rsa_key",
        "ssh_host_ecdsa_key",
        "ssh_host_ed25519_key",
    }:
        return True
    if p.endswith((".pem", ".key", ".p8", ".p12", ".pfx")):
        return True
    return False


def _evidence_path(
    run_dir: Path, path: Path, *, note: str | None = None
) -> dict[str, JsonValue]:
    ev: dict[str, JsonValue] = {
        "path": _safe_ascii_text(_rel_to_run_dir(run_dir, path))
    }
    if note:
        ev["note"] = _safe_ascii_text(note, max_len=240)
    return ev


def _evidence_snippet(
    path_s: str,
    snippet: str,
    *,
    note: str | None = None,
    max_len: int = 200,
) -> dict[str, JsonValue]:
    raw = snippet if len(snippet) <= max_len else (snippet[: max_len - 3] + "...")
    s = _safe_ascii_text(raw, max_len=max_len)
    ev: dict[str, JsonValue] = {
        "path": _safe_ascii_text(path_s),
        "snippet": s,
        "snippet_sha256": _sha256_text(s),
    }
    if note:
        ev["note"] = _safe_ascii_text(note, max_len=240)
    return ev


def _safe_load_json(path: Path) -> object | None:
    try:
        data = cast(object, json.loads(path.read_text(encoding="utf-8")))
        return data
    except Exception:
        return None


def _load_inventory_roots(
    run_dir: Path, inv_json_path: Path, fallback_root: Path
) -> list[Path]:
    roots: list[Path] = []
    seen: set[str] = set()

    inv_obj = _safe_load_json(inv_json_path)
    if isinstance(inv_obj, dict):
        inv_map = cast(dict[str, object], inv_obj)
        roots_any = inv_map.get("roots")
        if isinstance(roots_any, list):
            for item in cast(list[object], roots_any):
                if not isinstance(item, str) or not item or item.startswith("/"):
                    continue
                p = (run_dir / item).resolve()
                if not p.is_relative_to(run_dir.resolve()) or not p.exists():
                    continue
                key = str(p)
                if key in seen:
                    continue
                seen.add(key)
                roots.append(p)

    if fallback_root.exists():
        fallback_resolved = fallback_root.resolve()
        key = str(fallback_resolved)
        if key not in seen:
            roots.append(fallback_resolved)
    return roots


def _is_probably_binary(path: Path, *, sniff_bytes: int = 2048) -> bool:
    try:
        raw = path.read_bytes()[:sniff_bytes]
    except Exception:
        return True
    return b"\x00" in raw


def _iter_candidate_files(
    roots: list[Path],
    *,
    max_files: int = 3000,
) -> list[Path]:
    files: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        try:
            for p in root.rglob("*"):
                if not p.is_file():
                    continue
                try:
                    rel = p.resolve().relative_to(root.resolve())
                except Exception:
                    continue
                key = str((root / rel).resolve())
                if key in seen:
                    continue
                seen.add(key)
                files.append((root / rel).resolve())
                if len(files) >= max_files:
                    return files
        except Exception:
            continue
    return files


def _safe_read_text(path: Path, *, max_bytes: int = 256 * 1024) -> str:
    try:
        raw = path.read_bytes()[:max_bytes]
    except Exception:
        return ""
    if not raw:
        return ""
    try:
        return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _iter_non_comment_lines(text: str) -> list[str]:
    out: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out


def _masked_excerpt(text: str, *, max_len: int = 160) -> str:
    s = text.strip().replace("\t", " ")
    if len(s) > max_len:
        s = s[: max_len - 3] + "..."
    return _safe_ascii_text(s, max_len=max_len)


_CVE_ID_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def _known_disclosures_payload(
    run_dir: Path, candidate_files: list[Path]
) -> dict[str, JsonValue]:
    grouped: dict[str, dict[str, object]] = {}
    text_files_scanned = 0

    for p in sorted(candidate_files, key=lambda x: _rel_to_run_dir(run_dir, x)):
        if _is_probably_binary(p):
            continue
        rel = _rel_to_run_dir(run_dir, p).replace("\\", "/")
        if not _is_run_relative_ref(rel):
            continue
        text = _safe_read_text(p)
        if not text:
            continue
        text_files_scanned += 1
        for m in _CVE_ID_PATTERN.finditer(text):
            cve_id = m.group(0).upper()
            start = max(0, m.start() - 40)
            end = min(len(text), m.end() + 40)
            excerpt = _masked_excerpt(text[start:end], max_len=160)
            if cve_id not in excerpt.upper():
                excerpt = _masked_excerpt(cve_id, max_len=160)
            snippet_sha256 = _sha256_text(excerpt)

            bucket = grouped.setdefault(
                cve_id,
                {
                    "citations": set(),
                    "locations": set(),
                },
            )
            citations = cast(set[str], bucket["citations"])
            locations = cast(set[tuple[str, str]], bucket["locations"])
            citations.add(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
            locations.add((rel, snippet_sha256))

    matches: list[dict[str, JsonValue]] = []
    for cve_id in sorted(grouped):
        bucket = grouped[cve_id]
        citations = sorted(cast(set[str], bucket["citations"]))
        locations = [
            {"path": path_s, "snippet_sha256": sha}
            for path_s, sha in sorted(cast(set[tuple[str, str]], bucket["locations"]))
        ]
        matches.append(
            {
                "cve_id": cve_id,
                "citations": cast(list[JsonValue], cast(list[object], citations)),
                "locations": cast(list[JsonValue], cast(list[object], locations)),
            }
        )

    limitations: list[str] = []
    notes: list[str] = []
    if not candidate_files:
        limitations.append(
            "Known disclosure scan skipped because no candidate files were available."
        )
    elif text_files_scanned == 0:
        limitations.append(
            "Known disclosure scan skipped because no text candidate files were available."
        )
    if not matches:
        notes.append("No CVE identifiers matched candidate text files.")

    return {
        "schema_version": "known-disclosures-v1",
        "matches": cast(list[JsonValue], cast(list[object], matches)),
        "limitations": cast(list[JsonValue], cast(list[object], limitations)),
        "notes": cast(list[JsonValue], cast(list[object], notes)),
    }


def _add_match_evidence(
    evidence: list[dict[str, JsonValue]],
    *,
    run_dir: Path,
    file_path: Path,
    excerpt: str,
    note: str,
    max_matches: int,
) -> None:
    if len(evidence) >= max_matches:
        return
    rel = _rel_to_run_dir(run_dir, file_path)
    masked = _masked_excerpt(excerpt)
    evidence.append(_evidence_snippet(rel, masked, note=note, max_len=160))


def _rule_private_key_pem(
    run_dir: Path, files: list[Path], *, max_matches: int
) -> list[dict[str, JsonValue]]:
    pat = re.compile(r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----")
    evidence: list[dict[str, JsonValue]] = []
    for p in files:
        if _is_probably_binary(p):
            continue
        text = _safe_read_text(p)
        if not text:
            continue
        m = pat.search(text)
        if m is None:
            continue
        _add_match_evidence(
            evidence,
            run_dir=run_dir,
            file_path=p,
            excerpt=m.group(0),
            note="pem_header",
            max_matches=max_matches,
        )
        if len(evidence) >= max_matches:
            break
    return evidence


def _rule_telnet_enablement(
    run_dir: Path, files: list[Path], *, max_matches: int
) -> list[dict[str, JsonValue]]:
    evidence: list[dict[str, JsonValue]] = []
    for p in files:
        if _is_probably_binary(p):
            continue
        rel_l = _rel_to_run_dir(run_dir, p).lower()
        if "/etc/" not in rel_l and not rel_l.startswith("etc/"):
            continue
        text = _safe_read_text(p)
        if not text:
            continue
        lines = _iter_non_comment_lines(text)
        if not lines:
            continue

        if "xinetd.d/telnet" in rel_l and any(
            line.lower().replace(" ", "") == "disable=no" for line in lines
        ):
            _add_match_evidence(
                evidence,
                run_dir=run_dir,
                file_path=p,
                excerpt="disable = no",
                note="xinetd_telnet_enabled",
                max_matches=max_matches,
            )
        elif "inetd.conf" in rel_l:
            for line in lines:
                ll = line.lower()
                if "telnet" in ll and ("telnetd" in ll or "in.telnetd" in ll):
                    _add_match_evidence(
                        evidence,
                        run_dir=run_dir,
                        file_path=p,
                        excerpt=line,
                        note="inetd_telnet_service",
                        max_matches=max_matches,
                    )
                    break

        if len(evidence) >= max_matches:
            break
    return evidence


def _rule_adb_enablement(
    run_dir: Path, files: list[Path], *, max_matches: int
) -> list[dict[str, JsonValue]]:
    evidence: list[dict[str, JsonValue]] = []
    for p in files:
        if _is_probably_binary(p):
            continue
        rel_l = _rel_to_run_dir(run_dir, p).lower()
        text = _safe_read_text(p)
        if not text:
            continue
        lines = _iter_non_comment_lines(text)
        if not lines:
            continue

        is_build_prop = rel_l.endswith("build.prop") and (
            "/system/" in rel_l
            or rel_l.startswith("system/")
            or "/vendor/" in rel_l
            or rel_l.startswith("vendor/")
            or "/product/" in rel_l
            or rel_l.startswith("product/")
        )
        is_init_rc = (rel_l.endswith(".rc") or rel_l.endswith("init.rc")) and (
            rel_l.startswith("init") or "/init" in rel_l
        )

        for line in lines:
            ll = line.lower()
            if is_build_prop and ("ro.debuggable=1" in ll):
                _add_match_evidence(
                    evidence,
                    run_dir=run_dir,
                    file_path=p,
                    excerpt=line,
                    note="android_debuggable",
                    max_matches=max_matches,
                )
            if is_build_prop and ("persist.sys.usb.config=" in ll and "adb" in ll):
                _add_match_evidence(
                    evidence,
                    run_dir=run_dir,
                    file_path=p,
                    excerpt=line,
                    note="android_usb_adb",
                    max_matches=max_matches,
                )
            if is_init_rc and ll.startswith("service adbd"):
                _add_match_evidence(
                    evidence,
                    run_dir=run_dir,
                    file_path=p,
                    excerpt=line,
                    note="adbd_service",
                    max_matches=max_matches,
                )
            if len(evidence) >= max_matches:
                break
        if len(evidence) >= max_matches:
            break
    return evidence


def _rule_ssh_root_login(
    run_dir: Path, files: list[Path], *, max_matches: int
) -> list[dict[str, JsonValue]]:
    evidence: list[dict[str, JsonValue]] = []
    for p in files:
        if _is_probably_binary(p):
            continue
        rel_l = _rel_to_run_dir(run_dir, p).lower()
        if not rel_l.endswith("sshd_config") or (
            "/etc/" not in rel_l and not rel_l.startswith("etc/")
        ):
            continue
        text = _safe_read_text(p)
        if not text:
            continue
        for line in _iter_non_comment_lines(text):
            ll = line.lower()
            if ll.startswith("permitrootlogin") and "yes" in ll.split():
                _add_match_evidence(
                    evidence,
                    run_dir=run_dir,
                    file_path=p,
                    excerpt=line,
                    note="sshd_permit_root_login_yes",
                    max_matches=max_matches,
                )
                break
        if len(evidence) >= max_matches:
            break
    return evidence


def _rule_ssh_password_authentication(
    run_dir: Path, files: list[Path], *, max_matches: int
) -> list[dict[str, JsonValue]]:
    evidence: list[dict[str, JsonValue]] = []
    for p in files:
        if _is_probably_binary(p):
            continue
        rel_l = _rel_to_run_dir(run_dir, p).lower()
        if not rel_l.endswith("sshd_config") or (
            "/etc/" not in rel_l and not rel_l.startswith("etc/")
        ):
            continue
        text = _safe_read_text(p)
        if not text:
            continue
        for line in _iter_non_comment_lines(text):
            ll = line.lower()
            if ll.startswith("passwordauthentication") and "yes" in ll.split():
                _add_match_evidence(
                    evidence,
                    run_dir=run_dir,
                    file_path=p,
                    excerpt=line,
                    note="sshd_password_authentication_yes",
                    max_matches=max_matches,
                )
                break
        if len(evidence) >= max_matches:
            break
    return evidence


def _rule_ssh_permit_empty_passwords(
    run_dir: Path, files: list[Path], *, max_matches: int
) -> list[dict[str, JsonValue]]:
    evidence: list[dict[str, JsonValue]] = []
    for p in files:
        if _is_probably_binary(p):
            continue
        rel_l = _rel_to_run_dir(run_dir, p).lower()
        if not rel_l.endswith("sshd_config") or (
            "/etc/" not in rel_l and not rel_l.startswith("etc/")
        ):
            continue
        text = _safe_read_text(p)
        if not text:
            continue
        for line in _iter_non_comment_lines(text):
            ll = line.lower()
            if ll.startswith("permitemptypasswords") and "yes" in ll.split():
                _add_match_evidence(
                    evidence,
                    run_dir=run_dir,
                    file_path=p,
                    excerpt=line,
                    note="sshd_permit_empty_passwords_yes",
                    max_matches=max_matches,
                )
                break
        if len(evidence) >= max_matches:
            break
    return evidence


def _rule_android_manifest_debuggable(
    run_dir: Path, files: list[Path], *, max_matches: int
) -> list[dict[str, JsonValue]]:
    evidence: list[dict[str, JsonValue]] = []
    pat = re.compile(r"android:debuggable\s*=\s*['\"]true['\"]", re.IGNORECASE)
    for p in files:
        if _is_probably_binary(p):
            continue
        rel_l = _rel_to_run_dir(run_dir, p).lower()
        if not rel_l.endswith("androidmanifest.xml"):
            continue
        text = _safe_read_text(p)
        if not text:
            continue
        m = pat.search(text)
        if m is None:
            continue
        _add_match_evidence(
            evidence,
            run_dir=run_dir,
            file_path=p,
            excerpt=m.group(0),
            note="android_manifest_debuggable_true",
            max_matches=max_matches,
        )
        if len(evidence) >= max_matches:
            break
    return evidence


def _rule_telnet_disabled(
    run_dir: Path, files: list[Path], *, max_matches: int
) -> list[dict[str, JsonValue]]:
    evidence: list[dict[str, JsonValue]] = []
    for p in files:
        if _is_probably_binary(p):
            continue
        rel_l = _rel_to_run_dir(run_dir, p).lower()
        if "xinetd.d/telnet" not in rel_l:
            continue
        if "/etc/" not in rel_l and not rel_l.startswith("etc/"):
            continue
        text = _safe_read_text(p)
        if not text:
            continue
        lines = _iter_non_comment_lines(text)
        if any(line.lower().replace(" ", "") == "disable=yes" for line in lines):
            _add_match_evidence(
                evidence,
                run_dir=run_dir,
                file_path=p,
                excerpt="disable = yes",
                note="xinetd_telnet_disabled",
                max_matches=max_matches,
            )
        if len(evidence) >= max_matches:
            break
    return evidence


def _rule_update_metadata(ota_json: Path, run_dir: Path) -> list[dict[str, JsonValue]]:
    obj = _safe_load_json(ota_json)
    if not isinstance(obj, dict):
        return []
    m = cast(dict[str, object], obj)
    keys = [
        "selected_update_archive",
        "selected_payload",
        "payload_present",
        "payload_properties_present",
    ]
    seen = [k for k in keys if k in m]
    if not seen:
        return []
    return [
        _evidence_path(
            run_dir,
            ota_json,
            note="ota_metadata_keys:" + ",".join(sorted(seen)),
        )
    ]


def _load_nonzero_string_hit_counts(path: Path) -> dict[str, int]:
    obj = _safe_load_json(path)
    if not isinstance(obj, dict):
        return {}
    counts_any = cast(dict[str, object], obj).get("counts")
    if not isinstance(counts_any, dict):
        return {}

    out: dict[str, int] = {}
    for key, value in cast(dict[str, object], counts_any).items():
        if not key:
            continue
        if not isinstance(value, int) or value <= 0:
            continue
        out[key] = int(value)
    return out


def _iter_files_count(root: Path, *, max_files: int = 50_000) -> int:
    if not root.exists():
        return 0
    n = 0
    try:
        for p in root.rglob("*"):
            if p.is_file():
                n += 1
                if n >= max_files:
                    return n
    except Exception:
        return n
    return n


_NORMAL_BINARY_BUDGET = {
    "max_bytes_scanned_per_binary": 2 * 1024 * 1024,
    "max_strings_per_binary": 20_000,
    "max_anchors_per_binary": 10,
}

_AGGRESSIVE_BINARY_BUDGET = {
    "max_bytes_scanned_per_binary": 4 * 1024 * 1024,
    "max_strings_per_binary": 50_000,
    "max_anchors_per_binary": 10,
}

_ALLOWED_RAW_BINARY_PREVIEWS = {"/bin/sh", "sh -c", "busybox sh"}
_BINARY_SINK_TOKENS: tuple[tuple[str, str], ...] = (
    ("system", "system("),
    ("popen", "popen("),
    ("execl", "execl("),
    ("execv", "execv("),
    ("execve", "execve("),
    ("execvp", "execvp("),
    ("posix_spawn", "posix_spawn"),
    ("posix_spawnp", "posix_spawnp"),
)
_BINARY_SHELL_TOKENS = ("/bin/sh", "sh -c", "busybox sh", "/bin/bash")
_BINARY_SOURCE_TOKENS = (
    "query_string",
    "content_length",
    "request_method",
    "http_",
    "remote_addr",
    "argv",
    "getenv(",
    "recv(",
    "stdin",
)


def _stable_dump_json(path: Path, payload: dict[str, JsonValue]) -> None:
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _stable_finding_id(*parts: str) -> str:
    joined = "|".join(parts)
    return (
        "finding_"
        + hashlib.sha256(joined.encode("utf-8", errors="replace")).hexdigest()[:16]
    )


def _as_int(value: object, *, default: int = 0) -> int:
    if isinstance(value, int):
        return int(value)
    return default


def _parse_binary_strings_budget_mode(
    env_value: str | None,
) -> tuple[str, dict[str, int], list[str]]:
    warnings: list[str] = []
    raw = (env_value or "normal").strip().lower()
    if raw not in {"normal", "aggressive"}:
        warnings.append(
            "Invalid AIEDGE_BINARY_STRINGS_BUDGET value; falling back to normal."
        )
        raw = "normal"
    if raw == "aggressive":
        return "aggressive", dict(_AGGRESSIVE_BINARY_BUDGET), warnings
    return "normal", dict(_NORMAL_BINARY_BUDGET), warnings


def _extract_printable_ascii_strings(
    raw: bytes,
    *,
    min_len: int,
    max_strings: int,
) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    i = 0
    n = len(raw)
    while i < n and len(out) < max_strings:
        b = raw[i]
        if 32 <= b <= 126:
            start = i
            buf = bytearray()
            while i < n:
                b2 = raw[i]
                if 32 <= b2 <= 126:
                    buf.append(b2)
                    i += 1
                    continue
                break
            if len(buf) >= min_len:
                s = buf.decode("ascii", errors="ignore")
                out.append((start, s))
            continue
        i += 1
    return out


def _classify_binary_token(text_l: str) -> tuple[str, str, str] | None:
    for sink_kind, token in _BINARY_SINK_TOKENS:
        if token in text_l:
            return "sink", token, sink_kind
    for token in _BINARY_SHELL_TOKENS:
        if token in text_l:
            return "shell", token, ""
    for token in _BINARY_SOURCE_TOKENS:
        if token in text_l:
            return "source", token, ""
    return None


def _binary_anchor_score(
    *, near_shell: int, mid_shell: int, near_source: int, mid_source: int
) -> float:
    score = 0.2
    if near_shell > 0:
        score += 0.25
    elif mid_shell > 0:
        score += 0.15
    if near_source > 0:
        score += 0.2
    elif mid_source > 0:
        score += 0.1
    if near_shell == 0 and mid_shell == 0 and near_source == 0 and mid_source == 0:
        return 0.25
    return min(score, 0.85)


def _confidence_from_score(score: float) -> str:
    if score >= 0.7:
        return "high"
    if score >= 0.45:
        return "medium"
    return "low"


def _scan_binary_strings_hits(
    *,
    run_dir: Path,
    candidate_files: list[Path],
    firmware_id: str,
    budget_mode: str,
    bounds: dict[str, int],
    warnings: list[str],
    firmware_limitations: list[str],
) -> dict[str, JsonValue]:
    w_near = 4096
    w_mid = 16384
    max_bytes = int(bounds["max_bytes_scanned_per_binary"])
    max_strings = int(bounds["max_strings_per_binary"])
    max_anchors = int(bounds["max_anchors_per_binary"])

    binaries: list[dict[str, JsonValue]] = []
    for p in sorted(candidate_files, key=lambda x: _rel_to_run_dir(run_dir, x)):
        if not _is_probably_binary(p):
            continue
        try:
            rel_posix = _run_relative_posix(run_dir, p)
            file_size = int(p.stat().st_size)
            file_sha = _sha256_file(p)
            raw = p.read_bytes()[:max_bytes]
        except Exception:
            continue
        if not raw:
            continue

        binary_id = f"binary:{file_sha}"
        rel_path_sha256 = _sha256_text(rel_posix)

        extracted = _extract_printable_ascii_strings(
            raw,
            min_len=4,
            max_strings=max_strings,
        )
        token_candidates: list[dict[str, JsonValue]] = []
        for offset, text in extracted:
            text_l = text.lower()
            cls = _classify_binary_token(text_l)
            if cls is None:
                continue
            token_kind, token_norm, sink_kind = cls
            token_hash = hashlib.sha256(
                token_norm.encode("ascii", errors="ignore")
            ).hexdigest()
            token_obj: dict[str, JsonValue] = {
                "kind": token_kind,
                "offset": int(offset),
                "token_sha256": token_hash,
            }
            if token_kind == "sink":
                token_obj["sink_kind"] = sink_kind
            if token_norm in _ALLOWED_RAW_BINARY_PREVIEWS:
                token_obj["preview"] = token_norm
            token_candidates.append(token_obj)

        if not token_candidates:
            continue

        token_candidates = sorted(
            token_candidates,
            key=lambda item: (
                _as_int(item.get("offset")),
                str(item.get("kind", "")),
                str(item.get("token_sha256", "")),
            ),
        )
        sink_items = [t for t in token_candidates if t.get("kind") == "sink"]
        anchors: list[dict[str, JsonValue]] = []
        for sink_item in sink_items[:max_anchors]:
            anchor_offset = _as_int(sink_item.get("offset"))
            near_hits: list[dict[str, JsonValue]] = []
            mid_hits: list[dict[str, JsonValue]] = []
            for token in token_candidates:
                token_offset = _as_int(token.get("offset"))
                if token_offset == anchor_offset and token.get("kind") == "sink":
                    continue
                distance = abs(token_offset - anchor_offset)
                if distance > w_mid:
                    continue
                kind = str(token.get("kind", ""))
                hit: dict[str, JsonValue] = {
                    "kind": kind,
                    "token_sha256": str(token.get("token_sha256", "")),
                    "offset": token_offset,
                    "distance": int(distance),
                }
                if distance <= w_near:
                    near_hits.append(hit)
                else:
                    mid_hits.append(hit)

            near_hits = sorted(
                near_hits,
                key=lambda item: (
                    _as_int(item.get("offset")),
                    str(item.get("kind", "")),
                    str(item.get("token_sha256", "")),
                ),
            )
            mid_hits = sorted(
                mid_hits,
                key=lambda item: (
                    _as_int(item.get("offset")),
                    str(item.get("kind", "")),
                    str(item.get("token_sha256", "")),
                ),
            )
            anchors.append(
                {
                    "sink_kind": str(sink_item.get("sink_kind", "sink")),
                    "sink_token_sha256": str(sink_item.get("token_sha256", "")),
                    "offset": anchor_offset,
                    "windows": {
                        "near": [
                            max(0, anchor_offset - w_near),
                            anchor_offset + w_near,
                        ],
                        "mid": [
                            max(0, anchor_offset - w_mid),
                            anchor_offset + w_mid,
                        ],
                    },
                    "near_hits": cast(list[JsonValue], cast(list[object], near_hits)),
                    "mid_hits": cast(list[JsonValue], cast(list[object], mid_hits)),
                }
            )

        if not anchors:
            continue
        anchors = sorted(
            anchors,
            key=lambda item: (
                _as_int(item.get("offset")),
                str(item.get("sink_token_sha256", "")),
                str(item.get("sink_kind", "")),
            ),
        )
        binaries.append(
            {
                "binary_id": binary_id,
                "size_bytes": file_size,
                "rel_path_sha256": rel_path_sha256,
                "sink_anchors": cast(list[JsonValue], cast(list[object], anchors)),
            }
        )

    binaries = sorted(
        binaries,
        key=lambda item: str(item.get("binary_id", "")),
    )
    limitations: list[str] = []
    notes: list[str] = []
    if budget_mode == "aggressive":
        limitations.append(
            "Aggressive binary strings budget enabled with relaxed caps; increased scan bounds may increase weak-signal noise."
        )
        notes.append(
            "aggressive budget raises C/C++ string scan bounds for broader coverage"
        )

    return {
        "schema_version": "binary-strings-hits-v1",
        "scanner_version": AIEDGE_VERSION,
        "firmware_id": firmware_id,
        "budget_mode": budget_mode,
        "proximity": {"W_near": w_near, "W_mid": w_mid},
        "bounds": {
            "printable_ascii_min": 4,
            "max_bytes_scanned_per_binary": int(max_bytes),
            "max_strings_per_binary": int(max_strings),
            "max_anchors_per_binary": int(max_anchors),
        },
        "budget_modes": {
            "normal": cast(dict[str, JsonValue], dict(_NORMAL_BINARY_BUDGET)),
            "aggressive": cast(dict[str, JsonValue], dict(_AGGRESSIVE_BINARY_BUDGET)),
        },
        "binaries": cast(list[JsonValue], cast(list[object], binaries)),
        "warnings": cast(list[JsonValue], cast(list[object], sorted(set(warnings)))),
        "limitations": cast(
            list[JsonValue],
            cast(
                list[object],
                sorted(set(list(limitations) + list(firmware_limitations))),
            ),
        ),
        "notes": cast(list[JsonValue], cast(list[object], sorted(set(notes)))),
    }


def _detect_php_present(
    run_dir: Path, candidate_files: list[Path]
) -> tuple[bool, list[str]]:
    has_php_runtime = False
    has_php_source = False
    has_php_fastcgi_cfg = False
    evidence_tokens: list[str] = []

    fastcgi_pat = re.compile(
        r"(fastcgi_pass\s+[^;]*php|php-cgi|php-fpm|\.php)",
        re.IGNORECASE,
    )

    for p in sorted(candidate_files, key=lambda x: _rel_to_run_dir(run_dir, x)):
        rel = _rel_to_run_dir(run_dir, p).lower().replace("\\", "/")
        name = p.name.lower()
        if name in {"php", "php-cgi", "php-fpm"}:
            has_php_runtime = True
            evidence_tokens.append("php_runtime_binary")
        if "libphp" in name and p.suffix.lower() == ".so":
            has_php_runtime = True
            evidence_tokens.append("libphp_module")
        if "/etc/php" in rel or rel.startswith("etc/php"):
            has_php_runtime = True
            evidence_tokens.append("etc_php_config")
        if "/usr/lib/php" in rel or rel.startswith("usr/lib/php"):
            has_php_runtime = True
            evidence_tokens.append("usr_lib_php")
        if rel.endswith(".php"):
            has_php_source = True
            evidence_tokens.append("php_source_file")

        if p.suffix.lower() not in {".conf", ".ini", ".cfg", ".cnf", ".php", ".inc"}:
            continue
        if _is_probably_binary(p):
            continue
        text = _safe_read_text(p, max_bytes=64 * 1024)
        if not text:
            continue
        if fastcgi_pat.search(text):
            has_php_fastcgi_cfg = True
            evidence_tokens.append("fastcgi_php_config")

    php_present = has_php_runtime or (has_php_source and has_php_fastcgi_cfg)
    return php_present, sorted(set(evidence_tokens))


def _iter_text_rule_hits(
    *,
    run_dir: Path,
    candidate_files: list[Path],
    include_php: bool,
) -> list[dict[str, JsonValue]]:
    hits: list[dict[str, JsonValue]] = []
    max_per_rule = 20
    rule_counts: dict[str, int] = {}

    rule_specs: list[tuple[str, str, str, re.Pattern[str], float]] = [
        (
            "archive_extraction_sinks",
            "py_tar_extractall",
            "python",
            re.compile(
                r"\b(?:tarfile\.[A-Za-z_]+\([^\n]*\)\.)?extractall\s*\(", re.IGNORECASE
            ),
            0.62,
        ),
        (
            "archive_extraction_sinks",
            "shell_archive_extract",
            "shell",
            re.compile(r"\b(?:tar\s+-[A-Za-z]*x|unzip\s+|7z\s+x\b)", re.IGNORECASE),
            0.45,
        ),
        (
            "auth_decorator_gaps",
            "python_route_without_auth",
            "python",
            re.compile(
                r"^\s*@(?:app|bp|router)\.(?:route|get|post|put|delete|patch)\b",
                re.IGNORECASE,
            ),
            0.55,
        ),
        (
            "csrf_bypass_patterns",
            "python_csrf_exempt",
            "python",
            re.compile(r"csrf_exempt|WTF_CSRF_ENABLED\s*=\s*False", re.IGNORECASE),
            0.58,
        ),
        (
            "upload_exec_chains",
            "upload_source_signal",
            "python",
            re.compile(
                r"request\.files|multipart/form-data|save\s*\([^\n]*filename",
                re.IGNORECASE,
            ),
            0.45,
        ),
        (
            "command_execution_injection_risk",
            "python_exec_sink",
            "python",
            re.compile(
                r"subprocess\.[A-Za-z_]+\([^\n]*shell\s*=\s*True|os\.system\s*\(|os\.popen\s*\(",
                re.IGNORECASE,
            ),
            0.66,
        ),
        (
            "command_execution_injection_risk",
            "shell_eval_injection",
            "shell",
            re.compile(r"\beval\s+\"?\$|\bsh\s+-c\s+\$", re.IGNORECASE),
            0.6,
        ),
    ]
    if include_php:
        rule_specs.extend(
            [
                (
                    "command_execution_injection_risk",
                    "php_exec_sink",
                    "php",
                    re.compile(
                        r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(",
                        re.IGNORECASE,
                    ),
                    0.64,
                ),
                (
                    "csrf_bypass_patterns",
                    "php_csrf_bypass",
                    "php",
                    re.compile(
                        r"csrf[^\n]{0,40}(?:disable|off|false|bypass)", re.IGNORECASE
                    ),
                    0.46,
                ),
                (
                    "upload_exec_chains",
                    "php_upload_source",
                    "php",
                    re.compile(r"\$_FILES|move_uploaded_file\s*\(", re.IGNORECASE),
                    0.5,
                ),
            ]
        )

    def infer_lang(path: Path, text: str) -> str:
        suffix = path.suffix.lower()
        if suffix == ".py":
            return "python"
        if suffix in {".sh", ".bash", ".ash"}:
            return "shell"
        if suffix in {".php", ".phtml", ".inc"}:
            return "php"
        first_line = text.splitlines()[0] if text.splitlines() else ""
        if "python" in first_line:
            return "python"
        if "sh" in first_line:
            return "shell"
        return "other"

    for p in sorted(candidate_files, key=lambda x: _rel_to_run_dir(run_dir, x)):
        if _is_probably_binary(p):
            continue
        text = _safe_read_text(p)
        if not text:
            continue
        lang = infer_lang(p, text)
        rel = _rel_to_run_dir(run_dir, p)
        lines = text.splitlines()
        for line_idx, raw_line in enumerate(lines, start=1):
            line = _safe_ascii_text(raw_line, max_len=220)
            if not line:
                continue
            for family, rule_id, rule_lang, pattern, base_score in rule_specs:
                if lang != rule_lang:
                    continue
                key = f"{family}:{rule_id}"
                current = rule_counts.get(key, 0)
                if current >= max_per_rule:
                    continue
                if pattern.search(raw_line) is None:
                    continue

                if rule_id == "python_route_without_auth":
                    lookback = "\n".join(lines[max(0, line_idx - 4) : line_idx]).lower()
                    if any(
                        token in lookback
                        for token in (
                            "@login_required",
                            "@auth_required",
                            "@requires_auth",
                            "@jwt_required",
                        )
                    ):
                        continue

                fid = _stable_finding_id(
                    "pattern", family, rule_id, rel, str(line_idx), _sha256_text(line)
                )
                evidence = _evidence_snippet(
                    rel,
                    line,
                    note=f"rule={rule_id};line={line_idx}",
                    max_len=200,
                )
                hits.append(
                    {
                        "finding_id": fid,
                        "rule_family": family,
                        "rule_id": rule_id,
                        "language": lang,
                        "score": float(base_score),
                        "rationale": f"{rule_id} matched static pattern in {lang} source.",
                        "evidence": cast(
                            list[JsonValue], cast(list[object], [evidence])
                        ),
                        "chain_links": cast(list[JsonValue], []),
                    }
                )
                rule_counts[key] = current + 1

    return sorted(
        hits,
        key=lambda item: (
            str(item.get("rule_family", "")),
            str(item.get("rule_id", "")),
            str(item.get("finding_id", "")),
        ),
    )


def _binary_hits_to_pattern_hits(
    binary_hits: dict[str, JsonValue],
) -> list[dict[str, JsonValue]]:
    out: list[dict[str, JsonValue]] = []
    binaries_any = binary_hits.get("binaries")
    if not isinstance(binaries_any, list):
        return out
    for bin_item_any in binaries_any:
        if not isinstance(bin_item_any, dict):
            continue
        bin_item = cast(dict[str, object], bin_item_any)
        binary_id = str(bin_item.get("binary_id", ""))
        anchors_any = bin_item.get("sink_anchors")
        if not isinstance(anchors_any, list):
            continue
        for anchor_index, anchor_any in enumerate(cast(list[object], anchors_any)):
            if not isinstance(anchor_any, dict):
                continue
            anchor = cast(dict[str, object], anchor_any)
            near_hits_any = anchor.get("near_hits")
            mid_hits_any = anchor.get("mid_hits")
            near_hits = (
                cast(list[dict[str, object]], near_hits_any)
                if isinstance(near_hits_any, list)
                else []
            )
            mid_hits = (
                cast(list[dict[str, object]], mid_hits_any)
                if isinstance(mid_hits_any, list)
                else []
            )
            near_shell = sum(1 for x in near_hits if x.get("kind") == "shell")
            mid_shell = sum(1 for x in mid_hits if x.get("kind") == "shell")
            near_source = sum(1 for x in near_hits if x.get("kind") == "source")
            mid_source = sum(1 for x in mid_hits if x.get("kind") == "source")
            score = _binary_anchor_score(
                near_shell=near_shell,
                mid_shell=mid_shell,
                near_source=near_source,
                mid_source=mid_source,
            )

            token_sha256s = sorted(
                {
                    str(anchor.get("sink_token_sha256", "")),
                    *[
                        str(item.get("token_sha256", ""))
                        for item in near_hits + mid_hits
                    ],
                }
            )
            token_sha256s = [x for x in token_sha256s if x]

            sink_token = str(anchor.get("sink_token_sha256", ""))
            sink_offset = str(anchor.get("offset", "0"))
            finding_id = _stable_finding_id(
                "pattern",
                "binary",
                binary_id,
                sink_token,
                sink_offset,
                str(anchor_index),
            )
            out.append(
                {
                    "finding_id": finding_id,
                    "rule_family": "command_execution_injection_risk",
                    "rule_id": "cpp_strings_risk_link",
                    "language": "cpp_strings",
                    "score": score,
                    "rationale": "C/C++ printable-string sink anchor observed with bounded proximity scoring.",
                    "evidence": cast(
                        list[JsonValue],
                        cast(
                            list[object],
                            [
                                {
                                    "path": binary_id,
                                    "note": f"sink_anchor_index={anchor_index}",
                                }
                            ],
                        ),
                    ),
                    "evidence_refs": cast(
                        list[JsonValue], ["stages/findings/binary_strings_hits.json"]
                    ),
                    "chain_links": cast(
                        list[JsonValue],
                        cast(list[object], []),
                    ),
                    "binary_evidence": cast(
                        JsonValue,
                        {
                            "type": "cpp_strings",
                            "binary_id": binary_id,
                            "sink_anchor_index": int(anchor_index),
                            "token_sha256s": cast(
                                list[JsonValue], cast(list[object], token_sha256s)
                            ),
                        },
                    ),
                    "needs_manual": True,
                }
            )
    return sorted(
        out,
        key=lambda item: (
            str(item.get("rule_id", "")),
            str(item.get("finding_id", "")),
        ),
    )


_RULE_FAMILY_TO_V1 = {
    "archive_extraction_sinks": "archive_extraction",
    "auth_decorator_gaps": "auth_decorator_gaps",
    "csrf_bypass_patterns": "csrf_bypass",
    "upload_exec_chains": "upload_exec_chain",
    "command_execution_injection_risk": "cmd_exec_injection_risk",
}


def _to_pattern_v1_family(rule_family: str) -> str:
    return _RULE_FAMILY_TO_V1.get(rule_family, "cmd_exec_injection_risk")


def _stable_pattern_finding_id(*parts: str) -> str:
    return "finding:" + _sha256_text("|".join(parts))


def _is_run_relative_ref(value: str) -> bool:
    ref = value.strip()
    if not ref:
        return False
    if ref.startswith("/"):
        return False
    if re.match(r"^[A-Za-z]:\\", ref):
        return False
    if ":" in ref:
        return False
    if "/" not in ref:
        return False
    return True


def _hit_evidence_refs(hit: dict[str, JsonValue]) -> list[str]:
    refs: list[str] = []
    refs_any = hit.get("evidence_refs")
    if isinstance(refs_any, list):
        for item in refs_any:
            if isinstance(item, str) and _is_run_relative_ref(item):
                refs.append(item)
    evidence_any = hit.get("evidence")
    if isinstance(evidence_any, list):
        for item in evidence_any:
            if not isinstance(item, dict):
                continue
            path_s = item.get("path")
            if isinstance(path_s, str) and _is_run_relative_ref(path_s):
                refs.append(path_s)
    return sorted(set(refs))


def _build_pattern_scan_findings(
    pattern_hits: list[dict[str, JsonValue]],
) -> list[dict[str, JsonValue]]:
    findings: list[dict[str, JsonValue]] = []
    for hit in pattern_hits:
        family_src = str(hit.get("rule_family", ""))
        family = _to_pattern_v1_family(family_src)
        language = str(hit.get("language", "python"))
        score_any = hit.get("score")
        score = float(score_any) if isinstance(score_any, (int, float)) else 0.0
        confidence = _confidence_from_score(score)
        is_cpp = language == "cpp_strings"

        rationale_src = hit.get("rationale")
        rationale: list[str]
        if isinstance(rationale_src, str) and rationale_src.strip():
            rationale = [_safe_ascii_text(rationale_src, max_len=180)]
        else:
            rationale = ["deterministic static rule match"]

        evidence_refs = _hit_evidence_refs(hit)
        if is_cpp and "stages/findings/binary_strings_hits.json" not in evidence_refs:
            evidence_refs.append("stages/findings/binary_strings_hits.json")
            evidence_refs = sorted(set(evidence_refs))

        evidence_payload: list[JsonValue] = []
        if is_cpp:
            cpp_any = hit.get("binary_evidence")
            if isinstance(cpp_any, dict):
                evidence_payload.append(cast(JsonValue, cpp_any))
        else:
            for item in cast(list[object], hit.get("evidence", [])):
                if not isinstance(item, dict):
                    continue
                item_dict = cast(dict[str, object], item)
                path_s = item_dict.get("path")
                if not isinstance(path_s, str) or not path_s or path_s.startswith("/"):
                    continue
                ev_obj: dict[str, JsonValue] = {
                    "type": "static_snippet",
                    "path": _safe_ascii_text(path_s, max_len=240),
                }
                snippet_hash = item_dict.get("snippet_sha256")
                if isinstance(snippet_hash, str) and snippet_hash:
                    ev_obj["snippet_sha256"] = snippet_hash
                note = item_dict.get("note")
                if isinstance(note, str) and note:
                    ev_obj["note"] = _safe_ascii_text(note, max_len=180)
                evidence_payload.append(cast(JsonValue, ev_obj))

        chain_links = hit.get("chain_links")
        chain_refs = (
            sorted(
                {
                    str(x)
                    for x in cast(list[object], chain_links)
                    if isinstance(x, str) and x
                }
            )
            if isinstance(chain_links, list)
            else []
        )

        base_fid = str(hit.get("finding_id", ""))
        finding_id = _stable_pattern_finding_id(
            family,
            language,
            base_fid,
            str(score),
            ",".join(chain_refs),
            ",".join(evidence_refs),
        )

        findings.append(
            {
                "finding_id": finding_id,
                "family": family,
                "language_layer": language,
                "score": score,
                "confidence": confidence,
                "needs_manual": bool(is_cpp),
                "rationale": cast(list[JsonValue], cast(list[object], rationale)),
                "evidence_refs": cast(
                    list[JsonValue], cast(list[object], sorted(set(evidence_refs)))
                ),
                "evidence": cast(list[JsonValue], cast(list[object], evidence_payload)),
                "chain_refs": cast(list[JsonValue], cast(list[object], chain_refs)),
                "review_gate": {
                    "critic_questions": cast(list[JsonValue], []),
                    "triage_tags": cast(list[JsonValue], []),
                },
            }
        )

    return sorted(findings, key=lambda item: str(item.get("finding_id", "")))


def _build_chain_hypotheses(
    pattern_hits: list[dict[str, JsonValue]],
) -> list[dict[str, JsonValue]]:
    by_file: dict[str, list[dict[str, JsonValue]]] = {}
    for hit in pattern_hits:
        evidence_any = hit.get("evidence")
        if not isinstance(evidence_any, list) or not evidence_any:
            continue
        first = evidence_any[0]
        if not isinstance(first, dict):
            continue
        path_s = first.get("path")
        if not isinstance(path_s, str) or not path_s:
            continue
        by_file.setdefault(path_s, []).append(hit)

    chains: list[dict[str, JsonValue]] = []
    for path_s, items in sorted(by_file.items(), key=lambda pair: pair[0]):
        rule_ids = sorted(
            {
                str(item.get("rule_id", ""))
                for item in items
                if isinstance(item.get("rule_id"), str)
            }
        )
        has_upload = any("upload" in rid for rid in rule_ids)
        has_exec = any("exec" in rid or "sink" in rid for rid in rule_ids)
        has_auth_gap = any("auth" in rid for rid in rule_ids)
        if not ((has_upload and has_exec) or (has_auth_gap and has_exec)):
            continue
        finding_ids = sorted(
            {
                str(item.get("finding_id", ""))
                for item in items
                if isinstance(item.get("finding_id"), str)
            }
        )
        chain_id = _stable_finding_id(
            "chain", path_s, ",".join(rule_ids), ",".join(finding_ids)
        )
        score = min(0.9, 0.45 + 0.1 * float(len(rule_ids)))
        chains.append(
            {
                "chain_id": chain_id,
                "path": path_s,
                "rule_ids": cast(list[JsonValue], cast(list[object], rule_ids)),
                "finding_ids": cast(list[JsonValue], cast(list[object], finding_ids)),
                "score": score,
                "hypothesis": "Static sequence suggests input reachability to execution-relevant sink.",
                "evidence_refs": cast(
                    list[JsonValue],
                    [
                        "stages/findings/pattern_scan.json",
                        "stages/findings/binary_strings_hits.json",
                    ],
                ),
            }
        )

    return sorted(chains, key=lambda item: str(item.get("chain_id", "")))


def _build_review_gates(
    pattern_hits: list[dict[str, JsonValue]],
    chains: list[dict[str, JsonValue]],
) -> dict[str, JsonValue]:
    items: list[dict[str, JsonValue]] = []
    chain_finding_ids = {
        str(fid)
        for chain in chains
        for fid in cast(list[object], chain.get("finding_ids", []))
        if isinstance(fid, str)
    }

    for hit in pattern_hits:
        finding_id = str(hit.get("finding_id", ""))
        rule_family = str(hit.get("rule_family", ""))
        score_any = hit.get("score")
        score = float(score_any) if isinstance(score_any, (int, float)) else 0.0
        linked_chain = finding_id in chain_finding_ids

        critic_decision = "strengthen"
        critic_reasons: list[str] = ["insufficient_dynamic_evidence"]
        if (
            score <= 0.3
            and not linked_chain
            and rule_family != "command_execution_injection_risk"
        ):
            critic_decision = "kill"
            critic_reasons = ["low_roi_weak_signal", "no_chain_support"]

        next_evidence: list[str] = []
        if critic_decision != "kill":
            if rule_family == "archive_extraction_sinks":
                next_evidence = [
                    "Locate path-normalization checks before extraction call.",
                    "Confirm attacker-controlled archive source reaches extraction sink.",
                ]
            elif rule_family == "auth_decorator_gaps":
                next_evidence = [
                    "Trace route registration to verify endpoint exposure.",
                    "Identify compensating auth middleware or gateway controls.",
                ]
            elif rule_family == "csrf_bypass_patterns":
                next_evidence = [
                    "Verify request method and origin checks at handler entry.",
                    "Capture concrete unauthenticated state-change endpoint mapping.",
                ]
            elif rule_family == "upload_exec_chains":
                next_evidence = [
                    "Demonstrate upload path write location and extension controls.",
                    "Show invocation edge from uploaded artifact to execution sink.",
                ]
            else:
                next_evidence = [
                    "Correlate source token to sink call path in same component.",
                    "Collect deterministic boundary evidence for input controllability.",
                ]

        triager_reasons = [
            "chain_supported" if linked_chain else "standalone_signal",
            f"score_{'high' if score >= 0.65 else 'medium' if score >= 0.4 else 'low'}",
        ]

        items.append(
            {
                "finding_id": finding_id,
                "critic": {
                    "decision": critic_decision,
                    "reason_codes": cast(
                        list[JsonValue], cast(list[object], sorted(critic_reasons))
                    ),
                },
                "triager_sim": {
                    "decision": "strengthen" if critic_decision != "kill" else "defer",
                    "reason_codes": cast(
                        list[JsonValue], cast(list[object], sorted(triager_reasons))
                    ),
                    "next_evidence": cast(
                        list[JsonValue], cast(list[object], sorted(next_evidence))
                    ),
                },
            }
        )

    items = sorted(items, key=lambda item: str(item.get("finding_id", "")))
    return {
        "schema_version": "1.0",
        "items": cast(list[JsonValue], cast(list[object], items)),
    }


def _write_safe_poc_skeletons(
    *,
    skeleton_dir: Path,
    chains: list[dict[str, JsonValue]],
) -> list[str]:
    skeleton_dir.mkdir(parents=True, exist_ok=True)
    written: list[str] = []

    intro = (
        "SAFE PLACEHOLDER TEMPLATE ONLY\n"
        "This file is intentionally non-executable and contains no exploit payload.\n"
        "Fill placeholders during authorized review workflows only.\n"
    )
    readme = skeleton_dir / "README.txt"
    _ = readme.write_text(intro, encoding="utf-8")
    written.append(str(readme.name))

    for chain in chains[:10]:
        chain_id = str(chain.get("chain_id", ""))
        if not chain_id:
            continue
        fname = f"{chain_id}.txt"
        path = skeleton_dir / fname
        rule_ids = chain.get("rule_ids")
        rule_s = ", ".join(
            sorted(x for x in cast(list[object], rule_ids) if isinstance(x, str))
        )
        content = (
            "SAFE PLACEHOLDER TEMPLATE ONLY\n"
            "No runnable payload included.\n\n"
            f"chain_id: {chain_id}\n"
            f"related_rules: {rule_s or 'n/a'}\n"
            "target_component: <fill_me>\n"
            "controlled_input: <fill_me>\n"
            "expected_observation: <fill_me>\n"
            "non_destructive_validation_steps:\n"
            "  1) <fill_me>\n"
            "  2) <fill_me>\n"
        )
        _ = path.write_text(content, encoding="utf-8")
        written.append(fname)

    return sorted(written)


@dataclass(frozen=True)
class FindingsStageResult:
    status: str
    findings: list[dict[str, JsonValue]]
    evidence: list[dict[str, JsonValue]]
    limitations: list[str]


def run_findings(
    ctx: StageContext, *, firmware_name: str = "firmware.bin"
) -> FindingsStageResult:
    stage_dir = ctx.run_dir / "stages" / "findings"
    _assert_under_dir(ctx.run_dir, stage_dir)
    stage_dir.mkdir(parents=True, exist_ok=True)

    inv_dir = ctx.run_dir / "stages" / "inventory"
    inv_json = inv_dir / "inventory.json"
    inv_strings = inv_dir / "string_hits.json"

    ex_dir = ctx.run_dir / "stages" / "extraction"
    ex_log = ex_dir / "binwalk.log"
    extracted_dir = ex_dir / f"_{firmware_name}.extracted"
    ota_dir = ctx.run_dir / "stages" / "ota"
    ota_json = ota_dir / "ota.json"

    stage_evidence: list[dict[str, JsonValue]] = []
    limitations: list[str] = []

    if inv_json.exists():
        stage_evidence.append(_evidence_path(ctx.run_dir, inv_json))
    else:
        stage_evidence.append(_evidence_path(ctx.run_dir, inv_json, note="missing"))
        limitations.append("Inventory output missing; findings may be incomplete.")

    if inv_strings.exists():
        stage_evidence.append(_evidence_path(ctx.run_dir, inv_strings))
    else:
        stage_evidence.append(_evidence_path(ctx.run_dir, inv_strings, note="missing"))

    if ex_log.exists():
        stage_evidence.append(_evidence_path(ctx.run_dir, ex_log))
    else:
        stage_evidence.append(_evidence_path(ctx.run_dir, ex_log, note="missing"))

    if extracted_dir.exists():
        stage_evidence.append(_evidence_path(ctx.run_dir, extracted_dir))
    else:
        stage_evidence.append(
            _evidence_path(ctx.run_dir, extracted_dir, note="missing")
        )

    if ota_json.exists():
        stage_evidence.append(_evidence_path(ctx.run_dir, ota_json))

    findings: list[dict[str, JsonValue]] = []
    string_hit_counts = _load_nonzero_string_hit_counts(inv_strings)

    extracted_files = _iter_files_count(extracted_dir)
    candidate_roots = (
        _load_inventory_roots(ctx.run_dir, inv_json, extracted_dir)
        if extracted_files > 0
        else []
    )
    candidate_files = _iter_candidate_files(candidate_roots, max_files=3000)

    budget_mode, budget_bounds, budget_warnings = _parse_binary_strings_budget_mode(
        os.getenv("AIEDGE_BINARY_STRINGS_BUDGET")
    )
    firmware_id, firmware_limitations = _firmware_id(ctx.run_dir)
    for warning in budget_warnings:
        if warning not in limitations:
            limitations.append(warning)
    for limitation in firmware_limitations:
        if limitation not in limitations:
            limitations.append(limitation)

    php_present, php_presence_signals = _detect_php_present(
        ctx.run_dir, candidate_files
    )
    binary_hits_payload = _scan_binary_strings_hits(
        run_dir=ctx.run_dir,
        candidate_files=candidate_files,
        firmware_id=firmware_id,
        budget_mode=budget_mode,
        bounds=budget_bounds,
        warnings=budget_warnings,
        firmware_limitations=firmware_limitations,
    )

    binary_limitations_any = binary_hits_payload.get("limitations")
    if isinstance(binary_limitations_any, list):
        for item in binary_limitations_any:
            if isinstance(item, str) and item not in limitations:
                limitations.append(item)

    pattern_hits = _iter_text_rule_hits(
        run_dir=ctx.run_dir,
        candidate_files=candidate_files,
        include_php=php_present,
    )
    pattern_hits.extend(_binary_hits_to_pattern_hits(binary_hits_payload))
    pattern_hits = sorted(
        pattern_hits,
        key=lambda item: (
            str(item.get("rule_family", "")),
            str(item.get("rule_id", "")),
            str(item.get("finding_id", "")),
        ),
    )

    chains_payload: dict[str, JsonValue] = {
        "schema_version": "1.0",
        "chains": cast(
            list[JsonValue],
            cast(list[object], _build_chain_hypotheses(pattern_hits)),
        ),
    }
    review_gates_payload = _build_review_gates(
        pattern_hits,
        cast(list[dict[str, JsonValue]], cast(list[object], chains_payload["chains"])),
    )

    finding_to_chain_ids: dict[str, set[str]] = {}
    chains_any = chains_payload.get("chains")
    if isinstance(chains_any, list):
        for chain_any in chains_any:
            if not isinstance(chain_any, dict):
                continue
            chain_obj = cast(dict[str, object], chain_any)
            chain_id_any = chain_obj.get("chain_id")
            if not isinstance(chain_id_any, str) or not chain_id_any:
                continue
            for fid_any in cast(list[object], chain_obj.get("finding_ids", [])):
                if not isinstance(fid_any, str) or not fid_any:
                    continue
                finding_to_chain_ids.setdefault(fid_any, set()).add(chain_id_any)

    for hit in pattern_hits:
        fid_any = hit.get("finding_id")
        if not isinstance(fid_any, str):
            hit["chain_links"] = cast(list[JsonValue], [])
            continue
        chain_ids = sorted(finding_to_chain_ids.get(fid_any, set()))
        hit["chain_links"] = cast(list[JsonValue], cast(list[object], chain_ids))
        hit["evidence_refs"] = cast(
            list[JsonValue], ["stages/findings/binary_strings_hits.json"]
        )

    pattern_scan_findings = _build_pattern_scan_findings(pattern_hits)
    if budget_mode == "aggressive":
        for finding in pattern_scan_findings:
            rationale_any = finding.get("rationale")
            if isinstance(rationale_any, list):
                rationale_list = [
                    x for x in rationale_any if isinstance(x, str) and x.strip()
                ]
                rationale_list.append("aggressive budget mode enabled")
                finding["rationale"] = cast(
                    list[JsonValue], cast(list[object], sorted(set(rationale_list)))
                )

    pattern_scan_payload: dict[str, JsonValue] = {
        "schema_version": "pattern-scan-v1",
        "scanner_version": AIEDGE_VERSION,
        "firmware_id": firmware_id,
        "ruleset": {
            "v1_families": cast(
                list[JsonValue],
                [
                    "archive_extraction",
                    "auth_decorator_gaps",
                    "csrf_bypass",
                    "upload_exec_chain",
                    "cmd_exec_injection_risk",
                ],
            ),
            "proximity": {"W_near": 4096, "W_mid": 16384},
            "budget_mode": budget_mode,
        },
        "findings": cast(list[JsonValue], cast(list[object], pattern_scan_findings)),
        "warnings": cast(
            list[JsonValue], cast(list[object], sorted(set(budget_warnings)))
        ),
        "limitations": cast(
            list[JsonValue],
            cast(
                list[object],
                sorted(
                    set(
                        list(firmware_limitations)
                        + (
                            [
                                "Aggressive binary strings budget enabled with relaxed caps; increased scan bounds may increase weak-signal noise."
                            ]
                            if budget_mode == "aggressive"
                            else []
                        )
                    )
                ),
            ),
        ),
        "notes": cast(
            list[JsonValue],
            cast(
                list[object],
                sorted(
                    set(
                        list(php_presence_signals)
                        + (
                            [
                                "aggressive budget raises C/C++ string scan bounds for broader coverage"
                            ]
                            if budget_mode == "aggressive"
                            else []
                        )
                    )
                ),
            ),
        ),
        "chain_refs": cast(list[JsonValue], ["stages/findings/chains.json"]),
        "review_refs": cast(list[JsonValue], ["stages/findings/review_gates.json"]),
    }
    known_disclosures_payload = _known_disclosures_payload(ctx.run_dir, candidate_files)

    pattern_scan_path = stage_dir / "pattern_scan.json"
    binary_hits_path = stage_dir / "binary_strings_hits.json"
    chains_path = stage_dir / "chains.json"
    review_gates_path = stage_dir / "review_gates.json"
    known_disclosures_path = stage_dir / "known_disclosures.json"
    skeleton_dir = stage_dir / "poc_skeletons"
    _assert_under_dir(stage_dir, pattern_scan_path)
    _assert_under_dir(stage_dir, binary_hits_path)
    _assert_under_dir(stage_dir, chains_path)
    _assert_under_dir(stage_dir, review_gates_path)
    _assert_under_dir(stage_dir, known_disclosures_path)
    _assert_under_dir(stage_dir, skeleton_dir)

    if _contains_absolute_path_value(pattern_scan_payload):
        raise AIEdgePolicyViolation(
            "pattern_scan.json payload contains absolute-path value"
        )
    if _contains_absolute_path_value(binary_hits_payload):
        raise AIEdgePolicyViolation(
            "binary_strings_hits.json payload contains absolute-path value"
        )
    if _contains_absolute_path_value(known_disclosures_payload):
        raise AIEdgePolicyViolation(
            "known_disclosures.json payload contains absolute-path value"
        )

    _stable_dump_json(pattern_scan_path, pattern_scan_payload)
    _stable_dump_json(binary_hits_path, binary_hits_payload)
    _stable_dump_json(chains_path, chains_payload)
    _stable_dump_json(review_gates_path, review_gates_payload)
    _stable_dump_json(known_disclosures_path, known_disclosures_payload)
    skeleton_written = _write_safe_poc_skeletons(
        skeleton_dir=skeleton_dir,
        chains=cast(
            list[dict[str, JsonValue]], cast(list[object], chains_payload["chains"])
        ),
    )

    stage_evidence.append(_evidence_path(ctx.run_dir, pattern_scan_path))
    stage_evidence.append(_evidence_path(ctx.run_dir, binary_hits_path))
    stage_evidence.append(_evidence_path(ctx.run_dir, chains_path))
    stage_evidence.append(_evidence_path(ctx.run_dir, review_gates_path))
    stage_evidence.append(_evidence_path(ctx.run_dir, known_disclosures_path))
    stage_evidence.append(
        _evidence_path(
            ctx.run_dir,
            skeleton_dir,
            note=f"safe_placeholders={len(skeleton_written)}",
        )
    )

    if extracted_files <= 0:
        findings.append(
            {
                "id": "aiedge.findings.analysis_incomplete",
                "title": "Analysis incomplete",
                "severity": "info",
                "confidence": 0.9,
                "disposition": "confirmed",
                "description": "No extracted filesystem content was found; findings are best-effort and limited.",
                "evidence": cast(list[JsonValue], list(stage_evidence)),
            }
        )
    else:
        max_matches_per_rule = 5

        private_key_evidence = _rule_private_key_pem(
            ctx.run_dir,
            candidate_files,
            max_matches=max_matches_per_rule,
        )
        if private_key_evidence:
            key_like = False
            for ev in private_key_evidence:
                path_any = ev.get("path")
                if isinstance(path_any, str) and _is_key_like_path(path_any):
                    key_like = True
                    break
            key_conf = 0.8 if key_like else 0.6
            key_sev = "medium" if key_like else "low"
            findings.append(
                {
                    "id": "aiedge.findings.secrets.private_key_pem",
                    "title": "Private key material header detected",
                    "severity": key_sev,
                    "confidence": key_conf,
                    "disposition": "suspected",
                    "description": "Extracted content contains one or more PEM private key headers.",
                    "evidence": cast(
                        list[JsonValue],
                        cast(list[object], private_key_evidence),
                    ),
                }
            )

        telnet_evidence = _rule_telnet_enablement(
            ctx.run_dir,
            candidate_files,
            max_matches=max_matches_per_rule,
        )
        if telnet_evidence:
            findings.append(
                {
                    "id": "aiedge.findings.debug.telnet_enablement",
                    "title": "Telnet service enablement signal",
                    "severity": "medium",
                    "confidence": 0.75,
                    "disposition": "confirmed",
                    "description": "Configuration indicates telnet service may be enabled.",
                    "evidence": cast(
                        list[JsonValue],
                        cast(list[object], telnet_evidence),
                    ),
                }
            )

        adb_evidence = _rule_adb_enablement(
            ctx.run_dir,
            candidate_files,
            max_matches=max_matches_per_rule,
        )
        if adb_evidence:
            findings.append(
                {
                    "id": "aiedge.findings.debug.adb_enablement",
                    "title": "ADB/debuggable configuration signal",
                    "severity": "medium",
                    "confidence": 0.7,
                    "disposition": "confirmed",
                    "description": "Android properties/init scripts indicate adbd or debuggable mode enablement.",
                    "evidence": cast(
                        list[JsonValue],
                        cast(list[object], adb_evidence),
                    ),
                }
            )

        ssh_root_evidence = _rule_ssh_root_login(
            ctx.run_dir,
            candidate_files,
            max_matches=max_matches_per_rule,
        )
        if ssh_root_evidence:
            findings.append(
                {
                    "id": "aiedge.findings.config.ssh_permit_root_login",
                    "title": "SSH root login enabled",
                    "severity": "medium",
                    "confidence": 0.8,
                    "disposition": "confirmed",
                    "description": "sshd_config contains PermitRootLogin yes.",
                    "evidence": cast(
                        list[JsonValue],
                        cast(list[object], ssh_root_evidence),
                    ),
                }
            )

        ssh_password_auth_evidence = _rule_ssh_password_authentication(
            ctx.run_dir,
            candidate_files,
            max_matches=max_matches_per_rule,
        )
        if ssh_password_auth_evidence:
            findings.append(
                {
                    "id": "aiedge.findings.config.ssh_password_authentication",
                    "title": "SSH password authentication enabled",
                    "severity": "medium",
                    "confidence": 0.8,
                    "disposition": "confirmed",
                    "description": "sshd_config contains PasswordAuthentication yes.",
                    "evidence": cast(
                        list[JsonValue],
                        cast(list[object], ssh_password_auth_evidence),
                    ),
                }
            )

        ssh_empty_password_evidence = _rule_ssh_permit_empty_passwords(
            ctx.run_dir,
            candidate_files,
            max_matches=max_matches_per_rule,
        )
        if ssh_empty_password_evidence:
            findings.append(
                {
                    "id": "aiedge.findings.config.ssh_permit_empty_passwords",
                    "title": "SSH empty passwords permitted",
                    "severity": "high",
                    "confidence": 0.85,
                    "disposition": "confirmed",
                    "description": "sshd_config contains PermitEmptyPasswords yes.",
                    "evidence": cast(
                        list[JsonValue],
                        cast(list[object], ssh_empty_password_evidence),
                    ),
                }
            )

        manifest_debuggable_evidence = _rule_android_manifest_debuggable(
            ctx.run_dir,
            candidate_files,
            max_matches=max_matches_per_rule,
        )
        if manifest_debuggable_evidence:
            findings.append(
                {
                    "id": "aiedge.findings.debug.android_manifest_debuggable",
                    "title": "Android app manifest is debuggable",
                    "severity": "medium",
                    "confidence": 0.75,
                    "disposition": "confirmed",
                    "description": 'AndroidManifest.xml contains android:debuggable="true".',
                    "evidence": cast(
                        list[JsonValue],
                        cast(list[object], manifest_debuggable_evidence),
                    ),
                }
            )

        telnet_disabled_evidence = _rule_telnet_disabled(
            ctx.run_dir,
            candidate_files,
            max_matches=max_matches_per_rule,
        )
        if telnet_disabled_evidence:
            findings.append(
                {
                    "id": "aiedge.findings.hardening.telnet_disabled",
                    "title": "Telnet service explicitly disabled",
                    "severity": "info",
                    "confidence": 0.85,
                    "disposition": "confirmed",
                    "description": "xinetd telnet configuration contains disable = yes.",
                    "evidence": cast(
                        list[JsonValue],
                        cast(list[object], telnet_disabled_evidence),
                    ),
                }
            )

        ota_metadata_evidence = _rule_update_metadata(ota_json, ctx.run_dir)
        if ota_metadata_evidence:
            findings.append(
                {
                    "id": "aiedge.findings.update.metadata_present",
                    "title": "OTA update metadata present",
                    "severity": "info",
                    "confidence": 0.95,
                    "disposition": "confirmed",
                    "description": "OTA stage metadata is present and includes update/payload selection fields.",
                    "evidence": cast(
                        list[JsonValue],
                        cast(list[object], ota_metadata_evidence),
                    ),
                }
            )

    if string_hit_counts:
        counts_summary = ", ".join(
            f"{name}={string_hit_counts[name]}" for name in sorted(string_hit_counts)
        )
        findings.append(
            {
                "id": "aiedge.findings.inventory.string_hits_present",
                "title": "Inventory string-hit signals present",
                "severity": "info",
                "confidence": 0.95,
                "disposition": "confirmed",
                "description": (
                    "Inventory string-hit counters are non-zero: "
                    + counts_summary
                    + "."
                ),
                "evidence": cast(
                    list[JsonValue],
                    [
                        _evidence_path(
                            ctx.run_dir,
                            inv_strings,
                            note="nonzero_counts:" + counts_summary,
                        )
                    ],
                ),
            }
        )

    if not findings:
        findings.append(
            {
                "id": "aiedge.findings.no_signals",
                "title": "No heuristic findings detected",
                "severity": "info",
                "confidence": 0.7,
                "disposition": "confirmed",
                "description": "Heuristic checks did not surface noteworthy signals; this does not imply absence of issues.",
                "evidence": cast(list[JsonValue], list(stage_evidence)),
            }
        )

    normalized: list[dict[str, JsonValue]] = []
    for f in findings:
        evidence_any_obj: object = f.get("evidence")
        ev_list: list[dict[str, JsonValue]] = []
        if isinstance(evidence_any_obj, list):
            for ev_item in evidence_any_obj:
                if not isinstance(ev_item, dict):
                    continue
                ev_dict = cast(dict[str, object], ev_item)
                path_s = ev_dict.get("path")
                if isinstance(path_s, str):
                    ev_list.append(cast(dict[str, JsonValue], dict(ev_dict)))
        if not ev_list:
            ev_list = (
                list(stage_evidence)
                if stage_evidence
                else [{"path": "stages/findings", "note": "missing stage evidence"}]
            )

        f2: dict[str, JsonValue] = dict(f)
        f2["evidence"] = cast(JsonValue, ev_list)

        conf_any = f2.get("confidence")
        if not isinstance(conf_any, (int, float)):
            f2["confidence"] = 0.5
        else:
            f2["confidence"] = float(max(0.0, min(1.0, float(conf_any))))

        disp_any = f2.get("disposition")
        if not isinstance(disp_any, str) or disp_any not in ("confirmed", "suspected"):
            f2["disposition"] = "suspected"

        tier_any = f2.get("exploitability_tier")
        if is_valid_exploitability_tier(tier_any):
            tier = cast(str, tier_any)
        else:
            tier = default_exploitability_tier(disposition=f2.get("disposition"))
        f2["exploitability_tier"] = tier

        sev_any = f2.get("severity")
        if (
            isinstance(sev_any, str)
            and sev_any in ("high", "critical")
            and f2.get("disposition") == "confirmed"
        ):
            tier_rank = exploitability_tier_rank(f2.get("exploitability_tier"))
            if tier_rank is None or tier_rank < 2:
                f2["disposition"] = "suspected"

        normalized.append(f2)

    if not normalized:
        normalized = [
            {
                "id": "aiedge.findings.analysis_incomplete",
                "title": "Analysis incomplete",
                "severity": "info",
                "confidence": 0.5,
                "disposition": "suspected",
                "description": "No findings were generated; this indicates the analysis pipeline did not produce expected inputs.",
                "evidence": cast(
                    list[JsonValue],
                    list(stage_evidence)
                    or [{"path": "stages/findings", "note": "missing stage evidence"}],
                ),
            }
        ]

    payload: dict[str, JsonValue] = {
        "status": "ok" if normalized else "partial",
        "generated_at": _iso_utc_now(),
        "findings": cast(list[JsonValue], cast(list[object], normalized)),
        "evidence": cast(list[JsonValue], cast(list[object], stage_evidence)),
        "extracted_file_count": int(extracted_files),
    }

    out_path = stage_dir / "findings.json"
    _assert_under_dir(stage_dir, out_path)
    _ = out_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    status = cast(str, payload.get("status", "ok"))
    return FindingsStageResult(
        status=status,
        findings=normalized,
        evidence=stage_evidence,
        limitations=limitations,
    )
