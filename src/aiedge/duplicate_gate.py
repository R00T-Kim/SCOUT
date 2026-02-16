from __future__ import annotations

import json
import os
import tempfile
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .fingerprinting import (
    DUPLICATE_REGISTRY_SCHEMA_VERSION,
    DUPLICATE_TAXONOMY_VERSION,
    FINGERPRINT_VERSION,
    claim_fingerprint_sha256,
)
from .schema import JsonValue


DUPLICATE_GATE_SCHEMA_VERSION = "duplicate-gate-v1"
DUPLICATE_GATE_ANALYSIS_FAIL_OPEN = "DUPLICATE_GATE_ANALYSIS_FAIL_OPEN"
DUPLICATE_REGISTRY_LOAD_ERROR = "DUPLICATE_REGISTRY_LOAD_ERROR"

_DEFAULT_MAX_RECORDS = 4096
_DEFAULT_MAX_SOURCES_PER_RECORD = 8
_DEFAULT_T_REOPEN = 0.70
_DEFAULT_T_FORCE_RETRIAGE = 0.85

_AUTO_REOPEN_EVIDENCE_HASH_DELTA = "evidence_hash_delta"
_AUTO_REOPEN_LINEAGE_DIFF_DELTA = "lineage_diff_hash_delta"
_AUTO_REOPEN_NOVELTY_THRESHOLD_MET = "novelty_threshold_met"
_MANUAL_OVERRIDE_REASON = "manual_override"
_FORCE_RETRIAGE_REASON = "force_retriage_override"

_VOLATILE_META_KEYS = frozenset(
    {
        "path",
        "paths",
        "claim_path",
        "run_id",
        "session_id",
        "created_at",
        "updated_at",
        "started_at",
        "finished_at",
        "timestamp",
        "timestamps",
    }
)


class DuplicateRegistryError(RuntimeError):
    pass


@dataclass(frozen=True)
class DuplicateGateResult:
    findings: list[dict[str, JsonValue]]
    artifact: dict[str, JsonValue]
    report_section: dict[str, JsonValue]
    warnings: list[str]


def _parse_positive_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    if parsed <= 0:
        return default
    return parsed


def _parse_threshold_env(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        parsed = float(raw)
    except ValueError:
        return default
    if parsed < 0.0:
        return default
    if parsed > 1.0:
        return 1.0
    return round(parsed, 6)


def _canonical_json(value: object) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def _ensure_registry_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _atomic_write_json(path: Path, payload: dict[str, JsonValue]) -> None:
    _ensure_registry_dir(path)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f"{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as tmp:
        _ = tmp.write(_canonical_json(payload))
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = Path(tmp.name)
    os.replace(tmp_path, path)


def _rounded_score(value: float) -> float:
    return float(round(max(0.0, min(1.0, value)), 6))


def _claim_family(*, finding: dict[str, JsonValue], claim_path: str) -> str:
    finding_id_any = finding.get("id")
    if isinstance(finding_id_any, str) and finding_id_any:
        return finding_id_any
    return claim_path


def _normalize_nonvolatile(value: object) -> object:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, list):
        items = [_normalize_nonvolatile(item) for item in cast(list[object], value)]
        return sorted(items, key=lambda item: _canonical_json(item))
    if isinstance(value, dict):
        obj = cast(dict[object, object], value)
        out: dict[str, object] = {}
        for key_any, item in sorted(obj.items(), key=lambda pair: str(pair[0])):
            key = str(key_any)
            if key in _VOLATILE_META_KEYS or key.endswith(("_path", "_at", "_ts")):
                continue
            out[key] = _normalize_nonvolatile(item)
        return out
    return str(value)


def _collect_hash_signals(
    value: object,
    *,
    key_hint: str,
    out: list[str],
) -> None:
    if isinstance(value, dict):
        obj = cast(dict[object, object], value)
        for child_key_any, child_value in sorted(
            obj.items(), key=lambda pair: str(pair[0])
        ):
            _collect_hash_signals(
                child_value,
                key_hint=str(child_key_any),
                out=out,
            )
        return

    if isinstance(value, list):
        for child in cast(list[object], value):
            _collect_hash_signals(child, key_hint=key_hint, out=out)
        return

    hint = key_hint.lower()
    if "fingerprint" in hint:
        return
    if hint in _VOLATILE_META_KEYS:
        return
    if not (
        "sha256" in hint
        or hint.endswith("_hash")
        or hint.endswith("_hashes")
        or hint in {"hash", "hashes"}
    ):
        return

    if isinstance(value, str) and value.strip():
        out.append(value.strip().lower())


def _finding_evidence_hashes(finding: dict[str, JsonValue]) -> list[str]:
    hashes: list[str] = []
    _collect_hash_signals(finding.get("evidence"), key_hint="evidence", out=hashes)
    _collect_hash_signals(
        finding.get("evidence_refs"), key_hint="evidence_refs", out=hashes
    )
    _collect_hash_signals(finding.get("details"), key_hint="details", out=hashes)
    return sorted(set(hashes))


def _finding_lineage_diff_hash(
    finding: dict[str, JsonValue],
    *,
    claim_family: str,
) -> str:
    lineage_view = {
        "claim_family": claim_family,
        "lineage": finding.get("lineage"),
        "lineage_diff": finding.get("lineage_diff"),
        "diff": finding.get("diff"),
    }
    normalized = _normalize_nonvolatile(lineage_view)
    text = _canonical_json(normalized)
    if text == _canonical_json(
        {
            "claim_family": claim_family,
            "diff": None,
            "lineage": None,
            "lineage_diff": None,
        }
    ):
        return ""
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _coerce_hash_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in cast(list[object], value):
        if isinstance(item, str) and item.strip():
            out.append(item.strip().lower())
    return sorted(set(out))


def _ranking_sort_key(item: dict[str, JsonValue]) -> tuple[float, int, str, str, str]:
    novelty_any = item.get("novelty_score")
    novelty = float(novelty_any) if isinstance(novelty_any, (int, float)) else 0.0
    status_any = item.get("status")
    status = status_any if isinstance(status_any, str) else "suppressed"
    status_priority = 1 if status == "suppressed" else 0
    return (
        -novelty,
        status_priority,
        cast(str, item.get("fingerprint_sha256", "")),
        cast(str, item.get("finding_id", "")),
        cast(str, item.get("claim_path", "")),
    )


def _novelty_score(
    *,
    known_duplicate: bool,
    evidence_hash_delta: bool,
    lineage_diff_hash_delta: bool,
    force_retriage: bool,
    t_force_retriage: float,
) -> float:
    if not known_duplicate:
        return 1.0

    score = 0.1
    if evidence_hash_delta:
        score = max(score, 0.8)
    if lineage_diff_hash_delta:
        score = max(score, 0.75)
    if evidence_hash_delta and lineage_diff_hash_delta:
        score = max(score, 0.9)
    if force_retriage:
        score = max(score, t_force_retriage)
    return _rounded_score(score)


def _registry_rel_path(registry_path: Path, run_dir: Path) -> str:
    try:
        return registry_path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        pass
    try:
        return registry_path.resolve().relative_to(run_dir.resolve()).as_posix()
    except ValueError:
        return registry_path.name


def resolve_duplicate_registry_path(run_dir: Path) -> Path:
    env_path = os.environ.get("AIEDGE_DUPLICATE_REGISTRY_PATH")
    if env_path is not None and env_path.strip():
        return Path(env_path).expanduser().resolve()

    if run_dir.parent != run_dir:
        state_root = run_dir.parent.parent
        return state_root / ".sisyphus" / "state" / "aiedge" / "duplicate_registry.json"

    return (
        Path.cwd() / ".sisyphus" / "state" / "aiedge" / "duplicate_registry.json"
    ).resolve()


def _empty_registry(created_at: str) -> dict[str, JsonValue]:
    return {
        "schema_version": DUPLICATE_REGISTRY_SCHEMA_VERSION,
        "created_at": created_at,
        "records": {},
    }


def _load_registry(path: Path, *, created_at: str) -> dict[str, JsonValue]:
    if not path.exists():
        return _empty_registry(created_at)

    try:
        raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except Exception as exc:
        raise DuplicateRegistryError(
            f"{DUPLICATE_REGISTRY_LOAD_ERROR}: registry json decode failed: {exc}"
        ) from exc

    if not isinstance(raw, dict):
        raise DuplicateRegistryError(
            f"{DUPLICATE_REGISTRY_LOAD_ERROR}: registry root must be object"
        )

    registry = cast(dict[str, object], raw)
    version = registry.get("schema_version")
    if version != DUPLICATE_REGISTRY_SCHEMA_VERSION:
        raise DuplicateRegistryError(
            f"{DUPLICATE_REGISTRY_LOAD_ERROR}: schema_version must be {DUPLICATE_REGISTRY_SCHEMA_VERSION!r}"
        )

    created = registry.get("created_at")
    created_at_value = created if isinstance(created, str) and created else created_at

    records_any = registry.get("records")
    if not isinstance(records_any, dict):
        raise DuplicateRegistryError(
            f"{DUPLICATE_REGISTRY_LOAD_ERROR}: records must be object"
        )

    records = cast(dict[str, object], records_any)
    normalized_records: dict[str, JsonValue] = {}
    for fp, rec_any in sorted(records.items(), key=lambda item: str(item[0])):
        if len(fp) != 64:
            raise DuplicateRegistryError(
                f"{DUPLICATE_REGISTRY_LOAD_ERROR}: invalid fingerprint key {fp!r}"
            )
        if not isinstance(rec_any, dict):
            raise DuplicateRegistryError(
                f"{DUPLICATE_REGISTRY_LOAD_ERROR}: record {fp!r} must be object"
            )
        rec = cast(dict[str, object], rec_any)
        if rec.get("fingerprint") != fp:
            raise DuplicateRegistryError(
                f"{DUPLICATE_REGISTRY_LOAD_ERROR}: record fingerprint mismatch for {fp}"
            )
        if rec.get("fingerprint_version") != FINGERPRINT_VERSION:
            raise DuplicateRegistryError(
                f"{DUPLICATE_REGISTRY_LOAD_ERROR}: unsupported fingerprint_version for {fp}"
            )
        normalized_records[fp] = cast(JsonValue, rec)

    return {
        "schema_version": DUPLICATE_REGISTRY_SCHEMA_VERSION,
        "created_at": created_at_value,
        "records": cast(JsonValue, normalized_records),
    }


def _record_source(
    *,
    run_id: str,
    finding_id: str,
    claim_path: str,
) -> dict[str, JsonValue]:
    return {
        "run_id": run_id,
        "finding_id": finding_id,
        "claim_path": claim_path,
    }


def _normalize_sources(
    sources_any: object, *, max_sources_per_record: int
) -> list[dict[str, JsonValue]]:
    sources: list[dict[str, JsonValue]] = []
    if isinstance(sources_any, list):
        for item_any in cast(list[object], sources_any):
            if not isinstance(item_any, dict):
                continue
            item = cast(dict[str, object], item_any)
            run_id_any = item.get("run_id")
            finding_id_any = item.get("finding_id")
            claim_path_any = item.get("claim_path")
            if not isinstance(run_id_any, str) or not run_id_any:
                continue
            source: dict[str, JsonValue] = {"run_id": run_id_any}
            if isinstance(finding_id_any, str) and finding_id_any:
                source["finding_id"] = finding_id_any
            if isinstance(claim_path_any, str) and claim_path_any:
                source["claim_path"] = claim_path_any
            sources.append(source)

    deduped: dict[tuple[str, str, str], dict[str, JsonValue]] = {}
    for source in sources:
        key = (
            cast(str, source.get("run_id", "")),
            cast(str, source.get("finding_id", "")),
            cast(str, source.get("claim_path", "")),
        )
        deduped[key] = source

    ordered = [
        deduped[key]
        for key in sorted(
            deduped.keys(),
            key=lambda value: (value[0], value[1], value[2]),
        )
    ]
    if len(ordered) > max_sources_per_record:
        return ordered[-max_sources_per_record:]
    return ordered


def _prune_records(
    records: dict[str, dict[str, JsonValue]], *, max_records: int
) -> dict[str, dict[str, JsonValue]]:
    """Bounded retention policy.

    Keep at most `max_records` entries by descending `last_seen_at`, then by
    fingerprint lexical order for deterministic tie-breaking. This policy keeps
    storage bounded while preserving most recently observed fingerprints.
    """

    if len(records) <= max_records:
        return dict(sorted(records.items(), key=lambda item: item[0]))

    ordered = sorted(
        records.items(),
        key=lambda item: (
            cast(str, item[1].get("last_seen_at", "")),
            item[0],
        ),
        reverse=True,
    )
    kept = ordered[:max_records]
    return dict(sorted(kept, key=lambda item: item[0]))


def _write_duplicate_gate_artifact(
    *, run_dir: Path, payload: dict[str, JsonValue]
) -> str:
    rel = Path("report") / "duplicate_gate.json"
    path = run_dir / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(_canonical_json(payload), encoding="utf-8")
    return rel.as_posix()


def apply_duplicate_gate(
    *,
    findings: list[dict[str, JsonValue]],
    run_id: str,
    run_dir: Path,
    seen_at: str,
    force_retriage: bool = False,
) -> DuplicateGateResult:
    registry_path = resolve_duplicate_registry_path(run_dir)
    registry = _load_registry(registry_path, created_at=seen_at)
    records_any = registry.get("records")
    records = cast(dict[str, dict[str, JsonValue]], records_any)

    max_records = _parse_positive_int_env(
        "AIEDGE_DUPLICATE_REGISTRY_MAX_RECORDS", _DEFAULT_MAX_RECORDS
    )
    max_sources_per_record = _parse_positive_int_env(
        "AIEDGE_DUPLICATE_REGISTRY_MAX_SOURCES", _DEFAULT_MAX_SOURCES_PER_RECORD
    )
    t_reopen = _parse_threshold_env("AIEDGE_DUPLICATE_GATE_T_REOPEN", _DEFAULT_T_REOPEN)
    t_force_retriage = _parse_threshold_env(
        "AIEDGE_DUPLICATE_GATE_T_FORCE_RETRIAGE", _DEFAULT_T_FORCE_RETRIAGE
    )

    out_findings: list[dict[str, JsonValue]] = []
    new: list[dict[str, JsonValue]] = []
    suppressed: list[dict[str, JsonValue]] = []
    reopened: list[dict[str, JsonValue]] = []
    novelty_table: list[dict[str, JsonValue]] = []
    ranking: list[dict[str, JsonValue]] = []
    warnings: list[str] = []

    for idx, finding in enumerate(findings):
        finding_id_any = finding.get("id")
        finding_id = finding_id_any if isinstance(finding_id_any, str) else ""
        claim_path = f"findings[{idx}]"

        try:
            fingerprint = claim_fingerprint_sha256(cast(dict[str, object], finding))
        except Exception as exc:
            reason = (
                f"{DUPLICATE_GATE_ANALYSIS_FAIL_OPEN}: fingerprint failed for "
                f"{claim_path}: {type(exc).__name__}: {exc}"
            )
            warnings.append(reason)
            out_findings.append(dict(finding))
            new.append(
                {
                    "claim_path": claim_path,
                    "finding_id": finding_id,
                    "reason": "analysis_fail_open",
                }
            )
            continue

        fingerprint_meta: dict[str, JsonValue] = {
            "claim_path": claim_path,
            "finding_id": finding_id,
            "fingerprint_sha256": fingerprint,
            "fingerprint_version": FINGERPRINT_VERSION,
        }
        claim_family = _claim_family(finding=finding, claim_path=claim_path)
        evidence_hashes = _finding_evidence_hashes(finding)
        lineage_diff_hash = _finding_lineage_diff_hash(
            finding=finding,
            claim_family=claim_family,
        )

        existing = records.get(fingerprint)
        if existing is not None:
            previous_evidence_hashes = _coerce_hash_list(
                existing.get("evidence_hashes")
            )
            previous_lineage_diff_hash_any = existing.get("lineage_diff_hash")
            previous_lineage_diff_hash = (
                previous_lineage_diff_hash_any
                if isinstance(previous_lineage_diff_hash_any, str)
                else ""
            )
            previous_novelty_any = existing.get("last_novelty_score")
            previous_novelty = (
                float(previous_novelty_any)
                if isinstance(previous_novelty_any, (int, float))
                else 0.0
            )
            evidence_hash_delta = evidence_hashes != previous_evidence_hashes
            lineage_diff_hash_delta = (
                bool(lineage_diff_hash)
                and lineage_diff_hash != previous_lineage_diff_hash
            )
            novelty_score = _novelty_score(
                known_duplicate=True,
                evidence_hash_delta=evidence_hash_delta,
                lineage_diff_hash_delta=lineage_diff_hash_delta,
                force_retriage=force_retriage,
                t_force_retriage=t_force_retriage,
            )
            auto_reason_codes: list[str] = []
            if evidence_hash_delta:
                auto_reason_codes.append(_AUTO_REOPEN_EVIDENCE_HASH_DELTA)
            if lineage_diff_hash_delta:
                auto_reason_codes.append(_AUTO_REOPEN_LINEAGE_DIFF_DELTA)

            should_auto_reopen = bool(auto_reason_codes) and novelty_score >= t_reopen
            if should_auto_reopen:
                auto_reason_codes.append(_AUTO_REOPEN_NOVELTY_THRESHOLD_MET)

            source_entries = _normalize_sources(
                existing.get("sources"),
                max_sources_per_record=max_sources_per_record,
            )
            source_entries.append(
                _record_source(
                    run_id=run_id,
                    finding_id=finding_id,
                    claim_path=claim_path,
                )
            )
            existing["sources"] = cast(
                JsonValue,
                _normalize_sources(
                    source_entries,
                    max_sources_per_record=max_sources_per_record,
                ),
            )
            existing["last_seen_at"] = seen_at
            existing["claim_family"] = claim_family
            existing["evidence_hashes"] = cast(
                JsonValue, cast(list[object], evidence_hashes)
            )
            existing["lineage_diff_hash"] = lineage_diff_hash
            existing["last_novelty_score"] = novelty_score
            if force_retriage or should_auto_reopen:
                reason_codes = sorted(
                    set(
                        [_MANUAL_OVERRIDE_REASON, _FORCE_RETRIAGE_REASON]
                        if force_retriage
                        else auto_reason_codes
                    )
                )
                reopened_item = {
                    **fingerprint_meta,
                    "previous_status": "suppressed_exact_duplicate",
                    "new_status": "reopened",
                    "trigger_reason_codes": cast(
                        list[JsonValue], cast(list[object], reason_codes)
                    ),
                    "evidence_hashes_added": cast(
                        list[JsonValue],
                        cast(
                            list[object],
                            sorted(
                                set(evidence_hashes) - set(previous_evidence_hashes)
                            ),
                        ),
                    ),
                    "evidence_hashes_removed": cast(
                        list[JsonValue],
                        cast(
                            list[object],
                            sorted(
                                set(previous_evidence_hashes) - set(evidence_hashes)
                            ),
                        ),
                    ),
                    "lineage_diff_hash_before": previous_lineage_diff_hash,
                    "lineage_diff_hash_after": lineage_diff_hash,
                    "novelty_before": _rounded_score(previous_novelty),
                    "novelty_after": novelty_score,
                    "deterministic_recompute_ok": True,
                    "force_retriage": force_retriage,
                    "force_retriage_threshold": t_force_retriage,
                    "force_retriage_threshold_met": novelty_score >= t_force_retriage,
                }
                reopened.append(cast(dict[str, JsonValue], reopened_item))
                out_findings.append(dict(finding))
                existing["last_classification"] = "context_changed_reopen"
                existing["last_reopen_reason_codes"] = cast(
                    JsonValue, cast(list[object], reason_codes)
                )
                novelty_table.append(
                    {
                        **fingerprint_meta,
                        "status": "reopened",
                        "novelty_score": novelty_score,
                        "known_duplicate": True,
                    }
                )
                ranking.append(
                    {
                        **fingerprint_meta,
                        "status": "reopened",
                        "novelty_score": novelty_score,
                    }
                )
                continue

            suppressed.append(fingerprint_meta)
            existing["last_classification"] = "exact_fingerprint_duplicate"
            novelty_table.append(
                {
                    **fingerprint_meta,
                    "status": "suppressed",
                    "novelty_score": novelty_score,
                    "known_duplicate": True,
                }
            )
            ranking.append(
                {
                    **fingerprint_meta,
                    "status": "suppressed",
                    "novelty_score": novelty_score,
                }
            )
            continue

        out_findings.append(dict(finding))
        new.append(fingerprint_meta)
        novelty_table.append(
            {
                **fingerprint_meta,
                "status": "new",
                "novelty_score": 1.0,
                "known_duplicate": False,
            }
        )
        ranking.append(
            {
                **fingerprint_meta,
                "status": "new",
                "novelty_score": 1.0,
            }
        )
        records[fingerprint] = {
            "fingerprint": fingerprint,
            "fingerprint_version": FINGERPRINT_VERSION,
            "first_seen_run_id": run_id,
            "last_seen_at": seen_at,
            "sources": [
                _record_source(
                    run_id=run_id,
                    finding_id=finding_id,
                    claim_path=claim_path,
                )
            ],
            "claim_family": claim_family,
            "evidence_hashes": cast(JsonValue, cast(list[object], evidence_hashes)),
            "lineage_diff_hash": lineage_diff_hash,
            "last_novelty_score": 1.0,
            "last_classification": "exact_fingerprint_duplicate",
        }

    pruned_records = _prune_records(records, max_records=max_records)
    registry_payload = {
        "schema_version": DUPLICATE_REGISTRY_SCHEMA_VERSION,
        "created_at": cast(str, registry.get("created_at", seen_at)),
        "records": cast(JsonValue, pruned_records),
    }
    _atomic_write_json(registry_path, registry_payload)

    suppressed_sorted = sorted(
        suppressed,
        key=lambda item: (
            cast(str, item.get("fingerprint_sha256", "")),
            cast(str, item.get("finding_id", "")),
            cast(str, item.get("claim_path", "")),
        ),
    )
    new_sorted = sorted(
        new,
        key=lambda item: (
            cast(str, item.get("fingerprint_sha256", "")),
            cast(str, item.get("finding_id", "")),
            cast(str, item.get("claim_path", "")),
            cast(str, item.get("reason", "")),
        ),
    )
    warnings_sorted = sorted(set(warnings))
    reopened_sorted = sorted(
        reopened,
        key=lambda item: (
            cast(str, item.get("fingerprint_sha256", "")),
            cast(str, item.get("finding_id", "")),
            cast(str, item.get("claim_path", "")),
        ),
    )
    novelty_sorted = sorted(novelty_table, key=_ranking_sort_key)
    ranking_sorted = sorted(ranking, key=_ranking_sort_key)
    ranked_table: list[dict[str, JsonValue]] = []
    for idx, entry in enumerate(ranking_sorted, start=1):
        enriched = dict(entry)
        enriched["rank"] = idx
        ranked_table.append(enriched)

    artifact: dict[str, JsonValue] = {
        "schema_version": DUPLICATE_GATE_SCHEMA_VERSION,
        "taxonomy_version": DUPLICATE_TAXONOMY_VERSION,
        "fingerprint_version": FINGERPRINT_VERSION,
        "policy": {
            "reopen_mode": "hybrid-v1",
            "default_reopen": _MANUAL_OVERRIDE_REASON,
            "auto_reopen_allowed": [
                _AUTO_REOPEN_EVIDENCE_HASH_DELTA,
                _AUTO_REOPEN_LINEAGE_DIFF_DELTA,
            ],
            "auto_reopen_forbidden": [
                "llm_only_text_drift",
                "path_or_meta_only_changes",
                "score_drift_without_evidence_delta",
            ],
            "thresholds": {
                "t_reopen": t_reopen,
                "t_force_retriage": t_force_retriage,
            },
        },
        "force_retriage": bool(force_retriage),
        "registry": {
            "path": _registry_rel_path(registry_path, run_dir),
            "schema_version": DUPLICATE_REGISTRY_SCHEMA_VERSION,
            "retention": {
                "max_records": max_records,
                "max_sources_per_record": max_sources_per_record,
            },
        },
        "suppressed": cast(list[JsonValue], cast(list[object], suppressed_sorted)),
        "new": cast(list[JsonValue], cast(list[object], new_sorted)),
        "reopened": cast(list[JsonValue], cast(list[object], reopened_sorted)),
        "novelty": cast(list[JsonValue], cast(list[object], novelty_sorted)),
        "ranked": cast(list[JsonValue], cast(list[object], ranked_table)),
        "ranking_policy": {
            "name": "novelty_first_stable_v1",
            "priority": ["novelty_score_desc", "novel_items_before_suppressed"],
            "tie_breaks": ["fingerprint_sha256", "finding_id", "claim_path"],
        },
        "warnings": cast(list[JsonValue], cast(list[object], warnings_sorted)),
    }
    artifact_rel = _write_duplicate_gate_artifact(run_dir=run_dir, payload=artifact)

    report_section: dict[str, JsonValue] = {
        "taxonomy_version": DUPLICATE_TAXONOMY_VERSION,
        "exact_duplicate_count": len(suppressed_sorted),
        "near_duplicate_count": 0,
        "context_reopen_count": len(reopened_sorted),
        "reopened_count": len(reopened_sorted),
        "novel_count": len(new_sorted) + len(reopened_sorted),
        "suppressed_count": len(suppressed_sorted),
        "ranking_policy": "novelty_first_stable_v1",
        "thresholds": {
            "t_reopen": t_reopen,
            "t_force_retriage": t_force_retriage,
        },
        "artifact": artifact_rel,
    }
    if warnings_sorted:
        report_section["warning_token"] = DUPLICATE_GATE_ANALYSIS_FAIL_OPEN
        report_section["warning_reasons"] = cast(
            list[JsonValue], cast(list[object], warnings_sorted)
        )

    return DuplicateGateResult(
        findings=out_findings,
        artifact=artifact,
        report_section=report_section,
        warnings=warnings_sorted,
    )
