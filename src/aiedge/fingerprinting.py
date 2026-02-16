from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Final, cast


FINGERPRINT_VERSION: Final[str] = "claim-fp-v1"
DUPLICATE_TAXONOMY_VERSION: Final[str] = "duplicate-taxonomy-v1"
DUPLICATE_REGISTRY_SCHEMA_VERSION: Final[str] = "duplicate-registry-v1"

_FLOAT_ROUND_DIGITS: Final[int] = 6

_EXCLUDED_FIELD_NAMES: Final[frozenset[str]] = frozenset(
    {
        "created_at",
        "updated_at",
        "started_at",
        "finished_at",
        "timestamp",
        "timestamps",
        "run_id",
        "stage_run_id",
        "trace_id",
        "session_id",
        "path",
        "paths",
        "evidence_path",
        "evidence_paths",
        "evidence_ref",
        "evidence_refs",
        "file",
        "files",
        "blob",
        "blobs",
        "raw_blob",
        "raw_blobs",
        "binary",
        "binary_blob",
        "raw_bytes",
    }
)

_VOLATILE_SUFFIXES: Final[tuple[str, ...]] = (
    "_at",
    "_ts",
    "_timestamp",
    "_path",
    "_paths",
    "_blob",
    "_bytes",
)


DUPLICATE_REGISTRY_JSON_SCHEMA: Final[dict[str, object]] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "AIEdge Duplicate Registry",
    "type": "object",
    "additionalProperties": False,
    "required": ["schema_version", "created_at", "records"],
    "properties": {
        "schema_version": {
            "type": "string",
            "const": DUPLICATE_REGISTRY_SCHEMA_VERSION,
        },
        "created_at": {"type": "string", "format": "date-time"},
        "records": {
            "type": "object",
            "propertyNames": {
                "type": "string",
                "pattern": "^[a-f0-9]{64}$",
            },
            "additionalProperties": {
                "type": "object",
                "additionalProperties": False,
                "required": [
                    "fingerprint",
                    "fingerprint_version",
                    "first_seen_run_id",
                    "last_seen_at",
                    "sources",
                ],
                "properties": {
                    "fingerprint": {
                        "type": "string",
                        "pattern": "^[a-f0-9]{64}$",
                    },
                    "fingerprint_version": {
                        "type": "string",
                        "const": FINGERPRINT_VERSION,
                    },
                    "first_seen_run_id": {"type": "string", "minLength": 1},
                    "last_seen_at": {"type": "string", "format": "date-time"},
                    "sources": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "additionalProperties": False,
                            "required": ["run_id"],
                            "properties": {
                                "run_id": {"type": "string", "minLength": 1},
                                "finding_id": {"type": "string"},
                                "claim_path": {"type": "string"},
                            },
                        },
                    },
                    "last_classification": {
                        "type": "string",
                        "enum": [
                            "exact_fingerprint_duplicate",
                            "near_duplicate",
                            "context_changed_reopen",
                        ],
                    },
                },
            },
        },
    },
}


def _is_excluded_key(key: object) -> bool:
    if not isinstance(key, str):
        return True
    if key in _EXCLUDED_FIELD_NAMES:
        return True
    return key.endswith(_VOLATILE_SUFFIXES)


def _canonical_json_text(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _normalize_value(value: object) -> object:
    if value is None or isinstance(value, (str, int, bool)):
        return value

    if isinstance(value, float):
        return float(round(value, _FLOAT_ROUND_DIGITS))

    if isinstance(value, Mapping):
        obj = cast(Mapping[object, object], value)
        normalized_map: dict[str, object] = {}
        key_values = sorted(((str(k), v) for k, v in obj.items()), key=lambda kv: kv[0])
        for key, item in key_values:
            if _is_excluded_key(key):
                continue
            normalized_map[key] = _normalize_value(item)
        return normalized_map

    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        normalized_items = [_normalize_value(item) for item in value]
        return sorted(normalized_items, key=_canonical_json_text)

    return str(value)


def normalize_claim_for_fingerprint(claim: Mapping[str, object]) -> dict[str, object]:
    normalized = _normalize_value(dict(claim))
    return cast(dict[str, object], normalized)


def claim_fingerprint_preimage(
    claim: Mapping[str, object],
    *,
    fingerprint_version: str = FINGERPRINT_VERSION,
) -> str:
    normalized_claim = normalize_claim_for_fingerprint(claim)
    preimage = {
        "claim": normalized_claim,
        "fingerprint_version": fingerprint_version,
    }
    return _canonical_json_text(preimage)


def claim_fingerprint_sha256(
    claim: Mapping[str, object],
    *,
    fingerprint_version: str = FINGERPRINT_VERSION,
) -> str:
    preimage = claim_fingerprint_preimage(
        claim,
        fingerprint_version=fingerprint_version,
    )
    return hashlib.sha256(preimage.encode("ascii")).hexdigest()
