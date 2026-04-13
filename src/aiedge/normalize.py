"""Normalization helpers for evidence and limitations lists.

Extracted from run.py to reduce God Object complexity.
"""

from __future__ import annotations

from typing import cast

from .schema import JsonValue

__all__ = ["normalize_evidence_list", "normalize_limitations_list"]


def normalize_evidence_list(
    evidence_any: object, *, fallback: list[dict[str, JsonValue]]
) -> list[dict[str, JsonValue]]:
    if not isinstance(evidence_any, list):
        return list(fallback)
    out: list[dict[str, JsonValue]] = []
    for item in cast(list[object], evidence_any):
        if isinstance(item, dict):
            obj = cast(dict[str, object], item)
            path_s = obj.get("path")
            if isinstance(path_s, str) and path_s:
                ev: dict[str, JsonValue] = {"path": path_s}
                note_any = obj.get("note")
                if isinstance(note_any, str) and note_any:
                    ev["note"] = note_any
                snippet_any = obj.get("snippet")
                if isinstance(snippet_any, str) and snippet_any:
                    ev["snippet"] = snippet_any
                snippet_sha_any = obj.get("snippet_sha256")
                if isinstance(snippet_sha_any, str) and snippet_sha_any:
                    ev["snippet_sha256"] = snippet_sha_any
                out.append(ev)
        elif isinstance(item, str) and item:
            out.append({"path": item})
    return out if out else list(fallback)


def normalize_limitations_list(limits_any: object) -> list[str]:
    if not isinstance(limits_any, list):
        return []
    out: list[str] = []
    for x in cast(list[object], limits_any):
        if isinstance(x, str) and x:
            out.append(x)
    return out
