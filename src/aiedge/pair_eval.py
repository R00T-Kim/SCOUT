from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PairSide:
    firmware_path: str
    sha256: str


@dataclass(frozen=True)
class PairSpec:
    pair_id: str
    vendor: str
    model: str
    cve_id: str
    vulnerable: PairSide
    patched: PairSide


def load_pairs_manifest(path: Path) -> list[PairSpec]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != "pair-eval-v1":
        raise ValueError("unsupported pair manifest schema_version")
    pairs = payload.get("pairs")
    if not isinstance(pairs, list):
        raise ValueError("pairs must be a list")
    out: list[PairSpec] = []
    for item in pairs:
        if not isinstance(item, dict):
            continue
        vuln = item.get("vulnerable") or {}
        patched = item.get("patched") or {}
        out.append(
            PairSpec(
                pair_id=str(item["pair_id"]),
                vendor=str(item["vendor"]),
                model=str(item["model"]),
                cve_id=str(item["cve_id"]),
                vulnerable=PairSide(str(vuln["firmware_path"]), str(vuln["sha256"])),
                patched=PairSide(str(patched["firmware_path"]), str(patched["sha256"])),
            )
        )
    return out


def choose_primary_finding(findings_payload: dict[str, Any] | list[dict[str, Any]] | None) -> dict[str, Any] | None:
    findings: list[dict[str, Any]]
    if isinstance(findings_payload, dict):
        raw = findings_payload.get("findings")
        findings = [f for f in raw if isinstance(f, dict)] if isinstance(raw, list) else []
    elif isinstance(findings_payload, list):
        findings = [f for f in findings_payload if isinstance(f, dict)]
    else:
        findings = []
    if not findings:
        return None

    def rank(f: dict[str, Any]) -> tuple[int, float, float, str]:
        category = str(f.get("category") or "")
        is_vuln = 1 if category == "vulnerability" else 0
        priority = float(f.get("priority_score") or 0.0)
        confidence = float(f.get("confidence") or 0.0)
        return (is_vuln, priority, confidence, str(f.get("id") or ""))

    return max(findings, key=rank)


def extract_target_cve_hits(cve_matches_payload: dict[str, Any] | None, target_cve_id: str) -> list[dict[str, Any]]:
    if not isinstance(cve_matches_payload, dict):
        return []
    matches = cve_matches_payload.get("matches")
    if not isinstance(matches, list):
        return []
    return [m for m in matches if isinstance(m, dict) and m.get("cve_id") == target_cve_id]


def determine_ground_truth(side: str, *, status: str, extraction_status: str, target_hit: bool) -> str:
    if status != "success" or extraction_status != "ok":
        return "excluded"
    if side == "vulnerable":
        return "tp" if target_hit else "fn"
    if side == "patched":
        return "fp" if target_hit else "tn"
    raise ValueError(f"unknown side: {side}")


def aggregate_tier_metrics(records: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    out: dict[str, Counter[str]] = defaultdict(Counter)
    for rec in records:
        tier = str(rec.get("evidence_tier") or "unknown")
        gt = str(rec.get("ground_truth") or "")
        if gt in {"tp", "fp", "fn", "tn", "excluded"}:
            out[tier][gt] += 1
    return {tier: dict(counter) for tier, counter in sorted(out.items())}


def build_threshold_rows(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scored = [r for r in records if r.get("ground_truth") in {"tp", "fp", "fn", "tn"}]
    thresholds = sorted({float(r.get("confidence") or 0.0) for r in scored}, reverse=True)
    rows: list[dict[str, Any]] = []
    for threshold in thresholds:
        tp = fp = tn = fn = 0
        for rec in scored:
            conf = float(rec.get("confidence") or 0.0)
            actual_positive = rec.get("side") == "vulnerable"
            predicted_positive = conf >= threshold
            if actual_positive and predicted_positive:
                tp += 1
            elif actual_positive and not predicted_positive:
                fn += 1
            elif (not actual_positive) and predicted_positive:
                fp += 1
            else:
                tn += 1
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        rows.append(
            {
                "threshold": round(threshold, 6),
                "tp": tp,
                "fp": fp,
                "tn": tn,
                "fn": fn,
                "precision": round(precision, 6),
                "recall": round(recall, 6),
                "fpr": round(fpr, 6),
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
