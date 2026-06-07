from __future__ import annotations

import json
from pathlib import Path

from aiedge.phase01_readiness import (
    ArtifactSpec,
    build_artifact_entry,
    build_report_evidence_audit,
)


def test_report_evidence_audit_accepts_required_phase0_markers(tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text(
        "\n".join(
            [
                "작성일: 2026-06-07 KST",
                "작성/반영일: 2026-06-07 KST",
                "`scout-firmware 3.0.0rc1` / `v3.0.0-rc1`",
                "commit `a7891f0`",
                "S0 fresh evidence",
                "S1 revalidated evidence",
                "stale artifact policy",
                "승격 게이트",
                "P0 Evidence Ledger",
                "P1 Pair Benchmark Floor",
            ]
        ),
        encoding="utf-8",
    )

    payload = build_report_evidence_audit(repo_root=tmp_path, report_path=report)

    assert payload["passed"] is True
    assert payload["verdict"] == "pass"


def test_report_evidence_audit_fails_missing_version(tmp_path: Path) -> None:
    report = tmp_path / "report.md"
    report.write_text(
        "작성일: 2026-06-07 KST\n작성/반영일: 2026-06-07 KST\n",
        encoding="utf-8",
    )

    payload = build_report_evidence_audit(repo_root=tmp_path, report_path=report)

    assert payload["passed"] is False
    failed = {check["name"] for check in payload["checks"] if check["passed"] is False}
    assert "report_contains_version_name" in failed
    assert "report_contains_commit" in failed


def test_artifact_entry_blocks_stale_release_claim(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.json"
    artifact.write_text(json.dumps({"ok": True}), encoding="utf-8")

    entry = build_artifact_entry(
        tmp_path,
        ArtifactSpec(
            path=artifact,
            tier="S2",
            role="old_auxiliary_context",
            release_claim=True,
        ),
    )

    assert entry["exists"] is True
    assert entry["release_claim_allowed"] is False
    assert entry["blocker"] == "stale_or_unrevalidated_evidence_cannot_support_release_claim"
