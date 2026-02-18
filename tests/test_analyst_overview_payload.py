from __future__ import annotations

import hashlib
from pathlib import Path
from typing import cast

from aiedge.reporting import (
    ANALYST_OVERVIEW_GATE_ID_FINAL_REPORT_CONTRACT_8MB,
    ANALYST_OVERVIEW_GATE_ID_VERIFIED_CHAIN,
    ANALYST_OVERVIEW_GATE_STATUS_BLOCKED,
    ANALYST_OVERVIEW_GATE_STATUS_NOT_APPLICABLE,
    ANALYST_OVERVIEW_PANE_ANCHOR_ORDER,
    ANALYST_OVERVIEW_SCHEMA_VERSION,
    build_analyst_overview,
    collect_overview_artifact_statuses,
    resolve_overview_gate_applicability,
)
from aiedge.schema import JsonValue


def test_resolve_overview_gate_applicability_profile_analysis_track_missing() -> None:
    gates = resolve_overview_gate_applicability({"profile": "analysis"})

    assert gates[3]["id"] == ANALYST_OVERVIEW_GATE_ID_VERIFIED_CHAIN
    assert gates[3]["status"] == ANALYST_OVERVIEW_GATE_STATUS_NOT_APPLICABLE
    reasons_3_any = gates[3].get("reasons")
    assert isinstance(reasons_3_any, list)
    assert "profile!=exploit" in reasons_3_any

    assert gates[4]["id"] == ANALYST_OVERVIEW_GATE_ID_FINAL_REPORT_CONTRACT_8MB
    assert gates[4]["status"] == ANALYST_OVERVIEW_GATE_STATUS_NOT_APPLICABLE
    reasons_4_any = gates[4].get("reasons")
    assert isinstance(reasons_4_any, list)
    assert "track!=8mb or track missing" in reasons_4_any


def test_resolve_overview_gate_applicability_profile_exploit_track_8mb() -> None:
    gates = resolve_overview_gate_applicability(
        {"profile": "exploit", "track": {"track_id": "8mb"}}
    )

    assert gates[3]["id"] == ANALYST_OVERVIEW_GATE_ID_VERIFIED_CHAIN
    assert gates[3]["status"] == ANALYST_OVERVIEW_GATE_STATUS_BLOCKED
    reasons_any = gates[3].get("reasons")
    assert isinstance(reasons_any, list)
    reasons = reasons_any
    assert any(
        isinstance(reason, str) and "requires verifier artifacts" in reason
        for reason in reasons
    )

    assert gates[4]["id"] == ANALYST_OVERVIEW_GATE_ID_FINAL_REPORT_CONTRACT_8MB
    assert gates[4]["status"] == ANALYST_OVERVIEW_GATE_STATUS_BLOCKED
    reasons_any = gates[4].get("reasons")
    assert isinstance(reasons_any, list)
    reasons = reasons_any
    assert any(
        isinstance(reason, str) and "requires final report verifier" in reason
        for reason in reasons
    )


def test_resolve_overview_gate_applicability_malformed_profile_blocks_verified_chain() -> (
    None
):
    gates = resolve_overview_gate_applicability({})

    assert gates[3]["id"] == ANALYST_OVERVIEW_GATE_ID_VERIFIED_CHAIN
    assert gates[3]["status"] == ANALYST_OVERVIEW_GATE_STATUS_BLOCKED

    reasons_any = gates[3].get("reasons")
    assert isinstance(reasons_any, list) and reasons_any
    reason0 = reasons_any[0]
    assert isinstance(reason0, str)
    assert reason0.startswith("manifest.profile")


def test_collect_overview_artifact_statuses_normalizes_and_rejects_unsafe_refs(
    tmp_path: Path,
) -> None:
    run_dir = tmp_path
    report_dir = run_dir / "report"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = report_dir / "report.json"

    content = b"known-bytes-for-sha256"
    _ = report_path.write_bytes(content)
    expected_sha256 = hashlib.sha256(content).hexdigest()

    statuses = collect_overview_artifact_statuses(
        run_dir,
        refs=[
            ("./report/report.json", True),
            (r"report\\report.json", True),
            ("report/report.json", True),
            ("report/missing.json", True),
            ("../escape.txt", True),
            ("/abs/path.txt", True),
            ("C:/abs.txt", True),
            ("file:///abs/path.txt", True),
            ("javascript:alert(1)", True),
            ("data:text/html,hi", True),
        ],
    )
    by_ref = {item.get("ref"): item for item in statuses}
    normalized_report_entries = [
        item for item in statuses if item.get("ref") == "report/report.json"
    ]
    assert len(normalized_report_entries) == 3

    assert by_ref["report/report.json"]["status"] == "present"
    assert by_ref["report/report.json"]["sha256"] == expected_sha256

    assert by_ref["report/missing.json"]["status"] == "missing"

    assert by_ref["../escape.txt"]["status"] == "invalid"
    assert ".." in str(by_ref["../escape.txt"].get("reason", ""))

    assert by_ref["/abs/path.txt"]["status"] == "invalid"
    assert "run-relative" in str(by_ref["/abs/path.txt"].get("reason", ""))

    assert by_ref["C:/abs.txt"]["status"] == "invalid"
    assert "drive" in str(by_ref["C:/abs.txt"].get("reason", "")).lower()

    assert by_ref["file:///abs/path.txt"]["status"] == "invalid"
    assert "scheme" in str(by_ref["file:///abs/path.txt"].get("reason", "")).lower()

    assert by_ref["javascript:alert(1)"]["status"] == "invalid"
    assert "scheme" in str(by_ref["javascript:alert(1)"].get("reason", "")).lower()

    assert by_ref["data:text/html,hi"]["status"] == "invalid"
    assert "scheme" in str(by_ref["data:text/html,hi"].get("reason", "")).lower()


def test_build_analyst_overview_manifest_missing_blocks_all_gates_and_has_panes_order(
    tmp_path: Path,
) -> None:
    payload = build_analyst_overview({}, run_dir=tmp_path, digest={})

    assert payload["schema_version"] == ANALYST_OVERVIEW_SCHEMA_VERSION

    panes_any = payload.get("panes")
    assert isinstance(panes_any, list)
    pane_ids = [pane.get("id") for pane in panes_any if isinstance(pane, dict)]
    assert pane_ids == list(ANALYST_OVERVIEW_PANE_ANCHOR_ORDER)

    gates_any = payload.get("gates")
    assert isinstance(gates_any, list)
    assert len(gates_any) == 5
    for gate_any in gates_any:
        assert isinstance(gate_any, dict)
        assert gate_any.get("status") == ANALYST_OVERVIEW_GATE_STATUS_BLOCKED
        reasons_any = gate_any.get("reasons")
        assert isinstance(reasons_any, list)
        assert "manifest missing/invalid" in reasons_any


def test_build_analyst_overview_summary_includes_extraction_and_inventory(
    tmp_path: Path,
) -> None:
    report: dict[str, JsonValue] = {
        "extraction": {"status": "ok", "confidence": 0.5, "summary": {"k": 1}},
        "inventory": {"status": "partial", "summary": {"k": 2}},
    }

    payload = build_analyst_overview(
        report,
        run_dir=tmp_path,
        manifest={"profile": "analysis"},
        digest={},
    )

    summary_any = payload.get("summary")
    assert isinstance(summary_any, dict)

    assert "extraction_summary" in summary_any
    assert "inventory_summary" in summary_any
    extraction = summary_any["extraction_summary"]
    assert isinstance(extraction, dict)
    assert extraction.get("status") == "ok"
    assert extraction.get("confidence") == 0.5


def test_build_analyst_overview_redacts_absolute_paths_in_copied_summaries(
    tmp_path: Path,
) -> None:
    report: dict[str, JsonValue] = cast(
        dict[str, JsonValue],
        {
            "extraction": {
                "status": "ok",
                "summary": {
                    "extracted_dir": "/tmp/run/extracted",
                    "nested": {
                        "windows_path": r"C:\\work\\run\\extracted",
                        "windows_path_slash": "D:/work/run/extracted",
                        "run_relative": "stages/extraction/rootfs",
                    },
                },
            },
            "inventory": {
                "status": "ok",
                "summary": {
                    "items": ["report/report.json", "/var/tmp/inventory.json", "E:/a/b"]
                },
            },
            "endpoints": {
                "status": "ok",
                "summary": {
                    "source": "report/endpoints.json",
                    "abs": "/opt/endpoints.json",
                },
            },
        },
    )

    payload = build_analyst_overview(
        report,
        run_dir=tmp_path,
        manifest={"profile": "analysis"},
        digest={},
    )

    summary_any = payload.get("summary")
    assert isinstance(summary_any, dict)

    extraction_any = summary_any.get("extraction_summary")
    assert isinstance(extraction_any, dict)
    extraction_summary_any = extraction_any.get("summary")
    assert isinstance(extraction_summary_any, dict)
    assert extraction_summary_any.get("extracted_dir") == "(redacted: absolute path)"
    nested_any = extraction_summary_any.get("nested")
    assert isinstance(nested_any, dict)
    assert nested_any.get("windows_path") == "(redacted: absolute path)"
    assert nested_any.get("windows_path_slash") == "(redacted: absolute path)"
    assert nested_any.get("run_relative") == "stages/extraction/rootfs"

    inventory_any = summary_any.get("inventory_summary")
    assert isinstance(inventory_any, dict)
    inventory_summary_any = inventory_any.get("summary")
    assert isinstance(inventory_summary_any, dict)
    items_any = inventory_summary_any.get("items")
    assert isinstance(items_any, list)
    assert items_any == [
        "report/report.json",
        "(redacted: absolute path)",
        "(redacted: absolute path)",
    ]

    endpoints_any = summary_any.get("endpoints_summary")
    assert isinstance(endpoints_any, dict)
    endpoints_summary_any = endpoints_any.get("summary")
    assert isinstance(endpoints_summary_any, dict)
    assert endpoints_summary_any.get("source") == "report/endpoints.json"
    assert endpoints_summary_any.get("abs") == "(redacted: absolute path)"


def test_build_analyst_overview_cockpit_blocks_have_expected_shape(
    tmp_path: Path,
) -> None:
    report: dict[str, JsonValue] = {
        "attack_surface": {
            "summary": {
                "endpoints": 3,
                "surfaces": 2,
                "unknowns": 1,
                "non_promoted": 4,
            }
        }
    }
    digest: dict[str, JsonValue] = {
        "exploitability_verdict": {
            "state": "ATTEMPTED_INCONCLUSIVE",
            "reason_codes": ["ATTEMPTED_VERIFIER_FAILED"],
        },
        "next_actions": ["rerun verifier"],
    }

    payload = build_analyst_overview(
        report,
        run_dir=tmp_path,
        manifest={"profile": "analysis"},
        digest=digest,
    )

    cockpit_any = payload.get("cockpit")
    assert isinstance(cockpit_any, dict)

    executive_any = cockpit_any.get("executive_verdict")
    assert isinstance(executive_any, dict)
    assert isinstance(executive_any.get("status"), str)
    assert isinstance(executive_any.get("sources"), list)
    executive_data_any = executive_any.get("data")
    assert isinstance(executive_data_any, dict)
    assert isinstance(executive_data_any.get("verdict_state"), str)
    assert isinstance(executive_data_any.get("reason_codes"), list)
    assert isinstance(executive_data_any.get("next_actions"), list)

    attack_surface_any = cockpit_any.get("attack_surface_scale")
    assert isinstance(attack_surface_any, dict)
    assert isinstance(attack_surface_any.get("status"), str)
    assert isinstance(attack_surface_any.get("sources"), list)
    attack_surface_data_any = attack_surface_any.get("data")
    assert isinstance(attack_surface_data_any, dict)
    assert "endpoints" in attack_surface_data_any
    assert "surfaces" in attack_surface_data_any
    assert "unknowns" in attack_surface_data_any
    assert "non_promoted" in attack_surface_data_any

    verification_any = cockpit_any.get("verification_status")
    assert isinstance(verification_any, dict)
    assert isinstance(verification_any.get("status"), str)
    assert isinstance(verification_any.get("sources"), list)
    verification_data_any = verification_any.get("data")
    assert isinstance(verification_data_any, dict)
    assert isinstance(verification_data_any.get("gates"), list)
    assert isinstance(verification_data_any.get("artifacts"), list)
    assert isinstance(verification_data_any.get("artifact_counts"), dict)
    assert isinstance(verification_data_any.get("blockers"), list)

    evidence_nav_any = cockpit_any.get("evidence_navigator")
    assert isinstance(evidence_nav_any, dict)
    assert isinstance(evidence_nav_any.get("status"), str)
    assert isinstance(evidence_nav_any.get("sources"), list)
    evidence_nav_data_any = evidence_nav_any.get("data")
    assert isinstance(evidence_nav_data_any, dict)
    assert isinstance(evidence_nav_data_any.get("evidence_links"), list)


def test_build_analyst_overview_cockpit_executive_verdict_fails_closed_without_digest(
    tmp_path: Path,
) -> None:
    payload = build_analyst_overview(
        {},
        run_dir=tmp_path,
        manifest={"profile": "analysis"},
        digest={},
    )

    cockpit_any = payload.get("cockpit")
    assert isinstance(cockpit_any, dict)
    executive_any = cockpit_any.get("executive_verdict")
    assert isinstance(executive_any, dict)
    status_any = executive_any.get("status")
    assert isinstance(status_any, str)
    assert status_any in {"blocked", "partial"}

    executive_data_any = executive_any.get("data")
    assert isinstance(executive_data_any, dict)
    assert executive_data_any.get("verdict_state") == "unknown"


def test_build_analyst_overview_cockpit_evidence_links_are_run_relative_only(
    tmp_path: Path,
) -> None:
    digest: dict[str, JsonValue] = {
        "evidence_index": [
            {"ref": "report/report.json"},
            {"ref": "https://attacker.invalid/a"},
            {"ref": "file:///etc/passwd"},
            {"ref": "../escape.txt"},
            {"ref": "/etc/shadow"},
            {"ref": "javascript:alert(1)"},
            {"ref": "data:text/plain,hello"},
        ],
        "finding_verdicts": [
            {
                "evidence_refs": [
                    "stages/findings/pattern_scan.json",
                    "http://attacker.invalid/b",
                    "../outside",
                ],
                "verifier_refs": ["/abs/verifier.json", "data:text/plain,bad"],
            }
        ],
    }
    payload = build_analyst_overview(
        {},
        run_dir=tmp_path,
        manifest={"profile": "analysis"},
        digest=digest,
    )

    cockpit_any = payload.get("cockpit")
    assert isinstance(cockpit_any, dict)
    evidence_nav_any = cockpit_any.get("evidence_navigator")
    assert isinstance(evidence_nav_any, dict)
    evidence_nav_data_any = evidence_nav_any.get("data")
    assert isinstance(evidence_nav_data_any, dict)
    evidence_links_any = evidence_nav_data_any.get("evidence_links")
    assert isinstance(evidence_links_any, list)

    disallowed_prefixes = (
        "http://",
        "https://",
        "/",
        "file:",
        "javascript:",
        "data:",
    )
    for link_any in evidence_links_any:
        assert isinstance(link_any, str)
        link = link_any
        assert not link.startswith(disallowed_prefixes)
        assert ".." not in link

    evidence_links = set(cast(list[str], evidence_links_any))
    assert "report/report.json" in evidence_links
    assert "stages/findings/pattern_scan.json" in evidence_links
    assert "https://attacker.invalid/a" not in evidence_links
    assert "file:///etc/passwd" not in evidence_links
    assert "../escape.txt" not in evidence_links
    assert "/etc/shadow" not in evidence_links
    assert "javascript:alert(1)" not in evidence_links
    assert "data:text/plain,hello" not in evidence_links
