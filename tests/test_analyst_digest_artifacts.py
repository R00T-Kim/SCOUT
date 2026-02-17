from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import aiedge.reporting as reporting
from aiedge.run import analyze_run, create_run
from aiedge.schema import JsonValue, validate_analyst_digest


def _is_run_relative(ref: str) -> bool:
    if not ref:
        return False
    if ref.startswith("/"):
        return False
    if len(ref) >= 3 and ref[1:3] == ":\\":
        return False
    return True


def test_analyze_run_writes_analyst_digest_files(tmp_path: Path) -> None:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes((b"ABCD" * 4096)[:8192])

    info = create_run(
        str(fw),
        case_id="analyst-digest-write",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = analyze_run(info, time_budget_s=0, no_llm=True)

    report_dir = info.run_dir / "report"
    digest_json_path = report_dir / "analyst_digest.json"
    digest_md_path = report_dir / "analyst_digest.md"
    assert digest_json_path.is_file()
    assert digest_md_path.is_file()

    digest = cast(
        dict[str, object], json.loads(digest_json_path.read_text(encoding="utf-8"))
    )
    assert validate_analyst_digest(digest) == []

    finding_verdicts_any = digest.get("finding_verdicts")
    assert isinstance(finding_verdicts_any, list)
    for finding_any in cast(list[object], finding_verdicts_any):
        assert isinstance(finding_any, dict)
        finding = cast(dict[str, object], finding_any)
        evidence_refs_any = finding.get("evidence_refs")
        verifier_refs_any = finding.get("verifier_refs")
        assert isinstance(evidence_refs_any, list)
        assert isinstance(verifier_refs_any, list)
        evidence_refs = cast(list[object], evidence_refs_any)
        verifier_refs = cast(list[object], verifier_refs_any)
        assert evidence_refs
        for ref_any in evidence_refs + verifier_refs:
            assert isinstance(ref_any, str)
            assert _is_run_relative(ref_any)


def test_build_analyst_digest_is_deterministic_for_same_report(tmp_path: Path) -> None:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes((b"AIEdge" * 2048)[:8192])

    info = create_run(
        str(fw),
        case_id="analyst-digest-determinism",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = analyze_run(info, time_budget_s=0, no_llm=True)

    report_path = info.run_dir / "report" / "report.json"
    report = cast(
        dict[str, JsonValue], json.loads(report_path.read_text(encoding="utf-8"))
    )
    digest_1 = reporting.build_analyst_digest(
        report,
        run_dir=info.run_dir,
    )
    digest_2 = reporting.build_analyst_digest(
        report,
        run_dir=info.run_dir,
    )

    payload_1 = json.dumps(digest_1, sort_keys=True, ensure_ascii=True)
    payload_2 = json.dumps(digest_2, sort_keys=True, ensure_ascii=True)
    assert payload_1 == payload_2
