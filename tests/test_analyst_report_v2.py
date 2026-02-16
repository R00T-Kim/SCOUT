from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, cast

import aiedge.reporting as reporting
from aiedge.run import analyze_run, create_run
from aiedge.schema import JsonValue


BuildV2 = Callable[[dict[str, object]], dict[str, object]]


def _require_build_v2() -> BuildV2:
    build_any = getattr(reporting, "build_analyst_report_v2", None)
    assert callable(build_any), "missing reporting.build_analyst_report_v2"
    return cast(BuildV2, build_any)


def _top_risk_claims(report_v2: dict[str, object]) -> list[dict[str, object]]:
    claims_any = report_v2.get("top_risk_claims")
    assert isinstance(claims_any, list), (
        "analyst_report_v2.top_risk_claims must be list"
    )
    out: list[dict[str, object]] = []
    for idx, item_any in enumerate(cast(list[object], claims_any)):
        assert isinstance(item_any, dict), f"top_risk_claims[{idx}] must be object"
        out.append(cast(dict[str, object], item_any))
    return out


def _claim(
    claim_type: str, severity: str, confidence: float, ref: str
) -> dict[str, object]:
    return {
        "claim_type": claim_type,
        "value": claim_type,
        "severity": severity,
        "confidence": confidence,
        "evidence_refs": [ref],
    }


def _report_with_claims(claims: list[dict[str, object]]) -> dict[str, object]:
    return {
        "limitations": [],
        "claims": claims,
        "attribution": {},
        "endpoints": {},
        "surfaces": {},
        "graph": {},
        "attack_surface": {},
        "threat_model": {},
        "functional_spec": {},
        "poc_validation": {},
        "llm_synthesis": {},
    }


def test_v2_contract_sort_constants_and_severity_mapping() -> None:
    assert reporting.ANALYST_REPORT_V2_SEVERITY_ORDER == (
        "critical",
        "high",
        "medium",
        "low",
        "info",
    )
    assert reporting.ANALYST_REPORT_V2_SEVERITY_RANK == {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }
    assert reporting.ANALYST_REPORT_V2_TOP_RISK_TIEBREAK_ORDER == (
        "severity_desc",
        "confidence_desc",
        "claim_type_asc",
        "first_evidence_ref_asc",
    )


def test_analyze_run_writes_analyst_report_v2_files(tmp_path: Path) -> None:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes((b"ABCD" * 4096)[:8192])

    info = create_run(
        str(fw),
        case_id="analyst-report-v2-write",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = analyze_run(info, time_budget_s=0, no_llm=True)

    report_dir = info.run_dir / "report"
    assert (report_dir / "analyst_report.json").is_file()
    assert (report_dir / "analyst_report_v2.json").is_file()
    assert (report_dir / "analyst_report_v2.md").is_file()
    assert (report_dir / "viewer.html").is_file()


def test_write_analyst_report_v2_viewer_escapes_script_terminator(
    tmp_path: Path,
) -> None:
    report = _report_with_claims(
        [
            {
                "claim_type": "</script><script>alert(1)</script>",
                "value": "x",
                "severity": "high",
                "confidence": 0.9,
                "evidence_refs": ["stages/claims/x.json"],
            }
        ]
    )

    viewer_path = reporting.write_analyst_report_v2_viewer(
        tmp_path, cast(dict[str, JsonValue], report)
    )
    html = viewer_path.read_text(encoding="utf-8")

    assert "viewer.html" in str(viewer_path)
    assert "<script>alert(1)</script>" not in html
    assert "loadData().then(render)" in html


def test_build_analyst_report_v2_top5_order_is_deterministic() -> None:
    build_v2 = _require_build_v2()
    report_in = _report_with_claims(
        [
            _claim("zeta", "high", 0.90, "stages/claims/zeta.json"),
            _claim("alpha", "high", 0.90, "stages/claims/bravo.json"),
            _claim("alpha", "high", 0.90, "stages/claims/alpha.json"),
            _claim("bravo", "high", 0.80, "stages/claims/bravo.json"),
            _claim("charlie", "medium", 0.95, "stages/claims/charlie.json"),
            _claim("delta", "low", 1.00, "stages/claims/delta.json"),
        ]
    )

    out = build_v2(report_in)
    top = _top_risk_claims(out)

    assert len(top) == 5
    assert [cast(str, item["claim_type"]) for item in top] == [
        "alpha",
        "alpha",
        "zeta",
        "bravo",
        "charlie",
    ]
    assert [cast(list[str], item["evidence_refs"])[0] for item in top[:2]] == [
        "stages/claims/alpha.json",
        "stages/claims/bravo.json",
    ]


def test_build_analyst_report_v2_handles_zero_and_fewer_than_five_claims() -> None:
    build_v2 = _require_build_v2()

    out_zero = build_v2(_report_with_claims([]))
    assert _top_risk_claims(out_zero) == []

    out_small = build_v2(
        _report_with_claims(
            [
                _claim("alpha", "high", 0.90, "stages/claims/alpha.json"),
                _claim("bravo", "medium", 0.70, "stages/claims/bravo.json"),
                _claim("charlie", "low", 0.40, "stages/claims/charlie.json"),
            ]
        )
    )
    assert len(_top_risk_claims(out_small)) == 3


def test_build_analyst_report_v2_tolerates_missing_optional_fields() -> None:
    build_v2 = _require_build_v2()
    report_in = _report_with_claims(
        [
            {
                "claim_type": "alpha",
                "value": "alpha",
                "severity": "high",
                "confidence": 0.95,
                "evidence_refs": ["stages/claims/alpha.json"],
            }
        ]
    )

    out = build_v2(report_in)
    top = _top_risk_claims(out)
    assert len(top) == 1
    assert top[0]["claim_type"] == "alpha"


def test_v2_json_payload_is_deterministic_for_same_input() -> None:
    build_v2 = _require_build_v2()
    report_in = _report_with_claims(
        [
            _claim("alpha", "high", 0.95, "stages/claims/alpha.json"),
            _claim("bravo", "medium", 0.60, "stages/claims/bravo.json"),
        ]
    )

    out_1 = build_v2(report_in)
    out_2 = build_v2(report_in)
    payload_1 = json.dumps(out_1, sort_keys=True, ensure_ascii=True)
    payload_2 = json.dumps(out_2, sort_keys=True, ensure_ascii=True)
    assert payload_1 == payload_2
