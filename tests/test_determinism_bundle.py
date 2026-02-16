from __future__ import annotations

from pathlib import Path

import pytest

from aiedge.determinism import assert_bundles_equal, collect_run_bundle
from aiedge.run import create_run, run_subset


def _write_firmware(tmp_path: Path) -> Path:
    fw = tmp_path / "fw.bin"
    _ = fw.write_bytes(b"DETERMINISM-FW")
    return fw


def test_collect_run_bundle_is_deterministic_for_tooling_subset(tmp_path: Path) -> None:
    fw = _write_firmware(tmp_path)

    info1 = create_run(
        str(fw),
        case_id="case-det",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = run_subset(info1, ["tooling"], time_budget_s=5, no_llm=True)
    b1 = collect_run_bundle(info1.run_dir)

    info2 = create_run(
        str(fw),
        case_id="case-det",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = run_subset(info2, ["tooling"], time_budget_s=5, no_llm=True)
    b2 = collect_run_bundle(info2.run_dir)

    assert_bundles_equal(b1, b2)


def test_assert_bundles_equal_raises_with_reason(tmp_path: Path) -> None:
    fw = _write_firmware(tmp_path)
    info = create_run(
        str(fw),
        case_id="case-det-reason",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = run_subset(info, ["tooling"], time_budget_s=5, no_llm=True)
    b = collect_run_bundle(info.run_dir)

    altered = dict(b.items)
    altered["manifest.json"] = {"changed": True}
    b2 = type(b)(items=altered, digest_sha256="deadbeef")

    with pytest.raises(AssertionError) as exc:
        assert_bundles_equal(b, b2)
    assert "determinism bundle mismatch" in str(exc.value)
    assert "mismatched=" in str(exc.value) or "missing_in_" in str(exc.value)
    assert "diff_paths=" in str(exc.value)


def test_assert_bundles_equal_allows_allowlisted_mismatches() -> None:
    from aiedge.determinism import DeterminismBundle

    left = DeterminismBundle(
        items={
            "stages/extraction/stage.json": {"x": 1},
            "stages/emulation/stage.json": {"y": 1},
        },
        digest_sha256="a",
    )
    right = DeterminismBundle(
        items={
            "stages/extraction/stage.json": {"x": 2},
            "stages/emulation/stage.json": {"y": 2},
        },
        digest_sha256="b",
    )

    assert_bundles_equal(left, right)


def test_assert_bundles_equal_reports_nested_key_path() -> None:
    from aiedge.determinism import DeterminismBundle

    left = DeterminismBundle(
        items={
            "report/report.json": {
                "summary": {
                    "risk": "high",
                }
            }
        },
        digest_sha256="left",
    )
    right = DeterminismBundle(
        items={
            "report/report.json": {
                "summary": {
                    "risk": "medium",
                }
            }
        },
        digest_sha256="right",
    )

    with pytest.raises(AssertionError) as exc:
        assert_bundles_equal(left, right)
    assert "diff_paths=report/report.json/summary/risk" in str(exc.value)


def test_assert_bundles_equal_allows_known_analysis_final_noise() -> None:
    from aiedge.determinism import DeterminismBundle

    left = DeterminismBundle(
        items={
            "report/report.json": {
                "extraction": {
                    "summary": {
                        "extraction_timeout_s": 30,
                    }
                }
            },
            "stages/carving/stage.json": {
                "artifacts": [
                    {"sha256": "a"},
                ]
            },
            "stages/extraction/stage.json": {
                "params": {
                    "timeout_s": 30,
                },
                "stage_key": "one",
                "artifacts": [{"sha256": "a"}],
            },
        },
        digest_sha256="left",
    )
    right = DeterminismBundle(
        items={
            "report/report.json": {
                "extraction": {
                    "summary": {
                        "extraction_timeout_s": 60,
                    }
                }
            },
            "stages/carving/stage.json": {
                "artifacts": [
                    {"sha256": "b"},
                ]
            },
            "stages/extraction/stage.json": {
                "params": {
                    "timeout_s": 60,
                },
                "stage_key": "two",
                "artifacts": [{"sha256": "b"}],
            },
        },
        digest_sha256="right",
    )

    assert_bundles_equal(left, right)
