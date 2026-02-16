from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Callable, cast

import pytest

from aiedge.run import RunInfo, analyze_run, create_run, run_subset


def _zip_bytes(entries: dict[str, bytes]) -> bytes:
    with io.BytesIO() as bio:
        with zipfile.ZipFile(bio, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for name, data in entries.items():
                zf.writestr(name, data)
        return bio.getvalue()


def _load_report(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def _tiny_input() -> bytes:
    return b"TINY-FW-0123456789ABCDEFGHIJKLMNOPQRSTUVWX"


def _stub_input() -> bytes:
    return b"STUB-FIRMWARE\nmodel=aiedge\nrev=1\nmode=test\n"


def _ota_like_input() -> bytes:
    inner = _zip_bytes(
        {
            "payload.bin": b"P" * 32,
            "payload_properties.txt": b"FILE_HASH=not-used\n",
        }
    )
    return _zip_bytes({"BYDUpdatePackage/UpdateFull.zip": inner})


def _corrupt_truncated_input() -> bytes:
    return b"PK\x03\x04\x14\x00\x00\x00\x08\x00TRUNCATED"


FixtureFactory = Callable[[], bytes]


@pytest.mark.parametrize(
    ("fixture_name", "make_bytes"),
    [
        ("tiny", _tiny_input),
        ("stub", _stub_input),
        ("ota_like_zip", _ota_like_input),
        ("corrupt_truncated", _corrupt_truncated_input),
    ],
)
def test_fixture_matrix_analyze_run_finalizes_without_pending_required_stages(
    tmp_path: Path, fixture_name: str, make_bytes: FixtureFactory
) -> None:
    firmware = tmp_path / f"{fixture_name}.bin"
    _ = firmware.write_bytes(make_bytes())

    info = create_run(
        str(firmware),
        case_id=f"case-matrix-final-{fixture_name}",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = analyze_run(info, time_budget_s=1, no_llm=True)

    report = _load_report(info.report_json_path)
    completion = cast(dict[str, object], report["run_completion"])
    required = cast(dict[str, str], completion["required_stage_statuses"])

    assert completion["is_final"] is True
    assert completion["is_partial"] is False
    assert set(required.keys()) == {"tooling", "extraction", "inventory", "findings"}
    assert all(
        status in {"ok", "partial", "failed", "skipped"} for status in required.values()
    )
    assert all(status != "pending" for status in required.values())

    integrity = cast(dict[str, object], report["ingestion_integrity"])
    analyzed_input = cast(dict[str, object], integrity["analyzed_input"])
    assert analyzed_input["path"] == "input/firmware.bin"
    assert analyzed_input["exists"] is True
    assert isinstance(analyzed_input["sha256"], str)
    assert isinstance(analyzed_input["size_bytes"], int)

    completeness = cast(dict[str, object], report["report_completeness"])
    assert isinstance(completeness["gate_passed"], bool)


@pytest.mark.parametrize(
    ("fixture_name", "make_bytes"),
    [
        ("tiny", _tiny_input),
        ("stub", _stub_input),
        ("ota_like_zip", _ota_like_input),
        ("corrupt_truncated", _corrupt_truncated_input),
    ],
)
def test_fixture_matrix_run_subset_stays_non_final(
    tmp_path: Path, fixture_name: str, make_bytes: FixtureFactory
) -> None:
    firmware = tmp_path / f"{fixture_name}.bin"
    _ = firmware.write_bytes(make_bytes())

    info = create_run(
        str(firmware),
        case_id=f"case-matrix-subset-{fixture_name}",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = run_subset(info, ["tooling"], time_budget_s=5, no_llm=True)

    report = _load_report(info.report_json_path)
    completion = cast(dict[str, object], report["run_completion"])
    required = cast(dict[str, str], completion["required_stage_statuses"])

    assert completion["is_final"] is False
    assert completion["is_partial"] is True
    assert isinstance(completion.get("reason"), str) and cast(str, completion["reason"])
    assert required["findings"] == "pending"

    completeness = cast(dict[str, object], report["report_completeness"])
    assert completeness["gate_passed"] is False
    reasons = cast(list[object], completeness["reasons"])
    assert any(
        isinstance(reason, str) and "required stage pending" in reason
        for reason in reasons
    )


def test_lightweight_tiny_analyze_run_passes_completeness_gate_with_required_manifests(
    tmp_path: Path,
) -> None:
    firmware = tmp_path / "tiny.bin"
    _ = firmware.write_bytes(_tiny_input())

    info: RunInfo = create_run(
        str(firmware),
        case_id="case-gate-pass-lightweight",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )
    _ = analyze_run(info, time_budget_s=1, no_llm=True)

    report = _load_report(info.report_json_path)
    completeness = cast(dict[str, object], report["report_completeness"])
    completion = cast(dict[str, object], report["run_completion"])

    assert completeness["gate_passed"] is True
    assert cast(list[object], completeness["missing_required_stage_inputs"]) == []
    assert completion["conclusion_ready"] is True

    assert (info.run_dir / "stages" / "tooling" / "stage.json").is_file()
    assert (info.run_dir / "stages" / "extraction" / "stage.json").is_file()
    assert (info.run_dir / "stages" / "inventory" / "stage.json").is_file()

    findings = cast(list[dict[str, object]], report["findings"])
    assert findings
