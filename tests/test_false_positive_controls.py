from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aiedge.run import analyze_run, create_run


def _load_report(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def test_incomplete_completeness_gate_downgrades_findings_confidence_and_disposition(
    tmp_path: Path,
) -> None:
    firmware = tmp_path / "stub.bin"
    _ = firmware.write_bytes(b"STUB-FW\n")

    info = create_run(
        str(firmware),
        case_id="case-incomplete-downgrade",
        ack_authorization=True,
        runs_root=tmp_path / "runs",
    )

    extracted = (
        info.run_dir
        / "stages"
        / "extraction"
        / "_firmware.bin.extracted"
        / "rootfs"
        / "etc"
        / "ssh"
    )
    extracted.mkdir(parents=True, exist_ok=True)
    _ = (extracted / "sshd_config").write_text(
        "PermitRootLogin yes\n", encoding="utf-8"
    )

    _ = analyze_run(info, time_budget_s=0, no_llm=True)

    report = _load_report(info.report_json_path)
    completeness = cast(dict[str, object], report["report_completeness"])
    assert completeness["gate_passed"] is False

    findings = cast(list[dict[str, object]], report["findings"])
    by_id = {
        cast(str, f.get("id")): f for f in findings if isinstance(f.get("id"), str)
    }

    ssh = cast(dict[str, object], by_id["aiedge.findings.config.ssh_permit_root_login"])
    assert ssh["disposition"] == "suspected"
    assert float(cast(float, ssh["confidence"])) <= 0.6
    assert cast(str, ssh["severity"]) not in {"high", "critical"}
