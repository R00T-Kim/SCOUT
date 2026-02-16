from __future__ import annotations

from pathlib import Path

import pytest

import aiedge.run as run_mod
from aiedge.__main__ import main


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _canonical_8mb() -> Path:
    return (
        _repo_root()
        / "aiedge-runs"
        / "2026-02-12_1633_sha256-387d97fd9251"
        / "input"
        / "firmware.bin"
    )


def _truncated_root_new_firm() -> Path:
    return _repo_root() / "new_firm.bin"


def test_analyze_8mb_rejects_non_canonical_input(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    rc = main(
        [
            "analyze-8mb",
            str(_truncated_root_new_firm()),
            "--case-id",
            "case-8mb-reject",
            "--ack-authorization",
            "--no-llm",
        ]
    )

    captured = capsys.readouterr()
    assert rc == 30
    assert "8MB track requires the canonical snapshot" in captured.err


def test_analyze_8mb_uses_separate_runs_root_and_marks_manifest(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)

    canonical = _canonical_8mb()
    assert canonical.is_file()

    def fake_analyze_run(
        _info: run_mod.RunInfo,
        *,
        time_budget_s: int,
        no_llm: bool,
        force_retriage: bool,
    ) -> str:
        _ = time_budget_s, no_llm, force_retriage
        return "ok"

    monkeypatch.setattr(run_mod, "analyze_run", fake_analyze_run)

    rc = main(
        [
            "analyze-8mb",
            str(canonical),
            "--case-id",
            "case-8mb-ok",
            "--ack-authorization",
            "--no-llm",
            "--time-budget-s",
            "1",
        ]
    )
    assert rc == 0

    run_dir = Path(capsys.readouterr().out.strip())
    assert run_dir.is_dir()
    assert run_dir.parent == tmp_path / "aiedge-8mb-runs"

    manifest_path = run_dir / "manifest.json"
    assert manifest_path.is_file()
    manifest = manifest_path.read_text(encoding="utf-8")
    assert '"track_id": "8mb"' in manifest
    assert '"canonical_sha256_prefix": "387d97fd9251"' in manifest
    assert '"canonical_size_bytes": 8388608' in manifest
