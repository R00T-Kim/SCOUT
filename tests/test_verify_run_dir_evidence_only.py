from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def _run_verifier(run_dir: Path) -> subprocess.CompletedProcess[str]:
    repo_root = Path(__file__).resolve().parents[1]
    return subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts" / "verify_run_dir_evidence_only.py"),
            "--run-dir",
            str(run_dir),
        ],
        cwd=repo_root,
        text=True,
        capture_output=True,
        check=False,
    )


def _make_clean_run_dir(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    _ = (run_dir / "exploits" / "chain_demo").mkdir(parents=True)
    _ = (run_dir / "verified_chain").mkdir(parents=True)
    _ = (run_dir / "exploits" / "chain_demo" / "execution_log_1.txt").write_text(
        "ok\n",
        encoding="utf-8",
    )
    _ = (run_dir / "verified_chain" / "verified_chain.json").write_text(
        "{}\n",
        encoding="utf-8",
    )
    return run_dir


def test_verify_run_dir_evidence_only_ok(tmp_path: Path) -> None:
    run_dir = _make_clean_run_dir(tmp_path)
    res = _run_verifier(run_dir)
    assert res.returncode == 0
    assert res.stdout.startswith("[OK] run_dir evidence-only policy verified:")


def test_verify_run_dir_evidence_only_fails_on_blocked_extension(
    tmp_path: Path,
) -> None:
    run_dir = _make_clean_run_dir(tmp_path)
    _ = (run_dir / "exploits" / "chain_demo" / "payload.py").write_text(
        "print('x')\n",
        encoding="utf-8",
    )

    res = _run_verifier(run_dir)
    assert res.returncode != 0
    assert "[FAIL] disallowed_extension:" in res.stdout


def test_verify_run_dir_evidence_only_fails_on_executable_file(tmp_path: Path) -> None:
    run_dir = _make_clean_run_dir(tmp_path)
    proof = run_dir / "verified_chain" / "proof.txt"
    _ = proof.write_text("proof\n", encoding="utf-8")
    proof.chmod(0o755)

    res = _run_verifier(run_dir)
    assert res.returncode != 0
    assert "[FAIL] executable_file:" in res.stdout


def test_verify_run_dir_evidence_only_fails_on_symlink_escape(tmp_path: Path) -> None:
    run_dir = _make_clean_run_dir(tmp_path)
    outside = tmp_path / "outside.txt"
    _ = outside.write_text("outside\n", encoding="utf-8")

    link_path = run_dir / "exploits" / "chain_demo" / "outside_link"
    link_path.symlink_to(outside)

    res = _run_verifier(run_dir)
    assert res.returncode != 0
    assert "[FAIL] symlink_escape:" in res.stdout


def test_verify_run_dir_evidence_only_fails_closed_when_directory_missing(
    tmp_path: Path,
) -> None:
    run_dir = _make_clean_run_dir(tmp_path)
    chain_dir = run_dir / "exploits" / "chain_demo"
    for child in chain_dir.iterdir():
        if child.is_file():
            child.unlink()
    chain_dir.rmdir()
    (run_dir / "exploits").rmdir()

    res = _run_verifier(run_dir)
    assert res.returncode != 0
    assert "[FAIL] missing_required_artifact:" in res.stdout
