from __future__ import annotations

import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pytest

from aiedge.__main__ import main


def test_serve_cli_requires_existing_report_viewer(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    missing_run_dir = tmp_path / "missing-run"
    rc = main(["serve", str(missing_run_dir)])
    captured = capsys.readouterr()
    assert rc == 20
    assert "Run directory not found" in captured.err


def test_serve_cli_once_serves_viewer_html(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    report_dir = run_dir / "report"
    report_dir.mkdir(parents=True)
    viewer_path = report_dir / "viewer.html"
    _ = viewer_path.write_text(
        "<!doctype html><html><body>viewer-ready</body></html>\n",
        encoding="utf-8",
    )

    repo_root = Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = str(repo_root / "src")

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "aiedge",
            "serve",
            str(run_dir),
            "--host",
            "127.0.0.1",
            "--port",
            "0",
            "--once",
        ],
        cwd=repo_root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        assert proc.stdout is not None
        url_line = proc.stdout.readline().strip()
        if not url_line:
            stderr_text = proc.stderr.read() if proc.stderr is not None else ""
            if "Operation not permitted" in stderr_text or "PermissionError" in stderr_text:
                pytest.skip(
                    "serve CLI requires local socket bind permissions unavailable in this sandbox"
                )
            assert url_line, stderr_text
        assert re.match(r"^http://127\.0\.0\.1:\d+/viewer\.html$", url_line)

        body = ""
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                with urlopen(url_line, timeout=1.0) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                break
            except URLError:
                time.sleep(0.05)
        assert "viewer-ready" in body

        rc = proc.wait(timeout=5.0)
        stderr_text = proc.stderr.read() if proc.stderr is not None else ""
        assert rc == 0, stderr_text
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5.0)
