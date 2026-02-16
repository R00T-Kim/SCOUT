from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def test_smoke_import_and_module_run() -> None:
    import aiedge

    assert isinstance(aiedge.__version__, str)

    repo_root = Path(__file__).resolve().parents[1]
    src_dir = repo_root / "src"

    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(src_dir) + (os.pathsep + existing if existing else "")

    res = subprocess.run(
        [sys.executable, "-m", "aiedge"],
        cwd=str(repo_root),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert res.returncode == 0, res.stderr
    assert "aiedge" in (res.stdout or "")
