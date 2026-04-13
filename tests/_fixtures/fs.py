"""JSON file helpers for tests."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_json(path: Path, data: Any) -> None:
    """Write data as JSON to path. Creates parent dirs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def read_json(path: Path) -> Any:
    """Read JSON from path."""
    return json.loads(path.read_text(encoding="utf-8"))
