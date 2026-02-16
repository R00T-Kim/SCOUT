from __future__ import annotations

from pathlib import Path

from aiedge.reporting import write_report_html
from aiedge.schema import empty_report


def test_write_report_html_escapes_overview_note_script_tag(tmp_path: Path) -> None:
    report = empty_report()
    report["overview"] = {"note": "<script>alert(1)</script>"}

    html_path = write_report_html(tmp_path, report)
    html_content = html_path.read_text(encoding="utf-8")

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_content
    assert "<script>alert(1)</script>" not in html_content
