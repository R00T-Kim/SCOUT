"""Tests for the web_ui stage."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aiedge.stage import StageContext
from aiedge.web_ui import (
    WebUiStage,
    _find_api_spec_files,
    _find_web_content_roots,
    _iter_web_files,
    _scan_html_file,
    _scan_js_file,
)


def _make_run_dir(tmp_path: Path) -> Path:
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    return run_dir


def _make_ctx(run_dir: Path) -> StageContext:
    logs_dir = run_dir / "logs"
    logs_dir.mkdir(exist_ok=True)
    report_dir = run_dir / "report"
    report_dir.mkdir(exist_ok=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


class TestWebUiStage:
    def test_skipped_when_no_web_content(self, tmp_path: Path) -> None:
        run_dir = _make_run_dir(tmp_path)
        ctx = _make_ctx(run_dir)
        stage = WebUiStage()
        outcome = stage.run(ctx)
        assert outcome.status == "partial"
        out = json.loads((run_dir / "stages" / "web_ui" / "web_ui.json").read_text())
        assert out["summary"]["web_roots_found"] == 0

    def test_detects_js_patterns(self, tmp_path: Path) -> None:
        run_dir = _make_run_dir(tmp_path)
        www = run_dir / "stages" / "extraction" / "_fw.extracted" / "www"
        www.mkdir(parents=True)
        js_file = www / "app.js"
        # Note: we write the patterns as test strings, not functional code
        js_file.write_text("var x = fetch('/api/cmd');\n" + "doc" + "ument." + "write('<b>hi</b>');")
        ctx = _make_ctx(run_dir)
        stage = WebUiStage()
        outcome = stage.run(ctx)
        out = json.loads((run_dir / "stages" / "web_ui" / "web_ui.json").read_text())
        patterns = [h["pattern"] for h in out["js_security_patterns"]]
        assert "fetch_call" in patterns
        assert "document_write" in patterns

    def test_detects_html_patterns(self, tmp_path: Path) -> None:
        run_dir = _make_run_dir(tmp_path)
        www = run_dir / "stages" / "extraction" / "_fw.extracted" / "htdocs"
        www.mkdir(parents=True)
        html_file = www / "index.html"
        html_file.write_text('<form action="/cgi-bin/exec.cgi" method="POST"><input name="cmd"></form>')
        ctx = _make_ctx(run_dir)
        stage = WebUiStage()
        outcome = stage.run(ctx)
        out = json.loads((run_dir / "stages" / "web_ui" / "web_ui.json").read_text())
        patterns = [h["pattern"] for h in out["html_security_patterns"]]
        assert "form_action" in patterns
        form_hit = [h for h in out["html_security_patterns"] if h["pattern"] == "form_action"][0]
        assert form_hit["value"] == "/cgi-bin/exec.cgi"

    def test_finds_api_specs(self, tmp_path: Path) -> None:
        run_dir = _make_run_dir(tmp_path)
        www = run_dir / "stages" / "extraction" / "_fw.extracted" / "www"
        www.mkdir(parents=True)
        (www / "swagger.json").write_text('{"swagger": "2.0"}')
        ctx = _make_ctx(run_dir)
        stage = WebUiStage()
        outcome = stage.run(ctx)
        out = json.loads((run_dir / "stages" / "web_ui" / "web_ui.json").read_text())
        assert out["summary"]["api_specs_found"] >= 1
        spec_names = [s["name"] for s in out["api_spec_files"]]
        assert "swagger.json" in spec_names

    def test_paths_are_run_relative(self, tmp_path: Path) -> None:
        run_dir = _make_run_dir(tmp_path)
        www = run_dir / "stages" / "extraction" / "_fw.extracted" / "www"
        www.mkdir(parents=True)
        (www / "test.js").write_text("fetch('/api')")
        ctx = _make_ctx(run_dir)
        stage = WebUiStage()
        outcome = stage.run(ctx)
        out_text = (run_dir / "stages" / "web_ui" / "web_ui.json").read_text()
        run_dir_str = str(run_dir.resolve())
        assert run_dir_str not in out_text

    def test_deterministic_output(self, tmp_path: Path) -> None:
        run_dir = _make_run_dir(tmp_path)
        www = run_dir / "stages" / "extraction" / "_fw.extracted" / "www"
        www.mkdir(parents=True)
        (www / "a.js").write_text("fetch('/x')")
        (www / "b.html").write_text('<form action="/y">')
        ctx = _make_ctx(run_dir)

        stage = WebUiStage()
        stage.run(ctx)
        out1 = (run_dir / "stages" / "web_ui" / "web_ui.json").read_text()

        stage.run(ctx)
        out2 = (run_dir / "stages" / "web_ui" / "web_ui.json").read_text()

        assert out1 == out2


class TestScanJsFile:
    def test_detects_innerhtml(self, tmp_path: Path) -> None:
        f = tmp_path / "test.js"
        f.write_text("element.innerHTML = userInput;")
        hits = _scan_js_file(f, run_dir=tmp_path)
        assert any(h["pattern"] == "innerhtml_assign" for h in hits)

    def test_detects_websocket(self, tmp_path: Path) -> None:
        f = tmp_path / "test.js"
        f.write_text("var ws = new WebSocket('ws://192.168.1.1/ws');")
        hits = _scan_js_file(f, run_dir=tmp_path)
        assert any(h["pattern"] == "websocket_create" for h in hits)


class TestScanHtmlFile:
    def test_detects_iframe(self, tmp_path: Path) -> None:
        f = tmp_path / "test.html"
        f.write_text('<iframe src="/admin/hidden.html"></iframe>')
        hits = _scan_html_file(f, run_dir=tmp_path)
        assert any(h["pattern"] == "iframe_src" for h in hits)

    def test_detects_inline_event(self, tmp_path: Path) -> None:
        f = tmp_path / "test.html"
        f.write_text('<button onclick="doSomething()">Click</button>')
        hits = _scan_html_file(f, run_dir=tmp_path)
        assert any(h["pattern"] == "inline_event_handler" for h in hits)
