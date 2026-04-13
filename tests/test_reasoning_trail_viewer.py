"""Tests for the reasoning trail rendering surfaces (PR #13).

Covers the three analyst-visible surfaces added in PR #13:
1. ``report_assembler.build_finding_reasoning_trail_md`` -- per-finding
   markdown subsection that lands inside ``analyst_report_v2.md`` under
   each top risk.
2. ``report_assembler.reasoning_trail_for_analyst_json`` -- analyst JSON
   pass-through used by callers that want the raw trail entries.
3. ``cli_tui_render.render_finding_detail_with_trail`` -- TUI finding
   detail block that the snapshot renderer appends after the candidate
   group section.

Plus integration-style tests that exercise:
- ``reporting.write_analyst_report_v2_md`` to confirm the trail
  subsection lands in the actual markdown output and is hidden when
  absent.
- ``reporting.build_analyst_report_v2`` to confirm the JSON surface
  preserves the trail field on the per-claim level (mirroring PR #7a's
  ``category`` pass-through).
- ``reporting.write_analyst_report_v2_viewer`` to confirm the embedded
  HTML viewer template contains the reasoning-trail JS rendering hooks
  and CSS class names that the runtime JS reads.

Schema invariant: PR #13 is additive only -- the analyst report v2 schema
version must NOT change between a finding with a trail and one without.

Fixtures from ``tests/conftest.py`` (Phase 2A) are used where possible.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aiedge.cli_tui_render import (
    _build_tui_snapshot_lines,
    render_finding_detail_with_trail,
)
from aiedge.reasoning_trail import (
    format_trail_for_markdown,
    format_trail_for_tui,
    normalize_trail,
)
from aiedge.report_assembler import (
    build_finding_reasoning_trail_md,
    reasoning_trail_for_analyst_json,
)
from aiedge.reporting import (
    ANALYST_REPORT_V2_SCHEMA_VERSION,
    build_analyst_report_v2,
    write_analyst_report_v2_md,
    write_analyst_report_v2_viewer,
)
from aiedge.schema import JsonValue

# ---------------------------------------------------------------------------
# Synthetic fixtures
# ---------------------------------------------------------------------------


def _make_trail_entry(
    *,
    stage: str = "fp_verification",
    step: str = "sanitizer_detected",
    verdict: str = "downgrade",
    rationale: str = "atoi neutralizes taint",
    delta: float = -0.15,
    llm_model: str | None = None,
    raw_response_excerpt: str | None = None,
    timestamp: str = "2026-04-13T10:00:00+00:00",
) -> dict[str, object]:
    return {
        "stage": stage,
        "step": step,
        "verdict": verdict,
        "rationale": rationale,
        "delta": delta,
        "timestamp": timestamp,
        "llm_model": llm_model,
        "raw_response_excerpt": raw_response_excerpt,
    }


def _three_step_trail() -> list[dict[str, object]]:
    return [
        _make_trail_entry(
            stage="fp_verification",
            step="sanitizer_detected",
            verdict="downgrade",
            rationale="atoi neutralizes taint",
            delta=-0.15,
            timestamp="2026-04-13T10:00:00+00:00",
        ),
        _make_trail_entry(
            stage="adversarial_triage",
            step="advocate",
            verdict="exploit_path_plausible",
            rationale="recv() flows into system()",
            delta=0.0,
            llm_model="sonnet",
            timestamp="2026-04-13T10:01:00+00:00",
        ),
        _make_trail_entry(
            stage="adversarial_triage",
            step="critic",
            verdict="downgrade",
            rationale="chroot and input filter applied",
            delta=-0.05,
            llm_model="sonnet",
            raw_response_excerpt="The chroot policy blocks /etc, and the input is run through a strict allow-list before exec.",
            timestamp="2026-04-13T10:02:00+00:00",
        ),
    ]


def _finding_with_trail(
    *,
    finding_id: str = "FIND-001",
    severity: str = "high",
    confidence: float = 0.55,
    title: str = "command injection in /usr/sbin/httpd",
    trail: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "id": finding_id,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "category": "vulnerability",
        "evidence": [{"path": "stages/findings/findings.json"}],
        "reasoning_trail": trail if trail is not None else _three_step_trail(),
    }


def _finding_without_trail() -> dict[str, object]:
    return {
        "id": "FIND-002",
        "title": "stack overflow",
        "severity": "medium",
        "confidence": 0.40,
        "category": "vulnerability",
        "evidence": [{"path": "stages/findings/findings.json"}],
    }


# ---------------------------------------------------------------------------
# Pure helper tests: format_trail_for_markdown / format_trail_for_tui /
# normalize_trail
# ---------------------------------------------------------------------------


class TestNormalizeTrail:
    def test_returns_dicts_only(self) -> None:
        trail: list[object] = [
            {"stage": "a"},
            "garbage",
            None,
            {"stage": "b"},
            42,
        ]
        out = normalize_trail(trail)
        assert len(out) == 2
        assert out[0]["stage"] == "a"
        assert out[1]["stage"] == "b"

    def test_returns_empty_for_none(self) -> None:
        assert normalize_trail(None) == []

    def test_returns_empty_for_non_list(self) -> None:
        assert normalize_trail({"stage": "x"}) == []
        assert normalize_trail("trail") == []
        assert normalize_trail(42) == []

    def test_returns_empty_for_empty_list(self) -> None:
        assert normalize_trail([]) == []


class TestFormatTrailForMarkdown:
    def test_renders_three_step_trail(self) -> None:
        lines = format_trail_for_markdown(_three_step_trail())
        assert len(lines) == 3
        assert lines[0].startswith("1. ")
        assert "fp_verification" in lines[0]
        assert "sanitizer_detected" in lines[0]
        assert "downgrade" in lines[0]
        assert "-0.15" in lines[0]
        assert "atoi neutralizes taint" in lines[0]

    def test_includes_llm_model(self) -> None:
        lines = format_trail_for_markdown(_three_step_trail())
        assert "(sonnet)" in lines[1]

    def test_skips_zero_delta(self) -> None:
        # second entry has delta=0.0
        lines = format_trail_for_markdown(_three_step_trail())
        assert "+0.00" not in lines[1]
        assert "0.00" not in lines[1]

    def test_returns_empty_for_none(self) -> None:
        assert format_trail_for_markdown(None) == []

    def test_returns_empty_for_empty(self) -> None:
        assert format_trail_for_markdown([]) == []

    def test_returns_empty_for_malformed(self) -> None:
        assert format_trail_for_markdown(["garbage"]) == []
        assert format_trail_for_markdown({"x": 1}) == []


class TestFormatTrailForTui:
    def test_renders_three_step_trail(self) -> None:
        lines = format_trail_for_tui(_three_step_trail())
        assert len(lines) == 3
        assert "fp_verification" in lines[0]
        assert "sanitizer_detected" in lines[0]
        assert "atoi neutralizes taint" in lines[0]

    def test_truncates_long_rationale(self) -> None:
        long = "x" * 200
        trail = [_make_trail_entry(rationale=long)]
        lines = format_trail_for_tui(trail, max_rationale_chars=80)
        assert len(lines) == 1
        # 80-char limit, ending in '...'
        line = lines[0]
        # Find the '-- ' separator marking the rationale start
        assert " -- " in line
        rationale_part = line.split(" -- ", 1)[1]
        assert len(rationale_part) == 80
        assert rationale_part.endswith("...")
        assert rationale_part[:77] == "x" * 77

    def test_short_rationale_unchanged(self) -> None:
        trail = [_make_trail_entry(rationale="short text")]
        lines = format_trail_for_tui(trail, max_rationale_chars=80)
        assert "short text" in lines[0]
        assert "..." not in lines[0]

    def test_unicode_arrow_when_unicode_enabled(self) -> None:
        lines = format_trail_for_tui(_three_step_trail(), use_unicode=True)
        assert "\u2192" in lines[0]

    def test_ascii_arrow_when_unicode_disabled(self) -> None:
        lines = format_trail_for_tui(_three_step_trail(), use_unicode=False)
        # No non-ASCII characters at all
        for line in lines:
            assert all(ord(c) < 128 for c in line), f"Non-ASCII in: {line!r}"
        # Plain "->" arrow used instead
        assert "->" in lines[0]

    def test_returns_empty_for_no_trail(self) -> None:
        assert format_trail_for_tui(None) == []
        assert format_trail_for_tui([]) == []


# ---------------------------------------------------------------------------
# report_assembler facade tests
# ---------------------------------------------------------------------------


class TestBuildFindingReasoningTrailMd:
    def test_renders_header_with_step_count(self) -> None:
        finding = _finding_with_trail()
        lines = build_finding_reasoning_trail_md(finding)
        assert lines[0] == "**Reasoning Trail** (3 steps)"

    def test_each_step_present(self) -> None:
        finding = _finding_with_trail()
        lines = build_finding_reasoning_trail_md(finding)
        body = "\n".join(lines)
        assert "fp_verification" in body
        assert "sanitizer_detected" in body
        assert "atoi neutralizes taint" in body
        assert "adversarial_triage" in body
        assert "advocate" in body
        assert "critic" in body
        assert "exploit_path_plausible" in body
        assert "chroot and input filter applied" in body

    def test_omits_section_when_no_trail(self) -> None:
        finding = _finding_without_trail()
        assert build_finding_reasoning_trail_md(finding) == []

    def test_omits_section_when_empty_trail(self) -> None:
        finding = _finding_with_trail(trail=[])
        assert build_finding_reasoning_trail_md(finding) == []

    def test_handles_non_dict_input(self) -> None:
        # type: ignore[arg-type]
        assert build_finding_reasoning_trail_md(None) == []  # type: ignore[arg-type]
        assert build_finding_reasoning_trail_md("not a dict") == []  # type: ignore[arg-type]

    def test_indent_param(self) -> None:
        finding = _finding_with_trail()
        lines = build_finding_reasoning_trail_md(finding, indent="    ")
        # Header is unindented, body lines use the custom indent
        assert lines[0] == "**Reasoning Trail** (3 steps)"
        for line in lines[1:]:
            assert line.startswith("    ")


class TestReasoningTrailForAnalystJson:
    def test_returns_trail_unchanged(self) -> None:
        finding = _finding_with_trail()
        out = reasoning_trail_for_analyst_json(finding)
        assert len(out) == 3
        assert out[0]["stage"] == "fp_verification"
        assert out[1]["llm_model"] == "sonnet"
        assert out[2]["delta"] == -0.05

    def test_returns_empty_when_no_trail(self) -> None:
        assert reasoning_trail_for_analyst_json(_finding_without_trail()) == []

    def test_returns_shallow_copies(self) -> None:
        finding = _finding_with_trail()
        out = reasoning_trail_for_analyst_json(finding)
        out[0]["stage"] = "MUTATED"
        # source untouched
        original_trail = finding["reasoning_trail"]
        assert isinstance(original_trail, list)
        assert original_trail[0]["stage"] == "fp_verification"

    def test_handles_non_dict_input(self) -> None:
        # type: ignore[arg-type]
        assert reasoning_trail_for_analyst_json(None) == []  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Integration: write_analyst_report_v2_md
# ---------------------------------------------------------------------------


def _make_v2_report(
    findings: list[dict[str, object]] | None = None,
) -> dict[str, JsonValue]:
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "findings": cast(JsonValue, findings if findings is not None else []),
        "run_completion": cast(JsonValue, {"conclusion_note": "test conclusion"}),
    }
    return payload


class TestWriteAnalystReportV2MdWithTrail:
    def test_markdown_includes_reasoning_trail(self, tmp_path: Path) -> None:
        report_dir = tmp_path / "report"
        report_dir.mkdir()
        finding = _finding_with_trail()
        report = _make_v2_report(findings=[finding])
        path = write_analyst_report_v2_md(report_dir, report)
        text = path.read_text(encoding="utf-8")
        assert "**Reasoning Trail** (3 steps)" in text
        assert "fp_verification" in text
        assert "sanitizer_detected" in text
        assert "atoi neutralizes taint" in text
        assert "adversarial_triage" in text
        assert "(sonnet)" in text
        assert "exploit_path_plausible" in text
        assert "chroot and input filter applied" in text

    def test_markdown_omits_section_when_no_trail(self, tmp_path: Path) -> None:
        report_dir = tmp_path / "report"
        report_dir.mkdir()
        finding = _finding_without_trail()
        report = _make_v2_report(findings=[finding])
        path = write_analyst_report_v2_md(report_dir, report)
        text = path.read_text(encoding="utf-8")
        assert "Reasoning Trail" not in text

    def test_markdown_renders_only_trails_that_exist(self, tmp_path: Path) -> None:
        # Mix of with and without -- only the trail-bearing finding gets
        # the subsection, schema_version unchanged.
        report_dir = tmp_path / "report"
        report_dir.mkdir()
        report = _make_v2_report(
            findings=[_finding_without_trail(), _finding_with_trail()]
        )
        path = write_analyst_report_v2_md(report_dir, report)
        text = path.read_text(encoding="utf-8")
        # Exactly one trail header
        assert text.count("**Reasoning Trail**") == 1


# ---------------------------------------------------------------------------
# Integration: build_analyst_report_v2 JSON pass-through
# ---------------------------------------------------------------------------


class TestBuildAnalystReportV2JsonTrail:
    def test_json_preserves_reasoning_trail_per_claim(self) -> None:
        finding = _finding_with_trail()
        report = _make_v2_report(findings=[finding])
        v2 = build_analyst_report_v2(report)
        top = v2.get("top_risk_claims")
        assert isinstance(top, list)
        assert len(top) == 1
        claim = top[0]
        assert isinstance(claim, dict)
        trail = claim.get("reasoning_trail")
        assert isinstance(trail, list)
        assert len(trail) == 3
        first = trail[0]
        assert isinstance(first, dict)
        assert first["stage"] == "fp_verification"
        assert first["step"] == "sanitizer_detected"
        assert first["delta"] == -0.15

    def test_json_omits_trail_field_when_absent(self) -> None:
        finding = _finding_without_trail()
        report = _make_v2_report(findings=[finding])
        v2 = build_analyst_report_v2(report)
        top = v2.get("top_risk_claims")
        assert isinstance(top, list)
        assert len(top) == 1
        claim = top[0]
        assert isinstance(claim, dict)
        assert "reasoning_trail" not in claim

    def test_schema_version_unchanged_with_trail(self) -> None:
        # PR #13 is additive: schema version must stay stable.
        finding = _finding_with_trail()
        report = _make_v2_report(findings=[finding])
        v2 = build_analyst_report_v2(report)
        assert v2.get("schema_version") == ANALYST_REPORT_V2_SCHEMA_VERSION

    def test_schema_version_unchanged_without_trail(self) -> None:
        finding = _finding_without_trail()
        report = _make_v2_report(findings=[finding])
        v2 = build_analyst_report_v2(report)
        assert v2.get("schema_version") == ANALYST_REPORT_V2_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Integration: write_analyst_report_v2_viewer (embedded HTML/JS template)
# ---------------------------------------------------------------------------


class TestViewerHtmlReasoningTrail:
    def test_viewer_html_contains_trail_rendering_hooks(self, tmp_path: Path) -> None:
        # The viewer is generated by inlining JS/CSS that reads the
        # bootstrap data at runtime. We can't execute JS in pytest, but
        # we can assert the JS hooks and CSS class names that drive the
        # trail render are present in the emitted document. This protects
        # the contract between the JS code and the data shape.
        report_dir = tmp_path / "report"
        report_dir.mkdir()
        finding = _finding_with_trail()
        report = _make_v2_report(findings=[finding])
        path = write_analyst_report_v2_viewer(report_dir, report)
        html = path.read_text(encoding="utf-8")
        # JS hooks: the render code reads item.reasoning_trail
        assert "item.reasoning_trail" in html
        assert "reasoning-trail" in html  # CSS class root
        assert "Reasoning Trail (' + trailEntries.length + ' steps)" in html
        # Raw excerpt sub-details element (collapsible)
        assert "raw response excerpt" in html
        # CSS for the panel
        assert ".reasoning-trail" in html
        assert ".reasoning-trail-list" in html
        assert ".reasoning-trail-rationale" in html

    def test_viewer_html_bootstrap_includes_trail_when_present(
        self, tmp_path: Path
    ) -> None:
        # The viewer embeds analyst_report_v2.json as a bootstrap so that
        # opening it from file:// still has data. Confirm that bootstrap
        # carries the reasoning_trail field for trail-bearing findings.
        report_dir = tmp_path / "report"
        report_dir.mkdir()
        finding = _finding_with_trail()
        report = _make_v2_report(findings=[finding])
        path = write_analyst_report_v2_viewer(report_dir, report)
        html = path.read_text(encoding="utf-8")
        # The bootstrap is JSON-encoded inline; trail field will be
        # serialised verbatim with all four fp_verification keys.
        assert "fp_verification" in html
        assert "sanitizer_detected" in html
        assert "atoi neutralizes taint" in html

    def test_viewer_html_no_trail_section_when_absent(self, tmp_path: Path) -> None:
        # The JS render hooks are always emitted (the template is static),
        # but the bootstrap must NOT carry trail content for trail-less
        # findings -- additive-only invariant.
        report_dir = tmp_path / "report"
        report_dir.mkdir()
        finding = _finding_without_trail()
        report = _make_v2_report(findings=[finding])
        path = write_analyst_report_v2_viewer(report_dir, report)
        html = path.read_text(encoding="utf-8")
        # No trail-specific finding payload
        assert "fp_verification" not in html
        assert "atoi neutralizes taint" not in html


# ---------------------------------------------------------------------------
# Integration: cli_tui_render.render_finding_detail_with_trail
# ---------------------------------------------------------------------------


class TestRenderFindingDetailWithTrail:
    def test_renders_finding_header_and_trail(self) -> None:
        finding = _finding_with_trail()
        lines = render_finding_detail_with_trail(finding)
        body = "\n".join(lines)
        assert "FIND-001" in body
        assert "sev=high" in body
        assert "conf=0.55" in body
        # Title rendered when present
        assert "command injection" in body
        # Trail header
        assert "Reasoning Trail (3):" in body
        # Each step is present
        assert "fp_verification" in body
        assert "sanitizer_detected" in body
        assert "advocate" in body
        assert "critic" in body

    def test_truncates_long_rationale_to_80(self) -> None:
        long = "y" * 200
        trail = [_make_trail_entry(rationale=long)]
        finding = _finding_with_trail(trail=trail)
        lines = render_finding_detail_with_trail(finding)
        body = "\n".join(lines)
        # The truncated tail is " -- " + 80 chars ending in "..."
        assert " -- " in body
        # Locate the rationale segment
        for line in lines:
            if " -- " in line and "y" in line:
                rationale = line.split(" -- ", 1)[1]
                assert len(rationale) == 80
                assert rationale.endswith("...")
                assert rationale[:77] == "y" * 77
                break
        else:
            pytest.fail("No rationale line found")

    def test_omits_trail_section_when_no_trail(self) -> None:
        finding = _finding_without_trail()
        lines = render_finding_detail_with_trail(finding)
        body = "\n".join(lines)
        assert "Reasoning Trail" not in body
        # But the header is still rendered
        assert "FIND-002" in body

    def test_ascii_mode_no_unicode(self) -> None:
        finding = _finding_with_trail()
        lines = render_finding_detail_with_trail(finding, use_unicode=False)
        for line in lines:
            assert all(
                ord(c) < 128 for c in line
            ), f"Non-ASCII glyph in TUI ASCII-mode line: {line!r}"


# ---------------------------------------------------------------------------
# Integration: full TUI snapshot picks up findings_with_trails
# ---------------------------------------------------------------------------


def _write_run_skeleton(run_dir: Path, *, findings: list[dict[str, object]]) -> None:
    """Lay out the minimal subset of run_dir files the TUI snapshot reads."""
    (run_dir / "stages" / "findings").mkdir(parents=True)
    (run_dir / "report").mkdir(parents=True)

    findings_payload = {
        "status": "ok",
        "generated_at": "2026-04-13T10:00:00+00:00",
        "findings": findings,
        "evidence": [],
        "extracted_file_count": 0,
        "category_counts": {},
        "reasoning_trail_count": sum(
            1 for f in findings if isinstance(f, dict) and f.get("reasoning_trail")
        ),
    }
    (run_dir / "stages" / "findings" / "findings.json").write_text(
        json.dumps(findings_payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    # Minimal exploit_candidates so the snapshot doesn't hard-fail.
    (run_dir / "stages" / "findings" / "exploit_candidates.json").write_text(
        json.dumps(
            {
                "schema_version": "exploit-candidates-v1",
                "summary": {
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "chain_backed": 0,
                    "candidate_count": 0,
                },
                "candidates": [],
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    (run_dir / "manifest.json").write_text(
        json.dumps({"profile": "test"}, indent=2, sort_keys=True),
        encoding="utf-8",
    )
    (run_dir / "report" / "report.json").write_text(
        json.dumps(
            {"report_completeness": {"status": "complete", "gate_passed": True}},
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (run_dir / "report" / "analyst_digest.json").write_text(
        json.dumps(
            {"exploitability_verdict": {"state": "VERIFIED", "reason_codes": []}},
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )


class TestTuiSnapshotFindingsWithTrail:
    def test_snapshot_section_appears_when_trail_present(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        _write_run_skeleton(
            run_dir,
            findings=[_finding_with_trail(), _finding_without_trail()],
        )
        lines = _build_tui_snapshot_lines(
            run_dir=run_dir, limit=5, use_ansi=False, use_unicode=True
        )
        body = "\n".join(lines)
        assert "Findings with Reasoning Trail" in body
        assert "FIND-001" in body
        assert "fp_verification" in body
        assert "sanitizer_detected" in body
        # Finding without trail does not show in this section
        assert "FIND-002" not in body or "stack overflow" not in body

    def test_snapshot_section_hidden_when_no_trails(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        _write_run_skeleton(run_dir, findings=[_finding_without_trail()])
        lines = _build_tui_snapshot_lines(
            run_dir=run_dir, limit=5, use_ansi=False, use_unicode=True
        )
        body = "\n".join(lines)
        assert "Findings with Reasoning Trail" not in body

    def test_snapshot_ascii_mode_no_unicode_in_trail_section(
        self, tmp_path: Path
    ) -> None:
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        _write_run_skeleton(run_dir, findings=[_finding_with_trail()])
        lines = _build_tui_snapshot_lines(
            run_dir=run_dir, limit=5, use_ansi=False, use_unicode=False
        )
        # Find the trail section and assert ASCII-only inside it.
        in_trail = False
        for line in lines:
            if "Findings with Reasoning Trail" in line:
                in_trail = True
            if in_trail:
                assert all(
                    ord(c) < 128 for c in line
                ), f"Non-ASCII in TUI line under ASCII mode: {line!r}"

    def test_snapshot_respects_aiedge_tui_ascii_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # AIEDGE_TUI_ASCII=1 should propagate through _tui_unicode_supported
        # when callers pass use_unicode=None. Here we simulate the env path
        # by calling format_trail_for_tui directly (the snapshot helper
        # plumbs the bool through unchanged from the env in the real CLI).
        monkeypatch.setenv("AIEDGE_TUI_ASCII", "1")
        from aiedge.cli_common import _tui_unicode_supported

        assert _tui_unicode_supported() is False
        # And the helper called with that bool produces ASCII-only output.
        trail = _three_step_trail()
        for line in format_trail_for_tui(trail, use_unicode=False):
            assert all(ord(c) < 128 for c in line)
