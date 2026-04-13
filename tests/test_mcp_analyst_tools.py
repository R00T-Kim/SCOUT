"""PR #12 -- unit and integration tests for MCP analyst tools.

Covers:
- ``terminator_feedback.add_analyst_hint`` / ``get_analyst_hints`` /
  ``set_verdict_override`` helpers (registry schema extension + flock safety).
- ``mcp_server`` tools ``scout_get_finding_reasoning`` /
  ``scout_inject_hint`` / ``scout_override_verdict`` /
  ``scout_filter_by_category``.
- Integration: ``adversarial_triage._build_advocate_prompt`` reads
  ``AIEDGE_FEEDBACK_DIR`` and prefixes analyst hints when present.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Callable

import pytest

from aiedge import mcp_server, terminator_feedback
from aiedge.adversarial_triage import _build_advocate_prompt

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _read_registry(feedback_dir: Path) -> dict[str, Any]:
    path = feedback_dir / "registry.json"
    return json.loads(path.read_text(encoding="utf-8"))


def _write_findings(run_dir: Path, findings: list[dict[str, Any]]) -> Path:
    findings_dir = run_dir / "stages" / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    findings_path = findings_dir / "findings.json"
    findings_path.write_text(
        json.dumps({"findings": findings}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return findings_path


@pytest.fixture
def feedback_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolated AIEDGE_FEEDBACK_DIR for each test."""
    fb = tmp_path / "feedback"
    fb.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("AIEDGE_FEEDBACK_DIR", str(fb))
    return fb


@pytest.fixture
def fake_run_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create a fake aiedge-runs/<run_id> directory and rebind mcp_server._RUNS_DIR."""
    runs_root = tmp_path / "aiedge-runs"
    run_id = "20260413_run_pr12"
    run_dir = runs_root / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(mcp_server, "_RUNS_DIR", runs_root)
    return run_dir


# ---------------------------------------------------------------------------
# Unit tests: terminator_feedback extensions
# ---------------------------------------------------------------------------


class TestAddAnalystHint:
    def test_creates_registry(self, feedback_dir: Path) -> None:
        terminator_feedback.add_analyst_hint(
            "finding-abc",
            "Check the CGI handler at 0x401230",
            priority="high",
            added_by="analyst-alice",
        )

        registry_path = feedback_dir / "registry.json"
        assert registry_path.is_file()
        registry = _read_registry(feedback_dir)
        assert registry["schema_version"] == (
            terminator_feedback.FEEDBACK_SCHEMA_VERSION
        )
        assert "findings" in registry
        assert "finding-abc" in registry["findings"]
        hints = registry["findings"]["finding-abc"]["analyst_hints"]
        assert len(hints) == 1
        assert hints[0]["text"] == "Check the CGI handler at 0x401230"
        assert hints[0]["priority"] == "high"
        assert hints[0]["added_by"] == "analyst-alice"
        assert hints[0]["timestamp"]

    def test_appends_to_existing(self, feedback_dir: Path) -> None:
        terminator_feedback.add_analyst_hint("f1", "first", priority="low")
        terminator_feedback.add_analyst_hint("f1", "second", priority="high")

        registry = _read_registry(feedback_dir)
        hints = registry["findings"]["f1"]["analyst_hints"]
        assert len(hints) == 2
        assert hints[0]["text"] == "first"
        assert hints[0]["priority"] == "low"
        assert hints[1]["text"] == "second"
        assert hints[1]["priority"] == "high"

    def test_invalid_priority_defaults_to_medium(self, feedback_dir: Path) -> None:
        terminator_feedback.add_analyst_hint("f1", "some hint", priority="bogus")
        registry = _read_registry(feedback_dir)
        assert registry["findings"]["f1"]["analyst_hints"][0]["priority"] == "medium"

    def test_empty_finding_id_raises(self, feedback_dir: Path) -> None:
        with pytest.raises(ValueError):
            terminator_feedback.add_analyst_hint("", "hint")

    def test_empty_hint_text_raises(self, feedback_dir: Path) -> None:
        with pytest.raises(ValueError):
            terminator_feedback.add_analyst_hint("f1", "")

    def test_preserves_existing_verdicts_list(self, feedback_dir: Path) -> None:
        # Seed a pre-PR-#12 registry shape so we verify backwards compat.
        seed = {
            "schema_version": terminator_feedback.FEEDBACK_SCHEMA_VERSION,
            "verdicts": [
                {
                    "finding_fingerprint": "deadbeef" * 8,
                    "verdict": "false_positive",
                    "rationale": "pre-existing",
                    "original_run_id": "run-legacy",
                    "timestamp": "2025-01-01T00:00:00+00:00",
                }
            ],
        }
        (feedback_dir / "registry.json").write_text(json.dumps(seed), encoding="utf-8")

        terminator_feedback.add_analyst_hint("f-new", "hint text")

        registry = _read_registry(feedback_dir)
        assert registry["verdicts"] == seed["verdicts"]
        assert "findings" in registry
        assert "f-new" in registry["findings"]


class TestGetAnalystHints:
    def test_returns_empty_for_unknown_finding(self, feedback_dir: Path) -> None:
        assert terminator_feedback.get_analyst_hints("nonexistent") == []

    def test_returns_empty_when_registry_missing(self, feedback_dir: Path) -> None:
        # feedback_dir exists but registry.json does not.
        assert not (feedback_dir / "registry.json").exists()
        assert terminator_feedback.get_analyst_hints("f1") == []

    def test_round_trip(self, feedback_dir: Path) -> None:
        terminator_feedback.add_analyst_hint("f1", "round-trip", priority="medium")
        hints = terminator_feedback.get_analyst_hints("f1")
        assert len(hints) == 1
        assert hints[0]["text"] == "round-trip"
        assert hints[0]["priority"] == "medium"


class TestSetVerdictOverride:
    def test_writes_to_registry(self, feedback_dir: Path) -> None:
        terminator_feedback.set_verdict_override(
            "finding-1",
            "false_positive",
            rationale="confirmed sanitizer present",
        )
        registry = _read_registry(feedback_dir)
        entry = registry["findings"]["finding-1"]
        assert entry["verdict"] == "false_positive"
        assert entry["rationale"] == "confirmed sanitizer present"
        assert entry["last_updated"]

    def test_includes_confidence_override(self, feedback_dir: Path) -> None:
        terminator_feedback.set_verdict_override(
            "finding-1",
            "confirmed",
            rationale="exploit chain verified",
            confidence_override=0.9,
        )
        registry = _read_registry(feedback_dir)
        entry = registry["findings"]["finding-1"]
        assert entry["verdict"] == "confirmed"
        assert entry["confidence_override"] == 0.9

    def test_clamps_confidence_to_valid_range(self, feedback_dir: Path) -> None:
        terminator_feedback.set_verdict_override(
            "f-clamp-high", "confirmed", confidence_override=1.5
        )
        terminator_feedback.set_verdict_override(
            "f-clamp-low", "confirmed", confidence_override=-0.5
        )
        registry = _read_registry(feedback_dir)
        assert registry["findings"]["f-clamp-high"]["confidence_override"] == 1.0
        assert registry["findings"]["f-clamp-low"]["confidence_override"] == 0.0

    def test_invalid_verdict_raises(self, feedback_dir: Path) -> None:
        with pytest.raises(ValueError):
            terminator_feedback.set_verdict_override("f1", "bogus_verdict")

    def test_empty_finding_id_raises(self, feedback_dir: Path) -> None:
        with pytest.raises(ValueError):
            terminator_feedback.set_verdict_override("", "confirmed")


class TestConcurrentWriteSafety:
    def test_two_threads_add_hints(self, feedback_dir: Path) -> None:
        """Spawn 2 threads calling add_analyst_hint, assert both land."""
        barrier = threading.Barrier(2)

        def _worker(tag: str) -> None:
            barrier.wait()
            for i in range(10):
                terminator_feedback.add_analyst_hint(
                    "shared-finding",
                    f"{tag}-hint-{i}",
                    priority="medium",
                    added_by=tag,
                )

        t1 = threading.Thread(target=_worker, args=("t1",))
        t2 = threading.Thread(target=_worker, args=("t2",))
        t1.start()
        t2.start()
        t1.join(timeout=15)
        t2.join(timeout=15)
        assert not t1.is_alive()
        assert not t2.is_alive()

        hints = terminator_feedback.get_analyst_hints("shared-finding")
        assert len(hints) == 20
        texts = {h["text"] for h in hints}
        assert len(texts) == 20  # no lost updates
        assert any(t.startswith("t1-") for t in texts)
        assert any(t.startswith("t2-") for t in texts)


# ---------------------------------------------------------------------------
# Unit tests: MCP tools
# ---------------------------------------------------------------------------


def _extract_json_payload(content: list[dict[str, str]]) -> Any:
    """Parse the MCP text block into a JSON value."""
    assert content and content[0]["type"] == "text"
    return json.loads(content[0]["text"])


class TestScoutGetFindingReasoning:
    def test_returns_trail(
        self,
        fake_run_dir: Path,
    ) -> None:
        reasoning_trail = [
            {
                "stage": "fp_verification",
                "step": "sanitizer_scan",
                "verdict": "no_sanitizer_found",
                "rationale": "No escape_html wrapping detected",
                "delta": 0.0,
                "timestamp": "2026-04-13T00:00:00+00:00",
            },
            {
                "stage": "adversarial_triage",
                "step": "advocate",
                "verdict": "exploit_path_plausible",
                "rationale": "User-controlled buffer reaches system()",
                "delta": 0.0,
                "llm_model": "sonnet",
            },
        ]
        findings = [
            {
                "id": "finding-42",
                "confidence": 0.72,
                "original_confidence": 0.85,
                "category": "vulnerability",
                "severity": "high",
                "fp_verdict": "maintain",
                "triage_outcome": "debated",
                "reasoning_trail": reasoning_trail,
            }
        ]
        _write_findings(fake_run_dir, findings)

        content = mcp_server._tool_get_finding_reasoning(
            {"run_id": fake_run_dir.name, "finding_id": "finding-42"}
        )
        payload = _extract_json_payload(content)
        assert payload["finding_id"] == "finding-42"
        assert payload["original_confidence"] == 0.85
        assert payload["current_confidence"] == 0.72
        assert payload["category"] == "vulnerability"
        assert payload["fp_verdict"] == "maintain"
        assert payload["triage_outcome"] == "debated"
        trail = payload["reasoning_trail"]
        assert len(trail) == 2
        assert trail[0]["stage"] == "fp_verification"
        assert trail[1]["step"] == "advocate"
        assert trail[1]["llm_model"] == "sonnet"

    def test_unknown_id_returns_error(self, fake_run_dir: Path) -> None:
        _write_findings(fake_run_dir, [{"id": "other", "confidence": 0.5}])
        content = mcp_server._tool_get_finding_reasoning(
            {"run_id": fake_run_dir.name, "finding_id": "missing"}
        )
        payload = _extract_json_payload(content)
        assert payload["error"] == "finding_not_found"
        assert payload["finding_id"] == "missing"

    def test_missing_findings_file_returns_message(self, fake_run_dir: Path) -> None:
        content = mcp_server._tool_get_finding_reasoning(
            {"run_id": fake_run_dir.name, "finding_id": "finding-42"}
        )
        assert content[0]["type"] == "text"
        assert "No findings artifact" in content[0]["text"]

    def test_truncates_oversize_payload(
        self,
        fake_run_dir: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With a tiny AIEDGE_MCP_MAX_OUTPUT_KB the trail is summarised."""
        monkeypatch.setattr(mcp_server, "_MAX_OUTPUT_BYTES", 1024)

        huge_rationale = "x" * 2000
        reasoning_trail = [
            {
                "stage": "adversarial_triage",
                "step": f"step-{i}",
                "verdict": "reasoning",
                "rationale": huge_rationale,
                "delta": 0.0,
            }
            for i in range(50)
        ]
        _write_findings(
            fake_run_dir,
            [
                {
                    "id": "big-finding",
                    "confidence": 0.5,
                    "reasoning_trail": reasoning_trail,
                }
            ],
        )

        content = mcp_server._tool_get_finding_reasoning(
            {"run_id": fake_run_dir.name, "finding_id": "big-finding"}
        )
        payload = _extract_json_payload(content)
        assert payload.get("_trail_truncated") is True
        trimmed_trail = payload["reasoning_trail"]
        # Must be fewer than the original 50 or rationales must be cropped.
        if len(trimmed_trail) == 50:
            for entry in trimmed_trail:
                assert len(entry.get("rationale", "")) < len(huge_rationale)
        else:
            assert len(trimmed_trail) <= 20


class TestScoutInjectHint:
    def test_writes_to_feedback_registry(self, feedback_dir: Path) -> None:
        content = mcp_server._tool_inject_hint(
            {
                "finding_id": "finding-7",
                "hint_text": "Check for missing input validation",
                "priority": "high",
                "added_by": "analyst-bob",
            }
        )
        payload = _extract_json_payload(content)
        assert payload["success"] is True
        assert payload["finding_id"] == "finding-7"
        assert payload["hint_count"] == 1
        assert payload["priority"] == "high"

        registry = _read_registry(feedback_dir)
        hint = registry["findings"]["finding-7"]["analyst_hints"][0]
        assert hint["text"] == "Check for missing input validation"
        assert hint["priority"] == "high"
        assert hint["added_by"] == "analyst-bob"

    def test_empty_hint_returns_error(self, feedback_dir: Path) -> None:
        content = mcp_server._tool_inject_hint({"finding_id": "f1", "hint_text": ""})
        payload = _extract_json_payload(content)
        assert payload["success"] is False
        assert payload["error"] == "invalid_input"


class TestScoutOverrideVerdict:
    def test_validates_verdict_value(self, feedback_dir: Path) -> None:
        content = mcp_server._tool_override_verdict(
            {"finding_id": "f1", "verdict": "nonsense"}
        )
        payload = _extract_json_payload(content)
        assert payload["success"] is False
        assert payload["error"] == "invalid_verdict"
        # Registry should NOT have been written.
        assert not (feedback_dir / "registry.json").exists()

    def test_writes_to_registry(self, feedback_dir: Path) -> None:
        content = mcp_server._tool_override_verdict(
            {
                "finding_id": "finding-1",
                "verdict": "false_positive",
                "rationale": "sanitizer detected",
                "confidence_override": 0.1,
            }
        )
        payload = _extract_json_payload(content)
        assert payload["success"] is True
        assert payload["finding_id"] == "finding-1"
        assert payload["verdict"] == "false_positive"
        assert payload["rationale"] == "sanitizer detected"
        assert payload["confidence_override"] == 0.1

        registry = _read_registry(feedback_dir)
        entry = registry["findings"]["finding-1"]
        assert entry["verdict"] == "false_positive"
        assert entry["rationale"] == "sanitizer detected"
        assert entry["confidence_override"] == 0.1
        assert entry["last_updated"]

    def test_accepts_all_four_valid_verdicts(self, feedback_dir: Path) -> None:
        for verdict in (
            "confirmed",
            "false_positive",
            "wont_fix",
            "needs_info",
        ):
            content = mcp_server._tool_override_verdict(
                {"finding_id": f"f-{verdict}", "verdict": verdict}
            )
            payload = _extract_json_payload(content)
            assert payload["success"] is True


class TestScoutFilterByCategory:
    def test_returns_only_matching(self, fake_run_dir: Path) -> None:
        _write_findings(
            fake_run_dir,
            [
                {
                    "id": "v1",
                    "category": "vulnerability",
                    "severity": "high",
                    "confidence": 0.8,
                },
                {
                    "id": "m1",
                    "category": "misconfiguration",
                    "severity": "medium",
                    "confidence": 0.6,
                },
                {
                    "id": "p1",
                    "category": "pipeline_artifact",
                    "severity": "low",
                    "confidence": 0.3,
                },
                {
                    "id": "v2",
                    "category": "vulnerability",
                    "severity": "critical",
                    "confidence": 0.9,
                },
            ],
        )

        content = mcp_server._tool_filter_by_category(
            {"run_id": fake_run_dir.name, "category": "vulnerability"}
        )
        payload = _extract_json_payload(content)
        assert payload["category"] == "vulnerability"
        assert payload["total"] == 2
        ids = sorted(f["id"] for f in payload["findings"])
        assert ids == ["v1", "v2"]
        for entry in payload["findings"]:
            assert entry["category"] == "vulnerability"
            assert "severity" in entry
            assert "confidence" in entry

    def test_validates_category(self, fake_run_dir: Path) -> None:
        content = mcp_server._tool_filter_by_category(
            {"run_id": fake_run_dir.name, "category": "bogus_cat"}
        )
        payload = _extract_json_payload(content)
        assert payload["success"] is False
        assert payload["error"] == "invalid_category"

    def test_no_matches_returns_empty_list(self, fake_run_dir: Path) -> None:
        _write_findings(
            fake_run_dir,
            [
                {
                    "id": "v1",
                    "category": "vulnerability",
                    "severity": "high",
                    "confidence": 0.8,
                }
            ],
        )
        content = mcp_server._tool_filter_by_category(
            {
                "run_id": fake_run_dir.name,
                "category": "pipeline_artifact",
            }
        )
        payload = _extract_json_payload(content)
        assert payload["total"] == 0
        assert payload["findings"] == []


# ---------------------------------------------------------------------------
# Integration test: adversarial_triage reads analyst hints
# ---------------------------------------------------------------------------


class TestAdversarialTriageHintInjection:
    def test_advocate_prompt_includes_hints(self, feedback_dir: Path) -> None:
        """With a hint registered, the advocate prompt is prefixed."""
        terminator_feedback.add_analyst_hint(
            "finding-9",
            "Check the auth_check() wrapper — previously downgraded by mistake",
            priority="high",
            added_by="analyst-carol",
        )
        finding: dict[str, object] = {
            "id": "finding-9",
            "source_api": "recv",
            "sink_symbol": "system",
            "confidence": 0.7,
            "severity": "high",
        }
        prompt = _build_advocate_prompt(finding, decompiled_context=None)

        assert prompt.startswith("[Analyst hints from prior runs:")
        assert "Check the auth_check()" in prompt
        assert "high: Check the auth_check()" in prompt
        assert "## Finding" in prompt

    def test_advocate_prompt_unaffected_without_env(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No env var => zero behaviour change (byte-identical prefix)."""
        monkeypatch.delenv("AIEDGE_FEEDBACK_DIR", raising=False)
        finding: dict[str, object] = {
            "id": "finding-9",
            "source_api": "recv",
            "sink_symbol": "system",
        }
        prompt = _build_advocate_prompt(finding, decompiled_context=None)
        assert prompt.startswith("## Finding")
        assert "Analyst hints" not in prompt

    def test_advocate_prompt_no_hints_no_prefix(self, feedback_dir: Path) -> None:
        """Env set but finding has no hints => no prefix emitted."""
        # Register a hint for a DIFFERENT finding.
        terminator_feedback.add_analyst_hint(
            "finding-other", "unrelated", priority="medium"
        )
        finding: dict[str, object] = {
            "id": "finding-9",
            "source_api": "recv",
            "sink_symbol": "system",
        }
        prompt = _build_advocate_prompt(finding, decompiled_context=None)
        assert prompt.startswith("## Finding")
        assert "Analyst hints" not in prompt

    def test_hint_prefix_orders_by_priority(self, feedback_dir: Path) -> None:
        terminator_feedback.add_analyst_hint(
            "finding-10", "low priority note", priority="low"
        )
        terminator_feedback.add_analyst_hint(
            "finding-10", "urgent check", priority="high"
        )
        terminator_feedback.add_analyst_hint(
            "finding-10", "normal reminder", priority="medium"
        )
        finding: dict[str, object] = {"id": "finding-10"}
        prompt = _build_advocate_prompt(finding, decompiled_context=None)
        high_pos = prompt.find("urgent check")
        med_pos = prompt.find("normal reminder")
        low_pos = prompt.find("low priority note")
        assert 0 < high_pos < med_pos < low_pos


# ---------------------------------------------------------------------------
# Deferred import smoke: ensure the 4 new tools are registered
# ---------------------------------------------------------------------------


def test_new_tools_registered_in_dispatch_table() -> None:
    for tool_name in (
        "scout_get_finding_reasoning",
        "scout_inject_hint",
        "scout_override_verdict",
        "scout_filter_by_category",
    ):
        assert tool_name in mcp_server._TOOL_HANDLERS


def test_new_tools_declared_in_schema() -> None:
    declared = {t["name"] for t in mcp_server.TOOLS}
    for tool_name in (
        "scout_get_finding_reasoning",
        "scout_inject_hint",
        "scout_override_verdict",
        "scout_filter_by_category",
    ):
        assert tool_name in declared


# Placate linters that complain about unused typing imports.
_ = Callable
