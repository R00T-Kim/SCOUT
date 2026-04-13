"""Unit and integration tests for reasoning_trail (PR #11).

Covers:
1. Unit tests for reasoning_trail.py helpers
    (redact_excerpt, append_entry, ReasoningEntry, empty_trail).
2. Integration tests for adversarial_triage reasoning trail capture
    using scout_fake_llm_driver fixture.
3. Integration test for fp_verification reasoning trail capture on a
    static pre-filter (sanitizer) hit.
4. Backward-compat test confirming findings without a trail still build.
5. SARIF export test confirming scout_reasoning_trail in properties bag.

Fixtures come from tests/conftest.py (Phase 2A):
    scout_stage_ctx, scout_fake_llm_driver, scout_write_json, scout_read_json
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable, cast

from _fixtures.llm import FakeLLMDriver

from aiedge.adversarial_triage import AdversarialTriageStage
from aiedge.fp_verification import FPVerificationStage
from aiedge.reasoning_trail import (
    ReasoningEntry,
    append_entry,
    empty_trail,
    redact_excerpt,
)
from aiedge.sarif_export import findings_to_sarif
from aiedge.stage import StageContext

# ---------------------------------------------------------------------------
# Unit tests: reasoning_trail.py helpers
# ---------------------------------------------------------------------------


class TestRedactExcerpt:
    def test_redact_excerpt_short_unchanged(self) -> None:
        text = "short rationale"
        assert redact_excerpt(text) == "short rationale"

    def test_redact_excerpt_long_truncated_with_ellipsis(self) -> None:
        long = "x" * 500
        out = redact_excerpt(long)
        assert out is not None
        assert len(out) == 200
        assert out.endswith("...")
        assert out[:197] == "x" * 197

    def test_redact_excerpt_exactly_at_limit_unchanged(self) -> None:
        text = "y" * 200
        out = redact_excerpt(text)
        assert out == text
        assert out is not None and len(out) == 200

    def test_redact_excerpt_one_over_limit_truncated(self) -> None:
        text = "z" * 201
        out = redact_excerpt(text)
        assert out is not None
        assert len(out) == 200
        assert out.endswith("...")

    def test_redact_excerpt_none(self) -> None:
        assert redact_excerpt(None) is None

    def test_redact_excerpt_custom_limit(self) -> None:
        out = redact_excerpt("abcdefghij", max_chars=6)
        assert out == "abc..."

    def test_redact_excerpt_strips_whitespace(self) -> None:
        out = redact_excerpt("   padded   ")
        assert out == "padded"


class TestAppendEntry:
    def test_append_entry_to_empty_trail(self) -> None:
        entry = ReasoningEntry(
            stage="fp_verification",
            step="sanitizer_detected",
            verdict="downgrade",
            rationale="sanitizer present",
            delta=-0.15,
        )
        trail = append_entry(None, entry)
        assert len(trail) == 1
        assert trail[0]["stage"] == "fp_verification"
        assert trail[0]["step"] == "sanitizer_detected"
        assert trail[0]["verdict"] == "downgrade"
        assert trail[0]["delta"] == -0.15

    def test_append_entry_to_existing_trail(self) -> None:
        e1 = ReasoningEntry(
            stage="fp_verification",
            step="sanitizer_detected",
            verdict="downgrade",
            rationale="sanitizer",
            delta=-0.15,
        )
        e2 = ReasoningEntry(
            stage="adversarial_triage",
            step="advocate",
            verdict="reasoning",
            rationale="advocate argument",
        )
        trail1 = append_entry(None, e1)
        trail2 = append_entry(trail1, e2)
        assert len(trail2) == 2
        assert trail2[0]["step"] == "sanitizer_detected"
        assert trail2[1]["step"] == "advocate"
        # append_entry should not mutate the original trail
        assert len(trail1) == 1

    def test_append_entry_empty_trail_helper(self) -> None:
        trail = empty_trail()
        assert trail == []
        entry = ReasoningEntry(
            stage="fp_verification",
            step="decision",
            verdict="maintain",
            rationale="no mitigation cited",
        )
        trail = append_entry(trail, entry)
        assert len(trail) == 1


class TestReasoningEntry:
    def test_reasoning_entry_serializes_to_dict(self) -> None:
        entry = ReasoningEntry(
            stage="adversarial_triage",
            step="advocate",
            verdict="exploit_path_plausible",
            rationale="recv() flows into system()",
            delta=0.0,
            llm_model="sonnet",
            raw_response_excerpt="some raw output",
        )
        trail = append_entry(None, entry)
        d = trail[0]
        assert isinstance(d, dict)
        assert d["stage"] == "adversarial_triage"
        assert d["step"] == "advocate"
        assert d["verdict"] == "exploit_path_plausible"
        assert d["llm_model"] == "sonnet"
        assert d["raw_response_excerpt"] == "some raw output"
        assert "timestamp" in d
        assert isinstance(d["timestamp"], str)
        # ISO 8601 with timezone offset
        assert "T" in cast(str, d["timestamp"])

    def test_reasoning_entry_redacts_long_excerpt_at_construction(self) -> None:
        entry = ReasoningEntry(
            stage="adversarial_triage",
            step="critic",
            verdict="downgrade",
            rationale="critic rebuttal",
            raw_response_excerpt="a" * 1000,
        )
        # __post_init__ must apply the 200-char cap
        assert entry.raw_response_excerpt is not None
        assert len(entry.raw_response_excerpt) == 200
        assert entry.raw_response_excerpt.endswith("...")

    def test_reasoning_entry_defaults(self) -> None:
        entry = ReasoningEntry(
            stage="fp_verification",
            step="non_propagating_detected",
            verdict="downgrade",
            rationale="no xref path",
        )
        assert entry.delta == 0.0
        assert entry.llm_model is None
        assert entry.raw_response_excerpt is None
        assert entry.timestamp  # filled by default_factory


# ---------------------------------------------------------------------------
# Integration test: adversarial_triage records advocate/critic/decision trail
# ---------------------------------------------------------------------------


def _advocate_response() -> str:
    return json.dumps(
        {
            "exploitable": True,
            "argument": (
                "The recv() call at 0x4012A0 reads user input into a stack "
                "buffer that is passed directly to system() at 0x4012F0 "
                "with no length check or sanitization."
            ),
            "evidence_cited": [
                "recv() in handler_main",
                "system() call with user-controlled buffer",
            ],
            "attack_scenario": "Attacker sends crafted HTTP request.",
        }
    )


def _critic_strong_response() -> str:
    return json.dumps(
        {
            "exploitable": False,
            "rebuttal": (
                "The code path is protected by chroot and explicit input "
                "filter calls before the sink."
            ),
            "mitigations_cited": ["chroot", "input filter"],
            "exploitation_barriers": ["authentication required"],
        }
    )


def test_adversarial_triage_records_advocate_critic_trail(
    scout_stage_ctx: StageContext,
    scout_fake_llm_driver: FakeLLMDriver,
    scout_write_json: Callable[[Path, Any], None],
    scout_read_json: Callable[[Path], Any],
    monkeypatch,
) -> None:
    ctx = scout_stage_ctx

    # Seed fp_verification output so adversarial_triage has input findings.
    scout_write_json(
        ctx.run_dir / "stages" / "fp_verification" / "verified_alerts.json",
        {
            "verified_alerts": [
                {
                    "source_api": "recv",
                    "source_binary": "/usr/sbin/httpd",
                    "sink_symbol": "system",
                    "confidence": 0.8,
                    "original_confidence": 0.8,
                    "fp_verdict": "TP",
                    "fp_rationale": "kept",
                    "path_description": "network input reaches sink",
                }
            ]
        },
    )

    # FakeLLMDriver returns advocate then critic response on sequential calls.
    driver = FakeLLMDriver(responses=[_advocate_response(), _critic_strong_response()])
    monkeypatch.setattr(
        "aiedge.adversarial_triage.resolve_driver",
        lambda: driver,
    )

    # Suppress the deep repair-path LLM calls used for parse-failure recovery
    # by forcing the parser to succeed on first try (responses above are valid
    # JSON, so _repair_debate_response is never invoked).
    _ = scout_fake_llm_driver  # fixture marker for conftest wiring

    out = AdversarialTriageStage(no_llm=False).run(ctx)
    assert out.status in ("ok", "partial")

    payload = scout_read_json(
        ctx.run_dir / "stages" / "adversarial_triage" / "triaged_findings.json"
    )
    triaged = payload["triaged_findings"]
    assert isinstance(triaged, list) and len(triaged) == 1
    finding = triaged[0]

    # triage_outcome preserved
    assert finding["triage_outcome"] == "downgraded"

    # reasoning_trail attached with at least 3 entries: advocate, critic,
    # decision. In the worst case an upstream trail could pre-exist, so
    # assert >=3 rather than ==3.
    trail = finding.get("reasoning_trail")
    assert isinstance(trail, list)
    assert len(trail) >= 3

    # Verify the final three entries are advocate/critic/decision in order.
    advocate_entry = trail[-3]
    critic_entry = trail[-2]
    decision_entry = trail[-1]

    assert advocate_entry["stage"] == "adversarial_triage"
    assert advocate_entry["step"] == "advocate"
    assert advocate_entry["verdict"] == "exploit_path_plausible"
    assert advocate_entry["llm_model"] == "sonnet"
    # raw excerpt is capped at 200 chars
    excerpt = advocate_entry.get("raw_response_excerpt")
    if excerpt is not None:
        assert len(cast(str, excerpt)) <= 200

    assert critic_entry["stage"] == "adversarial_triage"
    assert critic_entry["step"] == "critic"
    assert critic_entry["verdict"] == "downgrade"
    assert critic_entry["llm_model"] == "sonnet"

    assert decision_entry["stage"] == "adversarial_triage"
    assert decision_entry["step"] == "decision"
    assert decision_entry["verdict"] == "downgrade"
    # Downgrade delta is -_CONFIDENCE_REDUCTION = -0.2
    assert float(cast(float, decision_entry["delta"])) < 0.0


def test_adversarial_triage_preserves_upstream_trail(
    scout_stage_ctx: StageContext,
    scout_write_json: Callable[[Path, Any], None],
    scout_read_json: Callable[[Path], Any],
    monkeypatch,
) -> None:
    """Upstream (fp_verification) trail entries must pass through unchanged."""
    ctx = scout_stage_ctx
    upstream_trail = [
        {
            "stage": "fp_verification",
            "step": "sanitizer_detected",
            "verdict": "downgrade",
            "rationale": "atoi neutralizes taint",
            "delta": -0.15,
            "timestamp": "2026-04-13T14:32:01+00:00",
            "llm_model": None,
            "raw_response_excerpt": None,
        }
    ]
    scout_write_json(
        ctx.run_dir / "stages" / "fp_verification" / "verified_alerts.json",
        {
            "verified_alerts": [
                {
                    "source_api": "recv",
                    "source_binary": "/usr/sbin/httpd",
                    "sink_symbol": "system",
                    "confidence": 0.7,
                    "original_confidence": 0.85,
                    "fp_verdict": "TP",
                    "fp_rationale": "kept",
                    "reasoning_trail": upstream_trail,
                }
            ]
        },
    )
    driver = FakeLLMDriver(responses=[_advocate_response(), _critic_strong_response()])
    monkeypatch.setattr(
        "aiedge.adversarial_triage.resolve_driver",
        lambda: driver,
    )
    _ = AdversarialTriageStage(no_llm=False).run(ctx)
    payload = scout_read_json(
        ctx.run_dir / "stages" / "adversarial_triage" / "triaged_findings.json"
    )
    finding = payload["triaged_findings"][0]
    trail = finding["reasoning_trail"]
    assert isinstance(trail, list)
    # Should have 1 upstream + 3 new entries
    assert len(trail) == 4
    assert trail[0]["step"] == "sanitizer_detected"
    assert trail[1]["step"] == "advocate"
    assert trail[2]["step"] == "critic"
    assert trail[3]["step"] == "decision"


# ---------------------------------------------------------------------------
# Integration test: fp_verification records pattern-match trail
# ---------------------------------------------------------------------------


def test_fp_verification_records_pattern_match_trail(
    scout_stage_ctx: StageContext,
    scout_write_json: Callable[[Path, Any], None],
    scout_read_json: Callable[[Path], Any],
    monkeypatch,
) -> None:
    """Static pre-filter (sanitizer) hit should produce a trail entry."""
    ctx = scout_stage_ctx

    # Seed alert with sanitizer-matching decompiled function body.
    scout_write_json(
        ctx.run_dir / "stages" / "taint_propagation" / "alerts.json",
        {
            "alerts": [
                {
                    "source_api": "recv",
                    "source_binary": "/usr/sbin/httpd",
                    "sink_symbol": "system",
                    "confidence": 0.8,
                    "path_description": "network input reaches sink",
                }
            ]
        },
    )

    # Decompiled function containing the sanitizer (atoi) in call path.
    scout_write_json(
        ctx.run_dir / "stages" / "ghidra_analysis" / "decompiled_functions.json",
        {
            "functions": [
                {
                    "name": "handler_main",
                    "binary": "httpd",
                    "body": (
                        "int handler_main(void) {\n"
                        "  char buf[256];\n"
                        "  recv(sock, buf, sizeof(buf), 0);\n"
                        "  int port = atoi(buf);\n"
                        "  system(buf);\n"
                        "  return 0;\n"
                        "}"
                    ),
                }
            ]
        },
    )

    # Fake driver returns a TP verdict so only the static sanitizer pre-filter
    # trail entry (+ LLM maintain entry) contributes to the trail.
    driver = FakeLLMDriver(
        responses=[
            json.dumps(
                {
                    "verdict": "TP",
                    "fp_pattern": None,
                    "confidence_adjustment": 0.0,
                    "rationale": "LLM confirmed exploitability",
                }
            )
        ]
    )
    monkeypatch.setattr(
        "aiedge.fp_verification.resolve_driver",
        lambda: driver,
    )

    out = FPVerificationStage(no_llm=False).run(ctx)
    assert out.status in ("ok", "partial")

    payload = scout_read_json(
        ctx.run_dir / "stages" / "fp_verification" / "verified_alerts.json"
    )
    alerts = payload["verified_alerts"]
    assert len(alerts) == 1
    alert = alerts[0]
    trail = alert.get("reasoning_trail")
    assert isinstance(trail, list)
    # At least one entry must be the sanitizer pattern match.
    sanitizer_entries = [e for e in trail if e.get("step") == "sanitizer_detected"]
    assert len(sanitizer_entries) == 1
    se = sanitizer_entries[0]
    assert se["stage"] == "fp_verification"
    assert se["verdict"] == "downgrade"
    assert float(cast(float, se["delta"])) < 0.0
    # Existing fp_verdict/fp_rationale still present (backward compat).
    assert "fp_verdict" in alert
    assert "fp_rationale" in alert


def test_fp_verification_records_llm_fp_trail(
    scout_stage_ctx: StageContext,
    scout_write_json: Callable[[Path, Any], None],
    scout_read_json: Callable[[Path], Any],
    monkeypatch,
) -> None:
    """LLM FP verdict should add a pattern-named trail entry."""
    ctx = scout_stage_ctx
    scout_write_json(
        ctx.run_dir / "stages" / "taint_propagation" / "alerts.json",
        {
            "alerts": [
                {
                    "source_api": "recv",
                    "source_binary": "/usr/sbin/httpd",
                    "sink_symbol": "system",
                    "confidence": 0.75,
                    "path_description": "network input reaches sink",
                }
            ]
        },
    )
    driver = FakeLLMDriver(
        responses=[
            json.dumps(
                {
                    "verdict": "FP",
                    "fp_pattern": "sysfile",
                    "confidence_adjustment": -0.3,
                    "rationale": (
                        "sink argument is a read-only /proc path; no "
                        "user-controlled data reaches the sink."
                    ),
                }
            )
        ]
    )
    monkeypatch.setattr("aiedge.fp_verification.resolve_driver", lambda: driver)
    _ = FPVerificationStage(no_llm=False).run(ctx)
    payload = scout_read_json(
        ctx.run_dir / "stages" / "fp_verification" / "verified_alerts.json"
    )
    alert = payload["verified_alerts"][0]
    trail = alert.get("reasoning_trail", [])
    assert isinstance(trail, list) and len(trail) >= 1
    llm_entries = [
        e
        for e in trail
        if e.get("stage") == "fp_verification" and e.get("step") == "sysfile_detected"
    ]
    assert len(llm_entries) == 1
    entry = llm_entries[0]
    assert entry["verdict"] == "downgrade"
    assert float(cast(float, entry["delta"])) < 0.0
    assert entry["llm_model"] == "sonnet"


# ---------------------------------------------------------------------------
# Backward-compat: findings without trail still build
# ---------------------------------------------------------------------------


def test_finding_without_trail_backward_compat() -> None:
    """A finding dict without reasoning_trail must be valid (missing field is
    fine). Existing category-annotation path must succeed and category_counts
    must be populated."""
    from aiedge.finding_categories import annotate_findings_with_categories

    findings: list[dict[str, object]] = [
        {
            "id": "aiedge.findings.debug.telnet_enablement",
            "title": "telnet enabled",
            "severity": "medium",
            "confidence": 0.6,
            "disposition": "confirmed",
            "evidence": [{"path": "stages/inventory/inventory.json"}],
        },
        {
            "id": "aiedge.findings.secrets.private_key_pem",
            "title": "private key present",
            "severity": "low",
            "confidence": 0.5,
            "disposition": "suspected",
            "evidence": [{"path": "stages/findings/credential_mapping.json"}],
        },
    ]
    # The annotator must not raise when reasoning_trail is absent.
    counts = annotate_findings_with_categories(findings)
    assert counts["misconfiguration"] == 1
    assert counts["pipeline_artifact"] == 1
    # No reasoning_trail added by the annotator (it's a separate concern).
    for f in findings:
        assert "reasoning_trail" not in f or f.get("reasoning_trail") == []


# ---------------------------------------------------------------------------
# SARIF export test: scout_reasoning_trail appears in properties bag
# ---------------------------------------------------------------------------


def test_sarif_includes_reasoning_trail_in_properties(tmp_path: Path) -> None:
    trail = [
        {
            "stage": "fp_verification",
            "step": "sanitizer_detected",
            "verdict": "downgrade",
            "rationale": "atoi sanitizer between source and sink",
            "delta": -0.15,
            "timestamp": "2026-04-13T14:32:01+00:00",
            "llm_model": None,
            "raw_response_excerpt": None,
        },
        {
            "stage": "adversarial_triage",
            "step": "advocate",
            "verdict": "exploit_path_plausible",
            "rationale": "recv() flows into system()",
            "delta": 0.0,
            "timestamp": "2026-04-13T14:32:02+00:00",
            "llm_model": "sonnet",
            "raw_response_excerpt": "short excerpt",
        },
    ]
    finding: dict[str, Any] = {
        "id": "aiedge.findings.web.exec_sink_overlap",
        "title": "command injection",
        "severity": "high",
        "confidence": 0.65,
        "disposition": "confirmed",
        "category": "vulnerability",
        "evidence": [{"path": "stages/findings/findings.json"}],
        "reasoning_trail": trail,
    }
    sarif = findings_to_sarif([finding], run_dir=tmp_path, tool_version="test")
    # SARIF 2.1.0 has runs[0].results[0].properties.
    runs = sarif["runs"]
    assert isinstance(runs, list) and len(runs) == 1
    results = runs[0]["results"]
    assert isinstance(results, list) and len(results) == 1
    props = results[0].get("properties")
    assert isinstance(props, dict)
    assert "scout_reasoning_trail" in props
    exported = props["scout_reasoning_trail"]
    assert isinstance(exported, list)
    assert len(exported) == 2
    assert exported[0]["step"] == "sanitizer_detected"
    assert exported[1]["step"] == "advocate"
    # category pass-through too (PR #7a backward compat)
    assert props["scout_category"] == "vulnerability"


def test_sarif_omits_reasoning_trail_when_absent(tmp_path: Path) -> None:
    """Findings without a trail must not have a scout_reasoning_trail key."""
    finding: dict[str, Any] = {
        "id": "aiedge.findings.debug.telnet_enablement",
        "title": "telnet enabled",
        "severity": "medium",
        "confidence": 0.55,
        "disposition": "confirmed",
        "category": "misconfiguration",
        "evidence": [{"path": "stages/inventory/inventory.json"}],
    }
    sarif = findings_to_sarif([finding], run_dir=tmp_path, tool_version="test")
    results = sarif["runs"][0]["results"]
    props = results[0].get("properties", {})
    assert "scout_reasoning_trail" not in props


# ---------------------------------------------------------------------------
# v2.6.1 — synthesis-level reasoning_trail inheritance
# ---------------------------------------------------------------------------


class TestSynthesisReasoningTrailInheritance:
    """Verify `_inherit_synthesis_reasoning_trail` pulls downstream stage
    aggregate outcomes onto top-level synthesis findings.
    """

    def _write_stage_summaries(
        self,
        ctx: StageContext,
        *,
        write_fp: bool = True,
        write_triage: bool = True,
    ) -> None:
        if write_fp:
            fp_dir = ctx.run_dir / "stages" / "fp_verification"
            fp_dir.mkdir(parents=True, exist_ok=True)
            (fp_dir / "verified_alerts.json").write_text(
                json.dumps(
                    {
                        "verified_alerts": [],
                        "summary": {
                            "total_input": 100,
                            "true_positives": 56,
                            "false_positives": 44,
                            "unverified": 0,
                            "parse_failures": 0,
                        },
                    }
                ),
                encoding="utf-8",
            )
        if write_triage:
            triage_dir = ctx.run_dir / "stages" / "adversarial_triage"
            triage_dir.mkdir(parents=True, exist_ok=True)
            (triage_dir / "triaged_findings.json").write_text(
                json.dumps(
                    {
                        "triaged_findings": [],
                        "summary": {
                            "debated": 100,
                            "downgraded": 97,
                            "maintained": 3,
                            "parse_failures": 0,
                            "llm_call_failures": 0,
                        },
                    }
                ),
                encoding="utf-8",
            )

    def test_inherits_both_summaries_on_target_finding(
        self, scout_stage_ctx: StageContext
    ) -> None:
        from aiedge.findings import _inherit_synthesis_reasoning_trail

        ctx = scout_stage_ctx
        self._write_stage_summaries(ctx)
        normalized: list[dict[str, Any]] = [
            {
                "id": "aiedge.findings.web.exec_sink_overlap",
                "title": "Web-exposed component with command-exec sink overlap",
                "severity": "high",
                "confidence": 0.78,
                "disposition": "suspected",
            }
        ]
        _inherit_synthesis_reasoning_trail(normalized, ctx.run_dir)
        trail = normalized[0].get("reasoning_trail")
        assert isinstance(trail, list)
        assert len(trail) == 2
        stages = {cast(dict[str, Any], e).get("stage") for e in trail}
        assert stages == {"fp_verification", "adversarial_triage"}
        for entry in trail:
            entry_d = cast(dict[str, Any], entry)
            assert entry_d.get("step") == "synthesis_inherit"
            assert entry_d.get("verdict") == "summary"
            assert entry_d.get("delta") == 0.0

    def test_skips_non_target_findings(self, scout_stage_ctx: StageContext) -> None:
        from aiedge.findings import _inherit_synthesis_reasoning_trail

        ctx = scout_stage_ctx
        self._write_stage_summaries(ctx)
        normalized: list[dict[str, Any]] = [
            {
                "id": "aiedge.findings.inventory.string_hits_present",
                "title": "Inventory string-hit signals present",
                "severity": "info",
                "confidence": 0.95,
                "disposition": "confirmed",
            }
        ]
        _inherit_synthesis_reasoning_trail(normalized, ctx.run_dir)
        assert "reasoning_trail" not in normalized[0]

    def test_fail_open_when_artifacts_missing(
        self, scout_stage_ctx: StageContext
    ) -> None:
        from aiedge.findings import _inherit_synthesis_reasoning_trail

        ctx = scout_stage_ctx
        # Neither fp_verification nor adversarial_triage artifacts exist.
        normalized: list[dict[str, Any]] = [
            {
                "id": "aiedge.findings.web.exec_sink_overlap",
                "title": "Web-exposed command-exec sink overlap",
                "severity": "high",
                "confidence": 0.78,
                "disposition": "suspected",
            }
        ]
        _inherit_synthesis_reasoning_trail(normalized, ctx.run_dir)
        assert "reasoning_trail" not in normalized[0]

    def test_preserves_existing_trail_entries(
        self, scout_stage_ctx: StageContext
    ) -> None:
        from aiedge.findings import _inherit_synthesis_reasoning_trail

        ctx = scout_stage_ctx
        self._write_stage_summaries(ctx, write_fp=False, write_triage=True)
        normalized: list[dict[str, Any]] = [
            {
                "id": "aiedge.findings.web.exec_sink_overlap",
                "title": "Web-exposed command-exec sink overlap",
                "severity": "high",
                "confidence": 0.78,
                "disposition": "suspected",
                "reasoning_trail": [
                    {
                        "stage": "custom_stage",
                        "step": "pre_existing",
                        "verdict": "note",
                        "rationale": "must not be dropped",
                        "delta": 0.0,
                        "timestamp": "2026-04-13T00:00:00+00:00",
                        "llm_model": None,
                        "raw_response_excerpt": None,
                    }
                ],
            }
        ]
        _inherit_synthesis_reasoning_trail(normalized, ctx.run_dir)
        trail = normalized[0].get("reasoning_trail")
        assert isinstance(trail, list)
        assert len(trail) == 2
        first = cast(dict[str, Any], trail[0])
        second = cast(dict[str, Any], trail[1])
        assert first.get("step") == "pre_existing"
        assert second.get("stage") == "adversarial_triage"

    def test_rationale_encodes_stage_summary_counts(
        self, scout_stage_ctx: StageContext
    ) -> None:
        from aiedge.findings import _inherit_synthesis_reasoning_trail

        ctx = scout_stage_ctx
        self._write_stage_summaries(ctx)
        normalized: list[dict[str, Any]] = [
            {
                "id": "aiedge.findings.web.exec_sink_overlap",
                "title": "Web-exposed command-exec sink overlap",
                "severity": "high",
                "confidence": 0.78,
                "disposition": "suspected",
            }
        ]
        _inherit_synthesis_reasoning_trail(normalized, ctx.run_dir)
        trail = cast(list[dict[str, Any]], normalized[0]["reasoning_trail"])
        fp_entry = next(e for e in trail if e["stage"] == "fp_verification")
        triage_entry = next(e for e in trail if e["stage"] == "adversarial_triage")
        assert "100" in fp_entry["rationale"]
        assert "56 TP" in fp_entry["rationale"]
        assert "44 FP" in fp_entry["rationale"]
        assert "100" in triage_entry["rationale"]
        assert "97 downgraded" in triage_entry["rationale"]
        assert "3 maintained" in triage_entry["rationale"]
