"""Tests for the LLM triage stage."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

from aiedge.llm_driver import LLMDriverResult
from aiedge.llm_triage import (
    LLMTriageStage,
    _build_triage_prompt,
    _parse_triage_response,
    _select_model_tier,
)
from aiedge.stage import StageContext


def _make_ctx(tmp_path: Path) -> StageContext:
    logs = tmp_path / "logs"
    logs.mkdir()
    report = tmp_path / "report"
    report.mkdir()
    return StageContext(run_dir=tmp_path, logs_dir=logs, report_dir=report)


def _write_candidates(run_dir: Path, candidates: list[dict[str, object]]) -> None:
    findings_dir = run_dir / "stages" / "findings"
    findings_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "exploit-candidates-v1",
        "candidates": candidates,
    }
    (findings_dir / "exploit_candidates.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )


def _write_binary_analysis(run_dir: Path) -> None:
    inv_dir = run_dir / "stages" / "inventory"
    inv_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "hardening_summary": {
            "nx_pct": 0.5,
            "pie_pct": 0.3,
            "canary_pct": 0.2,
        },
        "binaries": [],
    }
    (inv_dir / "binary_analysis.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )


def _write_attack_surface(run_dir: Path) -> None:
    as_dir = run_dir / "stages" / "attack_surface"
    as_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "summary": {
            "open_ports": 3,
            "listening_services": 2,
            "total_items": 15,
        },
    }
    (as_dir / "attack_surface.json").write_text(
        json.dumps(payload, indent=2) + "\n", encoding="utf-8"
    )


def _fake_driver_result(
    status: str = "ok",
    stdout: str = "",
    returncode: int = 0,
) -> LLMDriverResult:
    return LLMDriverResult(
        status=status,
        stdout=stdout,
        stderr="",
        argv=["codex"],
        attempts=[],
        returncode=returncode,
    )


# ---------------------------------------------------------------------------
# _select_model_tier
# ---------------------------------------------------------------------------
class TestSelectModelTier:
    def test_few_candidates_no_chains(self) -> None:
        assert _select_model_tier(5, False) == "haiku"

    def test_medium_candidates(self) -> None:
        assert _select_model_tier(15, False) == "sonnet"

    def test_many_candidates(self) -> None:
        assert _select_model_tier(60, False) == "opus"

    def test_chains_force_opus(self) -> None:
        assert _select_model_tier(3, True) == "opus"

    def test_boundary_ten(self) -> None:
        assert _select_model_tier(10, False) == "haiku"

    def test_boundary_eleven(self) -> None:
        assert _select_model_tier(11, False) == "sonnet"

    def test_boundary_fifty(self) -> None:
        assert _select_model_tier(50, False) == "sonnet"

    def test_boundary_fiftyone(self) -> None:
        assert _select_model_tier(51, False) == "opus"


# ---------------------------------------------------------------------------
# _build_triage_prompt
# ---------------------------------------------------------------------------
class TestBuildTriagePrompt:
    def test_basic_structure(self) -> None:
        candidates = [{"candidate_id": "c1", "score": 0.8}]
        prompt = _build_triage_prompt(candidates, None, None)
        assert "firmware vulnerability triage analyst" in prompt
        assert "c1" in prompt
        assert "rankings" in prompt

    def test_includes_hardening(self) -> None:
        candidates = [{"candidate_id": "c1"}]
        hardening = {"nx_pct": 0.5, "pie_pct": 0.3}
        prompt = _build_triage_prompt(candidates, hardening, None)
        assert "Binary Hardening Summary" in prompt
        assert "nx_pct" in prompt

    def test_includes_attack_surface(self) -> None:
        candidates = [{"candidate_id": "c1"}]
        attack = {"open_ports": 3}
        prompt = _build_triage_prompt(candidates, None, attack)
        assert "Attack Surface Summary" in prompt
        assert "open_ports" in prompt

    def test_includes_both_contexts(self) -> None:
        candidates = [{"candidate_id": "c1"}]
        hardening = {"nx_pct": 0.5}
        attack = {"open_ports": 3}
        prompt = _build_triage_prompt(candidates, hardening, attack)
        assert "Binary Hardening Summary" in prompt
        assert "Attack Surface Summary" in prompt


# ---------------------------------------------------------------------------
# _parse_triage_response
# ---------------------------------------------------------------------------
class TestParseTriageResponse:
    def test_valid_json(self) -> None:
        response = json.dumps({
            "rankings": [
                {
                    "candidate_id": "c1",
                    "priority": "high",
                    "rationale": "test",
                    "chain_potential": [],
                }
            ]
        })
        result = _parse_triage_response(response)
        assert result is not None
        assert len(result) == 1
        assert result[0]["candidate_id"] == "c1"
        assert result[0]["priority"] == "high"

    def test_code_fenced_json(self) -> None:
        response = '```json\n{"rankings": [{"candidate_id": "c2", "priority": "low", "rationale": "ok"}]}\n```'
        result = _parse_triage_response(response)
        assert result is not None
        assert result[0]["candidate_id"] == "c2"

    def test_empty_string(self) -> None:
        assert _parse_triage_response("") is None

    def test_invalid_json(self) -> None:
        assert _parse_triage_response("not json at all") is None

    def test_missing_rankings_key(self) -> None:
        assert _parse_triage_response('{"data": []}') is None

    def test_empty_rankings(self) -> None:
        assert _parse_triage_response('{"rankings": []}') is None

    def test_rankings_missing_required_keys(self) -> None:
        response = json.dumps({"rankings": [{"foo": "bar"}]})
        assert _parse_triage_response(response) is None

    def test_partial_valid_entries(self) -> None:
        response = json.dumps({
            "rankings": [
                {"candidate_id": "c1", "priority": "high"},
                {"bad": "entry"},
                {"candidate_id": "c3", "priority": "low"},
            ]
        })
        result = _parse_triage_response(response)
        assert result is not None
        assert len(result) == 2


# ---------------------------------------------------------------------------
# LLMTriageStage: no_llm mode
# ---------------------------------------------------------------------------
class TestLLMTriageStageNoLlm:
    def test_skipped(self, tmp_path: Path) -> None:
        ctx = _make_ctx(tmp_path)
        stage = LLMTriageStage(no_llm=True)
        assert stage.name == "llm_triage"
        outcome = stage.run(ctx)
        assert outcome.status == "skipped"
        assert "no_llm_mode" in outcome.limitations
        triage_path = tmp_path / "stages" / "llm_triage" / "triage.json"
        assert triage_path.is_file()
        data = json.loads(triage_path.read_text(encoding="utf-8"))
        assert data["status"] == "skipped"


# ---------------------------------------------------------------------------
# LLMTriageStage: missing findings
# ---------------------------------------------------------------------------
class TestLLMTriageStageMissingFindings:
    def test_partial_when_no_findings(self, tmp_path: Path) -> None:
        ctx = _make_ctx(tmp_path)
        stage = LLMTriageStage(no_llm=False)
        outcome = stage.run(ctx)
        assert outcome.status == "partial"
        assert "missing_exploit_candidates" in outcome.limitations

    def test_partial_when_empty_candidates(self, tmp_path: Path) -> None:
        ctx = _make_ctx(tmp_path)
        _write_candidates(tmp_path, [])
        stage = LLMTriageStage(no_llm=False)
        outcome = stage.run(ctx)
        assert outcome.status == "partial"
        assert "no_candidates" in outcome.limitations


# ---------------------------------------------------------------------------
# LLMTriageStage: driver unavailable
# ---------------------------------------------------------------------------
class TestLLMTriageStageDriverUnavailable:
    def test_partial_when_driver_unavailable(self, tmp_path: Path) -> None:
        ctx = _make_ctx(tmp_path)
        _write_candidates(tmp_path, [{"candidate_id": "c1", "score": 0.9}])

        with patch("aiedge.llm_triage.resolve_driver") as mock_resolve:
            mock_driver = mock_resolve.return_value
            mock_driver.available.return_value = False
            stage = LLMTriageStage(no_llm=False)
            outcome = stage.run(ctx)

        assert outcome.status == "partial"
        assert "llm_driver_unavailable" in outcome.limitations


# ---------------------------------------------------------------------------
# LLMTriageStage: mocked LLM driver -> ok
# ---------------------------------------------------------------------------
class TestLLMTriageStageSuccess:
    def test_ok_with_mocked_driver(self, tmp_path: Path) -> None:
        ctx = _make_ctx(tmp_path)
        candidates = [
            {"candidate_id": "c1", "score": 0.9, "chain_id": ""},
            {"candidate_id": "c2", "score": 0.7, "chain_id": ""},
        ]
        _write_candidates(tmp_path, candidates)
        _write_binary_analysis(tmp_path)
        _write_attack_surface(tmp_path)

        llm_response = json.dumps({
            "rankings": [
                {
                    "candidate_id": "c1",
                    "priority": "critical",
                    "rationale": "weak hardening + exposed",
                    "chain_potential": ["c2"],
                },
                {
                    "candidate_id": "c2",
                    "priority": "medium",
                    "rationale": "lower score",
                    "chain_potential": [],
                },
            ]
        })

        with patch("aiedge.llm_triage.resolve_driver") as mock_resolve:
            mock_driver = mock_resolve.return_value
            mock_driver.available.return_value = True
            mock_driver.execute.return_value = _fake_driver_result(
                status="ok", stdout=llm_response
            )
            stage = LLMTriageStage(no_llm=False)
            outcome = stage.run(ctx)

        assert outcome.status == "ok"
        assert outcome.details["ranking_count"] == 2
        assert outcome.details["model_tier"] == "haiku"

        triage_path = tmp_path / "stages" / "llm_triage" / "triage.json"
        assert triage_path.is_file()
        data = json.loads(triage_path.read_text(encoding="utf-8"))
        assert data["status"] == "ok"
        assert len(data["rankings"]) == 2

    def test_model_tier_passed_to_driver(self, tmp_path: Path) -> None:
        """Verify model_tier is forwarded to the LLM driver."""
        ctx = _make_ctx(tmp_path)
        # >50 candidates to trigger opus
        candidates = [
            {"candidate_id": f"c{i}", "score": 0.5}
            for i in range(55)
        ]
        _write_candidates(tmp_path, candidates)

        with patch("aiedge.llm_triage.resolve_driver") as mock_resolve:
            mock_driver = mock_resolve.return_value
            mock_driver.available.return_value = True
            mock_driver.execute.return_value = _fake_driver_result(
                status="ok",
                stdout=json.dumps({"rankings": [{"candidate_id": "c0", "priority": "high"}]}),
            )
            stage = LLMTriageStage(no_llm=False)
            outcome = stage.run(ctx)

        # Verify opus was selected and passed
        call_kwargs = mock_driver.execute.call_args
        assert call_kwargs is not None
        assert call_kwargs.kwargs.get("model_tier") == "opus"
        assert outcome.status == "ok"

    def test_falls_back_from_haiku_to_sonnet_on_nonzero_exit(
        self, tmp_path: Path
    ) -> None:
        ctx = _make_ctx(tmp_path)
        _write_candidates(
            tmp_path,
            [{"candidate_id": "c1", "score": 0.9, "chain_id": ""}],
        )

        llm_response = json.dumps({
            "rankings": [
                {
                    "candidate_id": "c1",
                    "priority": "high",
                    "rationale": "fallback succeeded",
                    "chain_potential": [],
                }
            ]
        })

        with patch("aiedge.llm_triage.resolve_driver") as mock_resolve:
            mock_driver = mock_resolve.return_value
            mock_driver.available.return_value = True
            mock_driver.execute.side_effect = [
                _fake_driver_result(status="nonzero_exit", returncode=1),
                _fake_driver_result(status="ok", stdout=llm_response),
            ]
            stage = LLMTriageStage(no_llm=False)
            outcome = stage.run(ctx)

        assert outcome.status == "ok"
        assert outcome.details["model_tier"] == "sonnet"
        assert mock_driver.execute.call_count == 2

    def test_unparseable_response(self, tmp_path: Path) -> None:
        ctx = _make_ctx(tmp_path)
        _write_candidates(tmp_path, [{"candidate_id": "c1", "score": 0.9}])

        with patch("aiedge.llm_triage.resolve_driver") as mock_resolve:
            mock_driver = mock_resolve.return_value
            mock_driver.available.return_value = True
            mock_driver.execute.return_value = _fake_driver_result(
                status="ok", stdout="this is not json"
            )
            stage = LLMTriageStage(no_llm=False)
            outcome = stage.run(ctx)

        assert outcome.status == "partial"
        assert "unparseable_llm_response" in outcome.limitations

    def test_llm_error_status(self, tmp_path: Path) -> None:
        ctx = _make_ctx(tmp_path)
        _write_candidates(tmp_path, [{"candidate_id": "c1", "score": 0.9}])

        with patch("aiedge.llm_triage.resolve_driver") as mock_resolve:
            mock_driver = mock_resolve.return_value
            mock_driver.available.return_value = True
            mock_driver.execute.return_value = _fake_driver_result(
                status="timeout", returncode=-1
            )
            stage = LLMTriageStage(no_llm=False)
            outcome = stage.run(ctx)

        assert outcome.status == "partial"
        assert "llm_timeout" in outcome.limitations
