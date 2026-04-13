from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from aiedge.adversarial_triage import AdversarialTriageStage
from aiedge.fp_verification import FPVerificationStage
from aiedge.llm_driver import LLMDriverResult
from aiedge.stage import StageContext


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _read_json(path: Path) -> dict[str, object]:
    raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    assert isinstance(raw, dict)
    return cast(dict[str, object], raw)


class _FakeDriver:
    def __init__(self, result: LLMDriverResult) -> None:
        self._result = result

    def available(self) -> bool:
        return True

    def execute(self, **kwargs) -> LLMDriverResult:
        _ = kwargs
        return self._result


def test_fp_verification_separates_parse_failures(
    tmp_path: Path, monkeypatch
) -> None:
    ctx = _ctx(tmp_path)
    _write_json(
        ctx.run_dir / "stages" / "taint_propagation" / "alerts.json",
        {
            "alerts": [
                {
                    "source_api": "recv",
                    "source_binary": "httpd",
                    "sink_symbol": "system",
                    "confidence": 0.8,
                    "path_description": "network input reaches sink",
                }
            ]
        },
    )
    fake_driver = _FakeDriver(
        LLMDriverResult(
            status="ok",
            stdout="not valid json",
            stderr="",
            argv=["codex"],
            attempts=[],
            returncode=0,
        )
    )
    monkeypatch.setattr("aiedge.fp_verification.resolve_driver", lambda: fake_driver)

    out = FPVerificationStage(no_llm=False).run(ctx)

    assert out.status == "partial"
    payload = _read_json(
        ctx.run_dir / "stages" / "fp_verification" / "verified_alerts.json"
    )
    summary = cast(dict[str, object], payload["summary"])
    assert summary["parse_failures"] == 1
    assert summary["llm_call_failures"] == 0
    alert = cast(dict[str, object], cast(list[object], payload["verified_alerts"])[0])
    assert alert["fp_failure_kind"] == "parse_failure"


def test_adversarial_triage_separates_llm_call_failures(
    tmp_path: Path, monkeypatch
) -> None:
    ctx = _ctx(tmp_path)
    _write_json(
        ctx.run_dir / "stages" / "fp_verification" / "verified_alerts.json",
        {
            "verified_alerts": [
                {
                    "source_api": "recv",
                    "source_binary": "httpd",
                    "sink_symbol": "system",
                    "confidence": 0.8,
                    "original_confidence": 0.8,
                    "fp_rationale": "kept",
                    "fp_verdict": "TP",
                    "path_description": "network input reaches sink",
                }
            ]
        },
    )
    fake_driver = _FakeDriver(
        LLMDriverResult(
            status="nonzero_exit",
            stdout="You've hit your limit · resets 12am (Asia/Seoul)\n",
            stderr="",
            argv=["claude"],
            attempts=[],
            returncode=1,
        )
    )
    monkeypatch.setattr("aiedge.adversarial_triage.resolve_driver", lambda: fake_driver)

    out = AdversarialTriageStage(no_llm=False).run(ctx)

    assert out.status == "partial"
    payload = _read_json(
        ctx.run_dir / "stages" / "adversarial_triage" / "triaged_findings.json"
    )
    summary = cast(dict[str, object], payload["summary"])
    assert summary["parse_failures"] == 0
    assert summary["llm_call_failures"] == 1
    finding = cast(dict[str, object], cast(list[object], payload["triaged_findings"])[0])
    assert "quota_exhausted" in cast(str, finding["triage_failure_kind"])
    advocate = cast(dict[str, object], finding["advocate_argument"])
    assert advocate["error"] == "llm_call_failed"
