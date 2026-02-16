from __future__ import annotations

import json
from pathlib import Path
from typing import cast

QUALITY_GATE_SCHEMA_VERSION = 1
QUALITY_GATE_THRESHOLD_MISS = "QUALITY_GATE_THRESHOLD_MISS"
QUALITY_GATE_INVALID_METRICS = "QUALITY_GATE_INVALID_METRICS"
QUALITY_GATE_INVALID_REPORT = "QUALITY_GATE_INVALID_REPORT"
QUALITY_GATE_RELEASE_CONSTRAINT = "QUALITY_GATE_RELEASE_CONSTRAINT"
QUALITY_GATE_LLM_REQUIRED = "QUALITY_GATE_LLM_REQUIRED"
QUALITY_GATE_LLM_INVALID = "QUALITY_GATE_LLM_INVALID"
QUALITY_GATE_LLM_VERDICT_MISS = "QUALITY_GATE_LLM_VERDICT_MISS"


class QualityGateError(ValueError):
    def __init__(self, token: str, message: str) -> None:
        super().__init__(message)
        self.token: str = token


def _rounded(value: float) -> float:
    return round(value, 6)


def _as_float(value: object) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    return None


def load_json_object(
    path: Path, *, error_token: str, object_name: str
) -> dict[str, object]:
    try:
        payload_any = cast(object, json.loads(path.read_text(encoding="utf-8")))
    except json.JSONDecodeError as e:
        raise QualityGateError(
            error_token,
            f"{object_name} JSON is invalid: {e.msg}",
        ) from e
    if not isinstance(payload_any, dict):
        raise QualityGateError(
            error_token, f"{object_name} payload must be a JSON object"
        )
    return cast(dict[str, object], payload_any)


def _metric_value(metrics_payload: dict[str, object], field: str) -> float:
    raw_value: object | None
    if field == "abstain_rate":
        raw_value = metrics_payload.get("abstain_rate")
    elif field.startswith("overall."):
        overall_any = metrics_payload.get("overall")
        if not isinstance(overall_any, dict):
            raise QualityGateError(
                QUALITY_GATE_INVALID_METRICS,
                "metrics payload is missing required field 'overall'",
            )
        metric_name = field.split(".", 1)[1]
        raw_value = cast(dict[str, object], overall_any).get(metric_name)
    else:
        raw_value = None

    if raw_value is None:
        raise QualityGateError(
            QUALITY_GATE_INVALID_METRICS,
            f"metrics payload is missing required field '{field}'",
        )

    value = _as_float(raw_value)
    if value is None:
        raise QualityGateError(
            QUALITY_GATE_INVALID_METRICS,
            f"metrics field '{field}' must be a numeric value",
        )
    return _rounded(value)


def _threshold_error(
    *,
    metric: str,
    source_field: str,
    actual: float,
    threshold: float,
    operator: str,
) -> dict[str, object]:
    return {
        "error_token": QUALITY_GATE_THRESHOLD_MISS,
        "metric": metric,
        "source_field": source_field,
        "actual": _rounded(actual),
        "threshold": _rounded(threshold),
        "operator": operator,
        "message": (
            f"threshold miss for {metric}: actual={_rounded(actual)} "
            f"{operator} threshold={_rounded(threshold)}"
        ),
    }


def _llm_gate_error(
    *,
    error_token: str,
    message: str,
    llm_gate_path: str | None,
) -> dict[str, object]:
    return {
        "error_token": error_token,
        "metric": "llm_gate_verdict",
        "llm_gate_path": llm_gate_path,
        "message": message,
    }


def _count_confirmed_high_or_critical(report_payload: dict[str, object]) -> int:
    findings_any = report_payload.get("findings")
    if findings_any is None:
        return 0
    if not isinstance(findings_any, list):
        raise QualityGateError(
            QUALITY_GATE_INVALID_REPORT,
            "report findings must be a list when provided",
        )

    count = 0
    for idx, finding_any in enumerate(cast(list[object], findings_any)):
        if not isinstance(finding_any, dict):
            raise QualityGateError(
                QUALITY_GATE_INVALID_REPORT,
                f"report findings[{idx}] must be an object",
            )
        finding = cast(dict[str, object], finding_any)
        severity = finding.get("severity")
        disposition = finding.get("disposition")
        if severity in {"high", "critical"} and disposition == "confirmed":
            count += 1
    return count


def evaluate_quality_gate(
    *,
    metrics_payload: dict[str, object],
    metrics_path: str,
    report_payload: dict[str, object] | None,
    report_path: str | None,
    release_mode: bool,
    llm_primary: bool = False,
    llm_gate_payload: dict[str, object] | None = None,
    llm_gate_path: str | None = None,
) -> dict[str, object]:
    policy = {
        "precision_min": 0.9,
        "recall_min": 0.6,
        "high_severity_false_positive_rate_max": 0.1,
        "high_severity_false_positive_rate_proxy": "overall.fpr",
        "abstain_rate_max": 0.25,
        "release_mode": release_mode,
        "llm_primary": llm_primary,
    }

    precision = _metric_value(metrics_payload, "overall.precision")
    recall = _metric_value(metrics_payload, "overall.recall")
    high_sev_fp_proxy = _metric_value(metrics_payload, "overall.fpr")
    abstain_rate = _metric_value(metrics_payload, "abstain_rate")

    measured = {
        "precision": precision,
        "recall": recall,
        "high_severity_false_positive_rate_proxy": high_sev_fp_proxy,
        "high_severity_false_positive_rate_proxy_field": "overall.fpr",
        "abstain_rate": abstain_rate,
    }

    errors: list[dict[str, object]] = []
    if precision < 0.9:
        errors.append(
            _threshold_error(
                metric="precision",
                source_field="overall.precision",
                actual=precision,
                threshold=0.9,
                operator=">=",
            )
        )
    if recall < 0.6:
        errors.append(
            _threshold_error(
                metric="recall",
                source_field="overall.recall",
                actual=recall,
                threshold=0.6,
                operator=">=",
            )
        )
    if high_sev_fp_proxy > 0.1:
        errors.append(
            _threshold_error(
                metric="high_severity_false_positive_rate",
                source_field="overall.fpr",
                actual=high_sev_fp_proxy,
                threshold=0.1,
                operator="<=",
            )
        )
    if abstain_rate > 0.25:
        errors.append(
            _threshold_error(
                metric="abstain_rate",
                source_field="abstain_rate",
                actual=abstain_rate,
                threshold=0.25,
                operator="<=",
            )
        )

    confirmed_high_critical_count = 0
    if release_mode and report_payload is not None:
        confirmed_high_critical_count = _count_confirmed_high_or_critical(
            report_payload
        )
        if errors and confirmed_high_critical_count > 0:
            errors.append(
                {
                    "error_token": QUALITY_GATE_RELEASE_CONSTRAINT,
                    "metric": "release_confirmed_high_critical_constraint",
                    "actual": confirmed_high_critical_count,
                    "threshold": 0,
                    "operator": "==",
                    "message": (
                        "release mode requires zero confirmed high/critical findings "
                        "while quality thresholds are unmet"
                    ),
                }
            )

    if not errors and llm_primary:
        if llm_gate_payload is None:
            errors.append(
                _llm_gate_error(
                    error_token=QUALITY_GATE_LLM_REQUIRED,
                    message="llm-primary policy requires llm gate payload",
                    llm_gate_path=llm_gate_path,
                )
            )
        else:
            llm_verdict = llm_gate_payload.get("verdict")
            if llm_verdict is None:
                errors.append(
                    _llm_gate_error(
                        error_token=QUALITY_GATE_LLM_VERDICT_MISS,
                        message="llm gate verdict is missing",
                        llm_gate_path=llm_gate_path,
                    )
                )
            elif llm_verdict not in {"pass", "fail"}:
                errors.append(
                    _llm_gate_error(
                        error_token=QUALITY_GATE_LLM_INVALID,
                        message="llm gate verdict must be 'pass' or 'fail'",
                        llm_gate_path=llm_gate_path,
                    )
                )
            elif llm_verdict == "fail":
                errors.append(
                    _llm_gate_error(
                        error_token=QUALITY_GATE_LLM_VERDICT_MISS,
                        message="llm gate verdict reported fail",
                        llm_gate_path=llm_gate_path,
                    )
                )

    passed = not errors
    return {
        "schema_version": QUALITY_GATE_SCHEMA_VERSION,
        "verdict": "pass" if passed else "fail",
        "passed": passed,
        "metrics_path": metrics_path,
        "report_path": report_path,
        "llm_gate_path": llm_gate_path,
        "policy": policy,
        "measured": measured,
        "confirmed_high_critical_count": confirmed_high_critical_count,
        "errors": errors,
    }


def format_quality_gate(payload: dict[str, object]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def write_quality_gate(path: Path, payload: dict[str, object]) -> None:
    _ = path.write_text(format_quality_gate(payload), encoding="utf-8")
