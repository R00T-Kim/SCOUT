from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from .corpus import load_corpus_manifest

QUALITY_METRICS_SCHEMA_VERSION = 1
QUALITY_METRICS_ALLOWED_LABELS: tuple[str, ...] = (
    "attack_surface",
    "metrics",
    "reference_context",
    "taxonomy",
)
QUALITY_METRICS_METRIC_KEYS: tuple[str, ...] = (
    "precision",
    "recall",
    "f1",
    "fpr",
    "fnr",
)
QUALITY_METRICS_HIGHER_IS_BETTER: tuple[str, ...] = ("precision", "recall", "f1")
QUALITY_METRICS_LOWER_IS_BETTER: tuple[str, ...] = ("fpr", "fnr")

_ABSTAIN_MARKER = "__abstain__"
_UNKNOWN_MARKER = "__unknown__"


class QualityMetricsError(ValueError):
    def __init__(self, token: str, message: str) -> None:
        super().__init__(message)
        self.token: str = token


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return value


def _safe_ratio(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return _clamp01(float(numerator) / float(denominator))


def _rounded(value: float) -> float:
    return round(value, 6)


def _f1(precision: float, recall: float) -> float:
    denom = precision + recall
    if denom <= 0.0:
        return 0.0
    return _clamp01((2.0 * precision * recall) / denom)


def _metric_payload(tp: int, fp: int, fn: int, tn: int) -> dict[str, float]:
    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    return {
        "precision": _rounded(precision),
        "recall": _rounded(recall),
        "f1": _rounded(_f1(precision, recall)),
        "fpr": _rounded(_safe_ratio(fp, fp + tn)),
        "fnr": _rounded(_safe_ratio(fn, fn + tp)),
    }


def _coerce_predicted_labels(sample: dict[str, object], sample_id: str) -> list[str]:
    predicted_any = sample.get("predicted_labels")
    if predicted_any is None:
        return []
    if not isinstance(predicted_any, list):
        raise QualityMetricsError(
            "QUALITY_METRICS_INVALID_LABEL",
            f"sample {sample_id!r} predicted_labels must be a list when provided",
        )
    predicted_raw = cast(list[object], predicted_any)
    predicted: list[str] = []
    for item in predicted_raw:
        if not isinstance(item, str) or not item.strip():
            raise QualityMetricsError(
                "QUALITY_METRICS_INVALID_LABEL",
                f"sample {sample_id!r} predicted_labels entries must be non-empty strings",
            )
        predicted.append(item.strip())
    return predicted


def _validate_label_taxonomy(label: str, *, sample_id: str, field: str) -> None:
    if label in QUALITY_METRICS_ALLOWED_LABELS:
        return
    if label in (_ABSTAIN_MARKER, _UNKNOWN_MARKER) and field == "predicted_labels":
        return
    raise QualityMetricsError(
        "QUALITY_METRICS_INVALID_LABEL",
        f"sample {sample_id!r} contains unsupported {field} label {label!r}",
    )


def _delta_metrics(
    *,
    current: dict[str, object],
    baseline: dict[str, object],
    class_names: list[str],
) -> dict[str, object]:
    current_overall = cast(dict[str, object], current.get("overall", {}))
    baseline_overall = cast(dict[str, object], baseline.get("overall", {}))

    overall_delta: dict[str, float] = {}
    for key in QUALITY_METRICS_METRIC_KEYS:
        cur_any = current_overall.get(key)
        base_any = baseline_overall.get(key)
        cur = float(cur_any) if isinstance(cur_any, (int, float)) else 0.0
        base = float(base_any) if isinstance(base_any, (int, float)) else 0.0
        overall_delta[key] = _rounded(cur - base)

    current_per_class = cast(dict[str, object], current.get("per_class", {}))
    baseline_per_class = cast(dict[str, object], baseline.get("per_class", {}))
    per_class_delta: dict[str, object] = {}
    for class_name in class_names:
        current_class_any = current_per_class.get(class_name)
        baseline_class_any = baseline_per_class.get(class_name)
        current_class = (
            cast(dict[str, object], current_class_any)
            if isinstance(current_class_any, dict)
            else {}
        )
        baseline_class = (
            cast(dict[str, object], baseline_class_any)
            if isinstance(baseline_class_any, dict)
            else {}
        )
        deltas: dict[str, float] = {}
        for key in QUALITY_METRICS_METRIC_KEYS:
            cur_any = current_class.get(key)
            base_any = baseline_class.get(key)
            cur = float(cur_any) if isinstance(cur_any, (int, float)) else 0.0
            base = float(base_any) if isinstance(base_any, (int, float)) else 0.0
            deltas[key] = _rounded(cur - base)
        per_class_delta[class_name] = deltas

    return {
        "delta": {
            "overall": overall_delta,
            "per_class": per_class_delta,
        }
    }


def _regression_entries(
    *,
    current_metrics: dict[str, object],
    baseline_metrics: dict[str, object],
    threshold: float,
) -> list[dict[str, object]]:
    regressions: list[dict[str, object]] = []
    for metric in QUALITY_METRICS_METRIC_KEYS:
        baseline_any = baseline_metrics.get(metric)
        current_any = current_metrics.get(metric)
        baseline_value = (
            float(baseline_any) if isinstance(baseline_any, (int, float)) else 0.0
        )
        current_value = (
            float(current_any) if isinstance(current_any, (int, float)) else 0.0
        )

        if metric in QUALITY_METRICS_HIGHER_IS_BETTER:
            regression_amount = baseline_value - current_value
        else:
            regression_amount = current_value - baseline_value
        regression_amount = _rounded(regression_amount)
        if regression_amount > threshold:
            regressions.append(
                {
                    "metric": metric,
                    "baseline": _rounded(baseline_value),
                    "current": _rounded(current_value),
                    "regression": regression_amount,
                }
            )
    return regressions


def compute_quality_metrics(
    manifest_payload: dict[str, object],
    *,
    manifest_path: str,
) -> dict[str, object]:
    samples_any = manifest_payload.get("samples")
    if not isinstance(samples_any, list):
        raise QualityMetricsError(
            "QUALITY_METRICS_INVALID_LABEL", "manifest samples must be a list"
        )
    samples = cast(list[object], samples_any)

    per_class_counts: dict[str, dict[str, int]] = {
        label: {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        for label in QUALITY_METRICS_ALLOWED_LABELS
    }

    abstain_count = 0
    unknown_count = 0
    unknown_sample_count = 0

    for sample_any in samples:
        sample = cast(dict[str, object], sample_any)
        sample_id = cast(str, sample.get("id", "<missing-id>"))
        labels_any = sample.get("labels")
        labels = cast(list[object], labels_any) if isinstance(labels_any, list) else []
        truth_set: set[str] = set()
        for label_any in labels:
            label = cast(str, label_any)
            _validate_label_taxonomy(label, sample_id=sample_id, field="labels")
            truth_set.add(label)

        predicted_raw = _coerce_predicted_labels(sample, sample_id)
        predicted_set: set[str] = set()
        sample_has_unknown = False
        sample_abstained = False
        for label in predicted_raw:
            _validate_label_taxonomy(
                label, sample_id=sample_id, field="predicted_labels"
            )
            if label == _UNKNOWN_MARKER:
                sample_has_unknown = True
                unknown_count += 1
                continue
            if label == _ABSTAIN_MARKER:
                sample_abstained = True
                continue
            predicted_set.add(label)
        if sample_abstained:
            abstain_count += 1
        if sample_has_unknown:
            unknown_sample_count += 1

        for label in QUALITY_METRICS_ALLOWED_LABELS:
            in_truth = label in truth_set
            in_pred = label in predicted_set
            counts = per_class_counts[label]
            if in_truth and in_pred:
                counts["tp"] += 1
            elif (not in_truth) and in_pred:
                counts["fp"] += 1
            elif in_truth and (not in_pred):
                counts["fn"] += 1
            else:
                counts["tn"] += 1

    per_class: dict[str, object] = {}
    total_tp = 0
    total_fp = 0
    total_fn = 0
    total_tn = 0
    for label in QUALITY_METRICS_ALLOWED_LABELS:
        counts = per_class_counts[label]
        total_tp += counts["tp"]
        total_fp += counts["fp"]
        total_fn += counts["fn"]
        total_tn += counts["tn"]
        per_class[label] = _metric_payload(
            tp=counts["tp"],
            fp=counts["fp"],
            fn=counts["fn"],
            tn=counts["tn"],
        )

    sample_count = len(samples)
    payload: dict[str, object] = {
        "schema_version": QUALITY_METRICS_SCHEMA_VERSION,
        "corpus_id": cast(str, manifest_payload.get("corpus_id", "")),
        "manifest": manifest_path,
        "version": cast(str, manifest_payload.get("version", "")),
        "taxonomy": list(QUALITY_METRICS_ALLOWED_LABELS),
        "sample_count": sample_count,
        "abstain_count": abstain_count,
        "abstain_rate": _rounded(_safe_ratio(abstain_count, sample_count)),
        "unknown_count": unknown_count,
        "unknown_sample_count": unknown_sample_count,
        "overall": _metric_payload(
            tp=total_tp,
            fp=total_fp,
            fn=total_fn,
            tn=total_tn,
        ),
        "per_class": per_class,
    }

    return payload


def build_quality_delta_report(
    *,
    current_metrics: dict[str, object],
    baseline_metrics: dict[str, object],
    manifest_path: str,
    baseline_path: str,
    max_regression: float,
) -> dict[str, object]:
    if max_regression < 0.0:
        raise QualityMetricsError(
            "QUALITY_METRICS_INVALID_THRESHOLD",
            "max regression threshold must be >= 0.0",
        )

    class_names = list(QUALITY_METRICS_ALLOWED_LABELS)
    delta = _delta_metrics(
        current=current_metrics,
        baseline=baseline_metrics,
        class_names=class_names,
    )

    current_overall = cast(dict[str, object], current_metrics.get("overall", {}))
    baseline_overall = cast(dict[str, object], baseline_metrics.get("overall", {}))
    overall_regressions = _regression_entries(
        current_metrics=current_overall,
        baseline_metrics=baseline_overall,
        threshold=max_regression,
    )

    current_per_class = cast(dict[str, object], current_metrics.get("per_class", {}))
    baseline_per_class = cast(dict[str, object], baseline_metrics.get("per_class", {}))
    per_class_regressions: dict[str, object] = {}
    total_regression_count = len(overall_regressions)
    for class_name in class_names:
        current_class_any = current_per_class.get(class_name)
        baseline_class_any = baseline_per_class.get(class_name)
        current_class = (
            cast(dict[str, object], current_class_any)
            if isinstance(current_class_any, dict)
            else {}
        )
        baseline_class = (
            cast(dict[str, object], baseline_class_any)
            if isinstance(baseline_class_any, dict)
            else {}
        )
        entries = _regression_entries(
            current_metrics=current_class,
            baseline_metrics=baseline_class,
            threshold=max_regression,
        )
        per_class_regressions[class_name] = entries
        total_regression_count += len(entries)

    return {
        "schema_version": QUALITY_METRICS_SCHEMA_VERSION,
        "corpus_id": cast(str, current_metrics.get("corpus_id", "")),
        "manifest": manifest_path,
        "version": cast(str, current_metrics.get("version", "")),
        "baseline": baseline_path,
        "max_regression": _rounded(max_regression),
        **delta,
        "regressions": {
            "threshold": _rounded(max_regression),
            "has_regressions": total_regression_count > 0,
            "count": total_regression_count,
            "overall": overall_regressions,
            "per_class": per_class_regressions,
        },
    }


def evaluate_quality_metrics_harness(
    *, manifest_path: Path, baseline_path: Path | None = None
) -> tuple[dict[str, object], dict[str, object] | None]:
    payload = load_corpus_manifest(manifest_path)

    current_metrics = compute_quality_metrics(
        payload,
        manifest_path=str(manifest_path),
    )

    baseline_payload: dict[str, object] | None = None
    if baseline_path is not None:
        baseline_any = cast(
            object, json.loads(baseline_path.read_text(encoding="utf-8"))
        )
        if not isinstance(baseline_any, dict):
            raise QualityMetricsError(
                "QUALITY_METRICS_INVALID_BASELINE",
                "baseline payload must be a JSON object",
            )
        baseline_payload = cast(dict[str, object], baseline_any)

    return current_metrics, baseline_payload


def format_quality_metrics(payload: dict[str, object]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def write_quality_metrics(path: Path, payload: dict[str, object]) -> None:
    _ = path.write_text(format_quality_metrics(payload), encoding="utf-8")
