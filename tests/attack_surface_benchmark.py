from __future__ import annotations

import json
from pathlib import Path
from typing import cast

_FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "attack_surface_accuracy"
_BENCHMARK_FIXTURE_PATH = _FIXTURE_DIR / "benchmark_fixture.json"
_METRICS_BASELINE_PATH = _FIXTURE_DIR / "metrics_baseline.json"


def _load_json_object(path: Path) -> dict[str, object]:
    raw = cast(object, json.loads(path.read_text(encoding="utf-8")))
    if not isinstance(raw, dict):
        raise ValueError(f"Expected JSON object at {path}")
    return cast(dict[str, object], raw)


def _endpoint_tuples(entries: list[object], *, field: str) -> list[tuple[str, str]]:
    tuples: list[tuple[str, str]] = []
    for item_any in entries:
        if not isinstance(item_any, dict):
            raise ValueError(f"{field} entry must be an object")
        item = cast(dict[str, object], item_any)
        endpoint_type = item.get("type")
        endpoint_value = item.get("value")
        if not isinstance(endpoint_type, str) or not endpoint_type:
            raise ValueError(f"{field} entry has invalid type")
        if not isinstance(endpoint_value, str) or not endpoint_value:
            raise ValueError(f"{field} entry has invalid value")
        tuples.append((endpoint_type, endpoint_value))
    if tuples != sorted(tuples, key=lambda x: (x[0], x[1])):
        raise ValueError(f"{field} must be sorted deterministically")
    if len(set(tuples)) != len(tuples):
        raise ValueError(f"{field} must not contain duplicates")
    return tuples


def _validate_fixture(payload: dict[str, object]) -> dict[str, object]:
    if payload.get("schema_version") != 1:
        raise ValueError("benchmark fixture schema_version must be 1")
    source = payload.get("source")
    if not isinstance(source, str) or not source:
        raise ValueError("benchmark fixture source must be a non-empty string")

    categories_any = payload.get("categories")
    if not isinstance(categories_any, list) or not categories_any:
        raise ValueError("benchmark fixture categories must be a non-empty list")
    categories = cast(list[object], categories_any)
    for category_any in categories:
        if not isinstance(category_any, dict):
            raise ValueError("category entry must be an object")
        category = cast(dict[str, object], category_any)
        name = category.get("name")
        refs_any = category.get("refs")
        if not isinstance(name, str) or not name:
            raise ValueError("category name must be non-empty string")
        if not isinstance(refs_any, list) or not refs_any:
            raise ValueError("category refs must be a non-empty list")
        refs_list = cast(list[object], refs_any)
        refs = [ref for ref in refs_list if isinstance(ref, str)]
        if len(refs) != len(refs_list):
            raise ValueError("category refs entries must be strings")

    labels_any = payload.get("labels")
    if not isinstance(labels_any, dict):
        raise ValueError("benchmark fixture labels must be an object")
    labels = cast(dict[str, object], labels_any)

    positive_any = labels.get("positive")
    negative_any = labels.get("negative")
    if not isinstance(positive_any, dict):
        raise ValueError("positive labels must be an object")
    if not isinstance(negative_any, dict):
        raise ValueError("negative labels must be an object")

    positive = cast(dict[str, object], positive_any)
    negative = cast(dict[str, object], negative_any)

    endpoint_candidates_any = positive.get("endpoint_candidates")
    promotion_labels_any = positive.get("promotion_labels")
    if not isinstance(endpoint_candidates_any, list) or not endpoint_candidates_any:
        raise ValueError("positive endpoint_candidates must be a non-empty list")
    if not isinstance(promotion_labels_any, list):
        raise ValueError("positive promotion_labels must be a list")

    endpoint_candidates = _endpoint_tuples(
        cast(list[object], endpoint_candidates_any),
        field="endpoint_candidates",
    )
    promotion_labels = _endpoint_tuples(
        cast(list[object], promotion_labels_any),
        field="promotion_labels",
    )

    candidate_set = set(endpoint_candidates)
    if any(label not in candidate_set for label in promotion_labels):
        raise ValueError("promotion_labels must be a subset of endpoint_candidates")

    noise_tokens_any = negative.get("noise_tokens")
    if not isinstance(noise_tokens_any, list) or not noise_tokens_any:
        raise ValueError("negative noise_tokens must be a non-empty list")
    noise_tokens_list = cast(list[object], noise_tokens_any)
    noise_tokens = [token for token in noise_tokens_list if isinstance(token, str)]
    if len(noise_tokens) != len(noise_tokens_list):
        raise ValueError("noise_tokens entries must be strings")
    if noise_tokens != sorted(noise_tokens):
        raise ValueError("noise_tokens must be sorted deterministically")

    return payload


def _validate_metrics_baseline(payload: dict[str, object]) -> dict[str, object]:
    if payload.get("schema_version") != 1:
        raise ValueError("metrics baseline schema_version must be 1")
    fixture = payload.get("fixture")
    if fixture != "tests/fixtures/attack_surface_accuracy/benchmark_fixture.json":
        raise ValueError("metrics baseline fixture path is invalid")

    metrics_any = payload.get("metrics")
    if not isinstance(metrics_any, dict):
        raise ValueError("metrics must be an object")
    metrics = cast(dict[str, object], metrics_any)

    expected_metric_keys = {
        "duplicate_ratio",
        "promotion_precision",
        "promotion_recall",
        "static_only_ratio",
        "taxonomy_precision",
        "taxonomy_recall",
    }
    if set(metrics.keys()) != expected_metric_keys:
        raise ValueError("metrics keys do not match benchmark contract")
    for key in sorted(expected_metric_keys):
        value = metrics.get(key)
        if not isinstance(value, (int, float)):
            raise ValueError(f"metric {key} must be numeric")
        if not 0.0 <= float(value) <= 1.0:
            raise ValueError(f"metric {key} must be in [0.0, 1.0]")

    calibration_any = payload.get("calibration")
    if not isinstance(calibration_any, dict):
        raise ValueError("calibration must be an object")
    calibration = cast(dict[str, object], calibration_any)
    if calibration.get("mode") != "rule_based":
        raise ValueError("calibration mode must be rule_based")
    if calibration.get("dataset") != "benchmark_fixture_labels":
        raise ValueError("calibration dataset must be benchmark_fixture_labels")
    if calibration.get("supports_probability_calibration") is not False:
        raise ValueError("supports_probability_calibration must be false")

    return payload


def load_attack_surface_benchmark_fixture() -> dict[str, object]:
    return _validate_fixture(_load_json_object(_BENCHMARK_FIXTURE_PATH))


def load_attack_surface_metrics_baseline() -> dict[str, object]:
    return _validate_metrics_baseline(_load_json_object(_METRICS_BASELINE_PATH))


def serialize_metrics_snapshot(payload: dict[str, object]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
