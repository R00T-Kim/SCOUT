from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aiedge.__main__ import main


def _write_json(path: Path, payload: dict[str, object]) -> None:
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _manifest_with_predictions() -> dict[str, object]:
    return {
        "corpus_id": "quality-metrics-test",
        "version": "1.0.0",
        "samples": [
            {
                "id": "sample-attack",
                "path": "tests/fixtures/attack_surface_accuracy/benchmark_fixture.json",
                "split": "dev",
                "labels": ["attack_surface"],
                "predicted_labels": ["attack_surface"],
                "license": "MIT",
            },
            {
                "id": "sample-metrics",
                "path": "tests/fixtures/attack_surface_accuracy/metrics_baseline.json",
                "split": "eval",
                "labels": ["metrics"],
                "predicted_labels": ["taxonomy"],
                "license": "MIT",
            },
            {
                "id": "sample-reference",
                "path": "ref.md",
                "split": "holdout",
                "labels": ["reference_context"],
                "predicted_labels": ["__unknown__"],
                "license": "Internal",
            },
            {
                "id": "sample-taxonomy",
                "path": "tests/fixtures/attack_surface_accuracy/taxonomy_marker.json",
                "split": "dev",
                "labels": ["taxonomy"],
                "predicted_labels": ["__abstain__"],
                "license": "MIT",
            },
        ],
    }


def _base_sample(*, sample_id: str, labels: list[str]) -> dict[str, object]:
    return {
        "id": sample_id,
        "path": f"fixtures/{sample_id}.json",
        "split": "dev",
        "labels": labels,
        "license": "MIT",
    }


def test_quality_metrics_harness_emits_deterministic_report(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    _write_json(manifest_path, _manifest_with_predictions())
    out_path = tmp_path / "metrics.json"

    rc_first = main(["quality-metrics", "--manifest", str(manifest_path)])
    first = capsys.readouterr()
    file_first = out_path.read_text(encoding="utf-8")
    rc_second = main(["quality-metrics", "--manifest", str(manifest_path)])
    second = capsys.readouterr()
    file_second = out_path.read_text(encoding="utf-8")

    assert rc_first == 0
    assert rc_second == 0
    assert first.err == ""
    assert second.err == ""
    assert first.out == second.out
    assert out_path.is_file()
    assert file_first == file_second
    assert first.out == file_first

    payload_any = cast(object, json.loads(first.out))
    assert isinstance(payload_any, dict)
    payload = cast(dict[str, object], payload_any)

    assert payload["corpus_id"] == "quality-metrics-test"
    assert payload["manifest"] == str(manifest_path)
    assert payload["version"] == "1.0.0"
    assert payload["sample_count"] == 4
    assert payload["abstain_count"] == 1
    assert payload["abstain_rate"] == 0.25
    assert payload["unknown_count"] == 1
    assert payload["unknown_sample_count"] == 1

    taxonomy = cast(list[object], payload["taxonomy"])
    assert taxonomy == ["attack_surface", "metrics", "reference_context", "taxonomy"]

    overall = cast(dict[str, object], payload["overall"])
    assert overall == {
        "precision": 0.5,
        "recall": 0.25,
        "f1": 0.333333,
        "fpr": 0.083333,
        "fnr": 0.75,
    }

    per_class = cast(dict[str, object], payload["per_class"])
    attack_surface = cast(dict[str, object], per_class["attack_surface"])
    taxonomy_class = cast(dict[str, object], per_class["taxonomy"])
    assert attack_surface == {
        "precision": 1.0,
        "recall": 1.0,
        "f1": 1.0,
        "fpr": 0.0,
        "fnr": 0.0,
    }
    assert taxonomy_class == {
        "precision": 0.0,
        "recall": 0.0,
        "f1": 0.0,
        "fpr": 0.333333,
        "fnr": 1.0,
    }


def test_quality_metrics_harness_supports_baseline_delta(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    manifest_path = tmp_path / "manifest.json"
    _write_json(manifest_path, _manifest_with_predictions())
    baseline_path = tmp_path / "baseline.json"
    out_path = tmp_path / "custom.metrics.json"
    delta_out_path = tmp_path / "custom.metrics.delta.json"
    _write_json(
        baseline_path,
        {
            "overall": {
                "precision": 1.0,
                "recall": 1.0,
                "f1": 1.0,
                "fpr": 0.0,
                "fnr": 0.0,
            },
            "per_class": {
                "attack_surface": {
                    "precision": 1.0,
                    "recall": 1.0,
                    "f1": 1.0,
                    "fpr": 0.0,
                    "fnr": 0.0,
                },
                "metrics": {
                    "precision": 1.0,
                    "recall": 1.0,
                    "f1": 1.0,
                    "fpr": 0.0,
                    "fnr": 0.0,
                },
                "reference_context": {
                    "precision": 1.0,
                    "recall": 1.0,
                    "f1": 1.0,
                    "fpr": 0.0,
                    "fnr": 0.0,
                },
                "taxonomy": {
                    "precision": 1.0,
                    "recall": 1.0,
                    "f1": 1.0,
                    "fpr": 0.0,
                    "fnr": 0.0,
                },
            },
        },
    )

    rc = main(
        [
            "quality-metrics",
            "--manifest",
            str(manifest_path),
            "--baseline",
            str(baseline_path),
            "--out",
            str(out_path),
            "--delta-out",
            str(delta_out_path),
            "--max-regression",
            "0.2",
        ]
    )
    captured = capsys.readouterr()
    metrics_first = out_path.read_text(encoding="utf-8")
    delta_first = delta_out_path.read_text(encoding="utf-8")

    rc_repeat = main(
        [
            "quality-metrics",
            "--manifest",
            str(manifest_path),
            "--baseline",
            str(baseline_path),
            "--out",
            str(out_path),
            "--delta-out",
            str(delta_out_path),
            "--max-regression",
            "0.2",
        ]
    )
    captured_repeat = capsys.readouterr()
    metrics_second = out_path.read_text(encoding="utf-8")
    delta_second = delta_out_path.read_text(encoding="utf-8")

    assert rc == 0
    assert rc_repeat == 0
    assert out_path.is_file()
    assert delta_out_path.is_file()
    assert captured.err == ""
    assert captured_repeat.err == ""
    assert captured.out == captured_repeat.out
    assert metrics_first == metrics_second
    assert delta_first == delta_second

    payload = cast(dict[str, object], json.loads(captured.out))
    assert payload == cast(dict[str, object], json.loads(metrics_first))

    delta_payload = cast(dict[str, object], json.loads(delta_first))
    assert delta_payload["baseline"] == str(baseline_path)
    assert delta_payload["manifest"] == str(manifest_path)
    assert delta_payload["max_regression"] == 0.2

    delta = cast(dict[str, object], delta_payload["delta"])
    overall_delta = cast(dict[str, object], delta["overall"])
    assert overall_delta == {
        "precision": -0.5,
        "recall": -0.75,
        "f1": -0.666667,
        "fpr": 0.083333,
        "fnr": 0.75,
    }

    regressions = cast(dict[str, object], delta_payload["regressions"])
    assert regressions["threshold"] == 0.2
    assert regressions["has_regressions"] is True
    assert int(cast(int, regressions["count"])) > 0
    overall_regressions = cast(list[object], regressions["overall"])
    first_regression = cast(dict[str, object], overall_regressions[0])
    assert first_regression["metric"] == "precision"
    assert first_regression["regression"] == 0.5


def test_quality_metrics_harness_fails_closed_on_invalid_label(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = _manifest_with_predictions()
    samples = cast(list[object], payload["samples"])
    malformed = cast(dict[str, object], samples[0]).copy()
    malformed["labels"] = ["attack_surface", "new_unapproved_label"]
    samples[0] = malformed

    manifest_path = tmp_path / "manifest.json"
    _write_json(manifest_path, payload)

    rc = main(["quality-metrics", "--manifest", str(manifest_path)])
    captured = capsys.readouterr()

    assert rc != 0
    assert captured.out == ""
    err = cast(dict[str, object], json.loads(captured.err))
    assert err["error_token"] == "QUALITY_METRICS_INVALID_LABEL"
    assert "sample-attack" in cast(str, err["message"])


def test_quality_metrics_harness_uses_explicit_abstain_and_unknown_markers(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    sample_missing = _base_sample(sample_id="sample-missing", labels=["attack_surface"])

    sample_empty = _base_sample(sample_id="sample-empty", labels=["metrics"])
    sample_empty["predicted_labels"] = []

    sample_abstain = _base_sample(
        sample_id="sample-abstain", labels=["reference_context"]
    )
    sample_abstain["predicted_labels"] = ["__abstain__"]

    sample_unknown = _base_sample(sample_id="sample-unknown", labels=["taxonomy"])
    sample_unknown["predicted_labels"] = ["__unknown__"]

    manifest_path = tmp_path / "manifest.json"
    _write_json(
        manifest_path,
        {
            "corpus_id": "quality-metrics-explicit-markers",
            "version": "1.0.0",
            "samples": [sample_missing, sample_empty, sample_abstain, sample_unknown],
        },
    )

    rc = main(["quality-metrics", "--manifest", str(manifest_path)])
    captured = capsys.readouterr()

    assert rc == 0
    assert captured.err == ""

    payload = cast(dict[str, object], json.loads(captured.out))
    assert payload["sample_count"] == 4
    assert payload["abstain_count"] == 1
    assert payload["abstain_rate"] == 0.25
    assert payload["unknown_count"] == 1
    assert payload["unknown_sample_count"] == 1
