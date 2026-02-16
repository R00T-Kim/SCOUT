from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest

from aiedge.__main__ import main


def _write_manifest(path: Path, payload: dict[str, object]) -> None:
    _ = path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def _valid_manifest() -> dict[str, object]:
    return {
        "corpus_id": "test-corpus",
        "version": "1.0.0",
        "samples": [
            {
                "id": "sample-dev",
                "path": "tests/fixtures/attack_surface_accuracy/benchmark_fixture.json",
                "split": "dev",
                "labels": ["attack_surface", "taxonomy"],
                "license": "MIT",
            },
            {
                "id": "sample-eval",
                "path": "tests/fixtures/attack_surface_accuracy/metrics_baseline.json",
                "split": "eval",
                "labels": ["attack_surface", "metrics"],
                "license": "MIT",
            },
            {
                "id": "sample-holdout",
                "path": "ref.md",
                "split": "holdout",
                "labels": ["reference_context"],
                "license": "Internal",
            },
        ],
    }


def test_corpus_validate_succeeds_and_outputs_deterministic_summary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, _valid_manifest())

    rc_first = main(["corpus-validate", "--manifest", str(manifest_path)])
    first = capsys.readouterr()
    rc_second = main(["corpus-validate", "--manifest", str(manifest_path)])
    second = capsys.readouterr()

    assert rc_first == 0
    assert rc_second == 0
    assert first.err == ""
    assert second.err == ""
    assert first.out == second.out

    payload_any = cast(object, json.loads(first.out))
    assert isinstance(payload_any, dict)
    payload = cast(dict[str, object], payload_any)
    assert list(payload.keys()) == ["corpus_id", "summary", "version"]

    summary = cast(dict[str, object], payload["summary"])
    assert summary["counts_by_split"] == {"dev": 1, "eval": 1, "holdout": 1}

    labels_by_split = cast(dict[str, object], summary["counts_by_label_per_split"])
    dev_labels = cast(dict[str, object], labels_by_split["dev"])
    assert list(dev_labels.keys()) == ["attack_surface", "taxonomy"]


def test_corpus_validate_fails_with_duplicate_id_token(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = _valid_manifest()
    samples = cast(list[object], payload["samples"])
    duplicate = cast(dict[str, object], samples[1]).copy()
    duplicate["id"] = "sample-dev"
    duplicate["split"] = "dev"
    duplicate["path"] = (
        "tests/fixtures/attack_surface_accuracy/metrics_baseline_alt.json"
    )
    samples[1] = duplicate

    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, payload)

    rc = main(["corpus-validate", "--manifest", str(manifest_path)])
    captured = capsys.readouterr()

    assert rc != 0
    err_any = cast(object, json.loads(captured.err))
    assert isinstance(err_any, dict)
    err = cast(dict[str, object], err_any)
    assert err["error_token"] == "CORPUS_DUPLICATE_ID"


def test_corpus_validate_fails_with_split_leakage_token(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = _valid_manifest()
    samples = cast(list[object], payload["samples"])
    leaked = cast(dict[str, object], samples[1]).copy()
    leaked["path"] = "tests/fixtures/attack_surface_accuracy/benchmark_fixture.json"
    samples[1] = leaked

    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, payload)

    rc = main(["corpus-validate", "--manifest", str(manifest_path)])
    captured = capsys.readouterr()

    assert rc != 0
    err_any = cast(object, json.loads(captured.err))
    assert isinstance(err_any, dict)
    err = cast(dict[str, object], err_any)
    assert err["error_token"] == "CORPUS_SPLIT_LEAKAGE"


def test_corpus_validate_fails_with_invalid_sample_token(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    payload = _valid_manifest()
    samples = cast(list[object], payload["samples"])
    malformed = cast(dict[str, object], samples[0]).copy()
    malformed["labels"] = "attack_surface"
    samples[0] = malformed

    manifest_path = tmp_path / "manifest.json"
    _write_manifest(manifest_path, payload)

    rc = main(["corpus-validate", "--manifest", str(manifest_path)])
    captured = capsys.readouterr()

    assert rc != 0
    err_any = cast(object, json.loads(captured.err))
    assert isinstance(err_any, dict)
    err = cast(dict[str, object], err_any)
    assert err["error_token"] == "CORPUS_INVALID_SAMPLE"
