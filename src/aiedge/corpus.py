from __future__ import annotations

import json
from pathlib import Path
from typing import cast

_ALLOWED_SPLITS = ("dev", "eval", "holdout")


class CorpusValidationError(ValueError):
    def __init__(self, token: str, message: str) -> None:
        super().__init__(message)
        self.token: str = token


def _invalid_sample(index: int, message: str) -> CorpusValidationError:
    return CorpusValidationError(
        "CORPUS_INVALID_SAMPLE",
        f"sample[{index}] {message}",
    )


def load_corpus_manifest(path: Path) -> dict[str, object]:
    payload_any = cast(object, json.loads(path.read_text(encoding="utf-8")))
    if not isinstance(payload_any, dict):
        raise CorpusValidationError(
            "CORPUS_INVALID_SAMPLE", "manifest must be an object"
        )
    payload = cast(dict[str, object], payload_any)
    _validate_manifest(payload)
    return payload


def _validate_manifest(payload: dict[str, object]) -> None:
    corpus_id = payload.get("corpus_id")
    version = payload.get("version")
    samples_any = payload.get("samples")

    if not isinstance(corpus_id, str) or not corpus_id.strip():
        raise CorpusValidationError(
            "CORPUS_INVALID_SAMPLE", "corpus_id must be a non-empty string"
        )
    if not isinstance(version, str) or not version.strip():
        raise CorpusValidationError(
            "CORPUS_INVALID_SAMPLE", "version must be a non-empty string"
        )
    if not isinstance(samples_any, list):
        raise CorpusValidationError("CORPUS_INVALID_SAMPLE", "samples must be a list")

    samples = cast(list[object], samples_any)
    seen_id_split: dict[str, str] = {}
    seen_path_split: dict[str, str] = {}

    for idx, sample_any in enumerate(samples):
        if not isinstance(sample_any, dict):
            raise _invalid_sample(idx, "must be an object")
        sample = cast(dict[str, object], sample_any)

        sample_id = sample.get("id")
        sample_path = sample.get("path")
        split = sample.get("split")
        labels_any = sample.get("labels")
        license_name = sample.get("license")
        notes = sample.get("notes")

        if not isinstance(sample_id, str) or not sample_id.strip():
            raise _invalid_sample(idx, "id must be a non-empty string")
        if not isinstance(sample_path, str) or not sample_path.strip():
            raise _invalid_sample(idx, "path must be a non-empty string")
        if Path(sample_path).is_absolute():
            raise _invalid_sample(idx, "path must be repository-relative")
        if not isinstance(split, str) or split not in _ALLOWED_SPLITS:
            raise _invalid_sample(
                idx,
                "split must be one of dev/eval/holdout",
            )
        if not isinstance(labels_any, list):
            raise _invalid_sample(idx, "labels must be a list")
        labels = cast(list[object], labels_any)
        if not labels:
            raise _invalid_sample(idx, "labels must be a non-empty list")
        for label in labels:
            if not isinstance(label, str) or not label.strip():
                raise _invalid_sample(idx, "labels entries must be non-empty strings")
        if not isinstance(license_name, str) or not license_name.strip():
            raise _invalid_sample(idx, "license must be a non-empty string")
        if notes is not None and not isinstance(notes, str):
            raise _invalid_sample(idx, "notes must be a string when provided")

        prior_id_split = seen_id_split.get(sample_id)
        if prior_id_split is not None:
            if prior_id_split != split:
                raise CorpusValidationError(
                    "CORPUS_SPLIT_LEAKAGE",
                    f"sample id {sample_id!r} appears in multiple splits: {prior_id_split!r} and {split!r}",
                )
            raise CorpusValidationError(
                "CORPUS_DUPLICATE_ID",
                f"sample id {sample_id!r} is duplicated",
            )
        seen_id_split[sample_id] = split

        prior_path_split = seen_path_split.get(sample_path)
        if prior_path_split is not None:
            raise CorpusValidationError(
                "CORPUS_SPLIT_LEAKAGE",
                f"sample path {sample_path!r} appears in multiple records: {prior_path_split!r} and {split!r}",
            )
        seen_path_split[sample_path] = split


def corpus_summary(payload: dict[str, object]) -> dict[str, object]:
    samples_any = payload.get("samples")
    if not isinstance(samples_any, list):
        raise CorpusValidationError("CORPUS_INVALID_SAMPLE", "samples must be a list")
    samples = cast(list[object], samples_any)

    counts_by_split: dict[str, int] = {split: 0 for split in _ALLOWED_SPLITS}
    labels_by_split: dict[str, dict[str, int]] = {
        split: {} for split in _ALLOWED_SPLITS
    }

    for sample_any in samples:
        sample = cast(dict[str, object], sample_any)
        split = cast(str, sample["split"])
        labels = cast(list[object], sample["labels"])
        counts_by_split[split] += 1
        for label_any in labels:
            label = cast(str, label_any)
            split_counts = labels_by_split[split]
            split_counts[label] = split_counts.get(label, 0) + 1

    ordered_labels_by_split: dict[str, dict[str, int]] = {}
    for split in _ALLOWED_SPLITS:
        counts = labels_by_split[split]
        ordered_labels_by_split[split] = {
            key: counts[key] for key in sorted(counts.keys())
        }

    return {
        "corpus_id": cast(str, payload["corpus_id"]),
        "summary": {
            "counts_by_split": counts_by_split,
            "counts_by_label_per_split": ordered_labels_by_split,
            "total_samples": len(samples),
        },
        "version": cast(str, payload["version"]),
    }


def format_summary(summary: dict[str, object]) -> str:
    return json.dumps(summary, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
