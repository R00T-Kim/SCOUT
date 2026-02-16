from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .policy import AIEdgePolicyViolation
from .schema import JsonValue
from .stage import StageContext, StageOutcome, StageStatus


def _assert_under_dir(base_dir: Path, target: Path) -> None:
    base = base_dir.resolve()
    resolved = target.resolve()
    if not resolved.is_relative_to(base):
        raise AIEdgePolicyViolation(
            f"Refusing to write outside run dir: target={resolved} base={base}"
        )


def _rel_to_run_dir(run_dir: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(run_dir.resolve()))
    except Exception:
        return str(path)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _firmware_obj(run_dir: Path, path: Path) -> dict[str, JsonValue]:
    digest = _sha256_file(path)
    return {
        "id": f"firmware:{digest}",
        "path": _rel_to_run_dir(run_dir, path),
        "sha256": digest,
        "size_bytes": int(path.stat().st_size),
    }


def _write_json(path: Path, obj: dict[str, JsonValue]) -> None:
    payload = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    _ = path.write_text(payload, encoding="utf-8")


@dataclass(frozen=True)
class FirmwareLineageStage:
    @property
    def name(self) -> str:
        return "firmware_lineage"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "firmware_lineage"
        lineage_path = stage_dir / "lineage.json"
        lineage_diff_path = stage_dir / "lineage_diff.json"
        firmware_path = run_dir / "input" / "firmware.bin"
        neighbor_path = run_dir / "input" / "neighbor_firmware.bin"

        _assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, lineage_path)
        _assert_under_dir(stage_dir, lineage_diff_path)

        limitations: list[str] = []

        if not firmware_path.is_file():
            limitations.append("firmware input missing: input/firmware.bin")
            failed_diff: dict[str, JsonValue] = {
                "schema_version": 1,
                "pair": {"firmware_sha256": None, "neighbor_sha256": None},
                "diff_summary": {"same_sha256": False, "size_delta_bytes": None},
                "limitations": cast(list[JsonValue], cast(list[object], limitations)),
            }
            failed_lineage: dict[str, JsonValue] = {
                "schema_version": 1,
                "firmware": None,
                "neighbor": None,
                "neighbor_reason": "missing primary firmware input",
                "limitations": cast(list[JsonValue], cast(list[object], limitations)),
                "evidence_refs": cast(
                    list[JsonValue],
                    cast(
                        list[object],
                        [
                            _rel_to_run_dir(run_dir, lineage_path),
                            _rel_to_run_dir(run_dir, lineage_diff_path),
                        ],
                    ),
                ),
            }
            _write_json(lineage_path, failed_lineage)
            _write_json(lineage_diff_path, failed_diff)
            failed_details: dict[str, JsonValue] = {
                "lineage": _rel_to_run_dir(run_dir, lineage_path),
                "lineage_diff": _rel_to_run_dir(run_dir, lineage_diff_path),
                "evidence": cast(
                    list[JsonValue],
                    cast(
                        list[object],
                        [
                            {"path": _rel_to_run_dir(run_dir, lineage_path)},
                            {"path": _rel_to_run_dir(run_dir, lineage_diff_path)},
                        ],
                    ),
                ),
                "limitations": cast(list[JsonValue], cast(list[object], limitations)),
            }
            return StageOutcome(
                status="failed", details=failed_details, limitations=limitations
            )

        firmware_obj = _firmware_obj(run_dir, firmware_path)
        neighbor_obj: dict[str, JsonValue] | None = None
        neighbor_reason: str | None = None

        if neighbor_path.is_file():
            neighbor_obj = _firmware_obj(run_dir, neighbor_path)
        else:
            neighbor_reason = "adjacent candidate missing: input/neighbor_firmware.bin"
            limitations.append(neighbor_reason)

        nodes: list[dict[str, JsonValue]] = [
            {
                "id": cast(str, firmware_obj["id"]),
                "kind": "firmware",
                "path": cast(str, firmware_obj["path"]),
                "sha256": cast(str, firmware_obj["sha256"]),
                "size_bytes": cast(int, firmware_obj["size_bytes"]),
            }
        ]
        edges: list[dict[str, JsonValue]] = []
        if neighbor_obj is not None:
            nodes.append(
                {
                    "id": cast(str, neighbor_obj["id"]),
                    "kind": "neighbor",
                    "path": cast(str, neighbor_obj["path"]),
                    "sha256": cast(str, neighbor_obj["sha256"]),
                    "size_bytes": cast(int, neighbor_obj["size_bytes"]),
                }
            )
            edge_id = f"adjacent:{cast(str, firmware_obj['sha256'])}:{cast(str, neighbor_obj['sha256'])}"
            edges.append(
                {
                    "id": edge_id,
                    "src": cast(str, firmware_obj["id"]),
                    "dst": cast(str, neighbor_obj["id"]),
                    "relation": "adjacent_version",
                }
            )

        lineage: dict[str, JsonValue] = {
            "schema_version": 1,
            "firmware": firmware_obj,
            "neighbor": cast(JsonValue, neighbor_obj),
            "neighbor_reason": neighbor_reason,
            "nodes": cast(list[JsonValue], cast(list[object], nodes)),
            "edges": cast(list[JsonValue], cast(list[object], edges)),
            "limitations": cast(list[JsonValue], cast(list[object], limitations)),
            "evidence_refs": cast(
                list[JsonValue],
                cast(
                    list[object],
                    [
                        _rel_to_run_dir(run_dir, lineage_path),
                        _rel_to_run_dir(run_dir, lineage_diff_path),
                        _rel_to_run_dir(run_dir, firmware_path),
                    ],
                ),
            ),
        }
        if neighbor_obj is not None:
            evidence_refs = cast(list[JsonValue], lineage["evidence_refs"])
            evidence_refs.append(_rel_to_run_dir(run_dir, neighbor_path))

        neighbor_sha = (
            cast(str, neighbor_obj["sha256"]) if neighbor_obj is not None else None
        )
        size_delta: int | None = None
        if neighbor_obj is not None:
            size_delta = cast(int, firmware_obj["size_bytes"]) - cast(
                int, neighbor_obj["size_bytes"]
            )
        same_sha256 = False
        if neighbor_obj is not None:
            same_sha256 = cast(str, firmware_obj["sha256"]) == cast(
                str, neighbor_obj["sha256"]
            )

        diff_limitations = list(limitations)
        lineage_diff: dict[str, JsonValue] = {
            "schema_version": 1,
            "pair": {
                "firmware_sha256": cast(str, firmware_obj["sha256"]),
                "neighbor_sha256": neighbor_sha,
            },
            "diff_summary": {
                "same_sha256": same_sha256,
                "size_delta_bytes": size_delta,
            },
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(diff_limitations)))
            ),
        }

        _write_json(lineage_path, lineage)
        _write_json(lineage_diff_path, lineage_diff)

        evidence = [
            {"path": _rel_to_run_dir(run_dir, lineage_path)},
            {"path": _rel_to_run_dir(run_dir, lineage_diff_path)},
            {"path": _rel_to_run_dir(run_dir, firmware_path)},
        ]
        if neighbor_obj is not None:
            evidence.append({"path": _rel_to_run_dir(run_dir, neighbor_path)})

        status: StageStatus = "ok" if neighbor_obj is not None else "partial"
        details: dict[str, JsonValue] = {
            "lineage": _rel_to_run_dir(run_dir, lineage_path),
            "lineage_diff": _rel_to_run_dir(run_dir, lineage_diff_path),
            "firmware": firmware_obj,
            "neighbor": cast(JsonValue, neighbor_obj),
            "neighbor_reason": neighbor_reason,
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limitations)))
            ),
            "evidence": cast(list[JsonValue], cast(list[object], evidence)),
        }
        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limitations)),
        )
