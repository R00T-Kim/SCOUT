from __future__ import annotations

import json
import os
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


def _safe_text_read(path: Path, *, max_bytes: int = 64 * 1024) -> str:
    try:
        data = path.read_bytes()
    except Exception:
        return ""
    if not data:
        return ""
    data = data[:max_bytes]
    try:
        return data.decode("utf-8", errors="replace")
    except Exception:
        return ""


def _clamp01(v: float) -> float:
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return float(v)


def _load_inventory_roots(
    run_dir: Path,
) -> tuple[list[Path], list[str], bool, Path | None]:
    inv_path = run_dir / "stages" / "inventory" / "inventory.json"
    if not inv_path.is_file():
        return (
            [],
            ["Inventory output missing: stages/inventory/inventory.json"],
            False,
            None,
        )

    try:
        inv_any = cast(object, json.loads(inv_path.read_text(encoding="utf-8")))
    except Exception as exc:
        return (
            [],
            [f"Inventory output unreadable: {type(exc).__name__}: {exc}"],
            True,
            inv_path,
        )
    if not isinstance(inv_any, dict):
        return (
            [],
            ["Inventory output shape invalid; expected JSON object"],
            True,
            inv_path,
        )

    inv = cast(dict[str, object], inv_any)
    roots_any = inv.get("roots")
    roots: list[Path] = []
    limits: list[str] = []
    if isinstance(roots_any, list):
        for item in cast(list[object], roots_any):
            if not isinstance(item, str) or not item or item.startswith("/"):
                continue
            p = (run_dir / item).resolve()
            if not p.is_relative_to(run_dir.resolve()):
                continue
            if p.is_dir():
                roots.append(p)

    extracted_dir: Path | None = None
    ext_any = inv.get("extracted_dir")
    if isinstance(ext_any, str) and ext_any and not ext_any.startswith("/"):
        extracted_dir_candidate = (run_dir / ext_any).resolve()
        if extracted_dir_candidate.is_relative_to(run_dir.resolve()):
            extracted_dir = extracted_dir_candidate

    if not roots:
        if isinstance(extracted_dir, Path) and extracted_dir.is_dir():
            roots.append(extracted_dir)
            limits.append(
                "Inventory roots unavailable; attribution fell back to inventory extracted_dir"
            )
        else:
            limits.append("Inventory roots unavailable for attribution")

    unique_roots: list[Path] = []
    seen: set[str] = set()
    for root in sorted(roots, key=lambda p: str(p)):
        key = str(root.resolve())
        if key in seen:
            continue
        seen.add(key)
        unique_roots.append(root)

    return unique_roots, limits, True, inv_path


def _iter_candidate_files(roots: list[Path], *, max_files: int = 2000) -> list[Path]:
    out: list[Path] = []
    seen: set[str] = set()
    stack = sorted(roots, key=lambda p: str(p), reverse=True)

    while stack and len(out) < max_files:
        current = stack.pop()
        try:
            with os.scandir(current) as it:
                entries = sorted(list(it), key=lambda e: e.name)
        except OSError:
            continue

        child_dirs: list[Path] = []
        for entry in entries:
            p = Path(entry.path)
            try:
                if entry.is_dir(follow_symlinks=False):
                    child_dirs.append(p)
                    continue
            except OSError:
                continue

            try:
                if not entry.is_file(follow_symlinks=True):
                    continue
            except OSError:
                continue

            key = str(p.resolve())
            if key in seen:
                continue
            seen.add(key)
            out.append(p)
            if len(out) >= max_files:
                break

        stack.extend(reversed(child_dirs))

    return out


def _strip_os_release_value(v: str) -> str:
    s = v.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ('"', "'"):
        s = s[1:-1]
    return s.strip()


def _parse_key_value_lines(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        key = k.strip()
        if not key:
            continue
        out[key] = _strip_os_release_value(v)
    return out


def _looks_like_version_path(rel: str) -> bool:
    rel_low = rel.lower()
    name = rel_low.split("/")[-1]
    if "version" in name:
        return True
    return name in {"issue", "os-release"}


def _claim(
    *,
    claim_type: str,
    value: str,
    confidence: float,
    evidence_refs: list[str],
    alternatives_considered: list[str] | None = None,
) -> dict[str, JsonValue] | None:
    val = value.strip()
    refs = [
        x for x in evidence_refs if isinstance(x, str) and x and not x.startswith("/")
    ]
    if not val or not refs:
        return None
    obj: dict[str, JsonValue] = {
        "claim_type": claim_type,
        "value": val,
        "confidence": _clamp01(confidence),
        "evidence_refs": cast(list[JsonValue], list(sorted(set(refs)))),
    }
    if alternatives_considered:
        alts = [x for x in alternatives_considered if isinstance(x, str) and x]
        if alts:
            obj["alternatives_considered"] = cast(list[JsonValue], sorted(set(alts)))
    return obj


@dataclass(frozen=True)
class AttributionStage:
    max_scan_files: int = 2000
    max_version_like_files: int = 16

    @property
    def name(self) -> str:
        return "attribution"

    def run(self, ctx: StageContext) -> StageOutcome:
        run_dir = ctx.run_dir
        stage_dir = run_dir / "stages" / "attribution"
        out_json = stage_dir / "attribution.json"

        _assert_under_dir(run_dir, stage_dir)
        stage_dir.mkdir(parents=True, exist_ok=True)
        _assert_under_dir(stage_dir, out_json)

        roots, limits, inventory_present, inventory_path = _load_inventory_roots(
            run_dir
        )
        if inventory_path is not None:
            inventory_rel = _rel_to_run_dir(run_dir, inventory_path)
        else:
            inventory_rel = "stages/inventory/inventory.json"

        extraction_stage_manifest = run_dir / "stages" / "extraction" / "stage.json"
        extraction_present = extraction_stage_manifest.is_file()
        if not extraction_present:
            limits.append("Extraction manifest missing: stages/extraction/stage.json")

        claims: list[dict[str, JsonValue]] = []
        evidence_refs: set[str] = set()
        files = _iter_candidate_files(roots, max_files=int(self.max_scan_files))

        build_prop_files: list[Path] = []
        os_release_files: list[Path] = []
        etc_version_files: list[Path] = []
        etc_issue_files: list[Path] = []
        version_like_files: list[Path] = []

        for p in files:
            rel = _rel_to_run_dir(run_dir, p).replace("\\", "/")
            rel_low = rel.lower()
            name_low = p.name.lower()
            if name_low == "build.prop":
                build_prop_files.append(p)
                continue
            if rel_low.endswith("/etc/os-release"):
                os_release_files.append(p)
                continue
            if rel_low.endswith("/etc/version"):
                etc_version_files.append(p)
                continue
            if rel_low.endswith("/etc/issue"):
                etc_issue_files.append(p)
                continue
            if _looks_like_version_path(rel):
                version_like_files.append(p)

        build_prop_files = sorted(
            build_prop_files, key=lambda p: _rel_to_run_dir(run_dir, p)
        )
        os_release_files = sorted(
            os_release_files, key=lambda p: _rel_to_run_dir(run_dir, p)
        )
        etc_version_files = sorted(
            etc_version_files, key=lambda p: _rel_to_run_dir(run_dir, p)
        )
        etc_issue_files = sorted(
            etc_issue_files, key=lambda p: _rel_to_run_dir(run_dir, p)
        )
        version_like_files = sorted(
            version_like_files, key=lambda p: _rel_to_run_dir(run_dir, p)
        )[: int(self.max_version_like_files)]

        android_vendor_vals: list[str] = []
        android_product_vals: list[str] = []
        android_version_vals: list[str] = []

        for bp in build_prop_files:
            rel = _rel_to_run_dir(run_dir, bp)
            evidence_refs.add(rel)
            kv = _parse_key_value_lines(_safe_text_read(bp))

            for key in (
                "ro.product.vendor.brand",
                "ro.product.brand",
                "ro.product.manufacturer",
            ):
                val = kv.get(key)
                if val and val not in android_vendor_vals:
                    android_vendor_vals.append(val)

            for key in ("ro.product.model", "ro.product.name", "ro.product.device"):
                val = kv.get(key)
                if val and val not in android_product_vals:
                    android_product_vals.append(val)

            for key in (
                "ro.build.version.release",
                "ro.build.display.id",
                "ro.build.id",
            ):
                val = kv.get(key)
                if val and val not in android_version_vals:
                    android_version_vals.append(val)

        if build_prop_files:
            primary_evidence = [_rel_to_run_dir(run_dir, build_prop_files[0])]
            c_platform = _claim(
                claim_type="platform",
                value="android",
                confidence=0.95,
                evidence_refs=primary_evidence,
            )
            if c_platform is not None:
                claims.append(c_platform)

            if android_vendor_vals:
                c_vendor = _claim(
                    claim_type="vendor",
                    value=android_vendor_vals[0],
                    confidence=0.88,
                    evidence_refs=primary_evidence,
                    alternatives_considered=android_vendor_vals[1:],
                )
                if c_vendor is not None:
                    claims.append(c_vendor)

            if android_product_vals:
                c_product = _claim(
                    claim_type="product",
                    value=android_product_vals[0],
                    confidence=0.86,
                    evidence_refs=primary_evidence,
                    alternatives_considered=android_product_vals[1:],
                )
                if c_product is not None:
                    claims.append(c_product)

            if android_version_vals:
                c_version = _claim(
                    claim_type="version",
                    value=android_version_vals[0],
                    confidence=0.82,
                    evidence_refs=primary_evidence,
                    alternatives_considered=android_version_vals[1:],
                )
                if c_version is not None:
                    claims.append(c_version)

        os_release_values: dict[str, tuple[str, str]] = {}
        for osr in os_release_files:
            rel = _rel_to_run_dir(run_dir, osr)
            evidence_refs.add(rel)
            kv = _parse_key_value_lines(_safe_text_read(osr))
            for k in ("ID", "NAME", "PRETTY_NAME", "VERSION", "VERSION_ID"):
                val = kv.get(k)
                if val and k not in os_release_values:
                    os_release_values[k] = (val, rel)

        if not build_prop_files and os_release_values:
            id_pair = os_release_values.get("ID")
            name_pair = os_release_values.get("NAME")
            pretty_pair = os_release_values.get("PRETTY_NAME")
            version_pair = os_release_values.get("VERSION")
            version_id_pair = os_release_values.get("VERSION_ID")

            platform_val = "linux"
            platform_ev = [
                id_pair[1]
                if id_pair is not None
                else next(iter(os_release_values.values()))[1]
            ]
            c_platform = _claim(
                claim_type="platform",
                value=platform_val,
                confidence=0.9,
                evidence_refs=platform_ev,
            )
            if c_platform is not None:
                claims.append(c_platform)

            if id_pair is not None:
                c_vendor = _claim(
                    claim_type="vendor",
                    value=id_pair[0],
                    confidence=0.72,
                    evidence_refs=[id_pair[1]],
                    alternatives_considered=[name_pair[0]]
                    if name_pair is not None
                    else None,
                )
                if c_vendor is not None:
                    claims.append(c_vendor)

            if name_pair is not None:
                alternatives: list[str] = []
                if pretty_pair is not None:
                    alternatives.append(pretty_pair[0])
                c_product = _claim(
                    claim_type="product",
                    value=name_pair[0],
                    confidence=0.8,
                    evidence_refs=[name_pair[1]],
                    alternatives_considered=alternatives,
                )
                if c_product is not None:
                    claims.append(c_product)

            if version_pair is not None or version_id_pair is not None:
                primary = version_pair if version_pair is not None else version_id_pair
                assert primary is not None
                alternatives = (
                    [version_id_pair[0]]
                    if version_pair is not None and version_id_pair is not None
                    else None
                )
                c_version = _claim(
                    claim_type="version",
                    value=primary[0],
                    confidence=0.78,
                    evidence_refs=[primary[1]],
                    alternatives_considered=alternatives,
                )
                if c_version is not None:
                    claims.append(c_version)

        if not build_prop_files:
            for p in etc_version_files + etc_issue_files + version_like_files:
                rel = _rel_to_run_dir(run_dir, p)
                evidence_refs.add(rel)
                text = _safe_text_read(p)
                first_line = ""
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped:
                        first_line = stripped[:120]
                        break
                if not first_line:
                    continue
                if "version" in first_line.lower() or p.name.lower() in {
                    "version",
                    "issue",
                }:
                    c_version = _claim(
                        claim_type="version",
                        value=first_line,
                        confidence=0.4,
                        evidence_refs=[rel],
                    )
                    if c_version is not None:
                        claims.append(c_version)

        deduped: dict[tuple[str, str], dict[str, JsonValue]] = {}
        for c in claims:
            key = (str(c.get("claim_type", "")), str(c.get("value", "")))
            existing = deduped.get(key)
            if existing is None:
                deduped[key] = c
                continue
            old_conf_any = existing.get("confidence")
            new_conf_any = c.get("confidence")
            old_conf = (
                float(old_conf_any) if isinstance(old_conf_any, (int, float)) else 0.0
            )
            new_conf = (
                float(new_conf_any) if isinstance(new_conf_any, (int, float)) else 0.0
            )
            if new_conf > old_conf:
                deduped[key] = c

        final_claims = sorted(
            deduped.values(),
            key=lambda c: (
                str(c.get("claim_type", "")),
                -float(c.get("confidence", 0.0))
                if isinstance(c.get("confidence"), (int, float))
                else 0.0,
                str(c.get("value", "")),
            ),
        )

        if not final_claims:
            limits.append(
                "No attribution claims derived from available static evidence"
            )

        if not inventory_present:
            limits.append(
                "Attribution used degraded mode because inventory stage output is missing"
            )
        if not extraction_present:
            limits.append(
                "Attribution used degraded mode because extraction stage manifest is missing"
            )

        status: StageStatus
        if final_claims and inventory_present and extraction_present and not limits:
            status = "ok"
        else:
            status = "partial"

        artifact_rel = _rel_to_run_dir(run_dir, out_json)
        payload: dict[str, JsonValue] = {
            "status": status,
            "claims": cast(list[JsonValue], cast(list[object], final_claims)),
            "limitations": cast(
                list[JsonValue], cast(list[object], sorted(set(limits)))
            ),
        }
        _ = out_json.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

        evidence_list: list[dict[str, JsonValue]] = []
        evidence_list.append({"path": artifact_rel})
        evidence_list.append({"path": inventory_rel})
        for rel in sorted(evidence_refs):
            evidence_list.append({"path": rel, "note": "attribution source"})

        details: dict[str, JsonValue] = {
            "claims": cast(list[JsonValue], cast(list[object], final_claims)),
            "attribution_json": artifact_rel,
            "evidence": cast(list[JsonValue], cast(list[object], evidence_list)),
            "inventory_present": bool(inventory_present),
            "extraction_present": bool(extraction_present),
        }

        return StageOutcome(
            status=status,
            details=details,
            limitations=sorted(set(limits)),
        )
