from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from .schema import JsonValue
from .stage import StageContext, StageOutcome

_REASON_PROFILE_NOT_EXPLOIT = "POLICY_PROFILE_NOT_EXPLOIT"
_REASON_EXPLOIT_GATE_MISSING = "POLICY_EXPLOIT_GATE_MISSING"
_REASON_SCOPE_NOT_LAB_ONLY = "POLICY_SCOPE_NOT_LAB_ONLY"
_REASON_ATTESTATION_NOT_AUTHORIZED = "POLICY_ATTESTATION_NOT_AUTHORIZED"
_REASON_PREREQ_STAGE_ARTIFACT_MISSING = "POLICY_PREREQ_STAGE_ARTIFACT_MISSING"
_REASON_NON_WEAPONIZED_ONLY = "POLICY_NON_WEAPONIZED_BOUNDED_CHECKS_ONLY"


def _read_manifest(run_dir: Path) -> dict[str, object] | None:
    p = run_dir / "manifest.json"
    if not p.is_file():
        return None
    try:
        raw_obj = cast(object, json.loads(p.read_text(encoding="utf-8")))
    except Exception:
        return None
    if not isinstance(raw_obj, dict):
        return None
    return cast(dict[str, object], raw_obj)


def _profile_and_gate(
    manifest: dict[str, object] | None,
) -> tuple[str, dict[str, str] | None]:
    if not manifest:
        return "analysis", None
    prof_any = manifest.get("profile")
    profile = prof_any if isinstance(prof_any, str) and prof_any else "analysis"
    gate_any = manifest.get("exploit_gate")
    if not isinstance(gate_any, dict):
        return profile, None
    gate_obj = cast(dict[str, object], gate_any)
    flag = gate_obj.get("flag")
    att = gate_obj.get("attestation")
    scope = gate_obj.get("scope")
    if not (isinstance(flag, str) and isinstance(att, str) and isinstance(scope, str)):
        return profile, None
    if not (flag and att and scope):
        return profile, None
    return profile, {"flag": flag, "attestation": att, "scope": scope}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _canonical_input_identity(
    run_dir: Path, manifest: dict[str, object] | None
) -> dict[str, str]:
    keys = ("analyzed_input_sha256", "input_sha256", "source_input_sha256")
    if manifest is not None:
        for key in keys:
            raw = manifest.get(key)
            if isinstance(raw, str) and raw:
                return {
                    "path": "input/firmware.bin",
                    "sha256": raw,
                    "sha256_source": f"manifest.{key}",
                }

    fw = run_dir / "input" / "firmware.bin"
    if fw.is_file():
        return {
            "path": "input/firmware.bin",
            "sha256": _sha256_file(fw),
            "sha256_source": "run_dir.input/firmware.bin",
        }

    return {
        "path": "input/firmware.bin",
        "sha256": "",
        "sha256_source": "missing",
    }


@dataclass(frozen=True)
class PocValidationStage:
    @property
    def name(self) -> str:
        return "poc_validation"

    def run(self, ctx: StageContext) -> StageOutcome:
        manifest = _read_manifest(ctx.run_dir)
        profile, gate = _profile_and_gate(manifest)
        canonical_input = _canonical_input_identity(ctx.run_dir, manifest)

        stage_dir = ctx.run_dir / "stages" / "poc_validation"
        stage_dir.mkdir(parents=True, exist_ok=True)
        validation_path = stage_dir / "poc_validation.json"

        evidence: list[JsonValue] = [
            {"path": "manifest.json"},
            {"path": "stages/poc_validation"},
            {"path": "stages/poc_validation/poc_validation.json"},
        ]

        if profile != "exploit":
            checks = [
                {
                    "id": "profile_gate",
                    "status": "skipped",
                    "result_code": _REASON_PROFILE_NOT_EXPLOIT,
                    "note": "PoC validation is scoped to exploit profile only.",
                },
                {
                    "id": "non_weaponized_constraints",
                    "status": "ok",
                    "result_code": _REASON_NON_WEAPONIZED_ONLY,
                    "note": "Validation remains bounded to artifact-only checks with no payload execution.",
                },
            ]
            _ = validation_path.write_text(
                json.dumps(
                    {
                        "profile": profile,
                        "canonical_input": canonical_input,
                        "status": "skipped",
                        "checked_paths": ["manifest.json"],
                        "checks": checks,
                        "blocked": [
                            {
                                "reason_code": _REASON_PROFILE_NOT_EXPLOIT,
                                "target": "manifest.profile",
                                "note": "Profile is not exploit; PoC validation skipped.",
                            }
                        ],
                    },
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=True,
                )
                + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="skipped",
                details={
                    "profile": profile,
                    "blocked_reason_codes": [_REASON_PROFILE_NOT_EXPLOIT],
                    "check_reason_codes": [
                        _REASON_NON_WEAPONIZED_ONLY,
                        _REASON_PROFILE_NOT_EXPLOIT,
                    ],
                    "evidence": evidence,
                },
                limitations=["PoC validation skipped: profile is not exploit."],
            )

        if gate is None:
            checks = [
                {
                    "id": "exploit_gate",
                    "status": "blocked",
                    "result_code": _REASON_EXPLOIT_GATE_MISSING,
                    "note": "Manifest exploit_gate fields are required before PoC validation.",
                },
                {
                    "id": "non_weaponized_constraints",
                    "status": "ok",
                    "result_code": _REASON_NON_WEAPONIZED_ONLY,
                    "note": "Validation remains bounded to artifact-only checks with no payload execution.",
                },
            ]
            _ = validation_path.write_text(
                json.dumps(
                    {
                        "profile": profile,
                        "canonical_input": canonical_input,
                        "status": "failed",
                        "checked_paths": ["manifest.json"],
                        "checks": checks,
                        "blocked": [
                            {
                                "reason_code": _REASON_EXPLOIT_GATE_MISSING,
                                "target": "manifest.exploit_gate",
                                "note": "exploit_gate is missing or malformed.",
                            }
                        ],
                    },
                    indent=2,
                    sort_keys=True,
                    ensure_ascii=True,
                )
                + "\n",
                encoding="utf-8",
            )
            return StageOutcome(
                status="failed",
                details={
                    "profile": profile,
                    "blocked_reason_codes": [_REASON_EXPLOIT_GATE_MISSING],
                    "check_reason_codes": [
                        _REASON_EXPLOIT_GATE_MISSING,
                        _REASON_NON_WEAPONIZED_ONLY,
                    ],
                    "evidence": evidence,
                },
                limitations=["PoC validation blocked: exploit_gate is missing."],
            )

        blocked: list[dict[str, str]] = []
        checked_paths = sorted(
            {
                "manifest.json",
                "stages/exploit_chain/milestones.json",
            }
        )

        missing_paths = [
            p
            for p in checked_paths
            if p != "manifest.json" and not (ctx.run_dir / p).is_file()
        ]
        if missing_paths:
            blocked.append(
                {
                    "reason_code": _REASON_PREREQ_STAGE_ARTIFACT_MISSING,
                    "target": "stages",
                    "note": "Required exploit-stage artifacts are missing.",
                }
            )

        if gate.get("scope") != "lab-only":
            blocked.append(
                {
                    "reason_code": _REASON_SCOPE_NOT_LAB_ONLY,
                    "target": "manifest.exploit_gate.scope",
                    "note": "PoC validation requires exploit_gate.scope=lab-only.",
                }
            )

        if gate.get("attestation") != "authorized":
            blocked.append(
                {
                    "reason_code": _REASON_ATTESTATION_NOT_AUTHORIZED,
                    "target": "manifest.exploit_gate.attestation",
                    "note": "PoC validation requires exploit_gate.attestation=authorized.",
                }
            )

        blocked_sorted = sorted(
            blocked,
            key=lambda item: (
                item["reason_code"],
                item["target"],
                item["note"],
            ),
        )
        blocked_codes = sorted({item["reason_code"] for item in blocked_sorted})

        prereq_status = "ok" if not missing_paths else "blocked"
        prereq_code = (
            "POLICY_PREREQ_STAGE_ARTIFACTS_READY"
            if not missing_paths
            else _REASON_PREREQ_STAGE_ARTIFACT_MISSING
        )
        scope_status = "ok" if gate.get("scope") == "lab-only" else "blocked"
        scope_code = (
            "POLICY_SCOPE_LAB_ONLY_CONFIRMED"
            if gate.get("scope") == "lab-only"
            else _REASON_SCOPE_NOT_LAB_ONLY
        )
        attestation_status = (
            "ok" if gate.get("attestation") == "authorized" else "blocked"
        )
        attestation_code = (
            "POLICY_ATTESTATION_AUTHORIZED_CONFIRMED"
            if gate.get("attestation") == "authorized"
            else _REASON_ATTESTATION_NOT_AUTHORIZED
        )

        checks = [
            {
                "id": "prerequisite_artifacts",
                "status": prereq_status,
                "result_code": prereq_code,
                "checked_paths": checked_paths,
                "missing_paths": missing_paths,
                "note": "Validation relies on existing exploit gate and chain artifacts only.",
            },
            {
                "id": "gate_scope",
                "status": scope_status,
                "result_code": scope_code,
                "expected": "lab-only",
                "actual": gate.get("scope", ""),
                "note": "Scope must remain lab-only for bounded PoC validation.",
            },
            {
                "id": "gate_attestation",
                "status": attestation_status,
                "result_code": attestation_code,
                "expected": "authorized",
                "actual": gate.get("attestation", ""),
                "note": "Attestation must explicitly authorize bounded PoC validation.",
            },
            {
                "id": "non_weaponized_constraints",
                "status": "ok",
                "result_code": _REASON_NON_WEAPONIZED_ONLY,
                "note": "Checks are read-only over run artifacts; no payload generation, persistence, or exploitation execution occurs.",
            },
        ]

        stage_status = "ok" if not blocked_sorted else "failed"
        _ = validation_path.write_text(
            json.dumps(
                {
                    "profile": profile,
                    "canonical_input": canonical_input,
                    "status": stage_status,
                    "checked_paths": checked_paths,
                    "checks": checks,
                    "blocked": blocked_sorted,
                    "exploit_gate": gate,
                },
                indent=2,
                sort_keys=True,
                ensure_ascii=True,
            )
            + "\n",
            encoding="utf-8",
        )

        check_reason_codes = [
            str(cast(dict[str, object], item).get("result_code", ""))
            for item in checks
            if cast(dict[str, object], item).get("result_code")
        ]

        return StageOutcome(
            status="ok" if stage_status == "ok" else "failed",
            details={
                "profile": profile,
                "blocked_reason_codes": cast(
                    list[JsonValue], cast(list[object], list(blocked_codes))
                ),
                "check_reason_codes": cast(
                    list[JsonValue], cast(list[object], check_reason_codes)
                ),
                "checked_paths": cast(
                    list[JsonValue], cast(list[object], list(checked_paths))
                ),
                "evidence": evidence,
            },
            limitations=(
                []
                if not blocked_sorted
                else [
                    "PoC validation blocked by exploit policy controls: "
                    + ", ".join(blocked_codes)
                ]
            ),
        )
