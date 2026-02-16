from __future__ import annotations

from collections.abc import Sequence

STATIC_ONLY_CAP = 0.60
EVIDENCE_LEVELS: tuple[str, ...] = ("L0", "L1", "L2", "L3", "L4")


def clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return float(value)


def _unique_refs(evidence_refs: Sequence[str] | None) -> tuple[str, ...]:
    if evidence_refs is None:
        return ()
    return tuple(sorted({ref for ref in evidence_refs if ref}))


def evidence_level(observation: str, evidence_refs: Sequence[str] | None) -> str:
    ref_count = len(_unique_refs(evidence_refs))
    if ref_count == 0:
        return "L0"

    if observation == "static_reference":
        if ref_count == 1:
            return "L1"
        if ref_count <= 3:
            return "L2"
        return "L3"

    if ref_count == 1:
        return "L2"
    if ref_count <= 3:
        return "L3"
    return "L4"


def calibrated_confidence(
    *,
    confidence: float,
    observation: str,
    evidence_refs: Sequence[str] | None,
) -> float:
    lvl = evidence_level(observation, evidence_refs)
    base = clamp01(float(confidence))
    level_bonuses: dict[str, float] = {
        "L0": -0.15,
        "L1": -0.08,
        "L2": -0.03,
        "L3": 0.0,
        "L4": 0.03,
    }
    calibrated = clamp01(base + level_bonuses.get(lvl, 0.0))
    if observation == "static_reference":
        calibrated = min(calibrated, STATIC_ONLY_CAP)
    return calibrated
