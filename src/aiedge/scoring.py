"""Detection confidence vs priority score separation.

Detection confidence: how strong is the evidence that a vulnerability exists?
- Static evidence depth (capped by ConfidenceCaps)
- Dynamic evidence (emulation, fuzzing crash)

Priority score: how urgently should an analyst look at this?
- Detection confidence is one INPUT
- EPSS (population-level exploitation likelihood) is another INPUT
- Reachability is another INPUT
- Backport status is another INPUT
- These combine into a separate score, not collapsed into confidence.

Reviewer critique addressed:
> "EPSS additive adjustment makes detection confidence look like a
>  ranking heuristic. They should be separate."

Phase 2B PR #15 -- additive rollout. The ``priority_score`` and
``priority_inputs`` fields are optional on findings; downstream consumers
that only read ``confidence`` continue to work unchanged. New ranking UIs
should read ``priority_score`` instead.

Weights (documented heuristic -- see docs/scoring_calibration.md):
    detection    50%   -- static evidence depth is the anchor
    EPSS         25%   -- population-level exploitation likelihood
    reachability 15%   -- does the vulnerable code touch an exposed surface?
    CVSS         10%   -- severity as a tiebreaker
    backport    -0.20   -- penalty if component shows a distro patch revision
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class PriorityInputs:
    """Inputs that feed into ``priority_score``, kept for transparency.

    Serialized into ``finding["priority_inputs"]`` so analysts can see
    exactly which signals were combined and with what weights.

    Attributes:
        detection_confidence: Detection confidence in [0.0, 1.0] -- the
            probability that the finding reflects a real vulnerability.
            Sourced from ``confidence_caps.py`` and must already be capped
            when passed in (the scorer does not re-cap it).
        epss_score: EPSS score in [0.0, 1.0] from FIRST.org, representing
            the probability of exploitation in the next 30 days. ``None``
            when EPSS lookup failed or the API was unreachable.
        epss_percentile: Companion percentile for ``epss_score`` (not used
            in the current weighting but kept for downstream consumers).
        reachability: One of ``"directly_reachable"``,
            ``"potentially_reachable"``, ``"unreachable"``, ``"unknown"``.
            Any other value (including ``None``) is treated as ``"unknown"``.
        backport_present: ``True`` when the component exposes a distro
            patch revision (e.g. ``opkg`` detection method with a non-empty
            ``patch_revision``), indicating the CVE may already be patched
            despite the old upstream version string.
        cvss_base: CVSS v3 base score in [0.0, 10.0] if known, else
            ``None``.
    """

    detection_confidence: float
    epss_score: float | None
    epss_percentile: float | None
    reachability: str | None
    backport_present: bool
    cvss_base: float | None


_PRIORITY_WEIGHTS: dict[str, float] = {
    "detection": 0.50,
    "epss": 0.25,
    "reachability": 0.15,
    "cvss": 0.10,
}

_REACHABILITY_MULTIPLIER: dict[str, float] = {
    "directly_reachable": 1.0,
    "potentially_reachable": 0.7,
    "unknown": 0.5,
    "unreachable": 0.2,
}

# Backport penalty -- documented constant so tests and callers can assert on it.
BACKPORT_PENALTY: float = 0.20


def compute_priority_score(inputs: PriorityInputs) -> float:
    """Operational priority signal for analyst triage.

    Returns a value in [0.0, 1.0]. NOT a probability of true positive --
    that's ``detection_confidence``.

    Components (documented additive heuristic):
      - 50% weight: detection_confidence
      - 25% weight: EPSS score (if available; omitted when ``None``)
      - 15% weight: reachability multiplier
      - 10% weight: CVSS base / 10 (if available; omitted when ``None``)
      - backport: -0.20 penalty (still relevant but lower priority)

    The final score is clamped into the unit interval so that analysts can
    always interpret it against a fixed scale.
    """
    score = inputs.detection_confidence * _PRIORITY_WEIGHTS["detection"]

    if inputs.epss_score is not None:
        score += inputs.epss_score * _PRIORITY_WEIGHTS["epss"]

    reach_key = inputs.reachability or "unknown"
    reach_multiplier = _REACHABILITY_MULTIPLIER.get(reach_key, 0.5)
    score += reach_multiplier * _PRIORITY_WEIGHTS["reachability"]

    if inputs.cvss_base is not None:
        score += (inputs.cvss_base / 10.0) * _PRIORITY_WEIGHTS["cvss"]

    if inputs.backport_present:
        score -= BACKPORT_PENALTY

    if score < 0.0:
        return 0.0
    if score > 1.0:
        return 1.0
    return score


def priority_inputs_to_dict(inputs: PriorityInputs) -> dict[str, Any]:
    """Serialize a :class:`PriorityInputs` instance to a JSON-safe dict.

    Used to populate ``finding["priority_inputs"]`` in the findings stage
    output. The returned dict is a shallow copy produced by
    :func:`dataclasses.asdict`, so callers may safely mutate it without
    affecting the frozen dataclass.
    """
    return asdict(inputs)


def priority_bucket(score: float) -> str:
    """Classify a priority score into an operational bucket.

    Buckets (documented contract):
      - ``critical``: score >= 0.8
      - ``high``:     0.6 <= score < 0.8
      - ``medium``:   0.4 <= score < 0.6
      - ``low``:      score < 0.4

    Used by ``quality_metrics`` and by analyst dashboards to group
    findings without re-computing the weights.
    """
    if score >= 0.8:
        return "critical"
    if score >= 0.6:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"
