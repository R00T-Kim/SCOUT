#!/usr/bin/env python3
"""Check SCOUT documentation for consistency violations.

Enforces:
1. No "deterministic ... pipeline/engine/analysis" patterns (use "deterministic evidence packaging")
2. No "2-tier confidence" or "3-tier confidence" (use 4-tier)
3. No bare "CRA compliant" or "compliance" (use "compatible with")
4. All percentage claims must be followed by baseline metadata in same paragraph
5. Stage count must be 42 or 43 (not 34, 41)

Exit 0 = clean. Exit 1 = violations.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Files to check
DOC_FILES = [
    "README.md",
    "README.ko.md",
    "CHANGELOG.md",
    "docs/status.md",
    "docs/strategic_roadmap_2026.md",
    "docs/blueprint.md",
    "docs/compliance_mapping/cra_annex_i.md",
    "pyproject.toml",
]

# External wiki (informational, not failed if missing)
EXTERNAL_DOCS = [
    "~/gnosis/wiki/projects/scout.md",
]


@dataclass
class Violation:
    file: str
    line_no: int
    line: str
    rule: str
    message: str


def check_deterministic(text: str, file: str) -> list[Violation]:
    """Rule 1: Forbid 'deterministic ... pipeline/engine/analysis' patterns."""
    violations = []
    pattern = re.compile(
        r"\bdeterministic\s+(?:firmware[\w\-]*|analysis|pipeline|engine|scanner)\b",
        re.IGNORECASE,
    )
    # Korean patterns: 결정론적 파이프라인/엔진/분석
    korean_pattern = re.compile(r"결정론적\s*(?:파이프라인|엔진|분석|스캐너)")
    for i, line in enumerate(text.splitlines(), 1):
        matched = pattern.search(line) or korean_pattern.search(line)
        if matched:
            # Allow "deterministic evidence packaging" / "결정론적 증거 패키징"
            if "evidence packaging" not in line.lower() and "증거 패키징" not in line:
                violations.append(
                    Violation(
                        file=file,
                        line_no=i,
                        line=line.strip(),
                        rule="deterministic_misuse",
                        message="Use 'deterministic evidence packaging' instead",
                    )
                )
    return violations


def check_tier_count(text: str, file: str) -> list[Violation]:
    """Rule 2: Forbid '2-tier' or '3-tier' confidence (4-tier only)."""
    violations = []
    pattern = re.compile(r"\b([23])-tier\s+confidence", re.IGNORECASE)
    for i, line in enumerate(text.splitlines(), 1):
        m = pattern.search(line)
        if m:
            violations.append(
                Violation(
                    file=file,
                    line_no=i,
                    line=line.strip(),
                    rule="tier_count",
                    message=f"{m.group(1)}-tier confidence found, use 4-tier",
                )
            )
    return violations


def check_cra_compliance(text: str, file: str) -> list[Violation]:
    """Rule 3: Forbid bare 'CRA compliant' / 'CRA compliance' (use 'compatible with')."""
    violations = []
    # Detect bare compliance claims (English)
    pattern = re.compile(
        r"\b(?:CRA|FDA|ISO\s*21434|UN\s*R155)\s+(?:compliant|compliance|ready)\b",
        re.IGNORECASE,
    )
    # Korean patterns: CRA-ready, CRA 준수, 규제 준수
    korean_cra = re.compile(r"CRA[\s-]*ready|CRA\s*준수|규제\s*준수")
    for i, line in enumerate(text.splitlines(), 1):
        m = pattern.search(line) or korean_cra.search(line)
        if m:
            # Allow "output formats compatible with CRA" / "호환" expressions
            if (
                "compatible with" not in line.lower()
                and "compatibility" not in line.lower()
                and "호환" not in line
                and "annex i" not in line.lower()
            ):
                matched_text = m.group(0) if hasattr(m, "group") else m.group(0)
                violations.append(
                    Violation(
                        file=file,
                        line_no=i,
                        line=line.strip(),
                        rule="cra_compliance_overclaim",
                        message=f"'{matched_text}' overclaims; use 'compatible with' or similar",
                    )
                )
    return violations


def check_stage_count(text: str, file: str) -> list[Violation]:
    """Rule 5: Stage count must be 42 or 43 (not 34, 35, 41)."""
    violations = []
    # Match "N-stage" or "N stages" where N is 30-41
    pattern = re.compile(r"\b(3[0-9]|4[01])[-\s]stages?\b")
    for i, line in enumerate(text.splitlines(), 1):
        m = pattern.search(line)
        if m:
            violations.append(
                Violation(
                    file=file,
                    line_no=i,
                    line=line.strip(),
                    rule="stage_count",
                    message=f"'{m.group(0)}' stage count, use '42-stage' or '43-stage'",
                )
            )
    return violations


# NOTE: check_baseline_metadata is intentionally NOT wired into CHECKERS
# for v2.5.0. It will be enabled after fresh corpus re-validation produces
# an authoritative baseline manifest. See docs/benchmark_governance.md
# "Current state (v2.5.0)" disclaimer.
def check_baseline_metadata(text: str, file: str) -> list[Violation]:
    """Rule 4: Percentage claims should have baseline metadata nearby."""
    violations = []
    # This is a heuristic — flag % numbers that aren't already inside a clear baseline context
    pattern = re.compile(r"\b(\d{1,3}(?:\.\d+)?%)\b")
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if pattern.search(line):
            # Check surrounding 5 lines for baseline keywords
            context = " ".join(lines[max(0, i - 3) : i + 2]).lower()
            keywords = [
                "baseline",
                "v2.",
                "firmware",
                "driver",
                "validation date",
                "tier 1",
                "tier 2",
            ]
            if not any(kw in context for kw in keywords):
                # Skip if line is in a code block, JSON, or is a header
                if line.strip().startswith(("|", "#", "```", "<", "-")):
                    continue
                if "%" in line and any(
                    c in line.lower() for c in ["baseline", "tier", "firmware"]
                ):
                    continue
                violations.append(
                    Violation(
                        file=file,
                        line_no=i,
                        line=line.strip()[:120],
                        rule="bare_percentage",
                        message="Percentage claim lacks baseline metadata in context",
                    )
                )
    return violations


CHECKERS = [
    check_deterministic,
    check_tier_count,
    check_cra_compliance,
    check_stage_count,
    # check_baseline_metadata,  # too noisy initially; enable after first pass
]


def main() -> int:
    all_violations: list[Violation] = []

    for rel_path in DOC_FILES:
        path = REPO_ROOT / rel_path
        if not path.exists():
            print(f"WARN: {rel_path} does not exist", file=sys.stderr)
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for checker in CHECKERS:
            all_violations.extend(checker(text, rel_path))

    # External docs (informational)
    for ext_path in EXTERNAL_DOCS:
        path = Path(ext_path).expanduser()
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            for checker in CHECKERS:
                ext_violations = checker(text, str(path))
                if ext_violations:
                    print(
                        f"INFO: {len(ext_violations)} violations in external doc {path}",
                        file=sys.stderr,
                    )
                    for v in ext_violations[:5]:
                        print(
                            f"  L{v.line_no} [{v.rule}]: {v.line[:100]}",
                            file=sys.stderr,
                        )

    if not all_violations:
        print("OK: All documentation consistent")
        return 0

    print(f"FAIL: {len(all_violations)} violation(s) found:\n")
    by_file: dict[str, list[Violation]] = {}
    for v in all_violations:
        by_file.setdefault(v.file, []).append(v)
    for file, vs in sorted(by_file.items()):
        print(f"\n{file}:")
        for v in vs:
            print(f"  L{v.line_no} [{v.rule}] {v.message}")
            print(f"    > {v.line[:120]}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
