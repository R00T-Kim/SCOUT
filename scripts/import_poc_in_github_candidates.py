#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import cast

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aiedge.exploit_rag.importers.aqua_vuln_list import (  # noqa: E402
    fetch_vuln_list_nvd_cve,
    load_local_vuln_list_nvd_cve,
    normalize_vuln_list_enrichment,
)
from aiedge.exploit_rag.importers.poc_in_github import (  # noqa: E402
    fetch_poc_in_github_cve,
    normalize_poc_in_github_candidate,
    write_candidate,
)
from aiedge.schema import JsonValue  # noqa: E402

_DEFAULT_SEEDS = _REPO_ROOT / "data" / "exploit_references" / "firmware_seed_cves.json"
_DEFAULT_OUTPUT = _REPO_ROOT / "data" / "exploit_references" / "candidates" / "poc_in_github"


def _load_seed_entries(path: Path) -> list[dict[str, JsonValue]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("seed file must be a JSON object")
    entries = raw.get("cves")
    if not isinstance(entries, list):
        raise ValueError("seed file must contain cves[]")
    out: list[dict[str, JsonValue]] = []
    for item in entries:
        if isinstance(item, dict) and isinstance(item.get("cve"), str):
            out.append(cast(dict[str, JsonValue], item))
    return out


def _entry_for_cve(
    cve: str, seed_entries: list[dict[str, JsonValue]] | None = None
) -> dict[str, JsonValue]:
    normalized = cve.upper()
    for entry in seed_entries or []:
        if str(entry.get("cve", "")).strip().upper() == normalized:
            return dict(entry)
    return {"cve": normalized, "summary": ""}


def _load_vuln_list_enrichment(
    cve: str,
    *,
    vuln_list_dir: Path | None,
    timeout_s: float,
) -> dict[str, JsonValue] | None:
    try:
        if vuln_list_dir is not None:
            payload = load_local_vuln_list_nvd_cve(cve, vuln_list_dir)
        else:
            payload = fetch_vuln_list_nvd_cve(cve, timeout_s=timeout_s)
        return normalize_vuln_list_enrichment(cve, payload)
    except Exception:
        return None


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Import PoC-in-GitHub CVE metadata as unreviewed SCOUT exploit "
            "pattern candidates. Optionally enrich candidates from Aqua "
            "vuln-list-update generated NVD metadata. This never clones or "
            "executes public PoC repos."
        )
    )
    parser.add_argument(
        "--cve",
        action="append",
        default=[],
        metavar="CVE-ID",
        help="CVE ID to import; may be repeated. If omitted, --seed-file is used.",
    )
    parser.add_argument(
        "--seed-file",
        type=Path,
        default=_DEFAULT_SEEDS,
        help=f"Seed JSON with cves[] (default: {_DEFAULT_SEEDS}).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_DEFAULT_OUTPUT,
        help=f"Candidate output directory (default: {_DEFAULT_OUTPUT}).",
    )
    parser.add_argument(
        "--timeout-s",
        type=float,
        default=10.0,
        help="HTTP timeout for metadata fetches.",
    )
    parser.add_argument(
        "--vuln-list-dir",
        type=Path,
        default=None,
        help=(
            "Optional local aquasecurity/vuln-list checkout populated by "
            "vuln-list-update; reads nvd/<year>/<CVE>.json before network."
        ),
    )
    parser.add_argument(
        "--no-vuln-list-update",
        action="store_true",
        help="Disable Aqua vuln-list-update/NVD enrichment.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Fetch and normalize but do not write candidate files.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    seed_entries: list[dict[str, JsonValue]] = []
    if args.seed_file.exists():
        seed_entries = _load_seed_entries(args.seed_file)

    entries = [_entry_for_cve(cve, seed_entries) for cve in args.cve]
    if not entries:
        entries = seed_entries

    written: list[str] = []
    failed: list[str] = []
    for entry in entries:
        cve = str(entry.get("cve", "")).strip().upper()
        if not cve:
            continue
        try:
            enrichment = None
            if not args.no_vuln_list_update:
                enrichment = _load_vuln_list_enrichment(
                    cve,
                    vuln_list_dir=args.vuln_list_dir,
                    timeout_s=float(args.timeout_s),
                )
            summary = str(entry.get("summary", ""))
            cwe: list[str] = []
            cvss: float | None = None
            cpe: list[str] = []
            if enrichment is not None:
                summary = str(enrichment.get("summary", "")) or summary
                cwe_any = enrichment.get("cwe")
                cpe_any = enrichment.get("cpe")
                cwe = [str(x) for x in cwe_any] if isinstance(cwe_any, list) else []
                cpe = [str(x) for x in cpe_any] if isinstance(cpe_any, list) else []
                cvss_any = enrichment.get("cvss")
                cvss = float(cvss_any) if isinstance(cvss_any, (int, float)) else None

            repos = fetch_poc_in_github_cve(cve, timeout_s=float(args.timeout_s))
            candidate = normalize_poc_in_github_candidate(
                cve,
                repos,
                cve_summary=summary,
                cwe=cwe,
                cvss=cvss,
                cpe=cpe,
            )
            if enrichment is not None:
                candidate["vuln_list_update"] = enrichment
                candidate["enrichment_sources"] = cast(
                    JsonValue,
                    ["aquasecurity/vuln-list-update", "aquasecurity/vuln-list"],
                )
            if args.dry_run:
                print(json.dumps(candidate, indent=2, sort_keys=True))
            else:
                path = write_candidate(candidate, args.output_dir)
                written.append(str(path))
        except Exception as exc:
            failed.append(f"{cve}:{type(exc).__name__}:{exc}")

    if written:
        print("written:")
        for path in written:
            print(f"  {path}")
    if failed:
        print("failed:", file=sys.stderr)
        for item in failed:
            print(f"  {item}", file=sys.stderr)
    return 1 if failed and not written else 0


if __name__ == "__main__":
    raise SystemExit(main())
