#!/usr/bin/env python3
"""Re-match known CVE signatures against benchmark archives.

Reads archived binary_analysis.json from benchmark results, extracts
vendor/model from firmware filenames, and runs match_known_signatures().
Pipeline re-execution is not required.

Usage:
    python3 scripts/cve_rematch.py --results-dir benchmark-results/firmae-YYYYMMDD_HHMM
    python3 scripts/cve_rematch.py --results-dir benchmark-results/firmae-YYYYMMDD_HHMM --csv-out cve_matches.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import Counter
from pathlib import Path

# ---------------------------------------------------------------------------
# sys.path bootstrap — allows running without installing the package
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from aiedge.known_cve_signatures import match_known_signatures  # noqa: E402
from aiedge.nvd_local import load_nvd_db, match_nvd_local  # noqa: E402

# ---------------------------------------------------------------------------
# Model extraction helpers
# ---------------------------------------------------------------------------

def extract_model_from_filename(filename: str, vendor: str) -> list[str]:
    """Extract model name from firmware filename."""
    models: list[str] = []
    name = filename.lower()
    # Remove common suffixes
    name = re.sub(r'\.(zip|bin|img|fw|chk|trx|rar|gz|bz2)$', '', name, flags=re.IGNORECASE)
    name = re.sub(r'^fw_', '', name, flags=re.IGNORECASE)

    if vendor == "netgear":
        m = re.match(r'(r\d{4}[a-z0-9]*)', name, re.IGNORECASE)
        if m:
            models.append(m.group(1).lower())
        m = re.match(r'(wndr?\d{4}[a-z0-9]*)', name, re.IGNORECASE)
        if m:
            models.append(m.group(1).lower())
        m = re.match(r'(dgn\d{4}[a-z0-9]*)', name, re.IGNORECASE)
        if m:
            models.append(m.group(1).lower())
    elif vendor == "dlink":
        m = re.search(r'(dir[_-]?\d{3}[a-z0-9]*)', name, re.IGNORECASE)
        if m:
            models.append(m.group(1).lower().replace('_', '-'))
        m = re.search(r'(dcs[_-]?\d{4}[a-z0-9]*)', name, re.IGNORECASE)
        if m:
            models.append(m.group(1).lower().replace('_', '-'))
    elif vendor == "asus":
        m = re.search(r'(rt[_-]?[a-z]*\d{2,}[a-z0-9]*)', name, re.IGNORECASE)
        if m:
            models.append(m.group(1).lower().replace('_', '-'))
    elif vendor == "linksys":
        m = re.search(r'(e\d{3,4}[a-z]*|ea\d{4}|wrt\d{2,}[a-z]*)', name, re.IGNORECASE)
        if m:
            models.append(m.group(1).lower())
    elif vendor == "tplink":
        m = re.search(r'(archer[_-]?[a-z]\d+|tl[_-]?w[a-z]*\d+[a-z]*)', name, re.IGNORECASE)
        if m:
            models.append(m.group(1).lower().replace('_', '-'))
    elif vendor == "trendnet":
        m = re.search(r'(tew[_-]?\d{3}[a-z0-9]*)', name, re.IGNORECASE)
        if m:
            models.append(m.group(1).lower().replace('_', '-'))
    elif vendor == "zyxel":
        m = re.search(r'(nbg[_-]?\d{3}[a-z0-9]*)', name, re.IGNORECASE)
        if m:
            models.append(m.group(1).lower().replace('_', '-'))
    elif vendor == "belkin":
        m = re.search(r'(f\d[a-z]\d{4}[a-z0-9]*)', name, re.IGNORECASE)
        if m:
            models.append(m.group(1).lower())

    # Generic fallback: first token with mixed letters+digits, length >= 3
    if not models:
        for tok in re.split(r'[_\-\s/]+', name):
            if len(tok) >= 3 and re.search(r'[a-z]', tok) and re.search(r'\d', tok):
                models.append(tok)
                break

    return models


# ---------------------------------------------------------------------------
# Archive resolution helpers
# ---------------------------------------------------------------------------

def _find_run_dir(archive_sha_dir: Path) -> Path | None:
    """Walk the archive tree to find the aiedge-runs/<run_id> directory."""
    # Archives embed full absolute paths: .../home/rootk1m/SCOUT/aiedge-runs/<run_id>/
    for p in archive_sha_dir.rglob("stages"):
        if p.is_dir():
            return p.parent
    return None


def _load_binary_analysis(run_dir: Path) -> tuple[set[str], dict[str, set[str]]]:
    """Return (binary_names, binary_symbols) from stages/inventory/binary_analysis.json.

    binary_analysis.json structure:
        {"hits": [{"path": "...", "matched_symbols": [...], ...}], "summary": {...}}
    """
    ba_path = run_dir / "stages" / "inventory" / "binary_analysis.json"
    if not ba_path.exists():
        return set(), {}

    try:
        data = json.loads(ba_path.read_text(encoding="utf-8", errors="replace"))
    except json.JSONDecodeError:
        return set(), {}

    binary_names: set[str] = set()
    binary_symbols: dict[str, set[str]] = {}

    hits = data.get("hits", [])
    if not isinstance(hits, list):
        return set(), {}

    for hit in hits:
        path_str = hit.get("path", "")
        basename = Path(path_str).name if path_str else ""
        if not basename:
            continue

        binary_names.add(basename)

        # matched_symbols: list[str] of sink-class symbol names already filtered
        syms: set[str] = set()
        for sym in hit.get("matched_symbols", []):
            if isinstance(sym, str):
                syms.add(sym)
        # symbol_details: list[{"name": str, ...}] with richer info
        for detail in hit.get("symbol_details", []):
            if isinstance(detail, dict) and isinstance(detail.get("name"), str):
                syms.add(detail["name"])

        if basename in binary_symbols:
            binary_symbols[basename] |= syms
        else:
            binary_symbols[basename] = syms

    return binary_names, binary_symbols


# ---------------------------------------------------------------------------
# Main processing
# ---------------------------------------------------------------------------

CSV_FIELDNAMES = [
    "firmware", "vendor", "model", "cve_id", "confidence",
    "vuln_type", "cvss_v3_score", "description", "entry_point",
    "vendor_match", "model_match", "binary_match", "sink_match",
]


def process_results_dir(
    results_dir: Path,
    csv_out: Path | None,
    verbose: bool,
    nvd_dir: Path | None = None,
) -> int:
    """Run CVE rematch over all entries in benchmark_summary.csv.

    Returns 0 on success, 1 on error.
    """
    summary_csv = results_dir / "benchmark_summary.csv"
    if not summary_csv.exists():
        print(f"ERROR: {summary_csv} not found", file=sys.stderr)
        return 1

    archives_root = results_dir / "archives"
    if not archives_root.exists():
        print(f"ERROR: {archives_root} not found", file=sys.stderr)
        return 1

    # Load NVD local DB if provided
    nvd_cves: list[dict[str, object]] = []
    if nvd_dir:
        nvd_cves = load_nvd_db(nvd_dir)
        print(f"Loaded {len(nvd_cves)} CVEs from local NVD DB", file=sys.stderr)

    rows: list[dict[str, str]] = []
    total_firmware = 0
    firmware_with_matches: set[str] = set()
    cve_counter: Counter[str] = Counter()
    skipped = 0

    with summary_csv.open(encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh)
        entries = list(reader)

    for entry in entries:
        total_firmware += 1
        vendor = entry.get("vendor", "").strip().lower()
        firmware_filename = entry.get("firmware", "").strip()
        sha = entry.get("sha256", "").strip()

        if not sha or not vendor:
            skipped += 1
            continue

        archive_sha_dir = archives_root / vendor / sha
        if not archive_sha_dir.is_dir():
            if verbose:
                print(f"  SKIP (no archive): {vendor}/{sha}")
            skipped += 1
            continue

        run_dir = _find_run_dir(archive_sha_dir)
        if run_dir is None:
            if verbose:
                print(f"  SKIP (no run_dir): {vendor}/{sha}")
            skipped += 1
            continue

        binary_names, binary_symbols = _load_binary_analysis(run_dir)
        if not binary_names:
            if verbose:
                print(f"  SKIP (no binary_analysis): {vendor}/{sha} — {firmware_filename}")
            skipped += 1
            continue

        model_claims = extract_model_from_filename(firmware_filename, vendor)
        vendor_claims = [vendor]

        matches = match_known_signatures(
            vendor_claims=vendor_claims,
            model_claims=model_claims,
            binary_names=binary_names,
            binary_symbols=binary_symbols,
        )

        # NVD local DB matching
        if nvd_cves:
            nvd_matches = match_nvd_local(
                nvd_cves, vendor, model_claims, binary_names,
            )
            # Deduplicate: skip NVD matches already found by signature
            existing_ids = {str(m.get("cve_id", "")) for m in matches}
            for nm in nvd_matches:
                if str(nm["cve_id"]) not in existing_ids:
                    matches.append(nm)
                    existing_ids.add(str(nm["cve_id"]))

        if matches:
            firmware_with_matches.add(sha)

        for m in matches:
            cve_id = str(m.get("cve_id", ""))
            cve_counter[cve_id] += 1
            rows.append({
                "firmware": firmware_filename,
                "vendor": vendor,
                "model": ",".join(model_claims) if model_claims else "",
                "cve_id": cve_id,
                "confidence": str(m.get("confidence", "")),
                "vuln_type": str(m.get("vuln_type", "")),
                "cvss_v3_score": str(m.get("cvss_v3_score", "")),
                "description": str(m.get("description", "")),
                "entry_point": str(m.get("entry_point", "")),
                "vendor_match": str(m.get("vendor_match", "")),
                "model_match": str(m.get("model_match", "")),
                "binary_match": str(m.get("binary_match", "")),
                "sink_match": str(m.get("sink_match", "")),
            })

    # --- Write CSV ---
    if csv_out is not None:
        csv_out.parent.mkdir(parents=True, exist_ok=True)
        with csv_out.open("w", encoding="utf-8", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=CSV_FIELDNAMES)
            writer.writeheader()
            writer.writerows(rows)
        print(f"Wrote {len(rows)} rows → {csv_out}")
    else:
        # Print to stdout
        writer = csv.DictWriter(sys.stdout, fieldnames=CSV_FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    # --- Summary ---
    print(file=sys.stderr)
    print("=" * 60, file=sys.stderr)
    print(f"Total firmware:          {total_firmware}", file=sys.stderr)
    print(f"Skipped (no archive):    {skipped}", file=sys.stderr)
    print(f"Firmware with CVE matches: {len(firmware_with_matches)}", file=sys.stderr)
    print(f"Total CVE matches:       {len(rows)}", file=sys.stderr)
    if cve_counter:
        cve_summary = ", ".join(
            f"{cve}({cnt})" for cve, cnt in cve_counter.most_common()
        )
        print(f"CVEs found: {cve_summary}", file=sys.stderr)

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Re-match known CVE signatures against benchmark archives.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--results-dir",
        required=True,
        type=Path,
        metavar="DIR",
        help="Benchmark results directory (contains benchmark_summary.csv and archives/).",
    )
    p.add_argument(
        "--csv-out",
        type=Path,
        default=None,
        metavar="FILE",
        help="Write CSV output to FILE instead of stdout.",
    )
    p.add_argument(
        "--nvd-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help="Local NVD JSON cache directory (e.g. data/nvd-cache). Enables bulk CVE matching.",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print per-firmware skip reasons.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return process_results_dir(
        results_dir=args.results_dir.resolve(),
        csv_out=args.csv_out.resolve() if args.csv_out else None,
        verbose=args.verbose,
        nvd_dir=args.nvd_dir.resolve() if args.nvd_dir else None,
    )


if __name__ == "__main__":
    sys.exit(main())
