#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="dry-run"
FROM_VERSION=""
TO_VERSION=""
RELEASE_DATE="$(date +%F)"
CREATE_TAG=0
CREATE_GH_RELEASE=0

usage() {
  cat <<'USAGE'
Usage: scripts/release.sh [--dry-run|--apply] [TARGET_VERSION]

Options:
  --dry-run              Show the edits without writing files (default)
  --apply                Write file changes
  --from-version X.Y.Z   Explicit source version (default: read from pyproject.toml)
  --to-version X.Y.Z     Explicit target version
  --date YYYY-MM-DD      Release date for CHANGELOG promotion
  --tag                  In apply mode, create git tag v<target>
  --gh-release           In apply mode, create/update GitHub release for v<target>
  -h, --help             Show this help

Notes:
  - If TARGET_VERSION is provided positionally, it behaves like --to-version.
  - The script updates pyproject.toml, README.md, README.ko.md, and CHANGELOG.md.
  - CHANGELOG promotion is idempotent: if the target section already exists, it is left as-is.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) MODE="dry-run"; shift ;;
    --apply) MODE="apply"; shift ;;
    --from-version) FROM_VERSION="$2"; shift 2 ;;
    --to-version) TO_VERSION="$2"; shift 2 ;;
    --date) RELEASE_DATE="$2"; shift 2 ;;
    --tag) CREATE_TAG=1; shift ;;
    --gh-release) CREATE_GH_RELEASE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *)
      if [[ -z "$TO_VERSION" ]]; then
        TO_VERSION="$1"
        shift
      else
        echo "Unknown argument: $1" >&2
        usage >&2
        exit 2
      fi
      ;;
  esac
done

exec python3 - "$MODE" "$REPO_ROOT" "$FROM_VERSION" "$TO_VERSION" "$RELEASE_DATE" "$CREATE_TAG" "$CREATE_GH_RELEASE" <<'PY'
from __future__ import annotations

import difflib
import re
import subprocess
import sys
from pathlib import Path

mode = sys.argv[1]
repo_root = Path(sys.argv[2]).resolve()
from_version_arg = sys.argv[3].strip()
to_version_arg = sys.argv[4].strip()
release_date = sys.argv[5].strip()
create_tag = bool(int(sys.argv[6]))
create_gh_release = bool(int(sys.argv[7]))

pyproject = repo_root / "pyproject.toml"
readmes = [repo_root / "README.md", repo_root / "README.ko.md"]
changelog = repo_root / "CHANGELOG.md"


def read_project_version(path: Path) -> str:
    m = re.search(r'^version\s*=\s*"([^"]+)"\s*$', path.read_text(encoding="utf-8"), re.MULTILINE)
    if not m:
        raise SystemExit(f"[RELEASE][FAIL] unable to read version from {path}")
    return m.group(1)


def bump_patch(version: str) -> str:
    parts = version.split('.')
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise SystemExit(f"[RELEASE][FAIL] version is not semver X.Y.Z: {version}")
    major, minor, patch = map(int, parts)
    return f"{major}.{minor}.{patch + 1}"


def patch_pyproject(text: str, from_version: str, to_version: str) -> str:
    return re.sub(r'(^version\s*=\s*")' + re.escape(from_version) + r'("\s*$)', r'\g<1>' + to_version + r'\2', text, flags=re.MULTILINE)


def patch_readme(text: str, from_version: str, to_version: str) -> str:
    return text.replace(f"Version-{from_version}-red", f"Version-{to_version}-red")


def patch_changelog(text: str, to_version: str, release_date: str) -> str:
    target_header = f"## [{to_version}]"
    if target_header in text:
        return text
    unreleased = "## [Unreleased]"
    if unreleased not in text:
        raise SystemExit("[RELEASE][FAIL] changelog missing [Unreleased] header")
    replacement = f"## [Unreleased]\n\n_No unreleased changes yet._\n\n## [{to_version}] — {release_date}"
    return text.replace(unreleased, replacement, 1)


from_version = from_version_arg or read_project_version(pyproject)
to_version = to_version_arg or bump_patch(from_version)
if from_version == to_version:
    raise SystemExit("[RELEASE][FAIL] from-version and to-version are identical")

print(f"[RELEASE][INFO] mode={mode} from={from_version} to={to_version} date={release_date}")

files = {
    pyproject: patch_pyproject(pyproject.read_text(encoding="utf-8"), from_version, to_version),
    changelog: patch_changelog(changelog.read_text(encoding="utf-8"), to_version, release_date),
}
for readme in readmes:
    files[readme] = patch_readme(readme.read_text(encoding="utf-8"), from_version, to_version)

changed = []
for path, updated in files.items():
    original = path.read_text(encoding="utf-8")
    if original == updated:
        continue
    changed.append(path)
    rel = path.relative_to(repo_root)
    print(f"[RELEASE][PLAN] {rel}")
    if mode == "apply":
        path.write_text(updated, encoding="utf-8")
        print(f"[RELEASE][WRITE] {rel}")
    else:
        diff = difflib.unified_diff(
            original.splitlines(keepends=True),
            updated.splitlines(keepends=True),
            fromfile=f"a/{rel}",
            tofile=f"b/{rel}",
        )
        sys.stdout.writelines(diff)

if not changed:
    print("[RELEASE][INFO] no file content changes were needed")

if mode == "apply" and create_tag:
    tag = f"v{to_version}"
    existing = subprocess.run(["git", "tag", "--list", tag], cwd=repo_root, capture_output=True, text=True, check=False)
    if existing.stdout.strip():
        print(f"[RELEASE][INFO] tag already exists: {tag}")
    else:
        subprocess.run(["git", "tag", tag], cwd=repo_root, check=True)
        print(f"[RELEASE][TAG] {tag}")
    if create_gh_release:
        subprocess.run([
            "gh", "release", "create", tag,
            "--title", tag,
            "--notes-file", str(changelog),
        ], cwd=repo_root, check=True)
        print(f"[RELEASE][GH] release created: {tag}")

print("[RELEASE][DONE]")
PY
