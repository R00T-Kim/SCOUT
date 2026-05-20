from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType


def _load_import_script() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / "import_poc_in_github_candidates.py"
    spec = importlib.util.spec_from_file_location("import_poc_in_github_candidates", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _repo(description: str = "Totolink X6000R command injection PoC") -> dict[str, object]:
    return {
        "id": 123,
        "name": "CVE-2024-1781",
        "full_name": "researcher/CVE-2024-1781",
        "owner": "researcher",
        "html_url": "https://github.com/researcher/CVE-2024-1781",
        "description": description,
        "fork": False,
        "created_at": "2024-02-12T00:00:00Z",
        "updated_at": "2024-02-12T00:00:00Z",
        "pushed_at": "2024-02-12T00:00:00Z",
        "stargazers_count": 0,
        "forks_count": 0,
        "watchers_count": 0,
        "topics": ["iot", "router", "command-injection"],
    }


def test_cli_imports_explicit_cve_without_cloning(monkeypatch, tmp_path: Path) -> None:
    module = _load_import_script()
    fetched: list[str] = []

    def fake_fetch(cve: str, *, timeout_s: float) -> list[dict[str, object]]:
        fetched.append(f"{cve}:{timeout_s}")
        return [_repo()]

    monkeypatch.setattr(module, "fetch_poc_in_github_cve", fake_fetch)

    rc = module.main(["--cve", "cve-2024-1781", "--output-dir", str(tmp_path), "--timeout-s", "2"])

    assert rc == 0
    assert fetched == ["CVE-2024-1781:2.0"]
    written = tmp_path / "cve-2024-1781.json"
    assert written.exists()
    candidate = json.loads(written.read_text(encoding="utf-8"))
    assert candidate["source"] == "nomi-sec/PoC-in-GitHub"
    assert candidate["status"] == "unreviewed_candidate"
    assert candidate["promotion_required"] is True
    assert candidate["candidate_family"] == "cmd_injection"
    assert candidate["candidate_domain"] == "firmware_or_network_appliance"
    assert any("clone referenced repositories" in item for item in candidate["extraction_contract"]["forbidden_use"])


def test_cli_dry_run_does_not_write(monkeypatch, tmp_path: Path, capsys) -> None:
    module = _load_import_script()
    monkeypatch.setattr(module, "fetch_poc_in_github_cve", lambda cve, *, timeout_s: [_repo()])

    rc = module.main(["--cve", "CVE-2024-1781", "--output-dir", str(tmp_path), "--dry-run"])

    assert rc == 0
    assert not list(tmp_path.glob("*.json"))
    stdout = capsys.readouterr().out
    assert '"cve": "CVE-2024-1781"' in stdout
    assert '"status": "unreviewed_candidate"' in stdout


def test_cli_uses_seed_file_when_cve_omitted(monkeypatch, tmp_path: Path) -> None:
    module = _load_import_script()
    seed_file = tmp_path / "seeds.json"
    seed_file.write_text(
        json.dumps(
            {
                "schema_version": "test",
                "cves": [
                    {"cve": "CVE-2023-1389", "summary": "TP-Link router command injection"},
                    {"cve": "CVE-2024-3273", "summary": "D-Link NAS CGI command injection"},
                ],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "fetch_poc_in_github_cve", lambda cve, *, timeout_s: [_repo()])

    rc = module.main(["--seed-file", str(seed_file), "--output-dir", str(tmp_path / "out")])

    assert rc == 0
    assert (tmp_path / "out" / "cve-2023-1389.json").exists()
    assert (tmp_path / "out" / "cve-2024-3273.json").exists()


def test_firmware_seed_file_is_metadata_only_allowlist() -> None:
    seed_file = Path(__file__).resolve().parents[1] / "data" / "exploit_references" / "firmware_seed_cves.json"
    seeds = json.loads(seed_file.read_text(encoding="utf-8"))

    assert seeds["source"] == "nomi-sec/PoC-in-GitHub"
    assert "Do not clone" in seeds["safety_note"]
    assert seeds["selection_policy"]["domain"] == "firmware_or_network_appliance"
    assert {entry["expected_family"] for entry in seeds["cves"]} == {"cmd_injection"}
    assert len(seeds["cves"]) >= 3
