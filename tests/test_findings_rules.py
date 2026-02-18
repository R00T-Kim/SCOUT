from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from _pytest.monkeypatch import MonkeyPatch

from aiedge.findings import _iter_candidate_files, run_findings
from aiedge.stage import StageContext


def _ctx(tmp_path: Path) -> StageContext:
    run_dir = tmp_path / "run"
    logs_dir = run_dir / "logs"
    report_dir = run_dir / "report"
    input_dir = run_dir / "input"
    logs_dir.mkdir(parents=True)
    report_dir.mkdir(parents=True)
    input_dir.mkdir(parents=True)
    return StageContext(run_dir=run_dir, logs_dir=logs_dir, report_dir=report_dir)


def _write_inventory_baseline(ctx: StageContext) -> None:
    inv_dir = ctx.run_dir / "stages" / "inventory"
    inv_dir.mkdir(parents=True, exist_ok=True)
    _ = (inv_dir / "inventory.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "roots": ["stages/extraction/_firmware.bin.extracted/rootfs"],
                "summary": {
                    "roots_scanned": 1,
                    "files": 5,
                    "binaries": 0,
                    "configs": 5,
                    "string_hits": 0,
                },
                "service_candidates": [],
                "services": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _ = (inv_dir / "string_hits.json").write_text(
        json.dumps({"counts": {}, "samples": []}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _read_json(path: Path) -> dict[str, object]:
    return cast(dict[str, object], json.loads(path.read_text(encoding="utf-8")))


def _all_paths_are_run_relative(obj: object) -> bool:
    if isinstance(obj, dict):
        for value in cast(dict[str, object], obj).values():
            if not _all_paths_are_run_relative(value):
                return False
        return True
    if isinstance(obj, list):
        return all(_all_paths_are_run_relative(x) for x in cast(list[object], obj))
    if isinstance(obj, str):
        return not obj.startswith("/") and not (
            len(obj) >= 3 and obj[1] == ":" and obj[2] == "\\"
        )
    return True


def test_run_findings_emits_v2_provenance_first_rules(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    (extracted / "etc" / "ssh").mkdir(parents=True)
    (extracted / "etc" / "xinetd.d").mkdir(parents=True)
    (extracted / "system").mkdir(parents=True)

    _ = (extracted / "etc" / "ssh" / "sshd_config").write_text(
        "PermitRootLogin yes\nPasswordAuthentication yes\nPermitEmptyPasswords yes\n",
        encoding="utf-8",
    )
    _ = (extracted / "etc" / "xinetd.d" / "telnet").write_text(
        "service telnet\n{\n disable = no\n}\n",
        encoding="utf-8",
    )
    _ = (extracted / "system" / "build.prop").write_text(
        "ro.debuggable=1\npersist.sys.usb.config=mtp,adb\n",
        encoding="utf-8",
    )
    _ = (extracted / "init.rc").write_text(
        "service adbd /sbin/adbd\n",
        encoding="utf-8",
    )
    (extracted / "system" / "priv-app" / "DemoApp").mkdir(parents=True)
    _ = (
        extracted / "system" / "priv-app" / "DemoApp" / "AndroidManifest.xml"
    ).write_text(
        '<manifest><application android:debuggable="true"/></manifest>\n',
        encoding="utf-8",
    )
    _ = (extracted / "id_rsa").write_text(
        "-----BEGIN PRIVATE KEY-----\nsecret-body-material\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )

    ota_dir = ctx.run_dir / "stages" / "ota"
    ota_dir.mkdir(parents=True, exist_ok=True)
    _ = (ota_dir / "ota.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "selected_update_archive": "stages/ota/BYDUpdatePackage/UpdateFull.zip",
                "payload_present": True,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    result = run_findings(ctx)
    ids = {cast(str, finding.get("id")) for finding in result.findings}

    assert "aiedge.findings.secrets.private_key_pem" in ids
    assert "aiedge.findings.debug.telnet_enablement" in ids
    assert "aiedge.findings.debug.adb_enablement" in ids
    assert "aiedge.findings.config.ssh_permit_root_login" in ids
    assert "aiedge.findings.config.ssh_password_authentication" in ids
    assert "aiedge.findings.config.ssh_permit_empty_passwords" in ids
    assert "aiedge.findings.debug.android_manifest_debuggable" in ids
    assert "aiedge.findings.update.metadata_present" in ids

    exploit_candidates = _read_json(
        ctx.run_dir / "stages" / "findings" / "exploit_candidates.json"
    )
    candidates = cast(list[dict[str, object]], exploit_candidates.get("candidates", []))
    families = {
        fam
        for item in candidates
        for fam in cast(list[object], item.get("families", []))
        if isinstance(fam, str)
    }
    assert "weak_ssh_password_auth" in families
    assert "weak_ssh_root_login" in families
    assert "weak_ssh_empty_passwords" in families

    by_id = {
        cast(str, f.get("id")): f
        for f in result.findings
        if isinstance(f.get("id"), str)
    }
    key_finding = cast(
        dict[str, object], by_id["aiedge.findings.secrets.private_key_pem"]
    )
    key_evidence = cast(list[dict[str, object]], key_finding["evidence"])
    assert key_evidence
    assert any("snippet_sha256" in ev for ev in key_evidence)
    assert all(not str(ev.get("path", "")).startswith("/") for ev in key_evidence)
    joined_snippets = "\n".join(str(ev.get("snippet", "")) for ev in key_evidence)
    assert "secret-body-material" not in joined_snippets


def test_iter_candidate_files_prioritizes_high_signal_paths_under_cap(
    tmp_path: Path,
) -> None:
    root = tmp_path / "rootfs"
    (root / "aaa" / "noise").mkdir(parents=True)
    for i in range(30):
        _ = (root / "aaa" / "noise" / f"file-{i}.txt").write_text(
            "noise\n", encoding="utf-8"
        )
    (root / "zzz" / "opt" / "vyatta" / "scripts").mkdir(parents=True)
    _ = (root / "zzz" / "opt" / "vyatta" / "scripts" / "peer.sh").write_text(
        '#!/bin/sh\neval "cfg_$1"\n',
        encoding="utf-8",
    )

    files = _iter_candidate_files([root], max_files=10)
    rels = [p.resolve().relative_to(root.resolve()).as_posix() for p in files]
    assert "zzz/opt/vyatta/scripts/peer.sh" in rels


def test_run_findings_keeps_no_signals_when_extracted_has_no_matches(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    (extracted / "etc").mkdir(parents=True)
    _ = (extracted / "etc" / "hostname").write_text("device\n", encoding="utf-8")

    result = run_findings(ctx)
    ids = [cast(str, finding.get("id")) for finding in result.findings]
    assert "aiedge.findings.no_signals" in ids


def test_run_findings_uses_inventory_roots_when_extraction_is_empty(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)

    alt_root = ctx.run_dir / "stages" / "ota" / "carved" / "rootfs"
    (alt_root / "etc" / "xinetd.d").mkdir(parents=True)
    _ = (alt_root / "etc" / "xinetd.d" / "telnet").write_text(
        "service telnet\n{\n disable = no\n}\n",
        encoding="utf-8",
    )

    inv_dir = ctx.run_dir / "stages" / "inventory"
    inv_dir.mkdir(parents=True, exist_ok=True)
    _ = (inv_dir / "inventory.json").write_text(
        json.dumps(
            {
                "status": "ok",
                "roots": [alt_root.relative_to(ctx.run_dir).as_posix()],
                "summary": {
                    "roots_scanned": 1,
                    "files": 1,
                    "binaries": 0,
                    "configs": 1,
                    "string_hits": 0,
                },
                "service_candidates": [],
                "services": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _ = (inv_dir / "string_hits.json").write_text(
        json.dumps({"counts": {}, "samples": []}, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    result = run_findings(ctx)
    ids = {cast(str, finding.get("id")) for finding in result.findings}
    assert "aiedge.findings.debug.telnet_enablement" in ids
    assert "aiedge.findings.analysis_incomplete" not in ids


def test_run_findings_writes_known_disclosures_with_citations(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    (extracted / "etc").mkdir(parents=True)
    _ = (extracted / "etc" / "release-notes.txt").write_text(
        "Patched issue cve-2024-12345 in parser component.\n",
        encoding="utf-8",
    )

    _ = run_findings(ctx)
    known_path = ctx.run_dir / "stages" / "findings" / "known_disclosures.json"
    assert known_path.is_file()

    payload = _read_json(known_path)
    assert payload.get("schema_version") == "known-disclosures-v1"

    matches = cast(list[dict[str, object]], payload.get("matches", []))
    by_id = {
        cast(str, item.get("cve_id")): item
        for item in matches
        if isinstance(item.get("cve_id"), str)
    }
    assert "CVE-2024-12345" in by_id

    record = by_id["CVE-2024-12345"]
    citations = cast(list[object], record.get("citations", []))
    assert "https://nvd.nist.gov/vuln/detail/CVE-2024-12345" in citations

    locations = cast(list[dict[str, object]], record.get("locations", []))
    assert locations
    assert all(not str(item.get("path", "")).startswith("/") for item in locations)


def test_run_findings_writes_known_disclosures_empty_matches(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    (extracted / "etc").mkdir(parents=True)
    _ = (extracted / "etc" / "hostname").write_text("device\n", encoding="utf-8")

    _ = run_findings(ctx)
    known_path = ctx.run_dir / "stages" / "findings" / "known_disclosures.json"
    assert known_path.is_file()

    payload = _read_json(known_path)
    assert payload.get("schema_version") == "known-disclosures-v1"
    assert payload.get("matches") == []
    notes = cast(list[object], payload.get("notes", []))
    assert any("No CVE identifiers matched" in str(note) for note in notes)


def test_run_findings_adds_inventory_string_hits_info_finding(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    (extracted / "etc").mkdir(parents=True)
    _ = (extracted / "etc" / "hostname").write_text("device\n", encoding="utf-8")

    inv_strings = ctx.run_dir / "stages" / "inventory" / "string_hits.json"
    _ = inv_strings.write_text(
        json.dumps(
            {
                "counts": {"password": 1, "api_key": 2, "zero": 0},
                "samples": [
                    {"type": "password", "sample": "super-secret-value"},
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    result = run_findings(ctx)
    by_id = {
        cast(str, f.get("id")): f
        for f in result.findings
        if isinstance(f.get("id"), str)
    }
    string_hits_finding = cast(
        dict[str, object], by_id["aiedge.findings.inventory.string_hits_present"]
    )
    assert string_hits_finding["severity"] == "info"

    description = cast(str, string_hits_finding["description"])
    assert "api_key=2, password=1" in description
    assert "super-secret-value" not in description

    evidence = cast(list[dict[str, object]], string_hits_finding["evidence"])
    assert evidence
    assert evidence[0].get("path") == "stages/inventory/string_hits.json"
    assert "super-secret-value" not in str(evidence[0].get("note", ""))


def test_run_findings_detects_telnet_disabled_info_signal(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    (extracted / "etc" / "xinetd.d").mkdir(parents=True)
    _ = (extracted / "etc" / "xinetd.d" / "telnet").write_text(
        "service telnet\n{\n disable = yes\n}\n",
        encoding="utf-8",
    )

    result = run_findings(ctx)
    by_id = {
        cast(str, f.get("id")): f
        for f in result.findings
        if isinstance(f.get("id"), str)
    }
    telnet_disabled = cast(
        dict[str, object], by_id["aiedge.findings.hardening.telnet_disabled"]
    )
    assert telnet_disabled["severity"] == "info"
    evidence = cast(list[dict[str, object]], telnet_disabled["evidence"])
    assert evidence
    assert all(not str(ev.get("path", "")).startswith("/") for ev in evidence)


def test_run_findings_caps_match_evidence_per_rule(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir
        / "stages"
        / "extraction"
        / "_firmware.bin.extracted"
        / "rootfs"
        / "system"
    )
    extracted.mkdir(parents=True)

    for i in range(10):
        _ = (extracted / f"init-{i}.rc").write_text(
            "service adbd /sbin/adbd\n",
            encoding="utf-8",
        )

    result = run_findings(ctx)
    by_id = {
        cast(str, f.get("id")): f
        for f in result.findings
        if isinstance(f.get("id"), str)
    }
    adb_finding = cast(dict[str, object], by_id["aiedge.findings.debug.adb_enablement"])
    adb_evidence = cast(list[dict[str, object]], adb_finding["evidence"])
    assert len(adb_evidence) <= 5


def test_run_findings_suppresses_non_config_paths_for_common_signals(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    (extracted / "docs").mkdir(parents=True)

    _ = (extracted / "docs" / "sshd_config").write_text(
        "PermitRootLogin yes\n",
        encoding="utf-8",
    )
    _ = (extracted / "docs" / "build.prop").write_text(
        "ro.debuggable=1\n",
        encoding="utf-8",
    )
    _ = (extracted / "docs" / "inetd.conf").write_text(
        "telnet stream tcp nowait root /usr/sbin/telnetd in.telnetd\n",
        encoding="utf-8",
    )

    result = run_findings(ctx)
    ids = {cast(str, finding.get("id")) for finding in result.findings}

    assert "aiedge.findings.config.ssh_permit_root_login" not in ids
    assert "aiedge.findings.debug.adb_enablement" not in ids
    assert "aiedge.findings.debug.telnet_enablement" not in ids
    assert "aiedge.findings.no_signals" in ids


def test_run_findings_writes_pattern_scan_chain_and_gate_artifacts(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    (extracted / "app").mkdir(parents=True)
    (extracted / "etc" / "nginx").mkdir(parents=True)

    handler_src = "\n".join(
        [
            "@app.route('/upload')",
            "def upload(request):",
            "    data = request.files['f']",
            "    tarfile.open(data.filename).extractall('/tmp/work')",
            "    subprocess.run(request.args['cmd'], shell=True)",
        ]
    )
    _ = (extracted / "app" / "handler.py").write_text(
        handler_src + "\n",
        encoding="utf-8",
    )
    _ = (extracted / "app" / "worker.sh").write_text(
        '#!/bin/sh\neval "$USER_INPUT"\n',
        encoding="utf-8",
    )
    _ = (extracted / "app" / "web.php").write_text(
        "<?php system($_GET['cmd']); ?>\n",
        encoding="utf-8",
    )
    _ = (extracted / "etc" / "nginx" / "site.conf").write_text(
        "location ~ \\.php$ { fastcgi_pass unix:/run/php-fpm.sock; }\n",
        encoding="utf-8",
    )
    _ = (extracted / "app" / "libnative.so").write_bytes(
        b"\x00AAAAsystem(\x00BBBBQUERY_STRING\x00CCCC/bin/sh\x00"
    )

    first = run_findings(ctx)
    second = run_findings(ctx)
    first_ids_set = {
        cast(str, finding.get("id"))
        for finding in first.findings
        if isinstance(finding.get("id"), str)
    }
    assert "aiedge.findings.exploit.candidate_plan" in first_ids_set

    findings_dir = ctx.run_dir / "stages" / "findings"
    pattern_scan_path = findings_dir / "pattern_scan.json"
    binary_hits_path = findings_dir / "binary_strings_hits.json"
    chains_path = findings_dir / "chains.json"
    review_path = findings_dir / "review_gates.json"
    exploit_candidates_path = findings_dir / "exploit_candidates.json"
    skeleton_dir = findings_dir / "poc_skeletons"

    assert pattern_scan_path.is_file()
    assert binary_hits_path.is_file()
    assert chains_path.is_file()
    assert review_path.is_file()
    assert exploit_candidates_path.is_file()
    assert skeleton_dir.is_dir()
    assert (skeleton_dir / "README.txt").is_file()

    pattern_scan = _read_json(pattern_scan_path)
    binary_hits = _read_json(binary_hits_path)
    chains_obj = _read_json(chains_path)
    review_obj = _read_json(review_path)
    exploit_candidates = _read_json(exploit_candidates_path)

    assert "generated_at" not in pattern_scan
    assert "generated_at" not in binary_hits
    assert pattern_scan.get("schema_version") == "pattern-scan-v1"
    assert binary_hits.get("schema_version") == "binary-strings-hits-v1"
    assert exploit_candidates.get("schema_version") == "exploit-candidates-v1"
    ruleset = cast(dict[str, object], pattern_scan.get("ruleset", {}))
    assert ruleset.get("budget_mode") == "normal"
    assert ruleset.get("proximity") == {"W_near": 4096, "W_mid": 16384}
    assert binary_hits.get("proximity") == {"W_near": 4096, "W_mid": 16384}
    assert _all_paths_are_run_relative(pattern_scan)
    assert _all_paths_are_run_relative(binary_hits)

    hits = cast(list[dict[str, object]], pattern_scan.get("findings", []))
    families = sorted(
        {
            cast(str, hit.get("family"))
            for hit in hits
            if isinstance(hit.get("family"), str)
        }
    )
    assert "archive_extraction" in families
    assert "auth_decorator_gaps" in families
    assert "upload_exec_chain" in families
    assert "cmd_exec_injection_risk" in families

    cpp_hits = [h for h in hits if h.get("language_layer") == "cpp_strings"]
    assert cpp_hits
    assert all(h.get("needs_manual") is True for h in cpp_hits)
    assert any(
        "stages/findings/binary_strings_hits.json"
        in cast(list[object], h.get("evidence_refs", []))
        for h in cpp_hits
    )

    first_ids = sorted(
        cast(str, hit.get("finding_id"))
        for hit in hits
        if isinstance(hit.get("finding_id"), str)
    )
    second_pattern_scan = _read_json(pattern_scan_path)
    second_hits = cast(list[dict[str, object]], second_pattern_scan.get("findings", []))
    second_ids = sorted(
        cast(str, hit.get("finding_id"))
        for hit in second_hits
        if isinstance(hit.get("finding_id"), str)
    )
    assert first_ids == second_ids

    assert isinstance(chains_obj.get("chains"), list)
    assert isinstance(review_obj.get("items"), list)
    assert _all_paths_are_run_relative(exploit_candidates)
    candidates = cast(list[dict[str, object]], exploit_candidates.get("candidates", []))
    assert candidates
    assert any(item.get("source") == "chain" for item in candidates)
    assert all(isinstance(c.get("candidate_id"), str) for c in candidates)
    assert all(
        c.get("priority") in {"high", "medium", "low"}
        for c in candidates
        if isinstance(c, dict)
    )
    assert all(
        isinstance(c.get("analyst_next_steps"), list) and bool(c.get("analyst_next_steps"))
        for c in candidates
        if isinstance(c, dict)
    )
    assert all(
        isinstance(c.get("attack_hypothesis"), str) and bool(c.get("attack_hypothesis"))
        for c in candidates
        if isinstance(c, dict)
    )
    assert all(
        isinstance(c.get("preconditions"), list) and bool(c.get("preconditions"))
        for c in candidates
        if isinstance(c, dict)
    )
    assert all(
        isinstance(c.get("expected_impact"), list) and bool(c.get("expected_impact"))
        for c in candidates
        if isinstance(c, dict)
    )
    assert all(
        isinstance(c.get("validation_plan"), list) and bool(c.get("validation_plan"))
        for c in candidates
        if isinstance(c, dict)
    )
    summary_any = exploit_candidates.get("summary")
    assert isinstance(summary_any, dict)
    assert cast(dict[str, object], summary_any).get("chain_backed", 0) >= 1

    second_exploit_candidates = _read_json(exploit_candidates_path)
    second_candidates = cast(
        list[dict[str, object]], second_exploit_candidates.get("candidates", [])
    )
    first_candidate_ids = sorted(
        cast(str, item.get("candidate_id"))
        for item in candidates
        if isinstance(item.get("candidate_id"), str)
    )
    second_candidate_ids = sorted(
        cast(str, item.get("candidate_id"))
        for item in second_candidates
        if isinstance(item.get("candidate_id"), str)
    )
    assert first_candidate_ids == second_candidate_ids
    assert first.limitations == second.limitations


def test_run_findings_cpp_sink_only_stays_low_confidence(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    extracted.mkdir(parents=True)
    _ = (extracted / "libcmd.so").write_bytes(b"\x00ABCDsystem(\x00EFGH")

    _ = run_findings(ctx)
    pattern_scan = _read_json(ctx.run_dir / "stages" / "findings" / "pattern_scan.json")
    hits = cast(list[dict[str, object]], pattern_scan.get("findings", []))
    cpp_hits = [h for h in hits if h.get("language_layer") == "cpp_strings"]
    assert cpp_hits
    assert all(float(cast(float, h.get("score", 0.0))) <= 0.35 for h in cpp_hits)
    assert all(cast(str, h.get("confidence", "")) == "low" for h in cpp_hits)
    assert all(h.get("needs_manual") is True for h in cpp_hits)


def test_run_findings_static_pattern_path_weighting_and_noise_suppression(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    (extracted / "app").mkdir(parents=True)
    (extracted / "docs").mkdir(parents=True)

    src = (
        "def handle(request):\n"
        "    subprocess.run(request.args['cmd'], shell=True)\n"
    )
    _ = (extracted / "app" / "handler.py").write_text(src, encoding="utf-8")
    _ = (extracted / "docs" / "sample.py").write_text(src, encoding="utf-8")

    _ = run_findings(ctx)
    pattern_scan = _read_json(ctx.run_dir / "stages" / "findings" / "pattern_scan.json")
    hits = cast(list[dict[str, object]], pattern_scan.get("findings", []))
    python_exec_hits = [
        h
        for h in hits
        if h.get("family") == "cmd_exec_injection_risk"
        and h.get("language_layer") == "python"
    ]
    assert python_exec_hits

    by_path: dict[str, float] = {}
    for hit in python_exec_hits:
        evidence = cast(list[dict[str, object]], hit.get("evidence", []))
        if not evidence:
            continue
        path_any = evidence[0].get("path")
        score_any = hit.get("score")
        if isinstance(path_any, str) and isinstance(score_any, (int, float)):
            by_path[path_any] = float(score_any)

    app_path = "stages/extraction/_firmware.bin.extracted/rootfs/app/handler.py"
    docs_path = "stages/extraction/_firmware.bin.extracted/rootfs/docs/sample.py"
    assert app_path in by_path
    assert by_path[app_path] > 0.66
    assert docs_path not in by_path


def test_run_findings_suppresses_stdlib_exec_noise_and_promotes_opt_shell_signal(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    (extracted / "usr" / "lib" / "python2.7").mkdir(parents=True)
    (extracted / "opt" / "vyatta" / "scripts").mkdir(parents=True)

    _ = (extracted / "usr" / "lib" / "python2.7" / "pipes.py").write_text(
        "import os\nos.system('echo test')\n",
        encoding="utf-8",
    )
    _ = (extracted / "opt" / "vyatta" / "scripts" / "peer.sh").write_text(
        '#!/bin/sh\neval "cfg_$1 ${2:-}"\n',
        encoding="utf-8",
    )

    _ = run_findings(ctx)
    pattern_scan = _read_json(ctx.run_dir / "stages" / "findings" / "pattern_scan.json")
    hits = cast(list[dict[str, object]], pattern_scan.get("findings", []))

    paths = []
    vyatta_scores: list[float] = []
    for hit in hits:
        ev = cast(list[dict[str, object]], hit.get("evidence", []))
        if not ev:
            continue
        path_any = ev[0].get("path")
        if not isinstance(path_any, str):
            continue
        paths.append(path_any)
        if path_any.endswith("/opt/vyatta/scripts/peer.sh"):
            score_any = hit.get("score")
            if isinstance(score_any, (int, float)):
                vyatta_scores.append(float(score_any))

    assert (
        "stages/extraction/_firmware.bin.extracted/rootfs/usr/lib/python2.7/pipes.py"
        not in paths
    )
    assert vyatta_scores and max(vyatta_scores) >= 0.74

    exploit_candidates = _read_json(
        ctx.run_dir / "stages" / "findings" / "exploit_candidates.json"
    )
    summary_any = exploit_candidates.get("summary")
    assert isinstance(summary_any, dict)
    assert cast(dict[str, object], summary_any).get("candidate_count", 0) >= 1


def test_run_findings_limits_per_file_rule_dominance_for_diversity(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    (extracted / "etc" / "bash_completion.d").mkdir(parents=True)
    (extracted / "usr" / "bin").mkdir(parents=True)

    noisy_lines = "\n".join(['eval "cfg_$1"' for _ in range(80)]) + "\n"
    _ = (extracted / "etc" / "bash_completion.d" / "vyatta-cfg").write_text(
        noisy_lines,
        encoding="utf-8",
    )
    _ = (extracted / "usr" / "bin" / "ubnt-helper").write_text(
        '#!/bin/sh\neval "$1"\n',
        encoding="utf-8",
    )

    _ = run_findings(ctx)
    pattern_scan = _read_json(ctx.run_dir / "stages" / "findings" / "pattern_scan.json")
    hits = cast(list[dict[str, object]], pattern_scan.get("findings", []))

    by_path: dict[str, int] = {}
    for hit in hits:
        family = hit.get("family")
        lang = hit.get("language_layer")
        if family != "cmd_exec_injection_risk" or lang != "shell":
            continue
        ev = cast(list[dict[str, object]], hit.get("evidence", []))
        if not ev:
            continue
        path_any = ev[0].get("path")
        if isinstance(path_any, str):
            by_path[path_any] = by_path.get(path_any, 0) + 1

    noisy_path = (
        "stages/extraction/_firmware.bin.extracted/rootfs/"
        "etc/bash_completion.d/vyatta-cfg"
    )
    diverse_path = "stages/extraction/_firmware.bin.extracted/rootfs/usr/bin/ubnt-helper"
    assert by_path.get(noisy_path, 0) <= 3
    assert by_path.get(diverse_path, 0) >= 1


def test_run_findings_promotes_priority_path_medium_score_candidate(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    (extracted / "usr" / "sbin").mkdir(parents=True)
    _ = (extracted / "usr" / "sbin" / "ubnt-update-dpi").write_text(
        "#!/bin/sh\ntar -xvf \"$1\" -C /tmp/dpi\n",
        encoding="utf-8",
    )

    _ = run_findings(ctx)
    exploit_candidates = _read_json(
        ctx.run_dir / "stages" / "findings" / "exploit_candidates.json"
    )
    candidates = cast(list[dict[str, object]], exploit_candidates.get("candidates", []))
    assert candidates
    ubnt_candidates = [
        c
        for c in candidates
        if isinstance(c.get("path"), str)
        and cast(str, c.get("path")).endswith("/usr/sbin/ubnt-update-dpi")
    ]
    assert ubnt_candidates
    assert any(float(cast(float, c.get("score", 0.0))) >= 0.56 for c in ubnt_candidates)


def test_run_findings_promotes_priority_path_low_medium_score_candidate(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    (extracted / "usr" / "bin").mkdir(parents=True)
    _ = (extracted / "usr" / "bin" / "ubnt-upgrade").write_text(
        "#!/bin/sh\ntar -xvf \"$1\" -C /tmp/fw\n",
        encoding="utf-8",
    )

    _ = run_findings(ctx)
    exploit_candidates = _read_json(
        ctx.run_dir / "stages" / "findings" / "exploit_candidates.json"
    )
    candidates = cast(list[dict[str, object]], exploit_candidates.get("candidates", []))
    ubnt_candidates = [
        c
        for c in candidates
        if isinstance(c.get("path"), str)
        and cast(str, c.get("path")).endswith("/usr/bin/ubnt-upgrade")
    ]
    assert ubnt_candidates
    assert all(float(cast(float, c.get("score", 0.0))) >= 0.48 for c in ubnt_candidates)


def test_run_findings_binary_budget_aggressive_mode(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    monkeypatch.setenv("AIEDGE_BINARY_STRINGS_BUDGET", "aggressive")
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    extracted.mkdir(parents=True)
    _ = (extracted / "libagg.so").write_bytes(
        b"\x00AAAApopen(\x00BBBBargv\x00CCCCsh -c\x00"
    )

    result = run_findings(ctx)
    payload = _read_json(
        ctx.run_dir / "stages" / "findings" / "binary_strings_hits.json"
    )
    pattern_scan = _read_json(ctx.run_dir / "stages" / "findings" / "pattern_scan.json")
    bounds = cast(dict[str, object], payload.get("bounds", {}))

    assert payload.get("budget_mode") == "aggressive"
    assert bounds.get("max_bytes_scanned_per_binary") == 4 * 1024 * 1024
    assert bounds.get("max_strings_per_binary") == 50_000
    assert bounds.get("max_anchors_per_binary") == 10
    assert any(
        "relaxed caps" in str(x)
        for x in cast(list[object], payload.get("limitations", []))
    )
    ruleset = cast(dict[str, object], pattern_scan.get("ruleset", {}))
    assert ruleset.get("budget_mode") == "aggressive"
    assert any(
        "Aggressive binary strings budget enabled" in x for x in result.limitations
    )


def test_run_findings_binary_budget_invalid_value_falls_back_to_normal(
    tmp_path: Path,
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setenv("AIEDGE_BINARY_STRINGS_BUDGET", "broken-mode")
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    extracted.mkdir(parents=True)
    _ = (extracted / "libnorm.so").write_bytes(
        b"\x00AAAAexecve(\x00BBBBQUERY_STRING\x00"
    )

    result = run_findings(ctx)
    payload = _read_json(
        ctx.run_dir / "stages" / "findings" / "binary_strings_hits.json"
    )
    bounds = cast(dict[str, object], payload.get("bounds", {}))

    assert payload.get("budget_mode") == "normal"
    assert bounds.get("max_bytes_scanned_per_binary") == 2 * 1024 * 1024
    assert bounds.get("max_strings_per_binary") == 20_000
    assert bounds.get("max_anchors_per_binary") == 10
    assert any(
        "Invalid AIEDGE_BINARY_STRINGS_BUDGET value" in str(x)
        for x in cast(list[object], payload.get("warnings", []))
    )
    assert any(
        "Invalid AIEDGE_BINARY_STRINGS_BUDGET value" in x for x in result.limitations
    )


def test_run_findings_task5_locked_schema_and_cpp_evidence_linkage(
    tmp_path: Path,
) -> None:
    ctx = _ctx(tmp_path)
    _write_inventory_baseline(ctx)

    firmware = ctx.run_dir / "input" / "firmware.bin"
    _ = firmware.write_bytes(b"fw-task5-schema")
    expected_firmware_id = (
        "firmware:80a769e81dc6cd670da55d6d44b9c2f58e96c3fd95407a8325f2a8f040c7cc3d"
    )

    extracted = (
        ctx.run_dir / "stages" / "extraction" / "_firmware.bin.extracted" / "rootfs"
    )
    extracted.mkdir(parents=True)
    _ = (extracted / "libcombo.so").write_bytes(
        b"\x00AAAAsystem(\x00BBBBquery_string\x00CCCC/bin/sh\x00"
    )

    _ = run_findings(ctx)

    binary_hits = _read_json(
        ctx.run_dir / "stages" / "findings" / "binary_strings_hits.json"
    )
    pattern_scan = _read_json(ctx.run_dir / "stages" / "findings" / "pattern_scan.json")

    assert binary_hits.get("schema_version") == "binary-strings-hits-v1"
    assert pattern_scan.get("schema_version") == "pattern-scan-v1"
    assert binary_hits.get("firmware_id") == expected_firmware_id
    assert pattern_scan.get("firmware_id") == expected_firmware_id

    budget_modes = cast(dict[str, object], binary_hits.get("budget_modes", {}))
    assert budget_modes.get("normal") == {
        "max_bytes_scanned_per_binary": 2 * 1024 * 1024,
        "max_strings_per_binary": 20_000,
        "max_anchors_per_binary": 10,
    }
    assert budget_modes.get("aggressive") == {
        "max_bytes_scanned_per_binary": 4 * 1024 * 1024,
        "max_strings_per_binary": 50_000,
        "max_anchors_per_binary": 10,
    }

    binaries = cast(list[dict[str, object]], binary_hits.get("binaries", []))
    assert binaries
    first_bin = binaries[0]
    assert "binary_path" not in first_bin
    assert cast(str, first_bin.get("binary_id", "")).startswith("binary:")
    anchors = cast(list[dict[str, object]], first_bin.get("sink_anchors", []))
    assert anchors

    findings = cast(list[dict[str, object]], pattern_scan.get("findings", []))
    cpp_findings = [
        f
        for f in findings
        if f.get("family") == "cmd_exec_injection_risk"
        and f.get("language_layer") == "cpp_strings"
    ]
    assert cpp_findings
    cpp = cpp_findings[0]
    assert cpp.get("needs_manual") is True
    refs = cast(list[object], cpp.get("evidence_refs", []))
    assert "stages/findings/binary_strings_hits.json" in refs
    assert all(isinstance(x, str) and "/" in x for x in refs)
    assert all(isinstance(x, str) and not x.startswith("/") for x in refs)
    assert all(isinstance(x, str) and ":" not in x for x in refs)
    evidence_items = cast(list[dict[str, object]], cpp.get("evidence", []))
    assert evidence_items
    assert evidence_items[0].get("type") == "cpp_strings"
    assert isinstance(evidence_items[0].get("sink_anchor_index"), int)
    assert isinstance(evidence_items[0].get("token_sha256s"), list)

    assert _all_paths_are_run_relative(binary_hits)
    assert _all_paths_are_run_relative(pattern_scan)
