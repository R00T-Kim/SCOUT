"""TUI rendering: snapshot lines and interactive frame drawing."""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import cast

from .cli_common import (
    _ANSI_BLUE,
    _ANSI_BOLD,
    _ANSI_DIM,
    _ANSI_GREEN,
    _ANSI_MAGENTA,
    _ANSI_RED,
    _ANSI_YELLOW,
    _ansi,
    _as_float,
    _as_int,
    _path_tail,
    _short_text,
    _sorted_count_pairs,
    _tui_ansi_supported,
    _tui_unicode_supported,
)
from .cli_tui_data import (
    _build_tui_snapshot,
    _candidate_evidence_refs,
    _candidate_next_step_text,
    _candidate_signal_badge,
    _candidate_verification_signals,
    _collect_tui_candidate_groups,
    _count_bar,
)


def _build_tui_snapshot_lines(
    *,
    run_dir: Path,
    limit: int,
    use_ansi: bool | None = None,
    use_unicode: bool | None = None,
) -> list[str]:
    if use_ansi is None:
        use_ansi = _tui_ansi_supported()
    if use_unicode is None:
        use_unicode = _tui_unicode_supported()

    snapshot = _build_tui_snapshot(run_dir=run_dir)
    profile = _short_text(snapshot.get("profile"), max_len=40) or "unknown"
    report_status = _short_text(snapshot.get("report_status"), max_len=40) or "unknown"
    gate_passed_text = (
        _short_text(snapshot.get("gate_passed_text"), max_len=16) or "unknown"
    )
    llm_status = _short_text(snapshot.get("llm_status"), max_len=40) or "unknown"
    verdict_state = _short_text(snapshot.get("verdict_state"), max_len=48) or "unknown"
    reason_codes = cast(list[str], snapshot.get("reason_codes", []))
    candidate_count = _as_int(snapshot.get("candidate_count"))
    chain_backed = _as_int(snapshot.get("chain_backed"))
    high = _as_int(snapshot.get("high"))
    medium = _as_int(snapshot.get("medium"))
    low = _as_int(snapshot.get("low"))
    max_bucket = _as_int(snapshot.get("max_bucket"), default=1)
    schema_version = _short_text(snapshot.get("schema_version"), max_len=48) or "unknown"
    verifier_artifacts = cast(
        dict[str, object], snapshot.get("verifier_artifacts", {})
    )
    chain_bundle_index = cast(
        dict[str, str], snapshot.get("chain_bundle_index", {})
    )
    dynamic_present = _as_int(
        len(cast(list[str], verifier_artifacts.get("dynamic_present_refs", [])))
    )
    dynamic_missing_refs = cast(list[str], verifier_artifacts.get("dynamic_missing_refs", []))
    dynamic_total = dynamic_present + _as_int(len(dynamic_missing_refs))
    exploit_bundle_refs = cast(list[str], verifier_artifacts.get("exploit_bundle_refs", []))
    verified_chain_present = bool(verifier_artifacts.get("verified_chain_present", False))

    horizontal = "\u2500" if use_unicode else "-"
    section_rule = horizontal * 96

    lines: list[str] = []
    lines.append(_ansi(f"SCOUT :: {run_dir}", _ANSI_BOLD, _ANSI_MAGENTA, enabled=use_ansi))
    lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
    lines.append(
        _ansi("Status", _ANSI_BOLD, _ANSI_MAGENTA, enabled=use_ansi)
        + f"  profile={profile} | report_completeness={report_status} (gate_passed={gate_passed_text}) | llm={llm_status}"
    )
    verdict_style = (_ANSI_BOLD, _ANSI_RED)
    verdict_upper = verdict_state.upper()
    if "VERIFIED" in verdict_upper:
        verdict_style = (_ANSI_BOLD, _ANSI_GREEN)
    elif "NOT_ATTEMPTED" in verdict_upper:
        verdict_style = (_ANSI_BOLD, _ANSI_YELLOW)
    lines.append("verdict=" + _ansi(verdict_state, *verdict_style, enabled=use_ansi))
    if reason_codes:
        lines.append("reason_codes=" + ", ".join(reason_codes[:5]))
    lines.append("")
    lines.append(_ansi("Exploit Candidate Map", _ANSI_BOLD, _ANSI_MAGENTA, enabled=use_ansi))
    lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
    lines.append(
        f"candidate_count={candidate_count} | chain_backed={chain_backed} | schema={schema_version}"
    )
    if dynamic_total == 0 and not exploit_bundle_refs and not verified_chain_present:
        lines.append(
            "Verifier artifacts: not_started (dynamic_validation=0/0) | verified_chain=no | exploit_bundles=0"
        )
    else:
        dynamic_status = (
            "present"
            if dynamic_missing_refs == []
            and dynamic_total > 0
            else "partial"
            if dynamic_missing_refs
            else "not_started"
        )
        lines.append(
            "Verifier artifacts: "
            f"dynamic_validation={dynamic_status} ({dynamic_present}/{dynamic_total}) | "
            f"verified_chain={'yes' if verified_chain_present else 'no'} | "
            f"exploit_bundles={len(exploit_bundle_refs)}"
        )
    if dynamic_missing_refs:
        lines.append(
            "  missing_dynamic="
            + ", ".join(dynamic_missing_refs[:3])
            + (" ..." if len(dynamic_missing_refs) > 3 else "")
        )
    if exploit_bundle_refs:
        lines.append(
            "  exploit_bundles="
            + ", ".join(
                _path_tail(x, max_segments=3, max_len=96) for x in exploit_bundle_refs[:2]
            )
            + (" ..." if len(exploit_bundle_refs) > 2 else "")
        )
    runtime_model = cast(dict[str, object], snapshot.get("runtime_model", {}))
    runtime_available = bool(runtime_model.get("available", False))
    if runtime_available:
        runtime_summary = cast(
            dict[str, object], runtime_model.get("summary", {})
        )
        rows = cast(list[object], runtime_model.get("rows", []))
        runtime_system_map_any = runtime_summary.get("runtime_system_map", [])
        (
            [cast(dict[str, object], x) for x in cast(list[object], runtime_system_map_any)]
            if isinstance(runtime_system_map_any, list)
            else []
        )
        runtime_protocol_counts_any = runtime_summary.get("service_count_by_protocol", {})
        runtime_protocol_counts = (
            cast(dict[str, int], runtime_protocol_counts_any)
            if isinstance(runtime_protocol_counts_any, dict)
            else {}
        )
        runtime_host_service_counts_any = runtime_summary.get("host_service_counts", {})
        runtime_host_service_counts = (
            cast(dict[str, int], runtime_host_service_counts_any)
            if isinstance(runtime_host_service_counts_any, dict)
            else {}
        )
        lines.append(
            f"runtime: hosts={_as_int(runtime_summary.get('hosts'))} | "
            f"services={_as_int(runtime_summary.get('services'))} | "
            f"components={_as_int(runtime_summary.get('components'))} | "
            f"D={_as_int(runtime_summary.get('rows_dynamic'))} "
            f"E={_as_int(runtime_summary.get('rows_exploit'))} "
            f"V={_as_int(runtime_summary.get('rows_verified_chain'))} "
            f"D+E={_as_int(runtime_summary.get('rows_dynamic_exploit'))} | "
            f"status={_short_text(runtime_model.get('status'), max_len=16) or 'partial'}"
        )
        if runtime_protocol_counts:
            protocol_text = ", ".join(
                f"{k}:{v}" for k, v in _sorted_count_pairs(runtime_protocol_counts, limit=4)
            )
            if protocol_text:
                lines.append(f"runtime_protocols: {protocol_text}")
        if runtime_host_service_counts:
            host_text = ", ".join(
                f"{k}->{v}"
                for k, v in _sorted_count_pairs(runtime_host_service_counts, limit=4)
            )
            if host_text:
                lines.append(f"runtime_system_map: {host_text}")
        lines.append(
            _ansi("Runtime Exposure Model", _ANSI_BOLD, _ANSI_MAGENTA, enabled=use_ansi)
        )
        lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
        if rows:
            lines.append("service_protocol_component map:")
            for row_any in rows[: min(limit, len(rows))]:
                row = cast(dict[str, object], row_any)
                row_host = _short_text(row.get("host"), max_len=24)
                row_service_host = _short_text(row.get("service_host"), max_len=24)
                row_port = _as_int(row.get("port"))
                row_protocol = (
                    _short_text(row.get("protocol"), max_len=10) or "tcp"
                ).upper()
                row_components = row.get("components", [])
                if not isinstance(row_components, list):
                    row_components = []
                components = ", ".join(
                    _short_text(v, max_len=24) for v in cast(list[str], row_components[:2])
                )
                evidence_badge = (
                    _short_text(row.get("evidence_badge"), max_len=16) or "S"
                )
                evidence_counts = (
                    f"D{_as_int(row.get('dynamic_evidence_count'))}"
                    f"/E{_as_int(row.get('exploit_evidence_count'))}"
                    f"/V{_as_int(row.get('verified_chain_evidence_count'))}"
                )
                dynamic_exploit = bool(row.get("dynamic_exploit_chain", False))
                badge_style = (_ANSI_BOLD, _ANSI_RED) if dynamic_exploit else (_ANSI_BOLD, _ANSI_YELLOW)
                rendered_badge = _ansi(
                    evidence_badge,
                    *badge_style,
                    enabled=use_ansi,
                )
                evidence_signals = row.get("evidence_signals")
                if not isinstance(evidence_signals, list):
                    evidence_signals = []
                evidence_text = ",".join(
                    sorted(
                        str(x)
                        for x in cast(list[object], evidence_signals)
                        if isinstance(x, str)
                    )
                )
                if not evidence_text:
                    evidence_text = evidence_badge
                service_endpoint = f"{row_service_host}:{row_port}/{row_protocol}"
                lines.append(
                    f"  {row_host: <24} | {service_endpoint: <18} | "
                    f"{(components if components else 'unmapped'): <24} "
                    f"[{rendered_badge}] {evidence_counts} ({evidence_text})"
                )
            lines.append(
                "  legend: D=dynamic, E=exploit, V=verified_chain, S=static, D+E=D+E"
            )
        else:
            lines.append("service_protocol_component map: (no mapped host->service rows)")
    else:
        lines.append("Runtime Exposure Model: unavailable")

    threat_model = cast(dict[str, object], snapshot.get("threat_model", {}))
    if threat_model:
        lines.append("")
        lines.append(_ansi("Threat Modeling Overview", _ANSI_BOLD, _ANSI_MAGENTA, enabled=use_ansi))
        lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
        if bool(threat_model.get("available")):
            tm_status = _short_text(threat_model.get("status"), max_len=20) or "unknown"
            tm_threats = _as_int(threat_model.get("threat_count"))
            tm_unknowns = _as_int(threat_model.get("unknown_count"))
            tm_mitigations = _as_int(threat_model.get("mitigation_count"))
            tm_assumptions = _as_int(threat_model.get("assumption_count"))
            tm_surface_items = _as_int(threat_model.get("attack_surface_items"))
            tm_class = _short_text(threat_model.get("classification"), max_len=20) or "-"
            tm_obs = _short_text(threat_model.get("observation"), max_len=28) or "-"
            lines.append(
                f"threat_model: status={tm_status} | threats={tm_threats} | unknowns={tm_unknowns} | "
                f"mitigations={tm_mitigations} | assumptions={tm_assumptions} | "
                f"attack_surface_items={tm_surface_items}"
            )
            lines.append(f"classification={tm_class} | observation={tm_obs}")
            category_counts_any = threat_model.get("category_counts")
            category_counts = (
                cast(dict[str, int], category_counts_any)
                if isinstance(category_counts_any, dict)
                else {}
            )
            category_text = ", ".join(
                f"{k}={v}" for k, v in _sorted_count_pairs(category_counts, limit=4)
            ) or "-"
            lines.append(f"categories: {category_text}")
            top_threats_any = threat_model.get("top_threats")
            top_threats = (
                [x for x in cast(list[object], top_threats_any) if isinstance(x, str)]
                if isinstance(top_threats_any, list)
                else []
            )
            if top_threats:
                lines.append("top_threats:")
                for sample in top_threats[:3]:
                    lines.append("  - " + sample)
            limitations_any = threat_model.get("limitations")
            limitations = (
                [x for x in cast(list[object], limitations_any) if isinstance(x, str)]
                if isinstance(limitations_any, list)
                else []
            )
            if limitations:
                lines.append("limitations: " + ", ".join(limitations[:3]))
        else:
            lines.append("threat_model: unavailable (run stage: threat_model)")

    runtime_health = cast(dict[str, object], snapshot.get("runtime_health", {}))
    if runtime_health:
        blockers_any = runtime_health.get("blockers")
        blockers = (
            [x for x in cast(list[object], blockers_any) if isinstance(x, str)]
            if isinstance(blockers_any, list)
            else []
        )
        limitations_any = runtime_health.get("limitations")
        limitations = (
            [x for x in cast(list[object], limitations_any) if isinstance(x, str)]
            if isinstance(limitations_any, list)
            else []
        )
        remediation_any = runtime_health.get("remediation")
        remediation = (
            [x for x in cast(list[object], remediation_any) if isinstance(x, str)]
            if isinstance(remediation_any, list)
            else []
        )

        state = _short_text(runtime_health.get("state"), max_len=20) or "unknown"
        dyn_status = _short_text(runtime_health.get("dynamic_status"), max_len=20) or "unknown"
        dyn_scope = _short_text(runtime_health.get("dynamic_scope"), max_len=28) or "unknown"
        target_ip = _short_text(runtime_health.get("target_ip"), max_len=40) or "-"
        boot_success = bool(runtime_health.get("boot_success"))
        boot_attempts = _as_int(runtime_health.get("boot_attempts"))
        emu_status = _short_text(runtime_health.get("emulation_status"), max_len=20) or "unknown"
        priv_mode = _short_text(runtime_health.get("privileged_mode"), max_len=20) or "-"
        status_color = (_ANSI_BOLD, _ANSI_GREEN) if state == "healthy" else (_ANSI_BOLD, _ANSI_YELLOW)

        lines.append("")
        lines.append(_ansi("Runtime Reliability", _ANSI_BOLD, _ANSI_MAGENTA, enabled=use_ansi))
        lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
        lines.append(
            "state="
            + _ansi(state, *status_color, enabled=use_ansi)
            + f" | dynamic={dyn_status}({dyn_scope}) | emulation={emu_status} | target={target_ip}"
        )
        lines.append(
            f"boot: success={'yes' if boot_success else 'no'} attempts={boot_attempts} | privileged={priv_mode}"
        )
        if limitations:
            lines.append("limitations: " + ", ".join(limitations[:3]))
        if blockers:
            lines.append(
                _ansi(
                    "blockers: " + ", ".join(blockers[:4]),
                    _ANSI_YELLOW,
                    enabled=use_ansi,
                )
            )
        last_error = _short_text(runtime_health.get("last_error"), max_len=180)
        if last_error:
            lines.append("last_error: " + last_error)
        if remediation:
            lines.append("quick_fix:")
            for hint in remediation[:4]:
                lines.append("  - " + hint)

    asset_inventory = cast(dict[str, object], snapshot.get("asset_inventory", {}))
    if asset_inventory:
        service_kinds_any = asset_inventory.get("service_kind_counts")
        service_kinds = (
            cast(dict[str, int], service_kinds_any)
            if isinstance(service_kinds_any, dict)
            else {}
        )
        endpoint_types_any = asset_inventory.get("endpoint_type_counts")
        endpoint_types = (
            cast(dict[str, int], endpoint_types_any)
            if isinstance(endpoint_types_any, dict)
            else {}
        )
        endpoint_protocols_any = asset_inventory.get("endpoint_protocol_counts")
        endpoint_protocols = (
            cast(dict[str, int], endpoint_protocols_any)
            if isinstance(endpoint_protocols_any, dict)
            else {}
        )
        dynamic_protocols_any = asset_inventory.get("dynamic_protocol_counts")
        dynamic_protocols = (
            cast(dict[str, int], dynamic_protocols_any)
            if isinstance(dynamic_protocols_any, dict)
            else {}
        )
        dynamic_states_any = asset_inventory.get("dynamic_state_counts")
        dynamic_states = (
            cast(dict[str, int], dynamic_states_any)
            if isinstance(dynamic_states_any, dict)
            else {}
        )
        top_daemons_any = asset_inventory.get("top_daemons")
        top_daemons = (
            [x for x in cast(list[object], top_daemons_any) if isinstance(x, str)]
            if isinstance(top_daemons_any, list)
            else []
        )
        service_paths_any = asset_inventory.get("service_paths")
        service_paths = (
            [x for x in cast(list[object], service_paths_any) if isinstance(x, str)]
            if isinstance(service_paths_any, list)
            else []
        )
        open_ports_any = asset_inventory.get("open_ports")
        open_ports = (
            [x for x in cast(list[object], open_ports_any) if isinstance(x, str)]
            if isinstance(open_ports_any, list)
            else []
        )
        port_samples_any = asset_inventory.get("port_samples")
        port_samples = (
            [x for x in cast(list[object], port_samples_any) if isinstance(x, str)]
            if isinstance(port_samples_any, list)
            else []
        )
        interfaces_any = asset_inventory.get("interfaces")
        interfaces = (
            [x for x in cast(list[object], interfaces_any) if isinstance(x, str)]
            if isinstance(interfaces_any, list)
            else []
        )
        candidate_paths_any = asset_inventory.get("candidate_paths")
        candidate_paths = (
            [x for x in cast(list[object], candidate_paths_any) if isinstance(x, str)]
            if isinstance(candidate_paths_any, list)
            else []
        )

        kind_text = ", ".join(
            f"{k}={v}" for k, v in _sorted_count_pairs(service_kinds, limit=4)
        ) or "-"
        endpoint_type_text = ", ".join(
            f"{k}={v}" for k, v in _sorted_count_pairs(endpoint_types, limit=4)
        ) or "-"
        endpoint_protocol_text = ", ".join(
            f"{k}={v}" for k, v in _sorted_count_pairs(endpoint_protocols, limit=4)
        ) or "-"
        dynamic_protocol_text = ", ".join(
            f"{k}={v}" for k, v in _sorted_count_pairs(dynamic_protocols, limit=3)
        ) or "-"
        dynamic_state_text = ", ".join(
            f"{k}={v}" for k, v in _sorted_count_pairs(dynamic_states, limit=4)
        ) or "-"
        scan_strategy = _short_text(asset_inventory.get("scan_strategy"), max_len=32) or "default"
        scan_coverage = _as_float(asset_inventory.get("scan_coverage_pct"), default=0.0)
        scan_range_total = _as_int(asset_inventory.get("scan_range_total"))
        scan_budget_hit = bool(asset_inventory.get("scan_budget_hit", False))
        target_ip = _short_text(asset_inventory.get("target_ip"), max_len=40) or "-"

        lines.append("")
        lines.append(
            _ansi("Firmware Service & Protocol Inventory", _ANSI_BOLD, _ANSI_MAGENTA, enabled=use_ansi)
        )
        lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
        lines.append(
            "inventory: "
            f"files={_as_int(asset_inventory.get('files'))} "
            f"binaries={_as_int(asset_inventory.get('binaries'))} "
            f"configs={_as_int(asset_inventory.get('configs'))} "
            f"service_candidates={_as_int(asset_inventory.get('service_candidates'))}"
        )
        lines.append(f"service_kinds: {kind_text}")
        if top_daemons:
            lines.append("daemon_candidates: " + ", ".join(top_daemons[:8]))
        if service_paths:
            lines.append(
                "daemon_evidence: "
                + ", ".join(_path_tail(x, max_segments=6, max_len=96) for x in service_paths[:3])
            )
        lines.append(
            f"endpoints: total={_as_int(asset_inventory.get('endpoint_total'))} | types={endpoint_type_text}"
        )
        lines.append(
            f"protocols: static_url={endpoint_protocol_text} | dynamic_probe={dynamic_protocol_text}"
        )
        port_line = (
            f"ports: target={target_ip} | probed={_as_int(asset_inventory.get('probed_ports'))} "
            f"| open={len(open_ports)} | states={dynamic_state_text}"
        )
        if scan_range_total > 0:
            port_line += f" | coverage={scan_coverage:.1f}%/{scan_range_total}"
        if scan_strategy and scan_strategy != "default":
            port_line += f" | scan={scan_strategy}"
        lines.append(port_line)
        if scan_budget_hit:
            lines.append("  scan_note=budget_hit (increase AIEDGE_PORTSCAN_BUDGET_S if needed)")
        if open_ports:
            lines.append("  open_ports=" + ", ".join(open_ports[:6]))
        elif port_samples:
            lines.append("  probed_sample=" + ", ".join(port_samples[:6]))
        if interfaces:
            lines.append("interfaces: " + ", ".join(interfaces[:4]))
        if candidate_paths:
            lines.append("candidate_paths(top): " + ", ".join(candidate_paths[:4]))

    lines.append(
        _ansi(_count_bar("HIGH", count=high, max_count=max_bucket), _ANSI_RED, enabled=use_ansi)
    )
    lines.append(
        _ansi(
            _count_bar("MEDIUM", count=medium, max_count=max_bucket),
            _ANSI_YELLOW,
            enabled=use_ansi,
        )
    )
    lines.append(
        _ansi(_count_bar("LOW", count=low, max_count=max_bucket), _ANSI_GREEN, enabled=use_ansi)
    )

    candidates = cast(list[dict[str, object]], snapshot.get("candidates", []))
    if not candidates:
        lines.append("")
        lines.append("(no candidates)")
        return lines

    lines.append("")
    candidate_groups = cast(
        list[dict[str, object]], snapshot.get("candidate_groups", [])
    )
    if not candidate_groups:
        candidate_groups = _collect_tui_candidate_groups(candidates)

    lines.append(
        f"Top {min(limit, len(candidate_groups))} grouped candidate(s) [compact]"
    )
    lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
    lines.append(f"Candidate groups: {len(candidate_groups)} unique")
    lines.append(_ansi("ID  P   Score   Hits  Evidence  Family", _ANSI_BOLD, _ANSI_BLUE, enabled=use_ansi))
    lines.append(_ansi(section_rule, _ANSI_DIM, enabled=use_ansi))
    previous_triplet: tuple[str, str, str] | None = None
    for idx, group in enumerate(candidate_groups[: min(limit, len(candidate_groups))], start=1):
        priority = _short_text(group.get("priority"), max_len=12) or "unknown"
        priority_tag = priority[:1].upper() if priority else "?"
        family = _short_text(group.get("family"), max_len=42) or "unknown"
        count = _as_int(group.get("path_count"))
        max_score = _as_float(group.get("max_score"))
        source = _short_text(group.get("source", ""), max_len=16) or "unknown"
        representative_id = _short_text(group.get("representative_id"), max_len=120)
        representative: dict[str, object] | None = None
        if representative_id:
            for candidate in candidates:
                if (
                    _short_text(candidate.get("candidate_id"), max_len=120)
                    == representative_id
                ):
                    representative = candidate
                    break
        signal_items = ["static"]
        if representative is not None:
            signal_text = ",".join(
                _candidate_verification_signals(
                    representative,
                    chain_bundle_index=chain_bundle_index,
                    verified_chain_present=verified_chain_present,
                )
            )
            if signal_text:
                signal_items = signal_text.split(",")
        signal_badge = _candidate_signal_badge(signal_items)
        header_line = (
            f"G{idx:02d} [{priority_tag}] family={family} source={source} "
            f"count={count} max_score={max_score:.3f} evidence={signal_badge}"
        )
        priority_style: tuple[str, ...] = (_ANSI_DIM,)
        if priority_tag == "H":
            priority_style = (_ANSI_BOLD, _ANSI_RED)
        elif priority_tag == "M":
            priority_style = (_ANSI_BOLD, _ANSI_YELLOW)
        elif priority_tag == "L":
            priority_style = (_ANSI_BOLD, _ANSI_GREEN)
        lines.append(_ansi(header_line, *priority_style, enabled=use_ansi))

        path_signature = _short_text(group.get("path_signature"), max_len=72) or "(unspecified)"
        lines.append(f"    path: {path_signature}")
        hypothesis = _short_text(group.get("hypothesis"), max_len=140)
        impact = _short_text(group.get("impact"), max_len=140)
        next_step = _short_text(group.get("next_step"), max_len=140)
        current_triplet = (hypothesis, impact, next_step)
        if previous_triplet is not None and current_triplet == previous_triplet:
            lines.append("    note: same attack/impact/next as previous candidate group")
        else:
            if hypothesis:
                lines.append(f"    attack: {hypothesis}")
            if impact:
                lines.append(f"    impact: {impact}")
            if next_step:
                lines.append(f"    next: {next_step}")
        previous_triplet = current_triplet

        lines.append(f"    source={source} | evidence={','.join(signal_items)}")
        sample_paths_all = cast(list[str], group.get("sample_paths"))
        sample_paths = [x for x in sample_paths_all if isinstance(x, str) and x]
        if sample_paths:
            lines.append("    sample_paths:")
            for sample in sample_paths[:3]:
                lines.append(f"      - {_path_tail(sample, max_segments=6, max_len=96)}")

    return lines


def _safe_curses_addstr(
    window: object,
    *,
    y: int,
    x: int,
    text: str,
    attr: int = 0,
) -> None:
    win = cast("curses._CursesWindow", window)  # noqa: F821
    max_y, max_x = win.getmaxyx()
    if y < 0 or y >= max_y or x >= max_x:
        return
    allowed = max(0, max_x - x - 1)
    if allowed <= 0:
        return
    snippet = text[:allowed]
    try:
        if attr:
            win.addstr(y, x, snippet, attr)
        else:
            win.addstr(y, x, snippet)
    except Exception:
        return


def _build_tui_color_theme(*, curses_mod: object) -> dict[str, int]:
    curses = cast(object, curses_mod)
    theme: dict[str, int] = {}
    try:
        has_colors = bool(getattr(curses, "has_colors")())
    except Exception:
        has_colors = False
    if not has_colors:
        return theme

    try:
        _ = getattr(curses, "start_color")()
    except Exception:
        return theme

    try:
        use_default = getattr(curses, "use_default_colors", None)
        if callable(use_default):
            use_default()
    except Exception:
        pass

    # pair id -> foreground / background(default)
    pair_defs: list[tuple[int, int]] = [
        (1, getattr(curses, "COLOR_MAGENTA")),  # header
        (2, getattr(curses, "COLOR_GREEN")),  # success
        (3, getattr(curses, "COLOR_YELLOW")),  # warning
        (4, getattr(curses, "COLOR_RED")),  # error/high
        (5, getattr(curses, "COLOR_MAGENTA")),  # accent
        (6, getattr(curses, "COLOR_BLUE")),  # divider/meta
    ]

    for pair_id, fg in pair_defs:
        try:
            getattr(curses, "init_pair")(pair_id, int(fg), -1)
        except Exception:
            continue

    try:
        theme["header"] = int(getattr(curses, "color_pair")(1)) | int(
            getattr(curses, "A_BOLD")
        )
        theme["success"] = int(getattr(curses, "color_pair")(2))
        theme["warning"] = int(getattr(curses, "color_pair")(3))
        theme["error"] = int(getattr(curses, "color_pair")(4))
        theme["accent"] = int(getattr(curses, "color_pair")(5))
        theme["meta"] = int(getattr(curses, "color_pair")(6))
    except Exception:
        return {}
    return theme


def _draw_interactive_tui_frame(
    *,
    stdscr: object,
    run_dir: Path,
    snapshot: dict[str, object],
    candidates: list[dict[str, object]],
    candidate_groups: list[dict[str, object]],
    selected_index: int,
    list_limit: int,
    detail_mode: str = "candidate",
    theme: dict[str, int] | None = None,
) -> None:
    import curses

    win = cast("curses._CursesWindow", stdscr)
    win.erase()
    max_y, max_x = win.getmaxyx()
    if max_y < 14 or max_x < 72:
        _safe_curses_addstr(
            win,
            y=0,
            x=0,
            text="Terminal too small (need >=72x14). Resize and retry.",
        )
        win.refresh()
        return

    theme = theme or {}

    def _attr(name: str, *, bold: bool = False) -> int:
        base = int(theme.get(name, 0))
        if bold:
            base |= curses.A_BOLD
        return base

    if not candidate_groups:
        candidate_groups = _collect_tui_candidate_groups(candidates)

    profile = _short_text(snapshot.get("profile"), max_len=24) or "unknown"
    report_status = _short_text(snapshot.get("report_status"), max_len=20) or "unknown"
    gate_passed_text = (
        _short_text(snapshot.get("gate_passed_text"), max_len=16) or "unknown"
    )
    llm_status = _short_text(snapshot.get("llm_status"), max_len=20) or "unknown"
    verdict_state = _short_text(snapshot.get("verdict_state"), max_len=40) or "unknown"
    reason_codes = cast(list[str], snapshot.get("reason_codes", []))
    high = _as_int(snapshot.get("high"))
    medium = _as_int(snapshot.get("medium"))
    low = _as_int(snapshot.get("low"))
    chain_backed = _as_int(snapshot.get("chain_backed"))
    candidate_count = _as_int(snapshot.get("candidate_count"))
    verifier_artifacts = cast(
        dict[str, object], snapshot.get("verifier_artifacts", {})
    )
    chain_bundle_index = cast(
        dict[str, str], snapshot.get("chain_bundle_index", {})
    )
    dynamic_missing = cast(list[str], verifier_artifacts.get("dynamic_missing_refs", []))
    dynamic_total = len(cast(list[str], verifier_artifacts.get("dynamic_required_refs", [])))
    dynamic_present = max(0, dynamic_total - len(dynamic_missing))
    exploit_bundle_refs = cast(list[str], verifier_artifacts.get("exploit_bundle_refs", []))
    verified_chain_present = bool(verifier_artifacts.get("verified_chain_present", False))
    runtime_model = cast(dict[str, object], snapshot.get("runtime_model", {}))
    runtime_summary = cast(dict[str, object], runtime_model.get("summary", {}))
    runtime_available = bool(runtime_model.get("available"))
    asset_inventory = cast(dict[str, object], snapshot.get("asset_inventory", {}))
    threat_model = cast(dict[str, object], snapshot.get("threat_model", {}))
    runtime_health = cast(dict[str, object], snapshot.get("runtime_health", {}))
    runtime_protocol_counts_any = runtime_summary.get("service_count_by_protocol", {})
    runtime_protocol_counts = (
        cast(dict[str, int], runtime_protocol_counts_any)
        if isinstance(runtime_protocol_counts_any, dict)
        else {}
    )
    runtime_system_map_any = runtime_summary.get("runtime_system_map", [])
    runtime_system_map = (
        [cast(dict[str, object], x) for x in cast(list[object], runtime_system_map_any)]
        if isinstance(runtime_system_map_any, list)
        else []
    )
    runtime_host_services_any = runtime_summary.get("host_service_counts", {})
    runtime_host_services = (
        cast(dict[str, int], runtime_host_services_any)
        if isinstance(runtime_host_services_any, dict)
        else {}
    )

    _safe_curses_addstr(
        win,
        y=0,
        x=0,
        text=f"SCOUT Interactive TUI :: {run_dir.name}",
        attr=_attr("header"),
    )
    _safe_curses_addstr(
        win,
        y=1,
        x=0,
        text=(
            f"status  profile:{profile}  report:{report_status}(gate={gate_passed_text})  "
            f"llm:{llm_status}"
        ),
        attr=_attr("accent"),
    )
    verdict_upper = verdict_state.upper()
    verdict_attr = _attr("warning")
    if "VERIFIED" in verdict_upper:
        verdict_attr = _attr("success", bold=True)
    elif "FAILED" in verdict_upper:
        verdict_attr = _attr("error", bold=True)
    _safe_curses_addstr(
        win,
        y=2,
        x=0,
        text=(
            f"verdict {verdict_state}"
            + (
                f"  |  reason: {', '.join(reason_codes[:2])}"
                + (f" (+{len(reason_codes) - 2})" if len(reason_codes) > 2 else "")
                if reason_codes
                else "  |  reason: -"
            )
        ),
        attr=verdict_attr,
    )
    _safe_curses_addstr(
        win,
        y=3,
        x=0,
        text=(
            f"scope   candidates:{candidate_count}  high:{high}  medium:{medium}  low:{low}  "
            f"chain_backed:{chain_backed}"
        ),
        attr=_attr("accent"),
    )
    proof_attr = (
        _attr("success")
        if dynamic_total > 0 and dynamic_present == dynamic_total
        else _attr("warning")
    )
    _safe_curses_addstr(
        win,
        y=4,
        x=0,
        text=(
            f"proof   dynamic:{dynamic_present}/{dynamic_total}  "
            f"verified_chain:{'on' if verified_chain_present else 'off'}  "
            f"bundles:{len(exploit_bundle_refs)}"
        ),
        attr=proof_attr,
    )
    _safe_curses_addstr(
        win,
        y=5,
        x=0,
        text=(
            f"runtime {'on' if runtime_available else 'off'}  "
            f"hosts:{_as_int(runtime_summary.get('hosts'))}  "
            f"services:{_as_int(runtime_summary.get('services'))}  "
            f"components:{_as_int(runtime_summary.get('components'))}  "
            f"D+E:{_as_int(runtime_summary.get('rows_dynamic_exploit'))}  "
            f"D:{_as_int(runtime_summary.get('rows_dynamic'))} "
            f"E:{_as_int(runtime_summary.get('rows_exploit'))} "
            f"V:{_as_int(runtime_summary.get('rows_verified_chain'))}"
        ),
        attr=_attr("meta"),
    )
    proto_text_runtime = ", ".join(
        f"{k}:{v}" for k, v in _sorted_count_pairs(runtime_protocol_counts, limit=4)
    ) or "-"
    map_text = ", ".join(
        f"{k}->{v}" for k, v in _sorted_count_pairs(runtime_host_services, limit=4)
    ) or "-"
    if proto_text_runtime:
        _safe_curses_addstr(
            win,
            y=6,
            x=0,
            text=f"runtime_proto:{proto_text_runtime}",
            attr=_attr("meta"),
        )
    if map_text:
        _safe_curses_addstr(
            win,
            y=7,
            x=0,
            text=f"runtime_map:{map_text}",
            attr=_attr("meta"),
        )
    asset_protocol_counts_any = asset_inventory.get("endpoint_protocol_counts")
    asset_protocol_counts = (
        cast(dict[str, int], asset_protocol_counts_any)
        if isinstance(asset_protocol_counts_any, dict)
        else {}
    )
    asset_open_ports_any = asset_inventory.get("open_ports")
    asset_open_ports = (
        [x for x in cast(list[object], asset_open_ports_any) if isinstance(x, str)]
        if isinstance(asset_open_ports_any, list)
        else []
    )
    proto_text = ",".join(
        f"{k}:{v}" for k, v in _sorted_count_pairs(asset_protocol_counts, limit=2)
    ) or "-"
    asset_scan_cov = _as_float(asset_inventory.get("scan_coverage_pct"), default=0.0)
    blockers_any = runtime_health.get("blockers")
    blockers_count = (
        len([x for x in cast(list[object], blockers_any) if isinstance(x, str)])
        if isinstance(blockers_any, list)
        else 0
    )
    health_line = 8
    _safe_curses_addstr(
        win,
        y=health_line,
        x=0,
        text=(
            f"health  state:{_short_text(runtime_health.get('state'), max_len=12) or '-'}  "
            f"dyn:{_short_text(runtime_health.get('dynamic_status'), max_len=12) or '-'}  "
            f"emu:{_short_text(runtime_health.get('emulation_status'), max_len=12) or '-'}  "
            f"boot:{'ok' if bool(runtime_health.get('boot_success')) else 'no'}  "
            f"blockers:{blockers_count}"
        ),
        attr=_attr("warning"),
    )
    _safe_curses_addstr(
        win,
        y=health_line + 1,
        x=0,
        text=(
            f"assets  files:{_as_int(asset_inventory.get('files'))}  "
            f"bins:{_as_int(asset_inventory.get('binaries'))}  "
            f"svcs:{_as_int(asset_inventory.get('service_candidates'))}  "
            f"proto:{proto_text}  "
            f"ports_open:{len(asset_open_ports)}/{_as_int(asset_inventory.get('probed_ports'))}  "
            f"scan_cov:{asset_scan_cov:.0f}%"
        ),
        attr=_attr("meta"),
    )
    threat_row_line = 9
    tm_available = bool(threat_model.get("available"))
    tm_status = _short_text(threat_model.get("status"), max_len=12) or "-"
    tm_threats = _as_int(threat_model.get("threat_count"))
    tm_unknowns = _as_int(threat_model.get("unknown_count"))
    tm_mitigations = _as_int(threat_model.get("mitigation_count"))
    tm_categories_any = threat_model.get("category_counts")
    tm_categories = (
        cast(dict[str, int], tm_categories_any)
        if isinstance(tm_categories_any, dict)
        else {}
    )
    tm_category_text = ",".join(
        f"{k}:{v}" for k, v in _sorted_count_pairs(tm_categories, limit=2)
    ) or "-"
    tm_attr = _attr("success") if tm_available and tm_threats > 0 else _attr("warning")
    _safe_curses_addstr(
        win,
        y=threat_row_line,
        x=0,
        text=(
            f"threat  {'on' if tm_available else 'off'}  status:{tm_status}  "
            f"threats:{tm_threats}  unknowns:{tm_unknowns}  mitigations:{tm_mitigations}  "
            f"top:{tm_category_text}"
        ),
        attr=tm_attr,
    )
    status_row = max_y - 1
    if runtime_system_map:
        map_line = threat_row_line + 1
        for map_entry in runtime_system_map[: max(1, max_y - map_line - 1)]:
            host_label = _short_text(map_entry.get("host"), max_len=24) or "unknown"
            service_count = _as_int(map_entry.get("service_count"))
            component_count = _as_int(map_entry.get("component_count"))
            services_any = map_entry.get("services")
            service_values = (
                [x for x in cast(list[object], services_any) if isinstance(x, str)]
                if isinstance(services_any, list)
                else []
            )
            service_sample = ", ".join(service_values[:2]) or "-"
            _safe_curses_addstr(
                win,
                y=map_line,
                x=0,
                text=(
                    f"runtime_map {host_label:<24} svcs={service_count:<3} "
                    f"daemons={component_count:<3} {service_sample}"
                ),
                attr=_attr("meta"),
            )
            map_line += 1
        divider_y = max(map_line, threat_row_line + 1)
    else:
        divider_y = threat_row_line

    divider_y = min(divider_y, status_row - 1)

    _safe_curses_addstr(
        win,
        y=divider_y,
        x=0,
        text="-" * (max_x - 1),
        attr=_attr("meta"),
    )

    list_top = divider_y + 1
    list_height = max(3, status_row - list_top)
    list_body_height = max(1, list_height - 1)
    left_width = max(42, int(max_x * 0.52))
    left_width = min(left_width, max_x - 24)
    right_x = left_width + 2

    _safe_curses_addstr(
        win,
        y=list_top - 1,
        x=0,
        text=(
            "[Candidate Groups] "
            f"showing {min(list_limit, len(candidate_groups))}/{len(candidate_groups)}"
        ),
        attr=_attr("header"),
    )
    detail_title = {
        "threat": "Threat Model",
        "runtime": "Runtime Model",
        "asset": "Asset & Protocol Inventory",
    }.get(detail_mode, "Details")
    _safe_curses_addstr(
        win,
        y=list_top - 1,
        x=right_x,
        text=f"[{detail_title}]",
        attr=_attr("header"),
    )
    _safe_curses_addstr(
        win,
        y=list_top,
        x=0,
        text="#  P  Score  Hits  Family                      Sig",
        attr=_attr("accent", bold=True),
    )
    _safe_curses_addstr(
        win,
        y=list_top,
        x=right_x,
        text="Sig: S=static C=chain D=dynamic E=bundle V=verified",
        attr=_attr("meta"),
    )
    for y in range(list_top - 1, status_row):
        _safe_curses_addstr(win, y=y, x=left_width + 1, text="|", attr=_attr("meta"))

    shown_groups = candidate_groups[:list_limit]
    if not shown_groups:
        _safe_curses_addstr(win, y=list_top + 1, x=0, text="(no candidate groups)")
    else:
        selected_index = max(0, min(selected_index, len(shown_groups) - 1))
        if selected_index < list_body_height // 2:
            start = 0
        else:
            start = selected_index - (list_body_height // 2)
        max_start = max(0, len(shown_groups) - list_body_height)
        start = min(start, max_start)
        stop = min(len(shown_groups), start + list_body_height)

        for row, idx in enumerate(range(start, stop), start=1):
            group = shown_groups[idx]
            pr = _short_text(group.get("priority"), max_len=12) or "unknown"
            pr_tag = pr[:1].upper() if pr else "?"
            score = _as_float(group.get("max_score"))
            family = _short_text(group.get("family"), max_len=24) or "unknown"
            path_count = _as_int(group.get("path_count"))
            representative_id = _short_text(group.get("representative_id"), max_len=120)
            representative: dict[str, object] | None = None
            if representative_id:
                for item in candidates:
                    if (
                        _short_text(item.get("candidate_id"), max_len=120)
                        == representative_id
                    ):
                        representative = item
                        break
            signal_items = ["static"]
            if representative is not None:
                signal_text = ",".join(
                    _candidate_verification_signals(
                        representative,
                        chain_bundle_index=chain_bundle_index,
                        verified_chain_present=verified_chain_present,
                    )
                )
                if signal_text:
                    signal_items = signal_text.split(",")
            signal_badge = _candidate_signal_badge(signal_items)
            family_cell = _short_text(family, max_len=26)
            line = (
                f"{idx + 1:02d} {pr_tag:>2} {score:>6.3f}  x{path_count:<2}  "
                f"{family_cell:<26}  [{signal_badge}]"
            )
            max_line_width = max(18, left_width - 3)
            if len(line) > max_line_width:
                line = line[:max_line_width]
            row_attr = 0
            if pr_tag == "H":
                row_attr = _attr("error")
            elif pr_tag == "M":
                row_attr = _attr("warning")
            elif pr_tag == "L":
                row_attr = _attr("success")
            else:
                row_attr = _attr("meta")
            attr = (row_attr | curses.A_REVERSE | curses.A_BOLD) if idx == selected_index else row_attr
            _safe_curses_addstr(win, y=list_top + row, x=0, text=line, attr=attr)

    details: list[str] = []
    right_width = max(24, max_x - right_x - 3)

    def _wrap_detail(text: str, *, prefix: str = "") -> list[str]:
        wrapped = textwrap.wrap(
            text,
            width=max(12, right_width - len(prefix)),
            break_long_words=False,
            break_on_hyphens=False,
        )
        if not wrapped:
            return [prefix]
        return [prefix + part for part in wrapped]

    dynamic_protocols_any = asset_inventory.get("dynamic_protocol_counts")
    dynamic_protocols = (
        cast(dict[str, int], dynamic_protocols_any)
        if isinstance(dynamic_protocols_any, dict)
        else {}
    )
    dynamic_states_any = asset_inventory.get("dynamic_state_counts")
    dynamic_states = (
        cast(dict[str, int], dynamic_states_any)
        if isinstance(dynamic_states_any, dict)
        else {}
    )
    endpoint_types_any = asset_inventory.get("endpoint_type_counts")
    endpoint_types = (
        cast(dict[str, int], endpoint_types_any)
        if isinstance(endpoint_types_any, dict)
        else {}
    )
    interfaces_any = asset_inventory.get("interfaces")
    interfaces = (
        [x for x in cast(list[object], interfaces_any) if isinstance(x, str)]
        if isinstance(interfaces_any, list)
        else []
    )
    service_paths_any = asset_inventory.get("service_paths")
    service_paths = (
        [x for x in cast(list[object], service_paths_any) if isinstance(x, str)]
        if isinstance(service_paths_any, list)
        else []
    )
    top_daemons_any = asset_inventory.get("top_daemons")
    top_daemons = (
        [x for x in cast(list[object], top_daemons_any) if isinstance(x, str)]
        if isinstance(top_daemons_any, list)
        else []
    )

    if detail_mode == "threat":
        details.append("view: threat model (c: candidates)")
        details.append("")
        tm = cast(dict[str, object], snapshot.get("threat_model", {}))
        if not bool(tm.get("available")):
            details.append("threat_model: unavailable")
            details.append("hint: run stage threat_model")
        else:
            details.append(
                f"status={_short_text(tm.get('status'), max_len=12) or '-'}  "
                f"threats={_as_int(tm.get('threat_count'))}  "
                f"unknowns={_as_int(tm.get('unknown_count'))}"
            )
            details.append(
                f"mitigations={_as_int(tm.get('mitigation_count'))}  "
                f"assumptions={_as_int(tm.get('assumption_count'))}"
            )
            details.append(
                f"attack_surface_items={_as_int(tm.get('attack_surface_items'))}"
            )
            tm_cat_any = tm.get("category_counts")
            tm_cat = cast(dict[str, int], tm_cat_any) if isinstance(tm_cat_any, dict) else {}
            cat_text = ", ".join(
                f"{k}:{v}" for k, v in _sorted_count_pairs(tm_cat, limit=4)
            ) or "-"
            details.extend(_wrap_detail("categories: " + cat_text))
            details.append("")
            tm_top_any = tm.get("top_threats")
            tm_top = (
                [x for x in cast(list[object], tm_top_any) if isinstance(x, str)]
                if isinstance(tm_top_any, list)
                else []
            )
            details.append("top_threats:")
            if tm_top:
                for sample in tm_top[:3]:
                    details.extend(_wrap_detail(sample, prefix="  - "))
            else:
                details.append("  - (none)")

            tm_lim_any = tm.get("limitations")
            tm_lim = (
                [x for x in cast(list[object], tm_lim_any) if isinstance(x, str)]
                if isinstance(tm_lim_any, list)
                else []
            )
            if tm_lim:
                details.append("")
                details.append("limitations:")
                for item in tm_lim[:3]:
                    details.extend(_wrap_detail(item, prefix="  - "))

        details.append("")
        details.append("system context:")
        details.append(
            f"runtime hosts={_as_int(runtime_summary.get('hosts'))} "
            f"services={_as_int(runtime_summary.get('services'))} "
            f"components={_as_int(runtime_summary.get('components'))}"
        )
        details.append(
            f"assets endpoints={_as_int(asset_inventory.get('endpoint_total'))} "
            f"daemons={_as_int(asset_inventory.get('service_candidates'))} "
            f"open_ports={len(asset_open_ports)}"
        )
    elif detail_mode == "runtime":
        details.append("view: runtime model (c: candidates)")
        details.append("")
        runtime_rows = cast(list[object], runtime_model.get("rows", []))
        runtime_system_map_local = runtime_summary.get("runtime_system_map", [])
        runtime_system_map_local_rows = (
            [cast(dict[str, object], x) for x in cast(list[object], runtime_system_map_local)]
            if isinstance(runtime_system_map_local, list)
            else []
        )
        details.append(
            f"status={_short_text(runtime_model.get('status'), max_len=12) or '-'}  "
            f"hosts={_as_int(runtime_summary.get('hosts'))}  "
            f"services={_as_int(runtime_summary.get('services'))}  "
            f"components={_as_int(runtime_summary.get('components'))}  "
            f"rows={len(runtime_rows)}"
        )
        details.append(
            f"evidence: "
            f"D={_as_int(runtime_summary.get('rows_dynamic'))}, "
            f"E={_as_int(runtime_summary.get('rows_exploit'))}, "
            f"V={_as_int(runtime_summary.get('rows_verified_chain'))}, "
            f"D+E={_as_int(runtime_summary.get('rows_dynamic_exploit'))}"
        )
        runtime_protocol_counts_any = runtime_summary.get("service_count_by_protocol", {})
        runtime_protocol_counts = (
            cast(dict[str, int], runtime_protocol_counts_any)
            if isinstance(runtime_protocol_counts_any, dict)
            else {}
        )
        if runtime_protocol_counts:
            details.append(
                "protocols: "
                + ", ".join(
                    f"{k}:{v}" for k, v in _sorted_count_pairs(runtime_protocol_counts, limit=6)
                )
            )
        if runtime_system_map_local_rows:
            details.append("")
            details.append("system map:")
            for row in runtime_system_map_local_rows[: max(3, min(6, right_width // 16))]:
                host = _short_text(row.get("host"), max_len=24)
                service_count = _as_int(row.get("service_count"))
                component_count = _as_int(row.get("component_count"))
                services_any = row.get("services")
                service_values = (
                    [x for x in cast(list[object], services_any) if isinstance(x, str)]
                    if isinstance(services_any, list)
                    else []
                )
                details.append(
                    f" - {host:<18} svcs:{service_count:>2} daemons:{component_count:>2} "
                    f"{', '.join(service_values[:3])}"
                )
        if runtime_rows:
            details.append("")
            details.append("top_communications:")
            for row_any in runtime_rows[: max(6, min(10, right_width // 12))]:
                row = cast(dict[str, object], row_any)
                row_host = _short_text(row.get("host"), max_len=16)
                row_service_host = _short_text(row.get("service_host"), max_len=16)
                row_port = _as_int(row.get("port"))
                row_protocol = (_short_text(row.get("protocol"), max_len=8) or "tcp").upper()
                row_badge = _short_text(row.get("evidence_badge"), max_len=8) or "S"
                row_components = row.get("components")
                if not isinstance(row_components, list):
                    row_components = []
                component_text = ", ".join(_short_text(v, max_len=20) for v in row_components[:2])
                if not component_text:
                    component_text = "unmapped"
                evidence_signals = row.get("evidence_signals")
                if not isinstance(evidence_signals, list):
                    evidence_signals = []
                evidence_text = ",".join(
                    sorted(
                        str(x)
                        for x in cast(list[object], evidence_signals)
                        if isinstance(x, str)
                    )
                )
                if not evidence_text:
                    evidence_text = row_badge
                evidence_counts = (
                    f"D{_as_int(row.get('dynamic_evidence_count'))}"
                    f"/E{_as_int(row.get('exploit_evidence_count'))}"
                    f"/V{_as_int(row.get('verified_chain_evidence_count'))}"
                )
                svc = f"{row_service_host}:{row_port}/{row_protocol}"
                details.extend(
                    _wrap_detail(
                        f" - {row_host: <15} => {svc: <16} [{row_badge}] "
                        f"{evidence_counts} {component_text} ({evidence_text})"
                    )
                )
        else:
            details.append("")
            details.append("communication matrix: unavailable or empty")
    elif detail_mode == "asset":
        details.append("view: asset inventory (c: candidates)")
        details.append("")
        details.append(
            f"files={_as_int(asset_inventory.get('files'))}  "
            f"binaries={_as_int(asset_inventory.get('binaries'))}  "
            f"configs={_as_int(asset_inventory.get('configs'))}  "
            f"service_candidates={_as_int(asset_inventory.get('service_candidates'))}"
        )
        kind_pairs = cast(
            dict[str, int],
            asset_inventory.get("service_kind_counts", {})
            if isinstance(asset_inventory.get("service_kind_counts"), dict)
            else {},
        )
        if kind_pairs:
            kind_text = ", ".join(
                f"{k}:{v}" for k, v in _sorted_count_pairs(kind_pairs, limit=6)
            )
            details.append(f"service_kinds={kind_text}")
        if endpoint_types:
            endpoint_text = ", ".join(
                f"{k}:{v}" for k, v in _sorted_count_pairs(endpoint_types, limit=5)
            )
            details.append(f"endpoint_types={endpoint_text}")
        details.append(
            f"open_ports={len(asset_open_ports)}  "
            f"probed={_as_int(asset_inventory.get('probed_ports'))}  "
            f"scan_strategy={_short_text(asset_inventory.get('scan_strategy'), max_len=16)}"
        )
        if asset_open_ports:
            details.append("open_ports=" + ", ".join(asset_open_ports[:6]))
        proto_pairs = _sorted_count_pairs(
            cast(
                dict[str, int],
                dynamic_protocols if isinstance(dynamic_protocols, dict) else {},
            ),
            limit=4,
        )
        if proto_pairs:
            details.append(
                "dynamic_proto="
                + ", ".join(f"{k}:{v}" for k, v in proto_pairs)
            )
        state_pairs = _sorted_count_pairs(
            cast(
                dict[str, int],
                dynamic_states if isinstance(dynamic_states, dict) else {},
            ),
            limit=4,
        )
        if state_pairs:
            details.append(
                "dynamic_state="
                + ", ".join(f"{k}:{v}" for k, v in state_pairs)
            )
        if interfaces:
            details.append("interfaces=" + ", ".join(interfaces[:5]))
        daemon_paths = [
            x for x in cast(list[object], service_paths) if isinstance(x, str)
        ]
        if daemon_paths:
            details.append(
                "daemon_evidence="
                + ", ".join(_path_tail(x, max_segments=5, max_len=96) for x in daemon_paths[:4])
            )
        if top_daemons:
            details.append("top_daemons=" + ", ".join(top_daemons[:6]))
    elif shown_groups:
        selected = cast(dict[str, object], shown_groups[selected_index])
        representative_id = _short_text(selected.get("representative_id"), max_len=120)
        representative = None
        if representative_id:
            for item in candidates:
                if _short_text(item.get("candidate_id"), max_len=120) == representative_id:
                    representative = item
                    break
        path_signature = _short_text(selected.get("path_signature"), max_len=72)

        details.append(
            f"group G{selected_index + 1:02d}  "
            f"priority={_short_text(selected.get('priority'), max_len=10)}  "
            f"family={_short_text(selected.get('family'), max_len=28)}"
        )
        details.append(
            f"score={_as_float(selected.get('max_score')):.3f}  hits={_as_int(selected.get('path_count'))}"
        )
        if path_signature:
            details.extend(_wrap_detail(f"path: {path_signature}"))
        details.append("")

        if representative is not None:
            details.extend(
                _wrap_detail(
                    "candidate_id: "
                    + (
                        _short_text(
                            representative.get("candidate_id"),
                            max_len=max(20, right_width - 2),
                        )
                        or "(none)"
                    )
                )
            )
            rep_chain_id = _short_text(representative.get("chain_id"), max_len=48)
            if rep_chain_id:
                details.append(f"chain_id: {rep_chain_id}")
            details.append(
                "source: "
                + (
                    f"{_short_text(representative.get('source'), max_len=16) or 'unknown'}"
                )
            )

            selected_signals = _candidate_verification_signals(
                representative,
                chain_bundle_index=chain_bundle_index,
                verified_chain_present=verified_chain_present,
            )
            details.append(
                "signals: "
                + (
                    ",".join(selected_signals)
                    if selected_signals
                    else "static"
                )
                + f" [{_candidate_signal_badge(selected_signals)}]"
            )
            details.append("")

            representative_path = (
                _path_tail(
                    representative.get("path"),
                    max_segments=6,
                    max_len=max(24, right_width - 2),
                )
                or "(none)"
            )
            details.extend(_wrap_detail("path: " + representative_path))

            attack_text = _short_text(
                representative.get("attack_hypothesis"),
                max_len=max(24, right_width * 3),
            ) or "(none)"
            details.append("attack:")
            details.extend(_wrap_detail(attack_text, prefix="  "))

            impacts_any = representative.get("expected_impact")
            if isinstance(impacts_any, list):
                impacts = [x for x in cast(list[object], impacts_any) if isinstance(x, str)]
            else:
                impacts = []
            impact_text = _short_text(
                impacts[0] if impacts else "(none)",
                max_len=max(24, right_width * 2),
            )
            details.append("impact:")
            details.extend(_wrap_detail(impact_text, prefix="  "))

            next_text = _candidate_next_step_text(representative) or "(none)"
            details.append("next:")
            details.extend(_wrap_detail(next_text, prefix="  "))

            refs = _candidate_evidence_refs(
                representative,
                chain_bundle_index=chain_bundle_index,
                include_chain_bundles=True,
            )
            details.append("evidence_refs:")
            if refs:
                for ref in refs[:3]:
                    details.extend(
                        _wrap_detail(
                            _short_text(ref, max_len=max(20, right_width * 2)),
                            prefix="  - ",
                        )
                    )
            else:
                details.append("  - (none)")
        else:
            details.append("No representative candidate available.")
    else:
        details.append("No candidate groups available.")

    truncated_detail_lines = max(0, len(details) - list_height)
    visible_detail_rows = list_height if truncated_detail_lines == 0 else max(1, list_height - 1)
    for i, line in enumerate(details[:visible_detail_rows]):
        detail_attr = 0
        if line.startswith("attack:") or line.startswith("impact:"):
            detail_attr = _attr("warning", bold=True)
        elif line.startswith("next:"):
            detail_attr = _attr("accent", bold=True)
        elif line.startswith("evidence_refs:"):
            detail_attr = _attr("meta", bold=True)
        elif line.startswith("  - "):
            detail_attr = _attr("meta")
        elif (
            line.startswith("candidate_id:")
            or line.startswith("group G")
            or line.startswith("view:")
            or line.startswith("status=")
            or line.startswith("threat_model:")
        ):
            detail_attr = _attr("header")
        _safe_curses_addstr(
            win,
            y=list_top + i,
            x=right_x,
            text=line,
            attr=detail_attr,
        )
    if truncated_detail_lines > 0:
        _safe_curses_addstr(
            win,
            y=list_top + visible_detail_rows,
            x=right_x,
            text=f"... (+{truncated_detail_lines} more lines)",
            attr=_attr("meta"),
        )

    _safe_curses_addstr(
        win,
        y=status_row,
        x=0,
        text="j/k or \u2191/\u2193 move | g/G top/bottom | c candidate | t threat | m runtime | a assets | r refresh | q quit",
        attr=_attr("meta"),
    )
    win.refresh()
