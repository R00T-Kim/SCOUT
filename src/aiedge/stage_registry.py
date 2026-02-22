from __future__ import annotations

import importlib
import json
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Protocol, cast

from .carving import CarvingStage
from .attack_surface import AttackSurfaceStage
from .attribution import AttributionStage
from .endpoints import EndpointsStage
from .extraction import ExtractionStage
from .firmware_profile import FirmwareProfileStage
from .firmware_lineage import FirmwareLineageStage
from .graph import GraphStage
from .inventory import InventoryStage
from .llm_synthesis import LLMSynthesisStage
from .functional_spec import FunctionalSpecStage
from .surfaces import SurfacesStage
from .ota import OtaStage
from .ota_payload import OtaPayloadStage
from .threat_model import ThreatModelStage
from .stage import Stage
from .structure import StructureStage
from .tooling import ToolingStage


class _RunInfoLike(Protocol):
    @property
    def firmware_dest(self) -> Path: ...


StageFactory = Callable[[_RunInfoLike, str | None, Callable[[], float], bool], Stage]


def _quantize_remaining_budget_s(remaining_budget_s: float) -> int:
    return max(0, int(float(remaining_budget_s)))


def _env_int(name: str, *, default: int, min_value: int, max_value: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return int(default)
    try:
        value = int(raw)
    except Exception:
        return int(default)
    if value < int(min_value):
        return int(min_value)
    if value > int(max_value):
        return int(max_value)
    return int(value)


def _load_manifest_rootfs_path(manifest_path: Path | None) -> Path | None:
    if not isinstance(manifest_path, Path) or not manifest_path.is_file():
        return None
    try:
        payload_any = cast(object, json.loads(manifest_path.read_text(encoding="utf-8")))
    except Exception:
        return None
    if not isinstance(payload_any, dict):
        return None
    rootfs_any = cast(dict[str, object], payload_any).get("rootfs_input_path")
    if not isinstance(rootfs_any, str):
        return None
    rootfs_s = rootfs_any.strip()
    if not rootfs_s:
        return None
    return Path(rootfs_s).expanduser()


def _make_emulation_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    mod = importlib.import_module("aiedge.emulation")
    cls = cast(type[Stage], getattr(mod, "EmulationStage"))
    return cls()


def _make_dynamic_validation_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    mod = importlib.import_module("aiedge.dynamic_validation")
    cls = cast(type[Stage], getattr(mod, "DynamicValidationStage"))
    return cls()


def _make_exploit_gate_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    mod = importlib.import_module("aiedge.exploit_chain")
    cls = cast(type[Stage], getattr(mod, "ExploitGateStage"))
    return cls()


def _make_exploit_chain_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    mod = importlib.import_module("aiedge.exploit_chain")
    cls = cast(type[Stage], getattr(mod, "ExploitChainStage"))
    return cls()


def _make_exploit_autopoc_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    mod = importlib.import_module("aiedge.exploit_autopoc")
    cls = cast(type[Stage], getattr(mod, "ExploitAutoPoCStage"))
    return cls(no_llm=no_llm)


def _make_exploit_policy_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    mod = importlib.import_module("aiedge.exploit_policy")
    cls = cast(type[Stage], getattr(mod, "ExploitEvidencePolicyStage"))
    return cls()


def _make_poc_validation_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    mod = importlib.import_module("aiedge.poc_validation")
    cls = cast(type[Stage], getattr(mod, "PocValidationStage"))
    return cls()


def _make_ota_fs_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    mod = importlib.import_module("aiedge.ota_fs")
    cls = cast(type[Stage], getattr(mod, "OtaFsStage"))
    return cls()


def _make_ota_roots_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    mod = importlib.import_module("aiedge.ota_roots")
    cls = cast(type[Stage], getattr(mod, "OtaRootsStage"))
    return cls()


def _make_ota_boottriage_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    mod = importlib.import_module("aiedge.ota_boottriage")
    cls = cast(type[Stage], getattr(mod, "OtaBootTriageStage"))
    return cls()


def _make_tooling_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    return ToolingStage()


def _make_ota_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = remaining_s, no_llm
    return OtaStage(info.firmware_dest, source_input_path=source_input_path)


def _make_ota_payload_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = source_input_path, remaining_s, no_llm
    return OtaPayloadStage(info.firmware_dest)


def _make_extraction_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = source_input_path, no_llm
    remaining_budget_s_raw = remaining_s()
    remaining_budget_s = _quantize_remaining_budget_s(remaining_budget_s_raw)
    timeout_s = min(600, remaining_budget_s)
    manifest_path_any = getattr(info, "manifest_path", None)
    manifest_path = manifest_path_any if isinstance(manifest_path_any, Path) else None
    rootfs_path = _load_manifest_rootfs_path(manifest_path)
    return ExtractionStage(
        info.firmware_dest,
        timeout_s=float(timeout_s),
        provided_rootfs_dir=rootfs_path,
    )


def _make_firmware_lineage_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    return FirmwareLineageStage()


def _make_structure_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = source_input_path, remaining_s, no_llm
    return StructureStage(info.firmware_dest)


def _make_carving_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = source_input_path, remaining_s, no_llm
    return CarvingStage(info.firmware_dest)


def _make_inventory_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    return InventoryStage()


def _make_firmware_profile_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    return FirmwareProfileStage()


def _make_attribution_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    return AttributionStage()


def _make_endpoints_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    return EndpointsStage()


def _make_surfaces_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    return SurfacesStage()


def _make_graph_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    return GraphStage()


def _make_attack_surface_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    max_items = _env_int(
        "AIEDGE_ATTACK_SURFACE_MAX_ITEMS",
        default=500,
        min_value=50,
        max_value=5000,
    )
    max_unknowns = _env_int(
        "AIEDGE_ATTACK_SURFACE_MAX_UNKNOWNS",
        default=400,
        min_value=50,
        max_value=10000,
    )
    return AttackSurfaceStage(max_items=max_items, max_unknowns=max_unknowns)


def _make_functional_spec_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    return FunctionalSpecStage()


def _make_threat_model_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s, no_llm
    return ThreatModelStage()


def _make_llm_synthesis_stage(
    info: _RunInfoLike,
    source_input_path: str | None,
    remaining_s: Callable[[], float],
    no_llm: bool,
) -> Stage:
    _ = info, source_input_path, remaining_s
    return LLMSynthesisStage(no_llm=no_llm)


_STAGE_FACTORIES: dict[str, StageFactory] = {
    "tooling": _make_tooling_stage,
    "ota": _make_ota_stage,
    "ota_payload": _make_ota_payload_stage,
    "ota_fs": _make_ota_fs_stage,
    "ota_roots": _make_ota_roots_stage,
    "ota_boottriage": _make_ota_boottriage_stage,
    "extraction": _make_extraction_stage,
    "firmware_lineage": _make_firmware_lineage_stage,
    "structure": _make_structure_stage,
    "carving": _make_carving_stage,
    "firmware_profile": _make_firmware_profile_stage,
    "inventory": _make_inventory_stage,
    "endpoints": _make_endpoints_stage,
    "surfaces": _make_surfaces_stage,
    "graph": _make_graph_stage,
    "attack_surface": _make_attack_surface_stage,
    "functional_spec": _make_functional_spec_stage,
    "threat_model": _make_threat_model_stage,
    "llm_synthesis": _make_llm_synthesis_stage,
    "attribution": _make_attribution_stage,
    "emulation": _make_emulation_stage,
    "dynamic_validation": _make_dynamic_validation_stage,
    "exploit_gate": _make_exploit_gate_stage,
    "exploit_chain": _make_exploit_chain_stage,
    "exploit_autopoc": _make_exploit_autopoc_stage,
    "poc_validation": _make_poc_validation_stage,
    "exploit_policy": _make_exploit_policy_stage,
}


def stage_factories() -> Mapping[str, StageFactory]:
    return _STAGE_FACTORIES
