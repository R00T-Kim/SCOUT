from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class QemuUserResult:
    """Result of a single QEMU user-mode binary execution."""

    binary: str  # rootfs-relative path of executed binary
    arch: str  # detected architecture
    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool
    args: list[str] = field(default_factory=list)  # arguments used


# Service binary probing priority: (rootfs-relative path, list of arg-sets to try)
_SERVICE_BINARIES: tuple[tuple[str, list[list[str]]], ...] = (
    ("usr/sbin/httpd", [["--help"], ["-V"]]),
    ("usr/sbin/lighttpd", [["--help"], ["-v"]]),
    ("usr/sbin/nginx", [["-V"], ["-h"]]),
    ("bin/busybox", [["--list"], ["--help"]]),
    ("usr/sbin/dropbear", [["-h"]]),
    ("usr/sbin/dnsmasq", [["--version"], ["--help"]]),
    ("usr/sbin/sshd", [["-h"]]),
    ("sbin/init", [["--help"]]),
    ("usr/bin/curl", [["--version"]]),
)

_QEMU_ARCH_MAP: dict[str, list[str]] = {
    # Endian-specific entries (preferred — exact match)
    "mips_be": ["qemu-mips-static"],
    "mips_le": ["qemu-mipsel-static"],
    "arm_le": ["qemu-arm-static"],
    "arm_be": ["qemu-armeb-static"],
    # Generic fallbacks (when endian is unknown, try both)
    "arm": ["qemu-arm-static", "qemu-armeb-static"],
    "aarch64": ["qemu-aarch64-static"],
    "mips": ["qemu-mips-static", "qemu-mipsel-static"],
    "mipsel": ["qemu-mipsel-static", "qemu-mips-static"],
    "x86": ["qemu-i386-static"],
    "x86_64": ["qemu-x86_64-static"],
    "powerpc": ["qemu-ppc-static"],
    "riscv": ["qemu-riscv64-static"],
}

# ELF machine IDs (mirrors inventory.py _ELF_MACHINE_MAP)
_ELF_MACHINE_MAP: dict[int, str] = {
    0x03: "x86",
    0x08: "mips",
    0x14: "powerpc",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "aarch64",
    0xF3: "riscv",
}

_ELF_MAGIC = b"\x7fELF"


def _detect_elf_arch_endian(head: bytes) -> tuple[str, str] | None:
    """Parse arch and endianness from a 20+ byte ELF header.

    Returns ``(arch, endian)`` where *endian* is ``"big"`` or
    ``"little"``, or ``None`` if the header is not a valid ELF.
    """
    if len(head) < 20 or head[:4] != _ELF_MAGIC:
        return None
    endian = "little" if head[5] == 1 else "big" if head[5] == 2 else "little"
    machine = int.from_bytes(head[18:20], endian, signed=False)
    arch = _ELF_MACHINE_MAP.get(machine)
    if arch is None:
        return None
    return arch, endian


# Architectures where endianness matters for QEMU binary selection
_ENDIAN_SENSITIVE_ARCHS: frozenset[str] = frozenset({"mips", "arm"})


def detect_rootfs_arch(rootfs: Path) -> str | None:
    """Detect architecture from the first ELF binary found in rootfs.

    Parses the ELF header (e_machine + EI_DATA fields) to determine both
    architecture and endianness.  For endian-sensitive architectures
    (MIPS, ARM), returns an endian-qualified string such as ``"mips_be"``
    or ``"arm_le"`` so that :func:`find_qemu_binary` picks the correct
    emulator.  Other architectures return the base name (e.g. ``"x86_64"``).
    """
    search_dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "lib"]
    for rel_dir in search_dirs:
        candidate_dir = rootfs / rel_dir
        if not candidate_dir.is_dir():
            continue
        try:
            entries = sorted(candidate_dir.iterdir())
        except OSError:
            continue
        for entry in entries:
            if not entry.is_file():
                continue
            try:
                with open(entry, "rb") as fh:
                    head = fh.read(20)
            except OSError:
                continue
            result = _detect_elf_arch_endian(head)
            if result is None:
                continue
            arch, endian = result
            if arch in _ENDIAN_SENSITIVE_ARCHS:
                suffix = "_be" if endian == "big" else "_le"
                return arch + suffix
            return arch
    return None


def find_qemu_binary(arch: str) -> str | None:
    """Find a suitable ``qemu-*-static`` binary on PATH for *arch*.

    Returns the full path string or ``None`` if nothing is available.
    """
    candidates = _QEMU_ARCH_MAP.get(arch, [])
    for name in candidates:
        path = shutil.which(name)
        if path is not None:
            return path
    return None


def execute_binary(
    qemu_bin: str,
    rootfs: Path,
    binary_rel: str,
    args: list[str],
    *,
    timeout_s: float = 10.0,
) -> QemuUserResult:
    """Run a single binary inside *rootfs* via QEMU user-mode.

    Uses ``-L`` to set the sysroot so that the target binary can
    resolve its shared libraries from *rootfs*.
    """
    binary_abs = rootfs / binary_rel
    arch = ""
    # Quick arch detect from the binary itself (endian-aware)
    try:
        with open(binary_abs, "rb") as fh:
            head = fh.read(20)
        result = _detect_elf_arch_endian(head)
        if result is not None:
            base_arch, endian = result
            if base_arch in _ENDIAN_SENSITIVE_ARCHS:
                arch = base_arch + ("_be" if endian == "big" else "_le")
            else:
                arch = base_arch
    except OSError:
        pass

    cmd = [qemu_bin, "-L", str(rootfs), str(binary_abs)] + args

    try:
        res = subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            check=False,
            timeout=timeout_s,
        )
        return QemuUserResult(
            binary=binary_rel,
            arch=arch,
            exit_code=res.returncode,
            stdout=res.stdout or "",
            stderr=res.stderr or "",
            timed_out=False,
            args=args,
        )
    except subprocess.TimeoutExpired as exc:
        return QemuUserResult(
            binary=binary_rel,
            arch=arch,
            exit_code=-1,
            stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
            stderr=(exc.stderr or "") if isinstance(exc.stderr, str) else "",
            timed_out=True,
            args=args,
        )
    except OSError as exc:
        return QemuUserResult(
            binary=binary_rel,
            arch=arch,
            exit_code=-1,
            stdout="",
            stderr=f"OSError: {exc}",
            timed_out=False,
            args=args,
        )


def execute_service_probes(
    rootfs: Path,
    *,
    arch: str | None = None,
    timeout_s: float = 30.0,
    max_probes: int = 8,
) -> list[QemuUserResult]:
    """Probe service binaries in *rootfs* using QEMU user-mode.

    Iterates ``_SERVICE_BINARIES`` looking for files that exist in
    *rootfs*.  For each one, tries arg-sets in order and keeps the first
    that returns any output.  Stops after *max_probes* successful probes.

    Returns an empty list when QEMU is unavailable or *rootfs* contains
    no recognised binaries.
    """
    if arch is None:
        arch = detect_rootfs_arch(rootfs)
    if arch is None:
        return []

    qemu_bin = find_qemu_binary(arch)
    if qemu_bin is None:
        return []

    per_binary_timeout = min(timeout_s / max(max_probes, 1), 10.0)
    results: list[QemuUserResult] = []

    for binary_rel, arg_sets in _SERVICE_BINARIES:
        if len(results) >= max_probes:
            break
        binary_abs = rootfs / binary_rel
        if not binary_abs.is_file():
            continue

        best: QemuUserResult | None = None
        for args in arg_sets:
            result = execute_binary(
                qemu_bin,
                rootfs,
                binary_rel,
                args,
                timeout_s=per_binary_timeout,
            )
            # Prefer a result that produced output (even on non-zero exit)
            if result.stdout.strip() or result.stderr.strip():
                best = result
                break
            if best is None:
                best = result

        if best is not None:
            results.append(best)

    return results
