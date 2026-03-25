from __future__ import annotations

import select
import socket
import struct
import time

# ---------------------------------------------------------------------------
# Signal number → name mapping
# ---------------------------------------------------------------------------

_SIGNALS: dict[int, str] = {
    2: "sigint",
    5: "sigtrap",   # breakpoint
    6: "sigabrt",
    8: "sigfpe",
    9: "sigkill",
    11: "sigsegv",  # segfault
    13: "sigpipe",
    14: "sigalrm",
    15: "sigterm",
}


# ---------------------------------------------------------------------------
# GdbSession
# ---------------------------------------------------------------------------


class GdbSession:
    """Pure-stdlib GDB Remote Serial Protocol client.

    Implements a minimal subset of the GDB RSP sufficient for firmware
    emulation diagnostics: register reads, memory reads/writes, breakpoints,
    continue/single-step, and a heuristic stack backtrace.

    Protocol wire format
    --------------------
    Send:    ``$<data>#<two-hex-digit checksum>``
    Receive: ``+`` (ACK) then ``$<data>#<checksum>``
    Checksum: sum of all character values in *data*, modulo 256, formatted
              as exactly two lowercase hex digits.
    """

    def __init__(self) -> None:
        self._sock: socket.socket | None = None
        self._connected: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(
        self,
        host: str = "127.0.0.1",
        port: int = 1234,
        timeout: float = 10.0,
    ) -> bool:
        """Connect to a GDB stub (e.g. QEMU ``-gdb tcp::<port>``).

        Sends the initial ``?`` query to confirm the stub is ready.
        Returns ``True`` on success, ``False`` on any failure.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))
            self._sock = sock
            self._connected = True
        except OSError:
            self._connected = False
            return False

        # Confirm the stub responds to the initial stop-reason query.
        try:
            self._send_packet("?")
            reply = self._recv_packet(timeout=timeout)
            return bool(reply)
        except OSError:
            self.close()
            return False

    def read_registers(self) -> dict[str, str]:
        """Read all general-purpose registers via the ``g`` command.

        The RSP returns register values as a single concatenated hex string.
        Because the register layout is architecture-specific and not encoded
        in the protocol, we return raw numbered blocks labelled ``r0``,
        ``r1``, …  (each block is 8 hex chars = 32-bit word).  Callers that
        need architecture-aware parsing can post-process the returned dict.

        Returns an empty dict on failure.
        """
        if not self._connected or self._sock is None:
            return {}
        try:
            self._send_packet("g")
            reply = self._recv_packet()
        except OSError:
            return {}

        if not reply or reply.startswith("E"):
            return {}

        # Split the hex blob into 8-char (32-bit) words.
        registers: dict[str, str] = {}
        chunk = 8  # 4 bytes per register → 8 hex chars
        for i in range(len(reply) // chunk):
            hex_val = reply[i * chunk : (i + 1) * chunk]
            registers[f"r{i}"] = hex_val

        return registers

    def read_memory(self, addr: int, size: int) -> bytes:
        """Read *size* bytes of target memory starting at *addr*.

        Returns the raw bytes on success, ``b""`` on any error (including
        ``E`` error replies from the stub).
        """
        if not self._connected or self._sock is None:
            return b""
        if size <= 0:
            return b""
        try:
            cmd = f"m{addr:x},{size:x}"
            self._send_packet(cmd)
            reply = self._recv_packet()
        except OSError:
            return b""

        if not reply or reply.startswith("E"):
            return b""

        try:
            return bytes.fromhex(reply)
        except ValueError:
            return b""

    def write_memory(self, addr: int, data: bytes) -> bool:
        """Write *data* to target memory at *addr*.

        Returns ``True`` on ``OK``, ``False`` on any error.
        """
        if not self._connected or self._sock is None:
            return False
        if not data:
            return False
        try:
            hex_data = data.hex()
            cmd = f"M{addr:x},{len(data):x}:{hex_data}"
            self._send_packet(cmd)
            reply = self._recv_packet()
        except OSError:
            return False

        return reply == "OK"

    def set_breakpoint(self, addr: int) -> bool:
        """Insert a software breakpoint (type 0) at *addr*.

        Uses ``Z0,<addr>,1`` (kind=1 is conventional for most archs).
        Returns ``True`` on ``OK``.
        """
        if not self._connected or self._sock is None:
            return False
        try:
            self._send_packet(f"Z0,{addr:x},1")
            reply = self._recv_packet()
        except OSError:
            return False
        return reply == "OK"

    def remove_breakpoint(self, addr: int) -> bool:
        """Remove a software breakpoint at *addr*.

        Uses ``z0,<addr>,1``.  Returns ``True`` on ``OK``.
        """
        if not self._connected or self._sock is None:
            return False
        try:
            self._send_packet(f"z0,{addr:x},1")
            reply = self._recv_packet()
        except OSError:
            return False
        return reply == "OK"

    def continue_execution(self, timeout: float = 5.0) -> str:
        """Resume target execution and wait for the next stop event.

        Returns a human-readable stop reason string:
        ``"breakpoint"``, ``"sigsegv"``, ``"sigabrt"``, ``"sigint"``,
        ``"exited"``, ``"timeout"``, or the raw signal name from
        :data:`_SIGNALS` / ``"signal:<n>"`` for unmapped signals.
        """
        return self._run_cmd("c", timeout=timeout)

    def single_step(self) -> str:
        """Execute exactly one instruction and return the stop reason.

        Uses the ``s`` (step) RSP command.  Same return values as
        :meth:`continue_execution`.
        """
        return self._run_cmd("s", timeout=5.0)

    def backtrace(self, depth: int = 10) -> list[int]:
        """Heuristic stack backtrace: read potential return addresses.

        This is necessarily approximate — without DWARF info we cannot do
        proper frame unwinding.  The approach:

        1. Read the stack-pointer register value (``r13`` in the raw block,
           which maps to ``sp`` on ARM; for other archs results may vary).
        2. Read ``depth * 4`` bytes of stack memory.
        3. Return all non-zero 32-bit aligned values as candidate addresses.

        Returns an empty list if registers or memory cannot be read.
        """
        regs = self.read_registers()
        if not regs:
            return []

        # Try a few common SP register positions:
        #   ARM32: r13 (index 13 in the 'g' reply)
        #   MIPS:  r29 (sp) at index 29
        # We try both and take the first non-zero value.
        sp_val: int | None = None
        for sp_idx in (13, 29, 7):  # ARM sp, MIPS sp, x86 esp
            key = f"r{sp_idx}"
            if key in regs:
                try:
                    # RSP register values are in target byte order; for a
                    # heuristic we just parse as hex integer.
                    sp_val = int(regs[key], 16)
                    if sp_val != 0:
                        break
                except ValueError:
                    continue

        if not sp_val:
            return []

        # Read 'depth' words (4 bytes each) from the stack.
        mem = self.read_memory(sp_val, depth * 4)
        if not mem:
            return []

        addrs: list[int] = []
        for i in range(len(mem) // 4):
            word = struct.unpack_from("<I", mem, i * 4)[0]
            if word != 0:
                addrs.append(word)

        return addrs[:depth]

    def get_stop_reason(self) -> str:
        """Send ``?`` and return the parsed stop reason string."""
        if not self._connected or self._sock is None:
            return "disconnected"
        try:
            self._send_packet("?")
            reply = self._recv_packet()
        except OSError:
            return "error"
        return self._parse_stop_reply(reply)

    def close(self) -> None:
        """Close the TCP connection to the GDB stub."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._connected = False

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _run_cmd(self, cmd: str, timeout: float) -> str:
        """Send *cmd* (``c`` or ``s``) and wait for a stop-reply packet."""
        if not self._connected or self._sock is None:
            return "disconnected"
        try:
            self._send_packet(cmd)
            reply = self._recv_packet(timeout=timeout)
        except TimeoutError:
            return "timeout"
        except OSError:
            return "error"

        if not reply:
            return "timeout"
        return self._parse_stop_reply(reply)

    def _parse_stop_reply(self, reply: str) -> str:
        """Translate a raw RSP stop-reply packet into a human-readable string.

        RSP stop-reply formats:
        - ``T<sig_hex>...``  — stopped with signal (may have k:v pairs)
        - ``S<sig_hex>``     — stopped with signal (short form)
        - ``W<exit_hex>``    — process exited
        - ``X<sig_hex>``     — process killed by signal
        """
        if not reply:
            return "unknown"

        prefix = reply[0].upper()

        if prefix in ("T", "S"):
            try:
                sig_num = int(reply[1:3], 16)
            except (ValueError, IndexError):
                return "stopped"
            return _SIGNALS.get(sig_num, f"signal:{sig_num}")

        if prefix == "W":
            return "exited"

        if prefix == "X":
            try:
                sig_num = int(reply[1:3], 16)
            except (ValueError, IndexError):
                return "killed"
            return _SIGNALS.get(sig_num, f"killed:signal:{sig_num}")

        return reply  # pass through for unexpected replies

    def _send_packet(self, data: str) -> None:
        """Encode and transmit a GDB RSP packet.

        Wire format: ``$<data>#<checksum>``
        where *checksum* is the 8-bit sum of all bytes in *data*,
        expressed as exactly two lowercase hex digits.
        """
        assert self._sock is not None
        checksum = self._checksum(data)
        packet = f"${data}#{checksum:02x}"
        self._sock.sendall(packet.encode("ascii"))

    def _recv_packet(self, timeout: float = 5.0) -> str:
        """Receive one GDB RSP response packet.

        Reads raw bytes from the socket until a complete ``$…#xx`` frame is
        assembled, then:

        1. Verifies the checksum.
        2. Sends a ``+`` ACK.
        3. Returns the data portion as a plain string.

        Returns ``""`` on timeout or malformed frame.
        """
        assert self._sock is not None
        deadline = time.monotonic() + timeout
        buf = bytearray()

        # ---- Phase 1: skip everything before '$' ----
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ""
            ready, _, _ = select.select([self._sock], [], [], remaining)
            if not ready:
                return ""
            chunk = self._sock.recv(1)
            if not chunk:
                return ""
            if chunk == b"+":
                # ACK from stub — ignore, keep reading.
                continue
            if chunk == b"-":
                # NAK — the stub wants a retransmit; return empty so the
                # caller can handle.
                return ""
            if chunk == b"$":
                buf.extend(chunk)
                break

        # ---- Phase 2: read until '#' + 2 checksum chars ----
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ""
            ready, _, _ = select.select([self._sock], [], [], remaining)
            if not ready:
                return ""
            chunk = self._sock.recv(256)
            if not chunk:
                return ""
            buf.extend(chunk)
            # Check whether we have a complete frame: $…#xx
            if b"#" in buf:
                hash_pos = buf.index(b"#")
                if len(buf) >= hash_pos + 3:
                    break  # we have the two checksum digits

        # ---- Phase 3: extract and validate ----
        try:
            raw = buf.decode("ascii", errors="replace")
        except Exception:
            return ""

        # Find the outermost $…#xx
        start = raw.find("$")
        hash_pos = raw.find("#", start + 1)
        if start < 0 or hash_pos < 0 or len(raw) < hash_pos + 3:
            return ""

        data = raw[start + 1 : hash_pos]
        given_cs_str = raw[hash_pos + 1 : hash_pos + 3]

        try:
            given_cs = int(given_cs_str, 16)
        except ValueError:
            # Malformed checksum — send NAK but still return empty.
            try:
                self._sock.sendall(b"-")
            except OSError:
                pass
            return ""

        expected_cs = self._checksum(data)
        if given_cs != expected_cs:
            try:
                self._sock.sendall(b"-")
            except OSError:
                pass
            return ""

        # Send ACK.
        try:
            self._sock.sendall(b"+")
        except OSError:
            pass

        return data

    def _checksum(self, data: str) -> int:
        """Return the RSP checksum: sum of ASCII values mod 256."""
        return sum(ord(c) for c in data) % 256


# ---------------------------------------------------------------------------
# Top-level helper
# ---------------------------------------------------------------------------


def probe_with_gdb(
    host: str,
    port: int,
    timeout_s: float = 10.0,
) -> dict[str, object]:
    """Connect to a running QEMU GDB stub and collect diagnostic info.

    Intended as a lightweight probe that the emulation stage calls after
    launching QEMU with ``-gdb tcp::<port>`` to capture an initial snapshot
    of the emulated environment.

    Returns a dict with the following keys:

    ``connected`` (bool)
        Whether the TCP connection and initial handshake succeeded.

    ``stop_reason`` (str | None)
        Human-readable stop reason (``"breakpoint"``, ``"sigsegv"``, …).

    ``registers`` (dict[str, str] | None)
        Raw register hex values keyed by ``r0``, ``r1``, … as returned by
        :meth:`GdbSession.read_registers`.

    ``stack_sample`` (list[int] | None)
        Up to 16 potential return addresses read heuristically from the stack.

    ``error`` (str | None)
        Error description if something failed, otherwise ``None``.
    """
    session = GdbSession()
    result: dict[str, object] = {
        "connected": False,
        "stop_reason": None,
        "registers": None,
        "stack_sample": None,
        "error": None,
    }

    try:
        if not session.connect(host, port, timeout=timeout_s):
            result["error"] = "connection_failed"
            return result

        result["connected"] = True

        result["stop_reason"] = session.get_stop_reason()

        regs = session.read_registers()
        result["registers"] = regs if regs else None

        # Attempt to read a stack sample; graceful on failure.
        try:
            stack = session.backtrace(depth=16)
            result["stack_sample"] = stack if stack else None
        except Exception:  # noqa: BLE001
            result["stack_sample"] = None

        # Attempt to read 64 bytes from SP area for raw inspection.
        if regs:
            for sp_idx in (13, 29, 7):
                sp_hex = regs.get(f"r{sp_idx}", "0")
                try:
                    sp_val = int(sp_hex, 16)
                except ValueError:
                    sp_val = 0
                if sp_val:
                    raw_stack = session.read_memory(sp_val, 64)
                    if raw_stack:
                        result["stack_raw_hex"] = raw_stack.hex()
                    break

    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
    finally:
        session.close()

    return result
