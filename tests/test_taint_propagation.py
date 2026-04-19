"""Phase 2C+.3 — sink coverage expansion + format-string variable detection.

These tests pin the post-2026-04-19 sink catalogue (≥50 dangerous symbols across
CWE-78 / 120 / 134 / 22 / 426 / 732 / 377 / 250 / 454) and the strengthened
format-string variable detector. They do **not** exercise the rest of
``taint_propagation`` — that module's LLM-driven flow has separate coverage
through the integration suite. The goal here is to lock the catalogue and
prevent silent regressions when new CWE families are added.
"""

from __future__ import annotations

from aiedge.taint_propagation import (
    _FORMAT_STRING_SINKS,
    _SINK_SYMBOLS,
    _is_format_string_variable,
)

# ---------------------------------------------------------------------------
# Sink catalogue size and CWE coverage
# ---------------------------------------------------------------------------


def test_sink_symbols_total_count_covers_phase_2c_plus_target() -> None:
    """Phase 2C+.3 raises the floor from 28/29 to >= 50 distinct symbols."""
    assert len(_SINK_SYMBOLS) >= 50


def test_sink_symbols_includes_cwe78_command_injection_extras() -> None:
    """Beyond the legacy execve family, the new catalogue covers wordexp /
    posix_spawn-style entry points commonly seen in modern CGI handlers."""
    new_cwe78 = {"wordexp", "posix_spawn", "posix_spawnp"}
    assert new_cwe78 <= _SINK_SYMBOLS


def test_sink_symbols_includes_cwe22_path_traversal() -> None:
    new_cwe22 = {"fopen", "open", "openat", "freopen", "chdir"}
    assert new_cwe22 <= _SINK_SYMBOLS


def test_sink_symbols_includes_cwe426_dynamic_loading() -> None:
    """dlopen was already present; dlsym / dlmopen close the search-path gap."""
    assert {"dlopen", "dlsym", "dlmopen"} <= _SINK_SYMBOLS


def test_sink_symbols_includes_cwe732_permission_calls() -> None:
    assert {"chmod", "fchmod", "chown", "fchown", "lchown"} <= _SINK_SYMBOLS


def test_sink_symbols_includes_cwe377_insecure_tmp_files() -> None:
    assert {"mktemp", "tmpnam", "tempnam", "tmpfile"} <= _SINK_SYMBOLS


def test_sink_symbols_includes_privilege_drop_calls() -> None:
    """CWE-250 / CWE-269 — privilege management primitives shipped without
    dropping or re-elevating privileges correctly are a recurring router-CGI
    bug class (e.g. setuid(0) without prior chroot)."""
    assert {"chroot", "setuid", "seteuid", "setgid", "setegid"} <= _SINK_SYMBOLS


def test_sink_symbols_includes_environment_injection() -> None:
    """CWE-454 — putenv/setenv variants accept attacker-controlled strings."""
    assert {"putenv", "setenv", "unsetenv"} <= _SINK_SYMBOLS


def test_sink_symbols_preserves_legacy_entries() -> None:
    """Regression guard: every pre-Phase 2C+.3 symbol stays in the set so
    existing rules and downstream consumers are not silently weakened."""
    legacy = {
        "system",
        "popen",
        "execve",
        "execvp",
        "execvpe",
        "execl",
        "execlp",
        "execle",
        "execv",
        "strcpy",
        "sprintf",
        "strcat",
        "strncpy",
        "strncat",
        "gets",
        "vsprintf",
        "memcpy",
        "memmove",
        "printf",
        "fprintf",
        "syslog",
        "vprintf",
        "vfprintf",
        "snprintf",
        "scanf",
        "sscanf",
        "fscanf",
        "dlopen",
        "realpath",
    }
    assert legacy <= _SINK_SYMBOLS


# ---------------------------------------------------------------------------
# Format-string sinks
# ---------------------------------------------------------------------------


def test_format_string_sinks_count_doubles() -> None:
    """Phase 2C+.3 brings the format-string sink count from 6 to >=12."""
    assert len(_FORMAT_STRING_SINKS) >= 12


def test_format_string_sinks_cover_size_bounded_and_wide_variants() -> None:
    """Add the size-bounded (vsnprintf), file-descriptor (dprintf/vdprintf),
    and wide-char (swprintf, wprintf, fwprintf, ...) variants explicitly."""
    additions = {
        "vsnprintf",
        "dprintf",
        "vdprintf",
        "swprintf",
        "vswprintf",
        "wprintf",
        "vwprintf",
        "fwprintf",
        "vfwprintf",
    }
    assert additions <= _FORMAT_STRING_SINKS


# ---------------------------------------------------------------------------
# Strengthened _is_format_string_variable detector
# ---------------------------------------------------------------------------


def test_format_var_skips_string_literal_first_arg() -> None:
    assert not _is_format_string_variable("printf", 'printf("hello")')
    assert not _is_format_string_variable("printf", 'printf("hello %s", name)')
    # Whitespace before the literal is fine
    assert not _is_format_string_variable("printf", 'printf(  "ok"  )')


def test_format_var_detects_bare_identifier_first_arg() -> None:
    """The detector flags any sink call whose first argument is not a string
    literal — even when the first arg is not the format-string position
    (e.g. syslog priority constant, fprintf stream). This intentional
    broadening lets downstream analysis discriminate further; the goal here
    is just to make sure no candidate is silently dropped."""
    assert _is_format_string_variable("printf", "printf(buf)")
    assert _is_format_string_variable("syslog", "syslog(LOG_INFO, message)")
    assert _is_format_string_variable("syslog", "syslog(user_buf)")


def test_format_var_detects_function_call_first_arg() -> None:
    body = "fprintf(stderr, get_template(name))"
    # fprintf's first arg is the FILE*, not the format. The detector doesn't
    # know about argument positions; it flags any non-literal first arg. This
    # is intentional — it catches the broad pattern and lets later analysis
    # discriminate.
    assert _is_format_string_variable("fprintf", body)


def test_format_var_detects_struct_field_access() -> None:
    assert _is_format_string_variable("printf", "printf(obj->field)")
    assert _is_format_string_variable("printf", "printf(record.fmt)")


def test_format_var_detects_array_subscript() -> None:
    assert _is_format_string_variable("printf", "printf(messages[i])")


def test_format_var_detects_c_style_cast() -> None:
    assert _is_format_string_variable("printf", "printf((char *) buf)")


def test_format_var_detects_parenthesised_ternary() -> None:
    body = "printf((cond ? warn : info))"
    assert _is_format_string_variable("printf", body)


def test_format_var_detects_pointer_dereference_first_arg() -> None:
    assert _is_format_string_variable("printf", "printf(*p_fmt)")
    assert _is_format_string_variable("printf", "printf(&buffer[0])")


def test_format_var_returns_false_for_non_format_sinks() -> None:
    """Sinks not in _FORMAT_STRING_SINKS (e.g. system, memcpy) are out of scope
    for this detector — even if called with a variable arg they don't represent
    a format-string vulnerability."""
    assert not _is_format_string_variable("system", "system(buf)")
    assert not _is_format_string_variable("memcpy", "memcpy(dest, src, n)")
    assert not _is_format_string_variable("strcpy", "strcpy(dest, src)")
