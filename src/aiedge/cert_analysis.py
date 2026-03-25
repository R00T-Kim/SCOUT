from __future__ import annotations

"""X.509 certificate analysis for SCOUT firmware security assessment.

Scans extracted firmware rootfs directories for certificate and private key
files, parses them using stdlib only (ssl + minimal ASN.1 TLV), and emits
security findings (expired certs, weak keys, weak signatures, private keys
embedded in firmware, world-readable key permissions, self-signed certs,
wildcard certs).

Output artifact: cert_analysis.json (schema: cert-analysis-v1)
"""

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from .path_safety import assert_under_dir

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SCHEMA_VERSION = "cert-analysis-v1"

_CERT_EXTENSIONS: frozenset[str] = frozenset(
    {".pem", ".crt", ".der", ".cer", ".key", ".p12", ".pfx"}
)

# PEM block header patterns
_PEM_CERT_HEADER = b"-----BEGIN CERTIFICATE-----"
_PEM_HEADERS: list[bytes] = [
    b"-----BEGIN CERTIFICATE-----",
    b"-----BEGIN RSA PRIVATE KEY-----",
    b"-----BEGIN EC PRIVATE KEY-----",
    b"-----BEGIN DSA PRIVATE KEY-----",
    b"-----BEGIN PRIVATE KEY-----",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----",
    b"-----BEGIN OPENSSH PRIVATE KEY-----",
    b"-----BEGIN PUBLIC KEY-----",
    b"-----BEGIN CERTIFICATE REQUEST-----",
]

# PEM header → key type label
_PRIVATE_KEY_HEADERS: dict[bytes, str] = {
    b"-----BEGIN RSA PRIVATE KEY-----": "RSA",
    b"-----BEGIN EC PRIVATE KEY-----": "EC",
    b"-----BEGIN DSA PRIVATE KEY-----": "DSA",
    b"-----BEGIN PRIVATE KEY-----": "PKCS8",
    b"-----BEGIN ENCRYPTED PRIVATE KEY-----": "PKCS8-ENCRYPTED",
    b"-----BEGIN OPENSSH PRIVATE KEY-----": "Ed25519/OpenSSH",
}

# Weak signature algorithm OIDs (dotted decimal)
_WEAK_SIG_OIDS: frozenset[str] = frozenset(
    {
        "1.2.840.113549.1.1.4",  # md5WithRSAEncryption
        "1.2.840.10040.4.3",    # dsa-with-sha1
        "1.2.840.113549.1.1.5",  # sha1WithRSAEncryption
        "1.2.840.10045.4.1",    # ecdsaWithSHA1
    }
)

# Human-readable OID names
_OID_NAMES: dict[str, str] = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsaWithSHA1",
    "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
    "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
    "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
    "1.2.840.10040.4.3": "dsa-with-sha1",
    "1.3.101.112": "ed25519",
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.10045.2.1": "ecPublicKey",
    "1.2.840.10040.4.1": "dsa",
}

# EC named-curve OIDs → bit-size
_EC_CURVE_BITS: dict[str, int] = {
    "1.2.840.10045.3.1.1": 192,   # prime192v1 / secp192r1
    "1.3.132.0.1": 193,            # sect193r1
    "1.2.840.10045.3.1.7": 256,   # prime256v1 / secp256r1
    "1.3.132.0.34": 384,           # secp384r1
    "1.3.132.0.35": 521,           # secp521r1
    "1.3.132.0.10": 256,           # secp256k1
    "1.3.132.0.33": 224,           # secp224r1
}

_MAX_FILES_SCANNED = 500
_MAX_CERTS_ANALYZED = 200
_MAX_FILE_SIZE_BYTES = 4 * 1024 * 1024  # 4 MB guard


def _rel_to_run_dir(run_dir: Path, path: Path) -> str:
    try:
        return str(path.resolve().relative_to(run_dir.resolve()))
    except Exception:
        return str(path)


# ---------------------------------------------------------------------------
# Hashing helpers
# ---------------------------------------------------------------------------

def _sha256_file(path: Path, *, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# Minimal ASN.1 TLV parser (DER encoding)
# ---------------------------------------------------------------------------

def _asn1_read_length(data: bytes, offset: int) -> tuple[int, int]:
    """Read ASN.1 length at *offset*. Returns (length, new_offset)."""
    if offset >= len(data):
        raise ValueError("ASN.1 length read past end of data")
    first = data[offset]
    offset += 1
    if first & 0x80 == 0:
        return first, offset
    num_bytes = first & 0x7F
    if num_bytes == 0 or num_bytes > 4:
        raise ValueError(f"Unsupported ASN.1 length encoding: {first:#x}")
    if offset + num_bytes > len(data):
        raise ValueError("ASN.1 length bytes past end of data")
    length = int.from_bytes(data[offset : offset + num_bytes], "big")
    return length, offset + num_bytes


def _asn1_read_tlv(data: bytes, offset: int) -> tuple[int, int, bytes, int]:
    """Read one TLV at *offset*. Returns (tag, length, value_bytes, next_offset)."""
    if offset >= len(data):
        raise ValueError("ASN.1 read past end of data")
    tag = data[offset]
    offset += 1
    length, offset = _asn1_read_length(data, offset)
    if offset + length > len(data):
        raise ValueError("ASN.1 value past end of data")
    value = data[offset : offset + length]
    return tag, length, value, offset + length


def _asn1_oid_to_dotted(raw: bytes) -> str:
    """Convert raw DER OID bytes to dotted-decimal string."""
    if not raw:
        return ""
    out: list[int] = []
    first = raw[0]
    out.append(first // 40)
    out.append(first % 40)
    acc = 0
    for byte in raw[1:]:
        acc = (acc << 7) | (byte & 0x7F)
        if byte & 0x80 == 0:
            out.append(acc)
            acc = 0
    return ".".join(str(v) for v in out)


def _asn1_parse_seq(data: bytes) -> list[tuple[int, bytes]]:
    """Parse a SEQUENCE/SET of TLV children. Returns [(tag, value), ...]."""
    children: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        try:
            tag, _length, value, offset = _asn1_read_tlv(data, offset)
            children.append((tag, value))
        except (ValueError, IndexError):
            break
    return children


# ASN.1 tag constants
_TAG_SEQ = 0x30
_TAG_SET = 0x31
_TAG_OID = 0x06
_TAG_UTF8STR = 0x0C
_TAG_PRINTABLESTR = 0x13
_TAG_T61STR = 0x14
_TAG_IA5STR = 0x16
_TAG_BMPSTR = 0x1E
_TAG_UNIVERSALSTR = 0x1C
_TAG_UTCTIME = 0x17
_TAG_GENERALIZEDTIME = 0x18
_TAG_BITSTRING = 0x03
_TAG_INTEGER = 0x02
_TAG_CONTEXT_0 = 0xA0
_TAG_CONTEXT_3 = 0xA3

_STRING_TAGS: frozenset[int] = frozenset(
    {
        _TAG_UTF8STR,
        _TAG_PRINTABLESTR,
        _TAG_T61STR,
        _TAG_IA5STR,
        _TAG_BMPSTR,
        _TAG_UNIVERSALSTR,
    }
)

# Well-known RDN attribute OIDs
_OID_CN = "2.5.4.3"
_OID_O = "2.5.4.10"
_OID_C = "2.5.4.6"


def _decode_string_value(tag: int, value: bytes) -> str:
    if tag == _TAG_BMPSTR:
        try:
            return value.decode("utf-16-be", errors="replace")
        except Exception:
            return value.hex()
    if tag == _TAG_UNIVERSALSTR:
        try:
            return value.decode("utf-32-be", errors="replace")
        except Exception:
            return value.hex()
    try:
        return value.decode("utf-8", errors="replace")
    except Exception:
        return value.hex()


def _parse_rdn_sequence(rdn_seq_bytes: bytes) -> dict[str, str]:
    """Parse RDNSequence → {oid_dotted: value_str}."""
    attrs: dict[str, str] = {}
    # RDNSequence is SEQUENCE OF SET OF AttributeTypeAndValue
    rdns = _asn1_parse_seq(rdn_seq_bytes)
    for tag, value in rdns:
        if tag not in (_TAG_SET, _TAG_SEQ):
            continue
        avs = _asn1_parse_seq(value)
        for av_tag, av_value in avs:
            if av_tag not in (_TAG_SET, _TAG_SEQ):
                continue
            atv = _asn1_parse_seq(av_value)
            if len(atv) < 2:
                continue
            oid_tag, oid_val = atv[0]
            str_tag, str_val = atv[1]
            if oid_tag != _TAG_OID:
                continue
            oid = _asn1_oid_to_dotted(oid_val)
            if str_tag in _STRING_TAGS:
                attrs[oid] = _decode_string_value(str_tag, str_val)
    return attrs


def _parse_utctime(raw: bytes) -> datetime | None:
    """Parse UTCTime (YYMMDDHHMMSSZ) → aware datetime."""
    try:
        s = raw.decode("ascii").strip()
        # YYMMDDHHMMSSZ or YYMMDDHHMMSS+HH'MM'
        if len(s) < 12:
            return None
        yy = int(s[0:2])
        year = 2000 + yy if yy < 50 else 1900 + yy
        month = int(s[2:4])
        day = int(s[4:6])
        hour = int(s[6:8])
        minute = int(s[8:10])
        second = int(s[10:12])
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except Exception:
        return None


def _parse_generalizedtime(raw: bytes) -> datetime | None:
    """Parse GeneralizedTime (YYYYMMDDHHMMSSZ) → aware datetime."""
    try:
        s = raw.decode("ascii").strip()
        if len(s) < 14:
            return None
        year = int(s[0:4])
        month = int(s[4:6])
        day = int(s[6:8])
        hour = int(s[8:10])
        minute = int(s[10:12])
        second = int(s[12:14])
        return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    except Exception:
        return None


def _parse_time_value(tag: int, value: bytes) -> datetime | None:
    if tag == _TAG_UTCTIME:
        return _parse_utctime(value)
    if tag == _TAG_GENERALIZEDTIME:
        return _parse_generalizedtime(value)
    return None


def _dt_to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------------------
# RSA public key size extraction
# ---------------------------------------------------------------------------

def _rsa_key_size_from_bitstring(bitstring_value: bytes) -> int | None:
    """Extract RSA modulus bit-length from a SubjectPublicKeyInfo BITSTRING value.

    The BITSTRING value for an RSA public key is:
      <unused_bits_byte> || DER(RSAPublicKey)
    RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
    """
    try:
        if not bitstring_value:
            return None
        # Skip unused-bits byte
        inner = bitstring_value[1:]
        tag, _length, seq_value, _ = _asn1_read_tlv(inner, 0)
        if tag != _TAG_SEQ:
            return None
        children = _asn1_parse_seq(seq_value)
        if not children:
            return None
        mod_tag, mod_value = children[0]
        if mod_tag != _TAG_INTEGER:
            return None
        # Remove leading zero byte (sign byte for positive integers)
        mod = mod_value.lstrip(b"\x00")
        if not mod:
            return None
        return len(mod) * 8
    except Exception:
        return None


# ---------------------------------------------------------------------------
# TBSCertificate parser
# ---------------------------------------------------------------------------

def _parse_tbs_certificate(tbs_bytes: bytes) -> dict:
    """Parse TBSCertificate fields. Returns partial dict on failure."""
    result: dict = {
        "subject_cn": None,
        "issuer_cn": None,
        "not_before": None,
        "not_after": None,
        "sig_alg_oid": None,
        "sig_alg_name": None,
        "pubkey_alg_oid": None,
        "pubkey_alg_name": None,
        "pubkey_bits": None,
    }
    try:
        children = _asn1_parse_seq(tbs_bytes)
    except Exception:
        return result

    # TBSCertificate field positions depend on optional version field [0] EXPLICIT
    # Fields: [version], serialNumber, signature, issuer, validity, subject,
    #         subjectPublicKeyInfo, [issuerUniqueID], [subjectUniqueID], [extensions]
    idx = 0

    # Skip optional version context tag [0]
    if children and children[0][0] == _TAG_CONTEXT_0:
        idx += 1

    # serialNumber (INTEGER)
    if idx < len(children) and children[idx][0] == _TAG_INTEGER:
        idx += 1

    # signature AlgorithmIdentifier (SEQUENCE)
    if idx < len(children) and children[idx][0] == _TAG_SEQ:
        alg_children = _asn1_parse_seq(children[idx][1])
        if alg_children and alg_children[0][0] == _TAG_OID:
            oid = _asn1_oid_to_dotted(alg_children[0][1])
            result["sig_alg_oid"] = oid
            result["sig_alg_name"] = _OID_NAMES.get(oid, oid)
        idx += 1

    # issuer RDNSequence (SEQUENCE)
    if idx < len(children) and children[idx][0] == _TAG_SEQ:
        rdn = _parse_rdn_sequence(children[idx][1])
        result["issuer_cn"] = rdn.get(_OID_CN)
        idx += 1

    # validity (SEQUENCE { notBefore, notAfter })
    if idx < len(children) and children[idx][0] == _TAG_SEQ:
        validity_children = _asn1_parse_seq(children[idx][1])
        if len(validity_children) >= 2:
            nb_tag, nb_val = validity_children[0]
            na_tag, na_val = validity_children[1]
            result["not_before"] = _dt_to_iso(_parse_time_value(nb_tag, nb_val))
            result["not_after"] = _dt_to_iso(_parse_time_value(na_tag, na_val))
        idx += 1

    # subject RDNSequence (SEQUENCE)
    if idx < len(children) and children[idx][0] == _TAG_SEQ:
        rdn = _parse_rdn_sequence(children[idx][1])
        result["subject_cn"] = rdn.get(_OID_CN)
        idx += 1

    # subjectPublicKeyInfo (SEQUENCE { algorithm, subjectPublicKey })
    if idx < len(children) and children[idx][0] == _TAG_SEQ:
        spki_children = _asn1_parse_seq(children[idx][1])
        if spki_children and spki_children[0][0] == _TAG_SEQ:
            alg_id_children = _asn1_parse_seq(spki_children[0][1])
            if alg_id_children and alg_id_children[0][0] == _TAG_OID:
                pk_oid = _asn1_oid_to_dotted(alg_id_children[0][1])
                result["pubkey_alg_oid"] = pk_oid
                result["pubkey_alg_name"] = _OID_NAMES.get(pk_oid, pk_oid)

                # Key size
                if pk_oid == "1.2.840.113549.1.1.1":  # rsaEncryption
                    if len(spki_children) >= 2 and spki_children[1][0] == _TAG_BITSTRING:
                        result["pubkey_bits"] = _rsa_key_size_from_bitstring(
                            spki_children[1][1]
                        )
                elif pk_oid == "1.2.840.10045.2.1":  # ecPublicKey
                    # Curve OID is parameter in AlgorithmIdentifier
                    if len(alg_id_children) >= 2 and alg_id_children[1][0] == _TAG_OID:
                        curve_oid = _asn1_oid_to_dotted(alg_id_children[1][1])
                        result["pubkey_bits"] = _EC_CURVE_BITS.get(curve_oid)
                elif pk_oid in ("1.3.101.112", "1.3.101.113"):  # Ed25519/Ed448
                    result["pubkey_bits"] = 255 if pk_oid == "1.3.101.112" else 448
        idx += 1

    return result


# ---------------------------------------------------------------------------
# DER / PEM parsing
# ---------------------------------------------------------------------------

def _parse_der_certificate(der_data: bytes) -> dict | None:
    """Parse a DER-encoded X.509 certificate. Returns None on parse failure."""
    try:
        # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
        tag, _length, cert_value, _ = _asn1_read_tlv(der_data, 0)
        if tag != _TAG_SEQ:
            return None
        cert_children = _asn1_parse_seq(cert_value)
        if not cert_children:
            return None
        # TBSCertificate is the first SEQUENCE child
        tbs_tag, tbs_value = cert_children[0]
        if tbs_tag != _TAG_SEQ:
            return None
        return _parse_tbs_certificate(tbs_value)
    except Exception:
        return None


_PEM_CERT_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----",
    re.DOTALL,
)

import base64 as _base64


def _extract_pem_certs(raw: bytes) -> list[bytes]:
    """Extract all DER blobs from PEM-encoded certificate data."""
    results: list[bytes] = []
    for match in _PEM_CERT_RE.finditer(raw):
        b64 = re.sub(rb"\s+", b"", match.group(1))
        try:
            results.append(_base64.b64decode(b64))
        except Exception:
            pass
    return results


def _detect_private_key_types(raw: bytes) -> list[str]:
    """Return list of private key type labels found in *raw* bytes."""
    found: list[str] = []
    for header, label in _PRIVATE_KEY_HEADERS.items():
        if header in raw:
            found.append(label)
    return found


def _file_has_pem_content(raw: bytes) -> bool:
    """Return True if any known PEM header is present in *raw*."""
    for header in _PEM_HEADERS:
        if header in raw:
            return True
    return False


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def _should_scan_path(path: Path) -> bool:
    """True if path has a certificate-related extension OR is a regular file we
    should peek at for PEM headers."""
    suffix = path.suffix.lower()
    return suffix in _CERT_EXTENSIONS


def _discover_cert_files(rootfs_dirs: list[Path]) -> list[Path]:
    """Walk rootfs directories and collect candidate certificate files.

    Respects _MAX_FILES_SCANNED limit. Returns list of absolute Paths.
    """
    seen: set[Path] = set()
    candidates: list[Path] = []
    total_walked = 0

    for rootfs in rootfs_dirs:
        if not rootfs.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(rootfs, followlinks=False):
            dirnames.sort()  # deterministic traversal order
            for fname in sorted(filenames):
                if total_walked >= _MAX_FILES_SCANNED:
                    break
                fpath = Path(dirpath) / fname
                total_walked += 1
                if fpath in seen:
                    continue
                seen.add(fpath)
                if _should_scan_path(fpath):
                    candidates.append(fpath)
            if total_walked >= _MAX_FILES_SCANNED:
                break

    # Second pass: scan non-extension files for PEM headers (up to remaining budget)
    # Only if we haven't hit the limit with extension-based candidates
    pem_candidates: list[Path] = []
    if total_walked < _MAX_FILES_SCANNED:
        for rootfs in rootfs_dirs:
            if not rootfs.is_dir():
                continue
            for dirpath, dirnames, filenames in os.walk(rootfs, followlinks=False):
                dirnames.sort()
                for fname in sorted(filenames):
                    if total_walked >= _MAX_FILES_SCANNED:
                        break
                    fpath = Path(dirpath) / fname
                    if fpath in seen:
                        continue
                    seen.add(fpath)
                    total_walked += 1
                    try:
                        stat = fpath.stat()
                        if not fpath.is_file() or stat.st_size > _MAX_FILE_SIZE_BYTES:
                            continue
                        # Read first 4 KB for PEM header sniff
                        with fpath.open("rb") as fh:
                            head = fh.read(4096)
                        if _file_has_pem_content(head):
                            pem_candidates.append(fpath)
                    except OSError:
                        continue
                if total_walked >= _MAX_FILES_SCANNED:
                    break

    # Merge, dedup, preserve original order
    seen_paths: set[Path] = set(candidates)
    for p in pem_candidates:
        if p not in seen_paths:
            candidates.append(p)
            seen_paths.add(p)

    return candidates


# ---------------------------------------------------------------------------
# Security check helpers
# ---------------------------------------------------------------------------

def _is_expired(not_after_iso: str | None) -> bool:
    if not_after_iso is None:
        return False
    try:
        dt = datetime.fromisoformat(not_after_iso.replace("Z", "+00:00"))
        return dt < datetime.now(timezone.utc)
    except Exception:
        return False


def _is_self_signed(subject_cn: str | None, issuer_cn: str | None) -> bool:
    if subject_cn is None or issuer_cn is None:
        return False
    return subject_cn.strip().lower() == issuer_cn.strip().lower()


def _is_wildcard(cn: str | None) -> bool:
    if cn is None:
        return False
    return cn.strip().startswith("*")


def _is_weak_sig(oid: str | None) -> bool:
    if oid is None:
        return False
    return oid in _WEAK_SIG_OIDS


def _is_weak_key(alg_oid: str | None, bits: int | None) -> bool:
    if alg_oid is None or bits is None:
        return False
    # RSA: rsaEncryption
    if alg_oid == "1.2.840.113549.1.1.1":
        return bits < 2048
    # EC: ecPublicKey
    if alg_oid == "1.2.840.10045.2.1":
        return bits < 256
    # DSA
    if alg_oid == "1.2.840.10040.4.1":
        return bits < 2048
    return False


def _world_readable(path: Path) -> bool:
    try:
        mode = path.stat().st_mode
        return bool(mode & 0o004)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Core analysis
# ---------------------------------------------------------------------------

def _analyze_file(
    fpath: Path,
    run_dir: Path,
) -> tuple[list[dict], list[str]]:
    """Analyze a single file for certs and private keys.

    Returns (cert_records, private_key_type_labels).
    cert_records is a list of parsed certificate dicts.
    private_key_type_labels is a list of key type strings found.
    """
    cert_records: list[dict] = []
    private_key_types: list[str] = []

    try:
        stat = fpath.stat()
        if stat.st_size == 0 or stat.st_size > _MAX_FILE_SIZE_BYTES:
            return cert_records, private_key_types
        raw = fpath.read_bytes()
    except OSError:
        return cert_records, private_key_types

    suffix = fpath.suffix.lower()
    file_rel = _rel_to_run_dir(run_dir, fpath)

    # --- Private key detection ---
    pk_types = _detect_private_key_types(raw)
    for kt in pk_types:
        private_key_types.append(kt)

    # --- Certificate parsing ---
    if suffix == ".der" or suffix == ".cer":
        # Try raw DER first
        parsed = _parse_der_certificate(raw)
        if parsed:
            cert_records.append(
                {
                    "file_path": file_rel,
                    "file_hash": "sha256:" + _sha256_bytes(raw),
                    **parsed,
                }
            )
        else:
            # Might still be PEM-wrapped despite extension
            for der in _extract_pem_certs(raw):
                p = _parse_der_certificate(der)
                if p:
                    cert_records.append(
                        {
                            "file_path": file_rel,
                            "file_hash": "sha256:" + _sha256_bytes(der),
                            **p,
                        }
                    )
    elif suffix in {".pem", ".crt", ".key", ".p12", ".pfx"}:
        # PEM-based: may contain one or multiple certs
        ders = _extract_pem_certs(raw)
        if ders:
            for der in ders:
                p = _parse_der_certificate(der)
                if p:
                    cert_records.append(
                        {
                            "file_path": file_rel,
                            "file_hash": "sha256:" + _sha256_bytes(der),
                            **p,
                        }
                    )
        else:
            # Try as raw DER anyway
            parsed = _parse_der_certificate(raw)
            if parsed:
                cert_records.append(
                    {
                        "file_path": file_rel,
                        "file_hash": "sha256:" + _sha256_bytes(raw),
                        **parsed,
                    }
                )
    else:
        # Content-sniffed: PEM headers present
        for der in _extract_pem_certs(raw):
            p = _parse_der_certificate(der)
            if p:
                cert_records.append(
                    {
                        "file_path": file_rel,
                        "file_hash": "sha256:" + _sha256_bytes(der),
                        **p,
                    }
                )

    return cert_records, private_key_types


def _build_issues(
    cert_records: list[dict],
    private_key_entries: list[dict],
    now_utc: datetime,
) -> list[dict]:
    """Generate issue records from analysed cert/key data."""
    issues: list[dict] = []

    for cert in cert_records:
        file_path = cert.get("file_path", "")
        evidence_ref = cert.get("file_hash", "")
        subject_cn = cert.get("subject_cn")
        issuer_cn = cert.get("issuer_cn")
        not_after = cert.get("not_after")
        sig_oid = cert.get("sig_alg_oid")
        pk_oid = cert.get("pubkey_alg_oid")
        pk_bits = cert.get("pubkey_bits")

        if _is_expired(not_after):
            issues.append(
                {
                    "type": "expired_certificate",
                    "severity": "medium",
                    "file_path": file_path,
                    "details": {
                        "subject_cn": subject_cn,
                        "expired_at": not_after,
                    },
                    "evidence_ref": evidence_ref,
                }
            )

        if _is_weak_sig(sig_oid):
            sig_name = cert.get("sig_alg_name", sig_oid)
            issues.append(
                {
                    "type": "weak_signature_algorithm",
                    "severity": "medium",
                    "file_path": file_path,
                    "details": {
                        "subject_cn": subject_cn,
                        "algorithm": sig_name,
                        "oid": sig_oid,
                    },
                    "evidence_ref": evidence_ref,
                }
            )

        if _is_weak_key(pk_oid, pk_bits):
            issues.append(
                {
                    "type": "weak_key_size",
                    "severity": "medium",
                    "file_path": file_path,
                    "details": {
                        "subject_cn": subject_cn,
                        "algorithm": cert.get("pubkey_alg_name"),
                        "key_bits": pk_bits,
                    },
                    "evidence_ref": evidence_ref,
                }
            )

        if _is_self_signed(subject_cn, issuer_cn):
            issues.append(
                {
                    "type": "self_signed_certificate",
                    "severity": "low",
                    "file_path": file_path,
                    "details": {
                        "subject_cn": subject_cn,
                        "issuer_cn": issuer_cn,
                    },
                    "evidence_ref": evidence_ref,
                }
            )

        if _is_wildcard(subject_cn):
            issues.append(
                {
                    "type": "wildcard_certificate",
                    "severity": "info",
                    "file_path": file_path,
                    "details": {"subject_cn": subject_cn},
                    "evidence_ref": evidence_ref,
                }
            )

    for pk in private_key_entries:
        file_path = pk.get("file_path", "")
        evidence_ref = pk.get("file_hash", "")
        key_type = pk.get("key_type", "unknown")

        issues.append(
            {
                "type": "private_key_in_firmware",
                "severity": "high",
                "file_path": file_path,
                "details": {"key_type": key_type},
                "evidence_ref": evidence_ref,
            }
        )

        if pk.get("world_readable", False):
            issues.append(
                {
                    "type": "private_key_world_readable",
                    "severity": "high",
                    "file_path": file_path,
                    "details": {"key_type": key_type},
                    "evidence_ref": evidence_ref,
                }
            )

    return issues


# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------

def _compute_summary(
    cert_records: list[dict],
    private_key_entries: list[dict],
    issues: list[dict],
) -> dict:
    issue_types = [i["type"] for i in issues]
    return {
        "expired": issue_types.count("expired_certificate"),
        "weak_key": issue_types.count("weak_key_size"),
        "weak_sig": issue_types.count("weak_signature_algorithm"),
        "self_signed": issue_types.count("self_signed_certificate"),
        "wildcard": issue_types.count("wildcard_certificate"),
        "private_keys_exposed": len(private_key_entries),
        "private_key_world_readable": issue_types.count("private_key_world_readable"),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_certificates(
    rootfs_dirs: list[Path],
    run_dir: Path,
    stage_dir: Path,
) -> dict:
    """Analyze X.509 certificates in firmware rootfs directories.

    Scans up to _MAX_FILES_SCANNED files and parses up to _MAX_CERTS_ANALYZED
    certificates. Writes cert_analysis.json to *stage_dir* and returns the
    result dict.

    Args:
        rootfs_dirs: List of rootfs directory paths to scan.
        run_dir:     The analysis run directory (used for path safety checks
                     and relative path computation).
        stage_dir:   The stage output directory where cert_analysis.json is
                     written. Must be under *run_dir*.

    Returns:
        The full cert_analysis dict (same content as cert_analysis.json).
    """
    # Safety: stage_dir must be inside run_dir
    out_path = stage_dir / "cert_analysis.json"
    assert_under_dir(run_dir, out_path)

    now_utc = datetime.now(timezone.utc)

    candidate_files = _discover_cert_files(rootfs_dirs)

    all_cert_records: list[dict] = []
    all_private_key_entries: list[dict] = []

    # Per-file tracking to avoid recording the same physical key multiple times
    seen_key_hashes: set[str] = set()
    certs_analyzed = 0

    for fpath in candidate_files:
        if not fpath.is_file():
            continue

        # Read raw once for private-key detection and cert extraction
        try:
            stat = fpath.stat()
            if stat.st_size == 0 or stat.st_size > _MAX_FILE_SIZE_BYTES:
                continue
            raw = fpath.read_bytes()
        except OSError:
            continue

        file_rel = _rel_to_run_dir(run_dir, fpath)
        file_hash = "sha256:" + _sha256_bytes(raw)

        # Private key detection (all files, no cap)
        pk_types = _detect_private_key_types(raw)
        for kt in pk_types:
            # Deduplicate by content hash + key type
            dedup_key = f"{file_hash}:{kt}"
            if dedup_key not in seen_key_hashes:
                seen_key_hashes.add(dedup_key)
                all_private_key_entries.append(
                    {
                        "file_path": file_rel,
                        "file_hash": file_hash,
                        "key_type": kt,
                        "world_readable": _world_readable(fpath),
                    }
                )

        # Certificate parsing (capped)
        if certs_analyzed >= _MAX_CERTS_ANALYZED:
            continue

        suffix = fpath.suffix.lower()
        cert_records: list[dict] = []

        if suffix in {".der", ".cer"}:
            parsed = _parse_der_certificate(raw)
            if parsed:
                cert_records.append(
                    {"file_path": file_rel, "file_hash": file_hash, **parsed}
                )
            else:
                for der in _extract_pem_certs(raw):
                    if certs_analyzed + len(cert_records) >= _MAX_CERTS_ANALYZED:
                        break
                    p = _parse_der_certificate(der)
                    if p:
                        cert_records.append(
                            {
                                "file_path": file_rel,
                                "file_hash": "sha256:" + _sha256_bytes(der),
                                **p,
                            }
                        )
        else:
            ders = _extract_pem_certs(raw)
            if ders:
                for der in ders:
                    if certs_analyzed + len(cert_records) >= _MAX_CERTS_ANALYZED:
                        break
                    p = _parse_der_certificate(der)
                    if p:
                        cert_records.append(
                            {
                                "file_path": file_rel,
                                "file_hash": "sha256:" + _sha256_bytes(der),
                                **p,
                            }
                        )
            else:
                # Try raw DER
                parsed = _parse_der_certificate(raw)
                if parsed:
                    cert_records.append(
                        {"file_path": file_rel, "file_hash": file_hash, **parsed}
                    )

        all_cert_records.extend(cert_records)
        certs_analyzed += len(cert_records)

    # Build issue list
    issues = _build_issues(all_cert_records, all_private_key_entries, now_utc)

    # Sort issues for deterministic output: severity → type → file_path
    _severity_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    issues.sort(
        key=lambda i: (
            _severity_rank.get(i.get("severity", "info"), 9),
            i.get("type", ""),
            i.get("file_path", ""),
        )
    )

    # Sort cert records and key entries for deterministic output
    all_cert_records.sort(key=lambda c: (c.get("file_path", ""), c.get("file_hash", "")))
    all_private_key_entries.sort(
        key=lambda k: (k.get("file_path", ""), k.get("key_type", ""))
    )

    summary = _compute_summary(all_cert_records, all_private_key_entries, issues)

    result: dict = {
        "schema_version": _SCHEMA_VERSION,
        "analyzed_at": now_utc.isoformat().replace("+00:00", "Z"),
        "certificates_found": len(all_cert_records),
        "private_keys_found": len(all_private_key_entries),
        "issues": issues,
        "certificates": all_cert_records,
        "private_keys": all_private_key_entries,
        "summary": summary,
    }

    # Write output artifact
    stage_dir.mkdir(parents=True, exist_ok=True)
    assert_under_dir(run_dir, out_path)
    out_path.write_text(
        json.dumps(result, sort_keys=True, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return result
