"""
eduroam_log_parser.parsers.radius_auth
=======================================
Parser for FreeRADIUS ``Auth:`` log lines.

These lines are written by the FreeRADIUS ``rlm_files`` / ``detail`` module
and carry explicit success/failure information along with a human-readable
reason string.  Two forms are supported::

    # Success
    Mon Oct  5 00:01:07 2025 : Auth: (42) Login OK: [user@realm] \
        (from client nas1 port 0 cli AA:BB:CC:DD:EE:FF via TLS tunnel)

    # Failure
    Mon Oct  5 00:02:11 2025 : Auth: (43) Login incorrect \
        (TLS Alert read:fatal:certificate unknown): [user@realm] \
        (from client nas2 port 1812 cli 00:11:22:33:44:55)
"""

import re
from typing import Optional

from eduroam_log_parser.anonymize import (
    anonymize,
    anonymize_ips_in_text,
    anonymize_mac,
    extract_tld,
)
from eduroam_log_parser.classify import (
    classify_failure,
    classify_outer_identity,
    classify_realm_signal,
)
from eduroam_log_parser.utils import normalize_ts

__all__ = ["parse_radius_auth"]

SCHEMA_VERSION = "2.0.0"

_AUTH_OK = re.compile(
    r"^(?P<ts>.+?)\s*:\s*Auth:\s*\(\d+\)\s+Login OK:\s*\[(?P<user>[^\]]+)\]\s+"
    r"\(from client (?P<client>\S+)\s+port (?P<port>\d+)"
    r"(?:\s+cli\s+(?P<cli>\S+))?(?P<tun>\s+via TLS tunnel)?\)"
)
_AUTH_FAIL = re.compile(
    r"^(?P<ts>.+?)\s*:\s*Auth:\s*\(\d+\)\s+Login incorrect\s*"
    r"(?:\((?P<reason>[^)]+)\))?:\s*\[(?P<user>[^\]]+)\]\s+"
    r"\(from client (?P<client>\S+)\s+port (?P<port>\d+)"
    r"(?:\s+cli\s+(?P<cli>\S+))?(?P<tun>\s+via TLS tunnel)?\)"
)

_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (_AUTH_OK,   "OK"),
    (_AUTH_FAIL, "FAIL"),
)


def parse_radius_auth(line: str, salt: str) -> Optional[dict]:
    """Parse a single FreeRADIUS ``Auth:`` log line and return an anonymised record.

    Parameters
    ----------
    line:
        A raw log line (newline need not be stripped).
    salt:
        Secret string used as HMAC-like prefix before SHA-256 hashing.

    Returns
    -------
    dict or None
        Structured record dictionary, or ``None`` when the line does not
        match either the ``Login OK`` or ``Login incorrect`` pattern.

    Record fields
    -------------
    schema_version, log_type, timestamp, result,
    username_hash, mac_hash, realm_hash, realm_tld, nas_hash,
    outer_identity_type, realm_signal,
    failure_category, failure_layer, failure_reason,
    port, via_tunnel
    """
    line = line.rstrip()
    if not line:
        return None

    for pattern, result in _PATTERNS:
        m = pattern.match(line)
        if not m:
            continue

        user_raw    = m.group("user")
        cli_raw     = m.group("cli") or ""
        nas_raw     = m.group("client")
        reason_raw  = (m.group("reason") if "reason" in m.groupdict() else "") or ""
        reason_clean = anonymize_ips_in_text(reason_raw, salt)

        local     = user_raw.rsplit("@", 1)[0] if "@" in user_raw else user_raw
        realm_raw = user_raw.rsplit("@", 1)[1].lower() if "@" in user_raw else ""

        realm_signal = classify_realm_signal(user_raw)
        oit          = classify_outer_identity(local)
        fcat, flayer = classify_failure(reason_raw, result, realm_signal)

        return {
            "schema_version":      SCHEMA_VERSION,
            "log_type":            "radius_auth",
            "timestamp":           normalize_ts(m.group("ts").strip()),
            "result":              result,
            "username_hash":       anonymize(local, salt),
            "mac_hash":            anonymize_mac(cli_raw, salt),
            "realm_hash":          anonymize(realm_raw, salt),
            "realm_tld":           extract_tld(realm_raw),
            "nas_hash":            anonymize(nas_raw.lower(), salt),
            "outer_identity_type": oit,
            "realm_signal":        realm_signal,
            "failure_category":    fcat,
            "failure_layer":       flayer,
            "failure_reason":      reason_clean,
            "port":                int(m.group("port")) if m.group("port") else 0,
            "via_tunnel":          bool(m.group("tun")),
        }

    return None
