"""
eduroam_log_parser.parsers.fticks
==================================
Parser for F-TICKS/eduroam syslog lines.

F-TICKS is the lightweight accounting protocol used across the eduroam
federation.  Each line looks like::

    2025-10-05T00:00:27+03:00 host freeradius: F-TICKS/eduroam/1.0#REALM=...#RESULT=FAIL#

Reference: https://wiki.geant.org/display/H2eduroam/F-TICKS
"""

import re
from typing import Optional

from eduroam_log_parser.anonymize import (
    anonymize,
    anonymize_mac,
    extract_tld,
)
from eduroam_log_parser.classify import (
    classify_failure,
    classify_outer_identity,
    classify_realm_signal,
)
from eduroam_log_parser.utils import normalize_ts

__all__ = ["parse_fticks"]

SCHEMA_VERSION = "2.0.0"

_FTICKS_LINE = re.compile(
    r"^(?P<ts>\S+)\s+\S+\s+freeradius:\s+F-TICKS/eduroam/[\d.]+#(?P<fields>.+)#\s*$"
)
_REPEATED = re.compile(r"message repeated \d+ times")


def parse_fticks(line: str, salt: str) -> Optional[dict]:
    """Parse a single F-TICKS syslog line and return an anonymised record.

    Parameters
    ----------
    line:
        A raw log line (newline need not be stripped).
    salt:
        Secret string used as HMAC-like prefix before SHA-256 hashing.
        Must be consistent across all lines in a dataset to preserve
        per-session correlation.

    Returns
    -------
    dict or None
        Structured record dictionary, or ``None`` when the line does not
        match the F-TICKS format (including ``message repeated`` collapsing).

    Record fields
    -------------
    schema_version, log_type, timestamp, result,
    username_hash, mac_hash, realm_hash, realm_tld,
    visinst_hash, visinst_country,
    outer_identity_type, realm_signal,
    failure_category, failure_layer, failure_reason
    """
    line = line.rstrip()
    if not line or _REPEATED.search(line):
        return None

    m = _FTICKS_LINE.match(line)
    if not m:
        return None

    # Parse key=value pairs separated by '#'
    fields: dict[str, str] = {}
    for tok in m.group("fields").split("#"):
        if "=" in tok:
            k, v = tok.split("=", 1)
            fields[k.upper()] = v

    username_raw = fields.get("USERNAME", "")
    realm_raw    = fields.get("REALM", "").lower()
    visinst_raw  = re.sub(r"^\d+", "", fields.get("VISINST", "")).lower()
    csi_raw      = fields.get("CSI", "")
    result       = fields.get("RESULT", "").upper()

    local = username_raw.rsplit("@", 1)[0] if "@" in username_raw else username_raw
    realm_signal = classify_realm_signal(username_raw)
    oit          = classify_outer_identity(local)
    fcat, flayer = classify_failure("", result, realm_signal)

    return {
        "schema_version":      SCHEMA_VERSION,
        "log_type":            "fticks",
        "timestamp":           normalize_ts(m.group("ts")),
        "result":              result,
        "username_hash":       anonymize(local, salt),
        "mac_hash":            anonymize_mac(csi_raw, salt),
        "realm_hash":          anonymize(realm_raw, salt),
        "realm_tld":           extract_tld(realm_raw),
        "visinst_hash":        anonymize(visinst_raw, salt),
        "visinst_country":     fields.get("VISCOUNTRY", ""),
        "outer_identity_type": oit,
        "realm_signal":        realm_signal,
        "failure_category":    fcat,
        "failure_layer":       flayer,
        "failure_reason":      "",
    }
