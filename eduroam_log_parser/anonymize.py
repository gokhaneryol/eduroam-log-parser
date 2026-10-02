"""
eduroam_log_parser.anonymize
============================
Deterministic pseudonymization helpers.

All sensitive fields (username local-part, MAC address, realm, NAS client
name, IP addresses) are replaced with a truncated SHA-256 digest seeded by a
caller-supplied secret salt.  The same input always produces the same digest,
so per-session correlation is preserved without exposing real identifiers.
"""

import hashlib
import re

__all__ = [
    "anonymize",
    "anonymize_mac",
    "anonymize_ips_in_text",
    "anonymize_reason",
    "extract_tld",
]

_EMPTY = {"", "-", "N/A", "n/a"}
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_IDENTITY_RE = re.compile(r"[^\s\"'\[\]()<>,;]+@[^\s\"'\[\]()<>,;]*")
# Accepted top-level labels: any two-letter ASCII label (country-code space),
# an IDNA "xn--" label, or a known generic TLD. Longer letter-only strings are
# NOT accepted on shape alone: in real logs they are often typed names or
# password fragments glued to ".tr" (e.g. "edu.tr<something>").
_CC_OR_IDN_RE = re.compile(r"^(?:[a-z]{2}|xn--[a-z0-9-]{1,59})$")
_GENERIC_TLDS = frozenset({
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name", "pro", "aero", "coop",
    "museum", "mobi", "asia", "tel", "travel", "jobs", "cat", "arpa", "eus", "gal", "scot", "wales",
    "cymru", "bzh", "swiss", "berlin", "hamburg", "nrw", "paris", "london", "amsterdam", "wien",
    "brussels", "vlaanderen", "tirol", "bayern", "koeln", "ruhr", "saarland", "quebec", "nyc",
    "tokyo", "istanbul", "ist", "academy", "college", "university", "education", "school", "science",
    "app", "dev", "io", "ai", "cloud", "online", "site", "tech", "network", "global", "world",
    "local", "lan", "internal", "corp", "home", "localdomain",
})


def _sha256(value: str, salt: str) -> str:
    """Return the first 32 hex characters of SHA-256(salt + value)."""
    raw = (salt + value.lower().strip()).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:32]


def anonymize(value: str, salt: str) -> str:
    """Hash an arbitrary string field (username local-part, realm, NAS name…).

    Returns an empty string for blank / placeholder values.
    """
    if not value or value.strip() in _EMPTY:
        return ""
    return _sha256(value, salt)


def anonymize_mac(mac: str, salt: str) -> str:
    """Hash a MAC address after normalising separators and case.

    Treats ``-`` and ``:`` as equivalent separators; compares upper-case.
    Returns an empty string for missing or placeholder MACs.
    """
    if not mac or mac.strip() in _EMPTY:
        return ""
    normalised = mac.upper().replace("-", ":")
    return _sha256(normalised, salt)


def anonymize_ips_in_text(text: str, salt: str) -> str:
    """Replace every IPv4 address found in *text* with its hash.

    Useful for failure-reason strings that may embed NAS or client IPs.
    """
    return _IP_RE.sub(lambda m: _sha256(m.group(1), salt), text)


def anonymize_reason(text: str, salt: str) -> str:
    """Pseudonymise a failure-reason string.

    Replaces IPv4 addresses and anything shaped like ``user@realm`` with
    hashes. FreeRADIUS reason strings sometimes quote the identity.
    """
    text = _IDENTITY_RE.sub(lambda m: _sha256(m.group(0), salt), text)
    return anonymize_ips_in_text(text, salt)


def extract_tld(domain: str) -> str:
    """Return the top-level label of *domain* (e.g. ``'tr'`` from ``'edu.tr'``).

    Only a syntactically plausible TLD (2-24 ASCII letters, or an ``xn--``
    label) is returned; anything else yields an empty string. Malformed realms
    are user-typed input and often contain fragments of usernames or
    passwords, so the raw last label must never be emitted.
    """
    parts = domain.lower().strip().rstrip(".").split(".")
    if len(parts) < 2:
        return ""
    last = parts[-1]
    return last if (_CC_OR_IDN_RE.match(last) or last in _GENERIC_TLDS) else ""
