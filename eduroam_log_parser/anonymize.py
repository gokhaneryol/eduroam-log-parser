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
    "extract_tld",
]

_EMPTY = {"", "-", "N/A", "n/a"}
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")


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


def extract_tld(domain: str) -> str:
    """Return the top-level label of *domain* (e.g. ``'tr'`` from ``'edu.tr'``).

    Returns an empty string when the domain is empty or the TLD is fewer than
    two characters long.
    """
    parts = domain.lower().strip().rstrip(".").split(".")
    if len(parts) < 2:
        return ""
    last = parts[-1]
    return last if len(last) >= 2 else ""
