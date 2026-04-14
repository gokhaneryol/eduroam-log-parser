"""
eduroam_log_parser.classify
============================
Heuristic classifiers for eduroam / FreeRADIUS log events.

Three independent classifiers are exported:

* :func:`classify_realm_signal`  — structural analysis of the outer identity
* :func:`classify_outer_identity` — local-part format classification
* :func:`classify_failure`        — failure category + protocol layer

All classifiers operate on *pre-hash* strings and return plain string labels
that are safe to include in public datasets.
"""

import re

__all__ = [
    "classify_realm_signal",
    "classify_outer_identity",
    "classify_failure",
    "REALM_SIGNAL_LABELS",
    "FAILURE_CATEGORY_LABELS",
]

# ---------------------------------------------------------------------------
# Known public e-mail providers — auth via eduroam is always a failure
# ---------------------------------------------------------------------------
PUBLIC_EMAIL_DOMAINS: frozenset[str] = frozenset({
    "gmail.com", "googlemail.com",
    "hotmail.com", "live.com", "outlook.com", "windowslive.com",
    "yahoo.com", "yahoo.cn",
    "icloud.com", "me.com", "mac.com",
    "msn.com", "yandex.com", "yandex.ru",
    "unimail.com",
})

# Sub-realm prefixes that indicate a valid institutional split
VALID_SUBREALM_PREFIXES: tuple[str, ...] = (
    "ogr.", "ogrenci.", "student.", "students.", "stu.", "stud.",
    "staff.", "personel.", "alumni.", "postgrad.", "pg.", "grad.",
    "edu.", "akademik.",
)

_TYPO_TLD_RE = re.compile(
    r"\.(ax\.edu|ac\.edu|ax\.uk|sc\.uk|au\.uk|ac\.ik|ac\.u|ac\.k|ac\.ukj)$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Realm signal labels (informational, not exhaustive)
# ---------------------------------------------------------------------------
REALM_SIGNAL_LABELS: tuple[str, ...] = (
    "syntactically_valid",
    "institution_subrealm",
    "well_known_public_domain",
    "auto_generated_sim",
    "auto_generated_client_app",
    "misrouted_local_subdomain",
    "malformed_no_at",
    "malformed_empty_domain",
    "malformed_multiple_at",
    "malformed_double_dot",
    "malformed_boundary_dot",
    "malformed_no_dot_in_domain",
    "malformed_trailing_garbage",
    "malformed_typo_tld",
    "unknown",
)

FAILURE_CATEGORY_LABELS: tuple[str, ...] = (
    "tls_handshake_failure",
    "eap_method_mismatch",
    "policy_reject",
    "proxy_routing_failure",
    "proxy_timeout",
    "public_domain_auth_failure",
    "auto_generated_realm_rejected",
    "misrouted_local_subdomain",
    "misconfiguration_warning",
    "no_detail_in_fticks",
    "other_failure",
)

# Mapping realm_signal → (failure_category, failure_layer) for F-TICKS FAIL
_FTICKS_FAIL_BY_REALM: dict[str, tuple[str, str]] = {
    "well_known_public_domain":   ("public_domain_auth_failure",   "policy"),
    "auto_generated_sim":         ("auto_generated_realm_rejected", "policy"),
    "auto_generated_client_app":  ("auto_generated_realm_rejected", "policy"),
    "misrouted_local_subdomain":  ("misrouted_local_subdomain",    "radius_proxy"),
    "malformed_no_at":            ("policy_reject",                "policy"),
    "malformed_empty_domain":     ("policy_reject",                "policy"),
    "malformed_multiple_at":      ("policy_reject",                "policy"),
    "malformed_double_dot":       ("policy_reject",                "policy"),
    "malformed_boundary_dot":     ("policy_reject",                "policy"),
    "malformed_no_dot_in_domain": ("policy_reject",                "policy"),
    "malformed_trailing_garbage": ("policy_reject",                "policy"),
    "malformed_typo_tld":         ("policy_reject",                "policy"),
}


def classify_realm_signal(username_raw: str) -> str:
    """Classify the structural quality of an outer identity string.

    Operates on the *raw* (pre-anonymisation) username.  The returned label
    characterises the realm portion without revealing the actual value.

    Parameters
    ----------
    username_raw:
        The full outer identity as it appears in the log line
        (e.g. ``"anonymous@university.ac.uk"``).

    Returns
    -------
    str
        One of :data:`REALM_SIGNAL_LABELS`.
    """
    raw = username_raw.strip()

    if raw.count("@") > 1:
        return "malformed_multiple_at"
    if "@" not in raw:
        return "malformed_no_at"

    _local, domain = raw.rsplit("@", 1)
    domain = domain.strip()

    if not domain:
        return "malformed_empty_domain"
    if re.search(r"[\x00-\x1f\x7f ]", domain):
        return "malformed_trailing_garbage"
    if ".." in domain:
        return "malformed_double_dot"
    if domain.startswith(".") or domain.endswith("."):
        return "malformed_boundary_dot"
    if "." not in domain:
        return "malformed_no_dot_in_domain"

    dl = domain.lower()

    if _TYPO_TLD_RE.search(dl):
        return "malformed_typo_tld"
    if dl in PUBLIC_EMAIL_DOMAINS:
        return "well_known_public_domain"
    if re.search(r"3gppnetworks?\.org", dl) or re.search(r"mnc\d+\.mcc\d+", dl):
        return "auto_generated_sim"
    if re.search(r"(myabc\.com|wifinetwork\.net)", dl):
        return "auto_generated_client_app"
    if any(dl.startswith(p) for p in VALID_SUBREALM_PREFIXES):
        return "institution_subrealm"
    if len(dl.split(".")) >= 4:
        return "misrouted_local_subdomain"
    if re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$", domain):
        return "syntactically_valid"
    return "unknown"


def classify_outer_identity(local: str) -> str:
    """Classify the local-part of an outer identity.

    Parameters
    ----------
    local:
        The part of the username before ``@``.

    Returns
    -------
    str
        One of ``"anonymous"``, ``"numeric_identifier"``,
        ``"institutional_format"``, ``"malformed"``, or ``"unknown"``.
    """
    if not local:
        return "unknown"
    if local.lower() == "anonymous":
        return "anonymous"
    if local.isdigit():
        return "numeric_identifier"
    if re.match(r"^[a-zA-Z][a-zA-Z0-9._\-]*$", local):
        return "institutional_format"
    return "malformed"


def classify_failure(
    reason: str,
    result: str,
    realm_signal: str,
) -> tuple[str, str]:
    """Derive ``(failure_category, failure_layer)`` from available context.

    Parameters
    ----------
    reason:
        The failure-reason string from a ``radius_auth`` log line (may be
        empty for F-TICKS records).
    result:
        ``"OK"`` or ``"FAIL"``.
    realm_signal:
        Output of :func:`classify_realm_signal` for the same event.

    Returns
    -------
    tuple[str, str]
        ``(failure_category, failure_layer)``.  Both are empty strings for
        successful authentications that show no misconfiguration signal.
    """
    if result == "OK":
        if realm_signal == "misrouted_local_subdomain":
            return ("misconfiguration_warning", "radius_proxy")
        return ("", "")

    # radius_auth: explicit reason string available
    if reason:
        r = reason.lower()
        if "tls" in r and ("failed" in r or "alert" in r or "handshake" in r):
            return ("tls_handshake_failure", "tls")
        if "eap_md5" in r or "cleartext-password" in r:
            return ("eap_method_mismatch", "eap")
        if "no mutually acceptable" in r:
            return ("eap_method_mismatch", "eap")
        if "no auth-type" in r or "post-auth-type" in r or (
            "reject" in r and "failure" not in r
        ):
            return ("policy_reject", "policy")
        if "timeout" in r:
            return ("proxy_timeout", "radius_proxy")
        if "proxy" in r or "unknown realm" in r:
            return ("proxy_routing_failure", "radius_proxy")
        return ("other_failure", "unknown")

    # F-TICKS: no reason — infer from realm signal
    if realm_signal in _FTICKS_FAIL_BY_REALM:
        return _FTICKS_FAIL_BY_REALM[realm_signal]

    return ("no_detail_in_fticks", "unknown")
