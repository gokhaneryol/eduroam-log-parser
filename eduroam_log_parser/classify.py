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

Failure labels follow the taxonomy of the HF dataset
``gokhaneryol/freeradius-8021x-log-dataset`` v4.0.0. The 0.1.x labels are
still available through :func:`classify_failure_legacy`.
"""

import re
from typing import Iterable

__all__ = [
    "classify_realm_signal",
    "classify_outer_identity",
    "classify_failure",
    "classify_failure_legacy",
    "REALM_SIGNAL_LABELS",
    "FAILURE_CATEGORY_LABELS",
    "LEGACY_FAILURE_CATEGORY_LABELS",
    "TAXONOMY_VERSION",
]

TAXONOMY_VERSION = "4.0.0"

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

# Internal / non-routable name space. A realm ending in one of these TLDs, or
# whose first label names an internal host or directory, should have been
# handled inside the institution and never reached the federation.
INTERNAL_TLDS: frozenset[str] = frozenset({
    "local", "lan", "internal", "intranet", "intra", "corp", "home", "localdomain", "private",
})
_INTERNAL_FIRST_LABEL_RE = re.compile(
    r"^(ad|dc\d*|corp|int|internal|intra|intranet|lan|local|radius\d*|nps\d*|ldap\d*|krb\d*|kerberos|srv\d*)$"
)

_TYPO_TLD_RE = re.compile(
    r"\.(ax\.edu|ac\.edu|ax\.uk|sc\.uk|au\.uk|ac\.ik|ac\.u|ac\.k|ac\.ukj)$",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Labels
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
    "certificate_error",
    "eap_method_mismatch",
    "eap_cleartext_required",
    "eap_inner_auth_failure",
    "policy_reject",
    "public_domain_rejected",
    "auto_generated_realm_rejected",
    "misrouted_local_subdomain",
    "invalid_realm_format",
    "realm_not_found",
    "timeout_or_no_response",
    "proxy_error",
    "unspecified_failure",
    "misconfiguration_warning",   # result=OK but realm looks misrouted
    "other_failure",              # FAIL with a reason no rule recognises
)

LEGACY_FAILURE_CATEGORY_LABELS: tuple[str, ...] = (
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

LAYER: dict[str, str] = {
    "tls_handshake_failure": "tls",
    "certificate_error": "tls",
    "eap_method_mismatch": "eap",
    "eap_cleartext_required": "eap",
    "eap_inner_auth_failure": "eap",
    "policy_reject": "policy",
    "public_domain_rejected": "policy",
    "auto_generated_realm_rejected": "policy",
    "misrouted_local_subdomain": "policy",
    "invalid_realm_format": "identity",
    "realm_not_found": "radius_proxy",
    "timeout_or_no_response": "radius_proxy",
    "proxy_error": "radius_proxy",
    "unspecified_failure": "unknown",
    "misconfiguration_warning": "policy",
    "other_failure": "unknown",
}

# realm_signal -> category when the realm itself explains the failure
_FAIL_BY_REALM: dict[str, str] = {
    "well_known_public_domain": "public_domain_rejected",
    "auto_generated_sim": "auto_generated_realm_rejected",
    "auto_generated_client_app": "auto_generated_realm_rejected",
    "misrouted_local_subdomain": "misrouted_local_subdomain",
    "malformed_no_at": "invalid_realm_format",
    "malformed_empty_domain": "invalid_realm_format",
    "malformed_multiple_at": "invalid_realm_format",
    "malformed_double_dot": "invalid_realm_format",
    "malformed_boundary_dot": "invalid_realm_format",
    "malformed_no_dot_in_domain": "invalid_realm_format",
    "malformed_trailing_garbage": "invalid_realm_format",
    "malformed_typo_tld": "invalid_realm_format",
}

# Reason-string rules, evaluated in order. First match wins. Order matters:
# certificate before generic TLS (both mention TLS), cleartext before inner
# auth (both can mention mschap).
#
# Evaluation note: these needles were written with the v4 dataset's train
# variants in view. Strings that occur only in v4's held-out (test-only)
# variants were deliberately NOT added, so scores on heldout_variant=true rows
# measure generalisation rather than memorisation.
_REASON_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("proxy_error", ("message-authenticator", "shared secret", "no eap session matching state")),
    ("realm_not_found", ("no such realm", "unknown realm", "failed to find live home server",
                         "failed to find home server")),
    ("timeout_or_no_response", ("failed to respond", "timeout", "timed out", "no response from home server",
                                "lack of any response", "as zombie")),
    ("certificate_error", ("verify error", "client certificate", "certificate has expired",
                           "unable to get local issuer", "certificate cn")),
    ("tls_handshake_failure", ("tls alert", "tls_accept", "handshake")),
    ("eap_cleartext_required", ("eap_md5", "eap-md5", "cleartext-password is required",
                                "no nt-password", "no nt/lm-password")),
    ("eap_method_mismatch", ("no mutually acceptable", "nak'd", "unsupported eap type")),
    ("eap_inner_auth_failure", ("mschap", "ms-chap", "crypt password", "password does not match",
                                "user not found", "invalid password", "wrong password")),
    ("policy_reject", ("no auth-type", "post-auth", "reject")),
)

# Generic policy reasons where the realm, if suspicious, is the real cause.
_GENERIC_POLICY = ("no auth-type", "post-auth")


def classify_realm_signal(
    username_raw: str,
    internal_prefixes: Iterable[str] = (),
    legacy_depth_rule: bool = False,
) -> str:
    """Classify the structural quality of an outer identity string.

    Operates on the *raw* (pre-anonymisation) username.  The returned label
    characterises the realm portion without revealing the actual value.

    Parameters
    ----------
    username_raw:
        The full outer identity as it appears in the log line
        (e.g. ``"anonymous@university.ac.uk"``).
    internal_prefixes:
        Extra first labels (e.g. ``("wifi", "lab")``) that mark a realm as an
        internal subdomain at *your* institution.
    legacy_depth_rule:
        Restore the 0.1.x heuristic that treats every realm with four or more
        labels as misrouted. Off by default: it flags legitimate department
        realms such as ``cs.example.ac.uk``.

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
    labels = dl.split(".")

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
    extra = {p.lower().strip(".") for p in internal_prefixes}
    if labels[-1] in INTERNAL_TLDS or (
        len(labels) >= 3 and (_INTERNAL_FIRST_LABEL_RE.match(labels[0]) or labels[0] in extra)
    ):
        return "misrouted_local_subdomain"
    if legacy_depth_rule and len(labels) >= 4:
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
        The failure-reason string from a ``radius_auth`` log line (empty for
        F-TICKS records).
    result:
        ``"OK"`` or ``"FAIL"``.
    realm_signal:
        Output of :func:`classify_realm_signal` for the same event.

    Returns
    -------
    tuple[str, str]
        ``(failure_category, failure_layer)`` using the v4 taxonomy. Both are
        empty strings for a successful authentication with no warning.
    """
    if result == "OK":
        if realm_signal == "misrouted_local_subdomain":
            return ("misconfiguration_warning", LAYER["misconfiguration_warning"])
        return ("", "")

    if reason:
        r = reason.lower()
        for category, needles in _REASON_RULES:
            if any(n in r for n in needles):
                if (category == "policy_reject" and realm_signal in _FAIL_BY_REALM
                        and any(g in r for g in _GENERIC_POLICY)):
                    category = _FAIL_BY_REALM[realm_signal]
                return (category, LAYER[category])
        return ("other_failure", LAYER["other_failure"])

    # F-TICKS: no reason — the realm is the only evidence
    category = _FAIL_BY_REALM.get(realm_signal, "unspecified_failure")
    return (category, LAYER[category])


# ---------------------------------------------------------------------------
# 0.1.x behaviour, kept verbatim for comparison and the failure_category_legacy
# output field.
# ---------------------------------------------------------------------------
_LEGACY_FTICKS_FAIL_BY_REALM: dict[str, tuple[str, str]] = {
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


def classify_failure_legacy(reason: str, result: str, realm_signal: str) -> tuple[str, str]:
    """0.1.x ``classify_failure`` (schema 2.0.0 labels)."""
    if result == "OK":
        if realm_signal == "misrouted_local_subdomain":
            return ("misconfiguration_warning", "radius_proxy")
        return ("", "")
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
    if realm_signal in _LEGACY_FTICKS_FAIL_BY_REALM:
        return _LEGACY_FTICKS_FAIL_BY_REALM[realm_signal]
    return ("no_detail_in_fticks", "unknown")
