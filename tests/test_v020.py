"""Tests for 0.2.0 changes: privacy hardening, F-TICKS realm fallback,
misrouted-subdomain heuristic, v4 taxonomy and legacy labels.

All identifiers are synthetic (example domains, RFC 5737 IPs, RFC 7042 MACs).
"""
import pytest

from eduroam_log_parser.anonymize import anonymize_reason, extract_tld
from eduroam_log_parser.classify import (
    FAILURE_CATEGORY_LABELS,
    LAYER,
    classify_failure,
    classify_failure_legacy,
    classify_realm_signal,
)
from eduroam_log_parser.parsers import parse_fticks, parse_radius_auth

SALT = "testsalt"


def auth_fail(reason: str, user: str = "anonymous@example.edu.tr", tunnel: bool = False) -> str:
    return (
        f"Mon Oct  7 12:35:10 2025 : Auth: (43) Login incorrect ({reason}): [{user}] "
        f"(from client nas1 port 0 cli 00-00-5E-00-53-01{' via TLS tunnel' if tunnel else ''})"
    )


# ---------------------------------------------------------------------------
# Privacy
# ---------------------------------------------------------------------------
class TestRealmTldPrivacy:
    @pytest.mark.parametrize("domain,expected", [
        ("example.edu.tr", "tr"),
        ("example.com", "com"),
        ("example.ac.uk", "uk"),
        ("example.xn--p1ai", "xn--p1ai"),
        ("example.local", "local"),
    ])
    def test_valid_tlds_kept(self, domain, expected):
        assert extract_tld(domain) == expected

    @pytest.mark.parametrize("domain", [
        "example.edu.trjohn1987",     # typed text glued to the TLD
        "example.edu.trpass*word",
        "example.edu tr",
        "example.c",
        "example.ogrenci",           # letters-only but not a known TLD
    ])
    def test_garbage_tlds_dropped(self, domain):
        assert extract_tld(domain) == ""

    def test_parser_does_not_emit_garbage_tld(self):
        line = auth_fail("No Auth-Type found", user="jdoe@example.edu.trsecret99")
        r = parse_radius_auth(line, SALT)
        assert r["realm_tld"] == ""
        assert "secret99" not in str(r.values())


class TestReasonAnonymisation:
    def test_identity_in_reason_is_hashed(self):
        out = anonymize_reason('Failing proxied request for user "jdoe@example.edu.tr"', SALT)
        assert "jdoe" not in out and "example.edu.tr" not in out

    def test_ip_in_reason_is_hashed(self):
        out = anonymize_reason("No response from home server 192.0.2.10 port 1812", SALT)
        assert "192.0.2.10" not in out

    def test_plain_reason_unchanged(self):
        assert anonymize_reason("No Auth-Type found", SALT) == "No Auth-Type found"


# ---------------------------------------------------------------------------
# F-TICKS without USERNAME (standard GÉANT format)
# ---------------------------------------------------------------------------
class TestFticksRealmFallback:
    BASE = ("2025-10-05T00:00:28+03:00 radius1 freeradius: F-TICKS/eduroam/1.0"
            "#REALM={realm}#VISCOUNTRY=TR#VISINST=1visited.example.org#CSI=00-00-5E-00-53-01#RESULT={res}#")

    def test_valid_realm_is_not_malformed(self):
        r = parse_fticks(self.BASE.format(realm="example.edu.tr", res="FAIL"), SALT)
        assert r["realm_signal"] == "syntactically_valid"
        assert r["outer_identity_type"] == "unknown"
        assert r["failure_category"] == "unspecified_failure"
        assert r["realm_tld"] == "tr"

    def test_public_domain_from_realm_field(self):
        r = parse_fticks(self.BASE.format(realm="gmail.com", res="FAIL"), SALT)
        assert r["realm_signal"] == "well_known_public_domain"
        assert r["failure_category"] == "public_domain_rejected"

    def test_ok_line(self):
        r = parse_fticks(self.BASE.format(realm="example.edu.tr", res="OK"), SALT)
        assert r["result"] == "OK"
        assert r["failure_category"] == ""

    def test_username_still_preferred_when_present(self):
        line = self.BASE.format(realm="example.edu.tr", res="OK") + "USERNAME=anonymous@example.edu.tr#"
        r = parse_fticks(line, SALT)
        assert r["outer_identity_type"] == "anonymous"


# ---------------------------------------------------------------------------
# Misrouted subdomain heuristic
# ---------------------------------------------------------------------------
class TestMisroutedHeuristic:
    @pytest.mark.parametrize("identity", [
        "anonymous@cs.example.ac.uk",
        "anonymous@ee.example.edu.tr",
        "a@std.example.edu.tr",
    ])
    def test_department_realms_are_valid(self, identity):
        assert classify_realm_signal(identity) == "syntactically_valid"

    @pytest.mark.parametrize("identity", [
        "a@example.local",
        "a@corp.lan",
        "a@ad.example.edu.tr",
        "a@dc01.corp.example.edu.tr",
        "a@radius.int.example.edu.tr",
    ])
    def test_internal_realms_are_misrouted(self, identity):
        assert classify_realm_signal(identity) == "misrouted_local_subdomain"

    def test_extra_internal_prefixes(self):
        assert classify_realm_signal("a@wifi.example.edu.tr") == "syntactically_valid"
        assert classify_realm_signal("a@wifi.example.edu.tr", internal_prefixes=["wifi"]) \
            == "misrouted_local_subdomain"

    def test_legacy_depth_rule_opt_in(self):
        assert classify_realm_signal("a@cs.example.ac.uk", legacy_depth_rule=True) \
            == "misrouted_local_subdomain"

    def test_subrealm_prefix_still_wins(self):
        assert classify_realm_signal("a@ogr.example.edu.tr") == "institution_subrealm"


# ---------------------------------------------------------------------------
# v4 taxonomy: reason rules
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("reason,expected", [
    ("eap_ttls: TLS Alert read:fatal:unknown CA", "tls_handshake_failure"),
    ("eap_peap: TLS_accept: Failed in error", "tls_handshake_failure"),
    ("eap_tls: --> verify error:num=10:certificate has expired", "certificate_error"),
    ("eap_tls: TLS_accept: error in SSLv3 read client certificate verify", "certificate_error"),
    ("rlm_eap: No mutually acceptable types found", "eap_method_mismatch"),
    ("eap: Peer NAK'd asking for unsupported EAP type peap", "eap_method_mismatch"),
    ("rlm_eap_md5: Cleartext-Password is required for EAP-MD5 authentication", "eap_cleartext_required"),
    ("mschap: FAILED: No NT-Password.  Cannot perform authentication", "eap_cleartext_required"),
    ("mschap: MS-CHAP2-Response is incorrect", "eap_inner_auth_failure"),
    ("pap: Crypt password check failed", "eap_inner_auth_failure"),
    ("ldap: User not found", "eap_inner_auth_failure"),
    ("No Auth-Type found", "policy_reject"),
    ("Rejected in post-auth", "policy_reject"),
    ("Home Server failed to respond", "timeout_or_no_response"),
    ("something nobody has seen", "other_failure"),
])
def test_reason_rules(reason, expected):
    cat, layer = classify_failure(reason, "FAIL", "syntactically_valid")
    assert cat == expected
    assert layer == LAYER[expected]


@pytest.mark.parametrize("realm_signal,expected", [
    ("well_known_public_domain", "public_domain_rejected"),
    ("auto_generated_sim", "auto_generated_realm_rejected"),
    ("misrouted_local_subdomain", "misrouted_local_subdomain"),
    ("malformed_double_dot", "invalid_realm_format"),
    ("syntactically_valid", "policy_reject"),
])
def test_generic_policy_reject_uses_realm(realm_signal, expected):
    assert classify_failure("No Auth-Type found", "FAIL", realm_signal)[0] == expected


def test_specific_reason_is_not_overridden_by_realm():
    cat, _ = classify_failure("pap: Crypt password check failed", "FAIL", "well_known_public_domain")
    assert cat == "eap_inner_auth_failure"


def test_every_category_has_a_layer():
    assert set(FAILURE_CATEGORY_LABELS) == set(LAYER)


def test_inner_identity_line_end_to_end():
    r = parse_radius_auth(auth_fail("mschap: MS-CHAP2-Response is incorrect",
                                    user="jdoe@example.edu.tr", tunnel=True), SALT)
    assert r["failure_category"] == "eap_inner_auth_failure"
    assert r["failure_category_legacy"] == "other_failure"
    assert r["via_tunnel"] is True


# ---------------------------------------------------------------------------
# Legacy labels
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("reason,result,signal,expected", [
    ("", "FAIL", "well_known_public_domain", "public_domain_auth_failure"),
    ("", "FAIL", "syntactically_valid", "no_detail_in_fticks"),
    ("proxy timeout", "FAIL", "syntactically_valid", "proxy_timeout"),
    ("TLS Alert read:fatal:unknown CA", "FAIL", "syntactically_valid", "tls_handshake_failure"),
])
def test_legacy_labels(reason, result, signal, expected):
    assert classify_failure_legacy(reason, result, signal)[0] == expected
