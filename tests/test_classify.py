"""Tests for eduroam_log_parser.classify"""
import pytest
from eduroam_log_parser.classify import (
    classify_realm_signal,
    classify_outer_identity,
    classify_failure,
)


class TestClassifyRealmSignal:
    def test_syntactically_valid(self):
        assert classify_realm_signal("user@university.edu.tr") == "syntactically_valid"

    def test_institution_subrealm(self):
        assert classify_realm_signal("230102044@ogr.alanya.edu.tr") == "institution_subrealm"
        assert classify_realm_signal("u@student.uni.ac.uk") == "institution_subrealm"

    def test_well_known_public_domain(self):
        assert classify_realm_signal("user@gmail.com") == "well_known_public_domain"
        assert classify_realm_signal("user@hotmail.com") == "well_known_public_domain"

    def test_auto_generated_sim(self):
        assert classify_realm_signal("user@mnc001.mcc310.3gppnetwork.org") == "auto_generated_sim"

    def test_malformed_no_at(self):
        assert classify_realm_signal("userwithoutat") == "malformed_no_at"

    def test_malformed_empty_domain(self):
        assert classify_realm_signal("user@") == "malformed_empty_domain"

    def test_malformed_multiple_at(self):
        assert classify_realm_signal("user@@domain.com") == "malformed_multiple_at"

    def test_malformed_double_dot(self):
        assert classify_realm_signal("user@domain..com") == "malformed_double_dot"

    def test_malformed_boundary_dot(self):
        assert classify_realm_signal("user@.domain.com") == "malformed_boundary_dot"
        assert classify_realm_signal("user@domain.com.") == "malformed_boundary_dot"

    def test_malformed_no_dot_in_domain(self):
        assert classify_realm_signal("user@localhost") == "malformed_no_dot_in_domain"

    def test_malformed_typo_tld(self):
        assert classify_realm_signal("user@university.ac.ik") == "malformed_typo_tld"


class TestClassifyOuterIdentity:
    def test_anonymous(self):
        assert classify_outer_identity("anonymous") == "anonymous"
        assert classify_outer_identity("Anonymous") == "anonymous"

    def test_numeric(self):
        assert classify_outer_identity("230102044") == "numeric_identifier"

    def test_institutional(self):
        assert classify_outer_identity("jsmith") == "institutional_format"
        assert classify_outer_identity("j.smith") == "institutional_format"

    def test_malformed(self):
        assert classify_outer_identity("user name") == "malformed"

    def test_empty(self):
        assert classify_outer_identity("") == "unknown"


class TestClassifyFailure:
    def test_ok_no_signal(self):
        cat, layer = classify_failure("", "OK", "syntactically_valid")
        assert cat == ""
        assert layer == ""

    def test_ok_misrouted_warning(self):
        cat, layer = classify_failure("", "OK", "misrouted_local_subdomain")
        assert cat == "misconfiguration_warning"
        assert layer == "radius_proxy"

    def test_tls_failure(self):
        cat, layer = classify_failure("TLS Alert read:fatal:handshake failure", "FAIL", "syntactically_valid")
        assert cat == "tls_handshake_failure"
        assert layer == "tls"

    def test_eap_mismatch(self):
        cat, layer = classify_failure("No mutually acceptable types", "FAIL", "syntactically_valid")
        assert cat == "eap_method_mismatch"
        assert layer == "eap"

    def test_proxy_timeout(self):
        cat, layer = classify_failure("proxy timeout", "FAIL", "syntactically_valid")
        assert cat == "proxy_timeout"
        assert layer == "radius_proxy"

    def test_fticks_public_domain(self):
        cat, layer = classify_failure("", "FAIL", "well_known_public_domain")
        assert cat == "public_domain_auth_failure"
        assert layer == "policy"

    def test_fticks_no_detail(self):
        cat, layer = classify_failure("", "FAIL", "syntactically_valid")
        assert cat == "no_detail_in_fticks"
