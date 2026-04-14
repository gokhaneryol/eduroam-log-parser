"""Tests for eduroam_log_parser.parsers — F-TICKS and radius_auth"""
import pytest
from eduroam_log_parser.parsers import parse_fticks, parse_radius_auth

SALT = "testsalt"

# ---------------------------------------------------------------------------
# Sample lines follow the real log formats; every identifier is synthetic
# (example domains, RFC 7042 documentation MAC range).
# ---------------------------------------------------------------------------

FTICKS_OK = (
    "2025-10-05T00:00:28+03:00 radius1 freeradius: "
    "F-TICKS/eduroam/1.0#REALM=ogr.example.edu.tr#VISCOUNTRY=TR"
    "#VISINST=1visited.example.org#USERNAME=2023000001@ogr.example.edu.tr"
    "#CSI=00-00-5E-00-53-01#RESULT=OK#"
)

FTICKS_FAIL_GMAIL = (
    "2025-10-05T00:00:27+03:00 radius1 freeradius: "
    "F-TICKS/eduroam/1.0#REALM=gmail.com#VISCOUNTRY=TR"
    "#VISINST=1campus.example.edu.tr#USERNAME=user@gmail.com"
    "#CSI=00005E005302#RESULT=FAIL#"
)

FTICKS_REPEATED = (
    "2025-10-05T00:00:37+03:00 radius1 freeradius: "
    "message repeated 2 times: [ F-TICKS/eduroam/1.0#REALM=gmail.com"
    "#VISCOUNTRY=TR#VISINST=1campus.example.edu.tr#USERNAME=user@gmail.com"
    "#CSI=00005E005302#RESULT=FAIL#]"
)

RADIUS_OK = (
    "Mon Oct  7 12:34:56 2025 : Auth: (42) Login OK: [jsmith@university.edu.tr] "
    "(from client nas-central port 0 cli AA:BB:CC:DD:EE:FF via TLS tunnel)"
)

RADIUS_FAIL = (
    "Mon Oct  7 12:35:10 2025 : Auth: (43) Login incorrect "
    "(TLS Alert read:fatal:certificate unknown): [baduser@university.edu.tr] "
    "(from client nas-central port 1812 cli 11:22:33:44:55:66)"
)


class TestParseFticks:
    def test_ok_record_shape(self):
        r = parse_fticks(FTICKS_OK, SALT)
        assert r is not None
        assert r["log_type"] == "fticks"
        assert r["result"] == "OK"
        assert r["realm_tld"] == "tr"
        assert r["realm_signal"] == "institution_subrealm"
        assert r["failure_category"] == ""
        # PII must not appear in output
        assert "ogr.example.edu.tr" not in str(r.values())
        assert "2023000001" not in str(r.values())

    def test_fail_gmail(self):
        r = parse_fticks(FTICKS_FAIL_GMAIL, SALT)
        assert r is not None
        assert r["result"] == "FAIL"
        assert r["realm_signal"] == "well_known_public_domain"
        assert r["failure_category"] == "public_domain_auth_failure"
        assert r["failure_layer"] == "policy"

    def test_repeated_line_skipped(self):
        assert parse_fticks(FTICKS_REPEATED, SALT) is None

    def test_empty_line_skipped(self):
        assert parse_fticks("", SALT) is None
        assert parse_fticks("\n", SALT) is None

    def test_non_fticks_line_skipped(self):
        assert parse_fticks("Oct  7 12:00:00 host sshd[1234]: Accepted key", SALT) is None

    def test_required_fields_present(self):
        r = parse_fticks(FTICKS_OK, SALT)
        required = {
            "schema_version", "log_type", "timestamp", "result",
            "username_hash", "mac_hash", "realm_hash", "realm_tld",
            "visinst_hash", "visinst_country",
            "outer_identity_type", "realm_signal",
            "failure_category", "failure_layer", "failure_reason",
        }
        assert required.issubset(r.keys())

    def test_hash_is_32_hex_chars(self):
        r = parse_fticks(FTICKS_OK, SALT)
        assert len(r["username_hash"]) == 32
        assert all(c in "0123456789abcdef" for c in r["username_hash"])


class TestParseRadiusAuth:
    def test_ok_record_shape(self):
        r = parse_radius_auth(RADIUS_OK, SALT)
        assert r is not None
        assert r["log_type"] == "radius_auth"
        assert r["result"] == "OK"
        assert r["via_tunnel"] is True
        assert r["port"] == 0
        assert r["failure_category"] == ""
        # PII must not appear
        assert "jsmith" not in str(r.values())
        assert "AA:BB:CC:DD:EE:FF" not in str(r.values())

    def test_fail_tls(self):
        r = parse_radius_auth(RADIUS_FAIL, SALT)
        assert r is not None
        assert r["result"] == "FAIL"
        assert r["failure_category"] == "tls_handshake_failure"
        assert r["failure_layer"] == "tls"
        # reason string should exist but not contain raw IPs
        assert isinstance(r["failure_reason"], str)

    def test_empty_line_skipped(self):
        assert parse_radius_auth("", SALT) is None

    def test_irrelevant_line_skipped(self):
        assert parse_radius_auth("Oct  7 info: rlm_python: doing something", SALT) is None

    def test_required_fields_present(self):
        r = parse_radius_auth(RADIUS_OK, SALT)
        required = {
            "schema_version", "log_type", "timestamp", "result",
            "username_hash", "mac_hash", "realm_hash", "realm_tld", "nas_hash",
            "outer_identity_type", "realm_signal",
            "failure_category", "failure_layer", "failure_reason",
            "port", "via_tunnel",
        }
        assert required.issubset(r.keys())
