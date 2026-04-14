"""Tests for eduroam_log_parser.anonymize"""
import pytest
from eduroam_log_parser.anonymize import (
    anonymize,
    anonymize_mac,
    anonymize_ips_in_text,
    extract_tld,
)

SALT = "testsalt"


class TestAnonymize:
    def test_basic_hash_length(self):
        result = anonymize("user123", SALT)
        assert len(result) == 32

    def test_deterministic(self):
        assert anonymize("user@example.com", SALT) == anonymize("user@example.com", SALT)

    def test_different_salt_different_hash(self):
        assert anonymize("user", SALT) != anonymize("user", "othersalt")

    def test_empty_returns_empty(self):
        assert anonymize("", SALT) == ""
        assert anonymize("-", SALT) == ""
        assert anonymize("N/A", SALT) == ""

    def test_case_insensitive(self):
        assert anonymize("User", SALT) == anonymize("user", SALT)


class TestAnonymizeMac:
    def test_normalises_separators(self):
        dash = anonymize_mac("AA-BB-CC-DD-EE-FF", SALT)
        colon = anonymize_mac("AA:BB:CC:DD:EE:FF", SALT)
        assert dash == colon

    def test_normalises_case(self):
        assert anonymize_mac("aabbccddeeff", SALT) == anonymize_mac("AABBCCDDEEFF", SALT)

    def test_empty_returns_empty(self):
        assert anonymize_mac("", SALT) == ""
        assert anonymize_mac("-", SALT) == ""


class TestAnonymizeIpsInText:
    def test_replaces_ip(self):
        result = anonymize_ips_in_text("Error from 192.168.1.1 in tunnel", SALT)
        assert "192.168.1.1" not in result

    def test_no_ip_unchanged_structure(self):
        text = "TLS Alert read:fatal:certificate unknown"
        result = anonymize_ips_in_text(text, SALT)
        assert "TLS Alert" in result

    def test_multiple_ips_replaced(self):
        result = anonymize_ips_in_text("src=10.0.0.1 dst=10.0.0.2", SALT)
        assert "10.0.0.1" not in result
        assert "10.0.0.2" not in result


class TestExtractTld:
    def test_simple(self):
        assert extract_tld("example.com") == "com"
        assert extract_tld("university.edu.tr") == "tr"

    def test_empty(self):
        assert extract_tld("") == ""

    def test_no_dot(self):
        assert extract_tld("localhost") == ""
