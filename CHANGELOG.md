# Changelog

## 0.2.0 — 2026-10-02

Record schema `3.0.0`; failure taxonomy aligned with the HF dataset v4.0.0.

### Privacy
- `realm_tld` no longer echoes arbitrary text: only two-letter, `xn--` or known generic TLDs are emitted. User-typed realms sometimes contain names or password fragments glued to the TLD; 0.1.x wrote these to records and to `stats.json`.
- Reason strings: `user@realm` substrings are hashed in addition to IPv4 addresses (`anonymize_reason`).
- Test fixtures now use synthetic identifiers only (example domains, RFC 7042 MACs).

### Fixed
- F-TICKS lines without a `USERNAME` field (the standard GÉANT format) were all classified `malformed_no_at` / `policy_reject`. The realm is now taken from `REALM` when `USERNAME` is absent; `outer_identity_type` is then `unknown`.
- `misrouted_local_subdomain` no longer fires on every realm with four or more labels (e.g. `cs.example.ac.uk`). It now requires an internal TLD (`.local`, `.lan`, `.corp`, …) or an internal first label (`ad.`, `dcNN.`, `radius.`, `int.`, …). `classify_realm_signal(..., internal_prefixes=...)` adds site-specific labels; `legacy_depth_rule=True` restores the old rule.

### Changed
- `failure_category` uses the v4 labels. New: `certificate_error`, `eap_cleartext_required`, `eap_inner_auth_failure`, `public_domain_rejected`, `invalid_realm_format`, `realm_not_found`, `timeout_or_no_response`, `proxy_error`, `unspecified_failure`. The 0.1.x label is in the new `failure_category_legacy` field (`classify_failure_legacy`).
- Recognises more FreeRADIUS 3 messages: certificate verify errors, `Peer NAK'd`, `unsupported EAP type`, `No NT-Password`, MS-CHAPv2/PAP/LDAP inner failures, `Home Server failed to respond`.
- Generic policy rejects (`No Auth-Type found`, post-auth) return the realm-based category when the realm is public, auto-generated, internal or malformed.
- New output field `taxonomy_version`.
- `process_directory(globs=...)` and CLI `--fticks-glob` / `--radius-glob` for non-default log file names.

### Evaluation note
Reason rules were written with the v4 dataset's train variants in view. Strings that occur only in v4 held-out (test-only) variants were deliberately left out, so held-out scores measure generalisation. On v4 `fticks` + `radius_auth` lines (v4 labels; 0.1.0 output mapped to v4 names):

| | test, seen variants | test, held-out variants |
|---|---:|---:|
| 0.1.0 | 59.4 % | 37.2 % |
| 0.2.0 | 97.6 % | 51.8 % |
