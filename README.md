# eduroam-log-parser

**Parse and pseudonymise FreeRADIUS / eduroam 802.1X authentication logs.**

`eduroam-log-parser` is a zero-dependency Python library and CLI tool for
converting raw FreeRADIUS log files into structured, privacy-safe JSONL records.
It is designed for network operators, researchers, and anyone who needs to
analyse eduroam authentication flows without exposing personally identifiable
information.

[![PyPI](https://img.shields.io/pypi/v/eduroam-log-parser)](https://pypi.org/project/eduroam-log-parser/)
[![Python](https://img.shields.io/pypi/pyversions/eduroam-log-parser)](https://pypi.org/project/eduroam-log-parser/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Dataset](https://img.shields.io/badge/HuggingFace-dataset-yellow)](https://huggingface.co/datasets/gokhaneryol/freeradius-8021x-log-dataset)

---

## Features

- **Two parsers** — F-TICKS/eduroam syslog lines and FreeRADIUS `Auth:` lines
- **Deterministic pseudonymisation** — SHA-256 + caller-supplied salt; consistent across files, reversible only by the operator who holds the salt
- **Realm signal classifier** — 14 categories (public domain, SIM-generated, typo TLD, misrouted sub-domain, …)
- **Failure classifier** — 16 categories aligned with the [HF dataset](https://huggingface.co/datasets/gokhaneryol/freeradius-8021x-log-dataset) v4 taxonomy (TLS, certificate, EAP method, inner auth, policy, realm-based rejects, proxy errors, …); 0.1.x labels kept in `failure_category_legacy`
- **Streaming API** — process arbitrarily large log archives without loading them into memory
- **gzip transparent** — `.gz` files are decompressed on the fly
- **Zero dependencies** — stdlib only, runs on Python 3.10+

---

## Installation

```bash
pip install eduroam-log-parser
```

---

## Quick start

### Python API

```python
from eduroam_log_parser import parse_fticks, parse_radius_auth

# Parse a single F-TICKS line
line = (
    "2025-10-05T00:00:28+03:00 host freeradius: "
    "F-TICKS/eduroam/1.0#REALM=university.edu.tr#VISCOUNTRY=TR"
    "#VISINST=1partner.edu#USERNAME=jsmith@university.edu.tr"
    "#CSI=AA:BB:CC:DD:EE:FF#RESULT=OK#"
)
record = parse_fticks(line, salt="YOUR_SECRET_SALT")
# {
#   "log_type": "fticks",
#   "result": "OK",
#   "username_hash": "3a7f…",
#   "realm_tld": "tr",
#   "realm_signal": "syntactically_valid",
#   "failure_category": "",
#   ...
# }
```

### Stream a whole file

```python
from pathlib import Path
from eduroam_log_parser import iter_file, parse_fticks

for record in iter_file(Path("fticks.log.gz"), parse_fticks, salt="secret"):
    print(record["result"], record["realm_signal"])
```

### Process a directory

```python
from pathlib import Path
from eduroam_log_parser import process_directory

stats = process_directory(
    data_dir=Path("./logs"),
    output_dir=Path("./out"),
    salt="secret",
    sources=["fticks", "radius"],
)
# Writes: out/fticks.jsonl, out/radius_auth.jsonl, out/stats.json
```

### CLI

```bash
eduroam-log-parser \
    --data-dir ./logs \
    --output   ./out \
    --salt     "YOUR_SECRET_SALT" \
    --sources  fticks radius \
    --limit    0 \
    --fticks-glob 'fticks.log*' \
    --radius-glob 'radius.log*'
```

F-TICKS lines are accepted with or without a `USERNAME` field. The standard
GÉANT format carries only `REALM`; some federations also log `USERNAME`.
Without it, the realm is classified from `REALM` and `outer_identity_type`
is `unknown`.

---

## Output schema

Each record is a JSON object. Fields common to both log types:

| Field | Type | Description |
|---|---|---|
| `schema_version` | str | Record schema version (`3.0.0` since 0.2.0) |
| `taxonomy_version` | str | Failure taxonomy version (`4.0.0`, same as the HF dataset) |
| `log_type` | str | `fticks` or `radius_auth` |
| `timestamp` | str | ISO 8601 normalised |
| `result` | str | `OK` or `FAIL` |
| `username_hash` | str | SHA-256[:32] of local-part |
| `mac_hash` | str | SHA-256[:32] of normalised MAC |
| `realm_hash` | str | SHA-256[:32] of realm domain |
| `realm_tld` | str | Top-level label of realm (e.g. `tr`); empty unless it is a two-letter, `xn--` or known generic TLD |
| `outer_identity_type` | str | `anonymous`, `numeric_identifier`, `institutional_format`, `malformed`, `unknown` |
| `realm_signal` | str | Structural quality of the outer identity (14 categories) |
| `failure_category` | str | Root cause category (empty for successful auths) |
| `failure_layer` | str | Protocol layer: `tls`, `eap`, `policy`, `identity`, `radius_proxy`, `unknown` |
| `failure_category_legacy` | str | The same event in 0.1.x labels |
| `failure_reason` | str | Sanitised reason string (IPs and `user@realm` strings replaced with hashes) |

Additional fields for `fticks`: `visinst_hash`, `visinst_country`  
Additional fields for `radius_auth`: `nas_hash`, `port`, `via_tunnel`

---

## Realm signal categories

| Label | Meaning |
|---|---|
| `syntactically_valid` | Well-formed institutional domain |
| `institution_subrealm` | Valid sub-realm (`ogr.`, `student.`, …) |
| `well_known_public_domain` | Gmail, Hotmail, iCloud, … |
| `auto_generated_sim` | 3GPP / SIM-based identity |
| `auto_generated_client_app` | Supplicant-generated realm |
| `misrouted_local_subdomain` | Internal name space reached the federation: TLD such as `.local`/`.lan`/`.corp`, or a first label naming an internal host (`ad.`, `dc01.`, `radius.`, `int.` …). Add your own with `internal_prefixes=`. The 0.1.x "four or more labels" rule is available as `legacy_depth_rule=True`; it is off by default because it flags department realms such as `cs.example.ac.uk`. |
| `malformed_*` | Various structural errors |

---

## Failure categories

| `failure_category` | Layer | Typical evidence |
|---|---|---|
| `tls_handshake_failure` | tls | `TLS Alert …`, `TLS_accept: Failed` |
| `certificate_error` | tls | `verify error:num=…`, client certificate verify |
| `eap_method_mismatch` | eap | `No mutually acceptable types`, `Peer NAK'd …` |
| `eap_cleartext_required` | eap | EAP-MD5 cleartext, `No NT-Password` |
| `eap_inner_auth_failure` | eap | `MS-CHAP2-Response is incorrect`, `Crypt password check failed`, `User not found` |
| `policy_reject` | policy | `No Auth-Type found`, `Rejected in post-auth` |
| `public_domain_rejected` | policy | public e-mail realm (reason generic or absent) |
| `auto_generated_realm_rejected` | policy | 3GPP / client-app realm |
| `misrouted_local_subdomain` | policy | internal realm |
| `invalid_realm_format` | identity | malformed realm |
| `realm_not_found` | radius_proxy | `No such realm`, `Failed to find … home server` |
| `timeout_or_no_response` | radius_proxy | `Home Server failed to respond`, timeouts |
| `proxy_error` | radius_proxy | invalid Message-Authenticator, `No EAP session matching state` |
| `unspecified_failure` | unknown | F-TICKS FAIL with a well-formed realm (no reason in the log) |
| `misconfiguration_warning` | policy | `OK` result but internal realm |
| `other_failure` | unknown | FAIL reason no rule recognises |

When the reason is generic (`No Auth-Type found`, post-auth reject) and the
realm is public, auto-generated, internal or malformed, the realm-based
category is returned instead of `policy_reject`.

---

## Privacy model

All pseudonymisation is **deterministic** but **one-way** without the salt:

- The same username/MAC always maps to the same hash within a dataset
- Cross-dataset correlation is impossible without the same salt
- The salt is never written to any output file

This approach follows the F-TICKS data minimisation guidelines and is
compatible with GDPR pseudonymisation requirements.

Realm and identity fields are user-typed. People put passwords and names
into them by mistake, so the parser never emits a raw label: `realm_tld` is
restricted to real TLD shapes, and identities inside reason strings are
hashed. **`stats.json` is an aggregate of production data — review it before
publishing it anywhere.**

---

## Related resources

- **Dataset** — anonymised sample on HuggingFace:
  [gokhaneryol/freeradius-8021x-log-dataset](https://huggingface.co/datasets/gokhaneryol/freeradius-8021x-log-dataset)
- **F-TICKS specification** — GÉANT eduroam wiki

---

## Citation

If you use this library or the associated dataset in academic work, please cite:

```bibtex
@software{eryol2025eduroam,
  author  = {Eryol, Gökhan},
  title   = {eduroam-log-parser: Parse and pseudonymise FreeRADIUS / eduroam logs},
  year    = {2025},
  url     = {https://github.com/gokhaneryol/eduroam-log-parser},
}
```

---

## License

MIT — see [LICENSE](LICENSE).
