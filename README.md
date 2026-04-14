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
- **Failure classifier** — TLS handshake, EAP method mismatch, policy reject, proxy routing failure, …
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

for record in iter_file(Path("trrad-ng.log.gz"), parse_fticks, salt="secret"):
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
    --limit    0
```

---

## Output schema

Each record is a JSON object. Fields common to both log types:

| Field | Type | Description |
|---|---|---|
| `schema_version` | str | Dataset schema version |
| `log_type` | str | `fticks` or `radius_auth` |
| `timestamp` | str | ISO 8601 normalised |
| `result` | str | `OK` or `FAIL` |
| `username_hash` | str | SHA-256[:32] of local-part |
| `mac_hash` | str | SHA-256[:32] of normalised MAC |
| `realm_hash` | str | SHA-256[:32] of realm domain |
| `realm_tld` | str | Top-level label of realm (e.g. `tr`) |
| `outer_identity_type` | str | `anonymous`, `numeric_identifier`, `institutional_format`, `malformed`, `unknown` |
| `realm_signal` | str | Structural quality of the outer identity (14 categories) |
| `failure_category` | str | Root cause category (empty for successful auths) |
| `failure_layer` | str | Protocol layer: `tls`, `eap`, `policy`, `radius_proxy`, … |
| `failure_reason` | str | Sanitised reason string (IPs replaced with hashes) |

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
| `misrouted_local_subdomain` | Operator sent internal sub-domain to federation |
| `malformed_*` | Various structural errors |

---

## Privacy model

All pseudonymisation is **deterministic** but **one-way** without the salt:

- The same username/MAC always maps to the same hash within a dataset
- Cross-dataset correlation is impossible without the same salt
- The salt is never written to any output file

This approach follows the F-TICKS data minimisation guidelines and is
compatible with GDPR pseudonymisation requirements.

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
