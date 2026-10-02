"""
eduroam-log-parser
==================
Parse and pseudonymise FreeRADIUS / eduroam authentication log files.

Supported formats
-----------------
* **F-TICKS** — federation-level accounting lines written by FreeRADIUS to
  syslog (``freeradius: F-TICKS/eduroam/1.0#…``)
* **radius_auth** — FreeRADIUS ``Auth:`` lines
  (``Login OK`` / ``Login incorrect``)

Quick start
-----------
Parse a single line::

    from eduroam_log_parser import parse_fticks, parse_radius_auth

    record = parse_fticks(line, salt="mysecret")
    record = parse_radius_auth(line, salt="mysecret")

Process a whole directory and write JSONL output::

    from eduroam_log_parser import process_directory
    from pathlib import Path

    stats = process_directory(
        data_dir=Path("./logs"),
        output_dir=Path("./out"),
        salt="mysecret",
    )

Stream records from a single file::

    from eduroam_log_parser import iter_file
    from eduroam_log_parser.parsers import parse_fticks
    from pathlib import Path

    for record in iter_file(Path("fticks.log.gz"), parse_fticks, salt="s"):
        print(record)
"""

from importlib.metadata import version, PackageNotFoundError

try:
    __version__: str = version("eduroam-log-parser")
except PackageNotFoundError:
    __version__ = "0.0.0+dev"

from eduroam_log_parser.parsers import parse_fticks, parse_radius_auth
from eduroam_log_parser.anonymize import anonymize, anonymize_mac, anonymize_reason, extract_tld
from eduroam_log_parser.classify import (
    TAXONOMY_VERSION,
    classify_realm_signal,
    classify_outer_identity,
    classify_failure,
    classify_failure_legacy,
)
from eduroam_log_parser.utils import open_log, normalize_ts
from eduroam_log_parser._pipeline import process_directory, iter_file

__all__ = [
    "__version__",
    # parsers
    "parse_fticks",
    "parse_radius_auth",
    # anonymisation
    "anonymize",
    "anonymize_mac",
    "anonymize_reason",
    "extract_tld",
    # classifiers
    "classify_realm_signal",
    "classify_outer_identity",
    "classify_failure",
    "classify_failure_legacy",
    "TAXONOMY_VERSION",
    # utilities
    "open_log",
    "normalize_ts",
    # pipeline
    "process_directory",
    "iter_file",
]
