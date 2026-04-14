"""
eduroam_log_parser.utils
=========================
Shared I/O and timestamp utilities.
"""

import gzip
from datetime import datetime, timezone
from pathlib import Path
from typing import IO

__all__ = ["open_log", "normalize_ts"]

_TS_FORMATS: tuple[str, ...] = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%a %b %d %H:%M:%S %Y",
    "%a %b  %d %H:%M:%S %Y",
)


def open_log(path: Path, encoding: str = "utf-8") -> IO[str]:
    """Open a plain-text or gzip-compressed log file for reading.

    Parameters
    ----------
    path:
        Path to the log file.  Files ending in ``.gz`` are decompressed
        transparently.
    encoding:
        Character encoding; decoding errors are replaced rather than raised.

    Returns
    -------
    IO[str]
        A text-mode file object.  The caller is responsible for closing it
        (or using it as a context manager).
    """
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding=encoding, errors="replace")
    return open(path, encoding=encoding, errors="replace")


def normalize_ts(raw: str) -> str:
    """Normalise a log timestamp to ISO 8601 with timezone offset.

    Tries a series of known FreeRADIUS / syslog timestamp formats.
    Falls back to returning the original string unchanged when none match.

    Parameters
    ----------
    raw:
        Raw timestamp string as it appears in the log line.

    Returns
    -------
    str
        ISO 8601 string (e.g. ``"2025-10-05T00:00:27+03:00"``) or the
        original *raw* value if parsing fails.
    """
    raw = raw.strip()
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            continue
    return raw
