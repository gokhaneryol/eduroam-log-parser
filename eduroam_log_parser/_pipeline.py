"""
eduroam_log_parser._pipeline
=============================
High-level helpers: streaming iterator and batch directory processor.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Callable, Iterable, Iterator, Optional

from eduroam_log_parser.utils import open_log
from eduroam_log_parser.parsers import parse_fticks, parse_radius_auth

__all__ = ["iter_file", "process_directory"]

log = logging.getLogger(__name__)

SCHEMA_VERSION = "3.0.0"


def iter_file(
    path: Path,
    parser: Callable[[str, str], Optional[dict]],
    salt: str,
) -> Iterator[dict]:
    """Yield parsed records from a single log file.

    Parameters
    ----------
    path:
        Path to a plain-text or ``.gz`` log file.
    parser:
        One of :func:`~eduroam_log_parser.parsers.parse_fticks` or
        :func:`~eduroam_log_parser.parsers.parse_radius_auth`.
    salt:
        Anonymisation salt.

    Yields
    ------
    dict
        One anonymised record per matching log line.
    """
    try:
        with open_log(path) as fh:
            for line in fh:
                record = parser(line, salt)
                if record is not None:
                    yield record
    except (EOFError, OSError) as exc:
        log.warning("Skipped (corrupt/partial): %s — %s", path.name, exc)


DEFAULT_GLOBS = {"fticks": "trrad-ng.log*", "radius": "radius.log*"}


def _collect_files(data_dir: Path, source: str, globs: dict | None = None) -> list[Path]:
    """Return sorted file list for a given source type.

    ``globs`` overrides the file-name patterns per source. Defaults keep the
    0.1.x behaviour (``trrad-ng.log*`` for F-TICKS, ``radius.log*`` for
    radius, plus a ``trrad/`` sub-directory for radius files).
    """
    pattern = {**DEFAULT_GLOBS, **(globs or {})}.get(source)
    if pattern is None:
        return []
    files = list(data_dir.glob(pattern))
    if source == "radius":
        sub = data_dir / "trrad"
        if sub.is_dir():
            files += list(sub.glob(pattern))
    return sorted(files)


def process_directory(
    data_dir: Path,
    output_dir: Path,
    salt: str,
    sources: Iterable[str] = ("fticks", "radius"),
    limit: int = 0,
    globs: Optional[dict] = None,
) -> dict:
    """Parse all log files in *data_dir* and write JSONL output to *output_dir*.

    Parameters
    ----------
    data_dir:
        Directory containing raw FreeRADIUS log files (plain or ``.gz``).
    output_dir:
        Directory for output JSONL files and a ``stats.json`` summary.
        Created automatically if it does not exist.
    salt:
        Anonymisation salt (never written to disk).
    sources:
        Which log types to process: any subset of ``{"fticks", "radius"}``.
    limit:
        Maximum number of records to emit per source (``0`` = unlimited).
    globs:
        Optional ``{"fticks": "...", "radius": "..."}`` file-name patterns.

    Returns
    -------
    dict
        Statistics dictionary also written to ``output_dir/stats.json``.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    sources = list(sources)

    stats: dict = {
        "schema_version":         SCHEMA_VERSION,
        "total_lines":            0,
        "parsed":                 0,
        "skipped":                0,
        "by_result":              {},
        "by_log_type":            {},
        "realm_signal_counts":    {},
        "failure_category_counts": {},
        "tld_counts":             {},
    }

    _parsers = {
        "fticks":  (parse_fticks,       "fticks.jsonl"),
        "radius":  (parse_radius_auth,  "radius_auth.jsonl"),
    }

    for source in sources:
        if source not in _parsers:
            log.warning("Unknown source %r — skipped.", source)
            continue

        parser_fn, out_name = _parsers[source]
        files = _collect_files(data_dir, source, globs)
        log.info("%s: %d file(s) found", source, len(files))

        n_parsed = 0
        with open(output_dir / out_name, "w", encoding="utf-8") as out_fh:
            for fpath in files:
                log.info("  Processing: %s", fpath.name)
                try:
                    with open_log(fpath) as in_fh:
                        for line in in_fh:
                            if limit and n_parsed >= limit:
                                break
                            stats["total_lines"] += 1
                            record = parser_fn(line, salt)
                            if record is None:
                                stats["skipped"] += 1
                                continue
                            _update_stats(stats, record)
                            out_fh.write(json.dumps(record, ensure_ascii=False) + "\n")
                            n_parsed += 1
                except (EOFError, OSError) as exc:
                    log.warning("  Skipped (corrupt/partial): %s — %s", fpath.name, exc)
                    stats.setdefault("skipped_files", []).append(fpath.name)

                if limit and n_parsed >= limit:
                    log.info("  Limit (%d) reached.", limit)
                    break

        log.info("  → %s: %d records", source, n_parsed)

    # Write summary
    stats_path = output_dir / "stats.json"
    with open(stats_path, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    log.info("Stats written to %s", stats_path)

    return stats


def _update_stats(stats: dict, record: dict) -> None:
    stats["parsed"] += 1
    result = record.get("result", "")
    stats["by_result"][result] = stats["by_result"].get(result, 0) + 1
    lt = record.get("log_type", "")
    stats["by_log_type"][lt] = stats["by_log_type"].get(lt, 0) + 1
    rs = record.get("realm_signal", "")
    stats["realm_signal_counts"][rs] = stats["realm_signal_counts"].get(rs, 0) + 1
    fc = record.get("failure_category", "")
    if fc:
        stats["failure_category_counts"][fc] = (
            stats["failure_category_counts"].get(fc, 0) + 1
        )
    tld = record.get("realm_tld", "")
    if tld:
        stats["tld_counts"][tld] = stats["tld_counts"].get(tld, 0) + 1
