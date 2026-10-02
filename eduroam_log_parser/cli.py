"""
eduroam_log_parser.cli
=======================
Command-line interface for the eduroam-log-parser package.

Entry point: ``eduroam-log-parser`` (defined in pyproject.toml).

Usage
-----
.. code-block:: bash

    eduroam-log-parser \\
        --data-dir  ./logs \\
        --output    ./out \\
        --salt      "SECRET" \\
        --sources   fticks radius \\
        --limit     0

Options
-------
--data-dir      Directory containing raw FreeRADIUS log files. Default: ./data
--output        Output directory for JSONL + stats.json.    Default: ./output
--salt          Anonymisation salt (required, never logged).
--sources       Which log types to process: fticks and/or radius.
--limit         Max records per source (0 = unlimited).
--log-level     Logging verbosity: DEBUG / INFO / WARNING.   Default: INFO
--fticks-glob   File-name pattern for F-TICKS logs.          Default: trrad-ng.log*
--radius-glob   File-name pattern for radius.log files.      Default: radius.log*
"""

import argparse
import logging
import sys
from pathlib import Path

from eduroam_log_parser._pipeline import process_directory


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="eduroam-log-parser",
        description=(
            "Parse and pseudonymise FreeRADIUS / eduroam authentication logs."
        ),
    )
    p.add_argument(
        "--data-dir",
        default="./data",
        metavar="DIR",
        help="Directory containing raw FreeRADIUS log files (default: ./data)",
    )
    p.add_argument(
        "--output",
        default="./output",
        metavar="DIR",
        help="Output directory for JSONL files and stats.json (default: ./output)",
    )
    p.add_argument(
        "--salt",
        required=True,
        metavar="SECRET",
        help="Anonymisation salt — kept only in memory, never written to disk",
    )
    p.add_argument(
        "--sources",
        nargs="+",
        choices=["fticks", "radius"],
        default=["fticks", "radius"],
        metavar="SOURCE",
        help="Log types to process: fticks, radius, or both (default: both)",
    )
    p.add_argument(
        "--limit",
        type=int,
        default=0,
        metavar="N",
        help="Maximum records per source — 0 means unlimited (default: 0)",
    )
    p.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    p.add_argument("--fticks-glob", default="trrad-ng.log*", metavar="PATTERN",
                   help="File-name pattern for F-TICKS logs (default: trrad-ng.log*)")
    p.add_argument("--radius-glob", default="radius.log*", metavar="PATTERN",
                   help="File-name pattern for radius.log files (default: radius.log*)")
    return p


def main(argv: list[str] | None = None) -> None:
    args = _build_parser().parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )
    log = logging.getLogger(__name__)

    data_dir = Path(args.data_dir)
    if not data_dir.exists():
        log.error("Data directory not found: %s", data_dir)
        sys.exit(1)

    stats = process_directory(
        data_dir=data_dir,
        output_dir=Path(args.output),
        salt=args.salt,
        sources=args.sources,
        limit=args.limit,
        globs={"fticks": args.fticks_glob, "radius": args.radius_glob},
    )

    sep = "=" * 55
    log.info(sep)
    log.info("Total lines  : %d", stats["total_lines"])
    log.info("Parsed       : %d", stats["parsed"])
    log.info("Skipped      : %d", stats["skipped"])
    log.info("By result    : %s", stats["by_result"])
    log.info("Realm signal distribution:")
    for k, v in sorted(stats["realm_signal_counts"].items(), key=lambda x: -x[1]):
        log.info("  %10d  %s", v, k)
    log.info(sep)


if __name__ == "__main__":
    main()
