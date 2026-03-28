# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
cli.py
======
Command-line entry point of **jibrilcon**.

Responsibilities
----------------
1. Parse and validate user arguments.
2. Initialise global logging **before** scanners emit any logs.
3. Call :pyfunc:`jibrilcon.core.run_scan` to perform the real work.
4. Write the JSON / Gzip report to disk (or stdout) via
   :pyfunc:`util.report_writer.write_report`.
5. Show a short colour summary for human readability.

No long-running logic or scanner code should live here - keep this file
focused on UX.
"""

from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
from jibrilcon.util.logging_utils import init_logging
import sys
from typing import Dict

from jibrilcon.core import run_scan
from jibrilcon.util.report_writer import write_report  # handles .json or .json.gz

# ---------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------


def _colour(val: str, colour: str, enable: bool = True) -> str:
    if not enable:
        return val
    codes = {"red": "31", "yellow": "33", "green": "32"}
    return f"\033[{codes[colour]}m{val}\033[0m"


def _print_summary(summary: Dict[str, int], use_color: bool) -> None:
    alerts = summary.get("alerts", 0)
    warnings = summary.get("warnings", 0)
    clean = summary.get("clean", 0)
    violated = summary.get("violated", 0)

    print("\n=== Scan Summary ===")
    print("  Alerts   :", _colour(str(alerts), "red", use_color))
    print("  Warnings :", _colour(str(warnings), "yellow", use_color))
    print("  Clean    :", _colour(str(clean), "green", use_color))
    print("  Violated :", _colour(str(violated), "red", use_color))
    print("--------------------")


# ---------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="jibrilcon container configuration scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "mount_path",
        help="Path where the filesystem image is mounted read-only",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write full JSON (or .json.gz) report to this path",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="Disable ANSI colour in terminal summary",
    )
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        default="info",
        help="Set logging threshold (default: info)",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=8,
        metavar="N",
        help="Maximum number of concurrent scanner threads (default: 8)",
    )

    args = parser.parse_args()

    if args.max_workers < 1:
        parser.error(
            f"--max-workers must be a positive integer, got {args.max_workers}"
        )

    mount = Path(args.mount_path)
    if not mount.is_dir():
        parser.error(f"mount_path does not exist or is not a directory: {mount}")

    # 1. Initialisation – must precede any scanner import that might log
    init_logging(args.log_level)
    logger = logging.getLogger(__name__)

    try:
        # 2. Run full scan – core.run_scan already returns the *final* report
        report = run_scan(args.mount_path, max_workers=args.max_workers)

        # 3. Output
        if args.output:
            write_report(report, args.output)  # supports .json /.json.gz
            print(f"Report written to {args.output}")
        else:
            print(json.dumps(report, indent=2))

        # 4. Colour summary (same behaviour as legacy CLI)
        if "summary" in report:
            _print_summary(report["summary"], use_color=not args.no_color)
    except KeyboardInterrupt:
        sys.exit("Interrupted by user")
    except (RuntimeError, OSError) as exc:
        logger.error("Scan failed: %s", exc, exc_info=True)
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------
# Boilerplate
# ---------------------------------------------------------------------

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("Interrupted by user")
