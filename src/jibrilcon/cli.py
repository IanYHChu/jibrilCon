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
import errno
import json
import logging
from pathlib import Path
from jibrilcon.util.logging_utils import init_logging
import sys
from typing import Dict

from jibrilcon import __version__
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
    _EPILOG = """\
examples:
  %(prog)s /mnt/target-rootfs
      Scan a mounted rootfs and print results to stdout.

  %(prog)s /mnt/target-rootfs -o report.json
      Scan and write a full JSON report to disk.

  %(prog)s /mnt/target-rootfs -o report.json.gz --log-level debug
      Scan with verbose logging and write a gzip-compressed report.

exit codes:
  0   Scan completed successfully (findings may still be present).
  1   Scan failed due to a runtime or I/O error.
  2   Invalid command-line arguments.
  130 Interrupted by Ctrl-C (SIGINT).
"""

    parser = argparse.ArgumentParser(
        description="jibrilcon -- static risk scanner for container "
        "configurations inside embedded Linux rootfs images",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "mount_path",
        help="path to the mounted rootfs directory (read-only access is "
        "sufficient; the scanner never modifies the target filesystem)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="write the full JSON report to this path; use a .json.gz "
        "extension for gzip-compressed output",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        default=False,
        help="disable ANSI colour codes in the terminal summary",
    )
    parser.add_argument(
        "--log-level",
        choices=["debug", "info", "warning", "error", "critical"],
        default="info",
        help="set logging verbosity: debug=trace every file inspected, "
        "info=progress and findings, warning=anomalies only "
        "(default: info)",
    )
    parser.add_argument(
        "--max-workers",
        type=int,
        default=8,
        metavar="N",
        help="maximum number of concurrent scanner threads; set to 1 for "
        "sequential execution (default: 8, limited by available "
        "scanner modules)",
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
        sys.exit(130)
    except RuntimeError as exc:
        logger.error("Scan failed: %s", exc, exc_info=True)
        print(
            f"Error: scan aborted during filesystem analysis: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
    except OSError as exc:
        logger.error("Scan failed: %s", exc, exc_info=True)
        hint = ""
        if exc.errno == errno.EACCES or exc.errno == errno.EPERM:
            hint = (
                "\nHint: permission denied -- ensure the current user "
                "has read access to the mounted rootfs, or re-run with "
                "appropriate permissions (e.g. sudo)."
            )
        elif exc.errno == errno.ENOENT:
            hint = (
                "\nHint: a required file or directory was not found; "
                "verify that the rootfs is fully mounted."
            )
        elif exc.errno == errno.ENOSPC:
            hint = (
                "\nHint: no space left on device; free disk space "
                "and retry."
            )
        print(f"Error: I/O failure during scan: {exc}{hint}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------
# Boilerplate
# ---------------------------------------------------------------------

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
