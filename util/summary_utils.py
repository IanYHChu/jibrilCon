"""
summary_utils.py

Utilities to aggregate and consolidate scan results produced by multiple
scanner modules (systemd, docker, lxc, podman, …).

The helpers here are pure functions; no shared state is kept.
"""

from __future__ import annotations

from typing import Any, Dict, List

# ---------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------

def _is_int(value: Any) -> bool:
    """Return True if *value* is an int and not a bool."""
    return isinstance(value, int) and not isinstance(value, bool)

def _add_numeric_fields(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
    """
    Add every numeric field in *src* to *dst*, creating the key if absent.

    Only plain integers are considered; bools are excluded.
    """
    for key, val in src.items():
        if _is_int(val):
            dst[key] = dst.get(key, 0) + val

def _merge_summaries(
    total: Dict[str, Any],
    part: Dict[str, Any],
    *,
    scanner_name: str = "unknown",
) -> None:
    """
    Merge numeric fields from *part* into *total* and record the scanner
    name inside ``total["scanners_run"]``.
    """
    _add_numeric_fields(total, part)
    total.setdefault("scanners_run", []).append(scanner_name)

def _merge_results_stats(total: Dict[str, Any], results: List[Dict[str, Any]]) -> None:
    """
    Analyse per-unit results (container or service entries) and count how
    many are clean vs. violated.
    """
    clean = violated = 0
    for item in results:
        status = item.get("status")
        if status == "clean":
            clean += 1
        else:
            violated += 1
    total["clean"] = total.get("clean", 0) + clean
    total["violated"] = total.get("violated", 0) + violated

# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

def generate_final_report(scanner_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build a unified report containing all scanner outputs plus a merged
    summary section.

    Parameters
    ----------
    scanner_results : list[dict]
        Each element must include:
            - "scanner": scanner name
            - "summary": summary dict
            - "results": list of per-unit result entries
    """
    final: Dict[str, Any] = {"report": scanner_results, "summary": {}}
    summary = final["summary"]

    for block in scanner_results:
        name = block.get("scanner", "unknown")
        part_summary = block.get("summary", {})
        result_list = block.get("results", [])

        _merge_summaries(summary, part_summary, scanner_name=name)
        _merge_results_stats(summary, result_list)

    return final
