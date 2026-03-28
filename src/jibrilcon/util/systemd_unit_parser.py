# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
Minimal parser for container-related systemd service units.

Configuration comes from ``config/systemd_filters.json``:

* container_keywords     – quick heuristic for “is this a container unit?”
* engine_detection       – how to detect (engine, container-name) from Exec line
* unit_dirs           – directories to search for *.service files
* exec_keys           – Exec* keys to inspect when building exec_lines
* fields_to_keep         – unit keys to preserve in the output
* extraction_patterns    – optional regex for refining certain key values

The function returns **list[dict]**; it does NOT perform rule evaluation.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from jibrilcon.util.context import ScanContext

logger = logging.getLogger(__name__)

_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
_DEFAULT_FILTER_FILE = _CONFIG_DIR / "systemd.json"
_UNIT_RE = re.compile(r"^(\w[\w\d]+)=(.*)$")


# --------------------------------------------------------------------------- #
# Configuration helpers
# --------------------------------------------------------------------------- #
def _load_filters(path: Optional[Path] = None) -> Dict[str, Any]:
    with open(path or _DEFAULT_FILTER_FILE, "r", encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #
def _parse_unit_lines(lines: List[str]) -> Dict[str, List[str]]:
    data: Dict[str, List[str]] = {}
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#") or "=" not in ln:
            continue
        m = _UNIT_RE.match(ln)
        if m:
            key, val = m.groups()
            data.setdefault(key, []).append(val.strip())
    return data


def _is_container_service(exec_lines: List[str], keywords: List[str]) -> bool:
    text = " ".join(exec_lines).lower()
    return any(k.lower() in text for k in keywords)


def _guess_engine_and_container(
    exec_lines: List[str],
    engine_map: Dict[str, Dict[str, str]],
) -> Tuple[str, str]:
    joined = " ".join(exec_lines)
    joined_lower = joined.lower()

    for engine, cfg in engine_map.items():
        keyword = cfg.get("keyword", "").lower()
        if keyword and keyword in joined_lower:
            regex = cfg.get("container_regex")
            if regex:
                m = re.search(regex, joined, flags=re.IGNORECASE)
                return engine, m.group(1) if m else ""
            return engine, ""
    return "", ""


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def scan_systemd_container_units(
    rootfs: str | Path,
    *,
    filters_path: Optional[Path] = None,
) -> List[Dict[str, Any]]:
    """
    Walk ``rootfs`` for *.service files and return structured container units.

    Each record contains:
        unit, engine, container, user,
        exec, path, fields, raw_lines
    """
    cfg = _load_filters(filters_path)
    keywords: List[str] = cfg["container_keywords"]
    engine_map: Dict[str, Dict[str, str]] = cfg["engine_detection"]
    wanted_fields: List[str] = cfg["fields_to_keep"]
    extraction_patterns: Dict[str, str] = cfg.get("extraction_patterns", {})

    unit_dirs_raw: List[str] = cfg.get(
        "unit_dirs",
        [
            "etc/systemd/system",
            "lib/systemd/system",
            "usr/lib/systemd/system",
        ],
    )
    rootfs = Path(rootfs)
    unit_dirs = [rootfs / d.lstrip("/") for d in unit_dirs_raw]

    exec_keys: List[str] = cfg.get("exec_keys", ["ExecStart", "ExecStartPre"])

    rows: List[Dict[str, Any]] = []

    for udir in unit_dirs:
        if not udir.is_dir():
            continue
        for svc_file in udir.rglob("*.service"):
            try:
                raw = svc_file.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue

            kvmap = _parse_unit_lines(raw)
            
            exec_lines: List[str] = []
            for key in exec_keys:
                exec_lines.extend(kvmap.get(key, []))

            if not _is_container_service(exec_lines, keywords):
                continue

            engine, cname = _guess_engine_and_container(exec_lines, engine_map)

            fields: Dict[str, Any] = {}
            raw_lines: Dict[str, List[str]] = {}
            for fld in wanted_fields:
                vals = kvmap.get(fld, [])
                if not vals:
                    continue
                raw_lines[fld.lower()] = vals
                first_val = vals[0]
                pattern = extraction_patterns.get(fld)
                if pattern:
                    m = re.search(pattern, first_val)
                    fields[fld.lower()] = m.group(1) if m else first_val
                else:
                    fields[fld.lower()] = first_val

            rows.append(
                {
                    "unit": svc_file.name,
                    "engine": engine,
                    "container": cname,
                    "user": kvmap.get("User", [""])[0] if kvmap.get("User") else "",
                    "exec": exec_lines[0] if exec_lines else "",
                    "path": str(svc_file.relative_to(rootfs)),
                    "fields": fields,
                    "raw_lines": raw_lines,
                }
            )
            logger.debug("parsed container unit: %s", svc_file.name)

    return rows

def collect_systemd_containers(
    rootfs: str | Path,
    ctx: ScanContext,
    *,
    filters_path: Optional[Path] = None,
) -> None:
    """
    One-stop helper: parse *.service files under *rootfs* and cache results
    into *ctx* so all scanners can reuse them.

    Side-effects on ScanContext:
        • mark_systemd_started()
        • mark_user_missing()
        • add_exec_lines()      (ExecStart / ExecStartPre)
    """
    rows = scan_systemd_container_units(rootfs, filters_path=filters_path)

    for row in rows:
        engine = row.get("engine") or ""
        cname = row.get("container") or ""
        if not engine or not cname:
            continue

        ctx.mark_systemd_started(engine, cname)

        user = row.get("user", "")
        if not user or user == "root":
            ctx.mark_user_missing(cname)

        # --- cache Exec* lines for later reuse ------------------------
        raw = row.get("raw_lines", {})
        all_exec: List[str] = []
        for key, lines in raw.items():
            if key.startswith("execstart"):
                all_exec.extend(lines)
        if all_exec:
            ctx.add_exec_lines(engine, cname, all_exec)
        
        # Development-time information
        logger.info(
            "[systemd] unit=%s engine=%s container=%s user=%s exec=%s",
            row["unit"],
            engine or "<unknown>",
            cname or "<unknown>",
            user,
            row["exec"],
        )
