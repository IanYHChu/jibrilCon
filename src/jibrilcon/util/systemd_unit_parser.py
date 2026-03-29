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
from typing import Any

from jibrilcon.util.context import ScanContext

logger = logging.getLogger(__name__)

_CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"
_DEFAULT_FILTER_FILE = _CONFIG_DIR / "systemd.json"
_UNIT_RE = re.compile(r"^(\w+)=(.*)$")


# --------------------------------------------------------------------------- #
# Configuration helpers
# --------------------------------------------------------------------------- #
def _load_filters(path: Path | None = None) -> dict[str, Any]:
    target = path or _DEFAULT_FILTER_FILE
    try:
        with open(target, encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        logger.error("Failed to load systemd filters from %s: %s", target, exc)
        raise RuntimeError(f"Cannot load systemd config: {exc}") from exc


# --------------------------------------------------------------------------- #
# Parsing helpers
# --------------------------------------------------------------------------- #
def _parse_unit_lines(lines: list[str]) -> dict[str, list[str]]:
    data: dict[str, list[str]] = {}
    for ln in lines:
        ln = ln.strip()
        if not ln or ln.startswith("#") or "=" not in ln:
            continue
        m = _UNIT_RE.match(ln)
        if m:
            key, val = m.groups()
            data.setdefault(key, []).append(val.strip())
    return data


def _is_container_service(exec_lines: list[str], keywords: list[str]) -> bool:
    text = " ".join(exec_lines).lower()
    return any(k.lower() in text for k in keywords)


def _guess_engine_and_container(
    exec_lines: list[str],
    engine_map: dict[str, dict[str, str]],
) -> tuple[str, str]:
    joined = " ".join(exec_lines)
    joined_lower = joined.lower()

    for engine, cfg in engine_map.items():
        keyword = cfg.get("keyword", "").lower()
        if keyword and keyword in joined_lower:
            regex = cfg.get("container_regex")
            if regex:
                m = re.search(regex, joined, flags=re.IGNORECASE)
                if m and m.lastindex and m.lastindex >= 1:
                    return engine, m.group(1)
                return engine, ""
            return engine, ""
    return "", ""


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #
def scan_systemd_container_units(
    rootfs: str | Path,
    *,
    filters_path: Path | None = None,
) -> list[dict[str, Any]]:
    """
    Walk ``rootfs`` for *.service files and return structured container units.

    Each record contains:
        unit, engine, container, user,
        exec, path, fields, raw_lines
    """
    cfg = _load_filters(filters_path)
    keywords: list[str] = cfg["container_keywords"]
    engine_map: dict[str, dict[str, str]] = cfg["engine_detection"]
    wanted_fields: list[str] = cfg["fields_to_keep"]
    extraction_patterns: dict[str, str] = cfg.get("extraction_patterns", {})

    unit_dirs_raw: list[str] = cfg.get(
        "unit_dirs",
        [
            "etc/systemd/system",
            "lib/systemd/system",
            "usr/lib/systemd/system",
        ],
    )
    rootfs = Path(rootfs)
    unit_dirs = [rootfs / d.lstrip("/") for d in unit_dirs_raw]

    # Discover user-scope systemd unit directories for rootless daemons
    user_suffix = cfg.get("user_unit_dir_suffix", "")
    if user_suffix:
        from jibrilcon.util.passwd_utils import get_user_home_dirs

        for home_abs in get_user_home_dirs(str(rootfs)):
            user_unit_dir = Path(home_abs) / user_suffix
            if user_unit_dir not in unit_dirs:
                unit_dirs.append(user_unit_dir)

    exec_keys: list[str] = cfg.get("exec_keys", ["ExecStart", "ExecStartPre"])

    rows: list[dict[str, Any]] = []

    for udir in unit_dirs:
        if not udir.is_dir():
            continue
        for svc_file in udir.rglob("*.service"):
            try:
                raw = svc_file.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeDecodeError):
                continue

            kvmap = _parse_unit_lines(raw)

            exec_lines: list[str] = []
            for key in exec_keys:
                exec_lines.extend(kvmap.get(key, []))

            if not _is_container_service(exec_lines, keywords):
                continue

            engine, cname = _guess_engine_and_container(exec_lines, engine_map)

            fields: dict[str, Any] = {}
            raw_lines: dict[str, list[str]] = {}
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
    filters_path: Path | None = None,
) -> None:
    """
    One-stop helper: parse *.service files under *rootfs* and cache results
    into *ctx* so all scanners can reuse them.

    Side-effects on ScanContext:
        • mark_systemd_started()
        • mark_user_missing()
        • add_exec_lines()      (ExecStart / ExecStartPre)
    """
    try:
        rows = scan_systemd_container_units(rootfs, filters_path=filters_path)
    except RuntimeError:
        logger.error(
            "Failed to load systemd filters from %s; skipping systemd collection",
            filters_path or _DEFAULT_FILTER_FILE,
        )
        return

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
        all_exec: list[str] = []
        for key, lines in raw.items():
            if key.startswith("execstart"):
                all_exec.extend(lines)
        if all_exec:
            ctx.add_exec_lines(engine, cname, all_exec)

        # --- cache service metadata for scanner cross-validation ------
        fields = row.get("fields", {})
        ctx.set_service_meta(
            engine,
            cname,
            {
                "user": user,
                "unit": row.get("unit", ""),
                "path": row.get("path", ""),
                "cap_bounding_set": fields.get("capabilityboundingset", ""),
                "ambient_capabilities": fields.get("ambientcapabilities", ""),
            },
        )

        # Development-time information
        logger.info(
            "[systemd] unit=%s engine=%s container=%s user=%s exec=%s",
            row["unit"],
            engine or "<unknown>",
            cname or "<unknown>",
            user,
            row["exec"],
        )
