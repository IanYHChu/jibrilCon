# Copyright (c) 2025 IanYHChu
# Licensed under the Apache License, Version 2.0
# See LICENSE file in the project root for full license information.

"""
pdf_report.py

Generate a PDF compliance report from jibrilcon scan results, mapping
findings to MITRE ATT&CK, CIS Docker Benchmark, and NIST 800-190.

Requires the ``fpdf2`` library (optional dependency).
Install with::

    pip install jibrilcon[pdf]
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    from fpdf import FPDF
except ImportError:
    FPDF = None  # type: ignore[assignment,misc]

# ------------------------------------------------------------------ #
# Static lookup tables for compliance framework references             #
# ------------------------------------------------------------------ #

MITRE_TECHNIQUES: dict[str, str] = {
    "T1003": "OS Credential Dumping",
    "T1068": "Exploitation for Privilege Escalation",
    "T1078.003": "Valid Accounts: Local Accounts",
    "T1190": "Exploit Public-Facing Application",
    "T1195.002": "Supply Chain Compromise: Compromise Software Supply Chain",
    "T1525": "Implant Internal Image",
    "T1548": "Abuse Elevation Control Mechanism",
    "T1552": "Unsecured Credentials",
    "T1557": "Adversary-in-the-Middle",
    "T1565.001": "Data Manipulation: Stored Data Manipulation",
    "T1574": "Hijack Execution Flow",
    "T1611": "Escape to Host",
}

CIS_DOCKER_SECTIONS: dict[str, str] = {
    "5.3": "Ensure that Linux kernel capabilities are restricted within containers",
    "5.4": "Ensure that privileged containers are not used",
    "5.5": "Ensure sensitive host system directories are not mounted on containers",
    "5.6": "Ensure sshd is not run within containers / Do not use host network mode",
    "5.7": "Ensure the host's IPC namespace is not shared",
    "5.8": "Ensure that only needed ports are open on the container",
    "5.12": "Ensure that the container's root filesystem is mounted as read only",
    "5.21": "Ensure the default seccomp profile is not disabled",
    "5.25": "Ensure container is restricted from acquiring "
    "additional privileges",
    "5.26": "Ensure that container health is checked at runtime",
}

NIST_800_190_SECTIONS: dict[str, str] = {
    "4.4": "Container Runtime Security",
}

# ------------------------------------------------------------------ #
# Severity helpers                                                     #
# ------------------------------------------------------------------ #

_SEVERITY_BANDS: list[tuple[float, str]] = [
    (9.0, "Critical"),
    (7.0, "High"),
    (5.0, "Medium"),
    (0.0, "Low"),
]

# RGB tuples: (background, text)
_SEVERITY_COLORS: dict[str, tuple[tuple[int, int, int], tuple[int, int, int]]] = {
    "Critical": ((220, 53, 69), (255, 255, 255)),
    "High": ((255, 152, 0), (0, 0, 0)),
    "Medium": ((255, 193, 7), (0, 0, 0)),
    "Low": ((0, 123, 255), (255, 255, 255)),
}


def severity_band(score: float) -> str:
    for threshold, label in _SEVERITY_BANDS:
        if score >= threshold:
            return label
    return "Low"


# ------------------------------------------------------------------ #
# Data extraction helpers                                              #
# ------------------------------------------------------------------ #

# A flat finding: (scanner_name, container_name, violation_dict)
Finding = tuple[str, str, dict[str, Any]]


def collect_findings(report: dict[str, Any]) -> list[Finding]:
    """Flatten the nested report into (scanner, container, violation) tuples."""
    findings: list[Finding] = []
    for block in report.get("report", []):
        scanner = block.get("scanner", "unknown")
        for result in block.get("results", []):
            container = result.get("container", "unknown")
            for vio in result.get("violations", []):
                findings.append((scanner, container, vio))
    return findings


def group_by_framework(
    findings: list[Finding],
) -> dict[str, dict[str, list[Finding]]]:
    """Group findings by each compliance framework reference.

    Returns::

        {
            "mitre_attack": {"T1611": [finding, ...], ...},
            "cis_docker_benchmark": {"5.4": [finding, ...], ...},
            "nist_800_190": {"4.4": [finding, ...], ...},
        }
    """
    grouped: dict[str, dict[str, list[Finding]]] = {
        "mitre_attack": {},
        "cis_docker_benchmark": {},
        "nist_800_190": {},
    }
    for finding in findings:
        refs = finding[2].get("references", {})
        for framework, ref_ids in refs.items():
            if framework not in grouped:
                continue
            for ref_id in ref_ids:
                ref_id_str = str(ref_id)
                grouped[framework].setdefault(ref_id_str, []).append(finding)
    return grouped


# ------------------------------------------------------------------ #
# PDF builder                                                          #
# ------------------------------------------------------------------ #

# Page geometry (A4)
_PAGE_W = 210
_MARGIN = 10
_USABLE_W = _PAGE_W - 2 * _MARGIN


class _CompliancePDF(FPDF if FPDF is not None else object):  # type: ignore[misc]
    """Custom FPDF subclass with header/footer for the compliance report."""

    def __init__(self, report: dict[str, Any]) -> None:
        if FPDF is None:
            raise ImportError(
                "PDF report generation requires fpdf2. "
                "Install with: pip install jibrilcon[pdf]"
            )
        super().__init__(orientation="P", unit="mm", format="A4")
        self.set_auto_page_break(auto=True, margin=15)
        self._report = report
        self._gen_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # -- header / footer ------------------------------------------- #

    def header(self) -> None:
        if self.page_no() == 1:
            return
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 6, "jibrilcon Compliance Report", align="L")
        self.cell(0, 6, self._gen_time, align="R", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 200, 200)
        self.line(self.l_margin, self.get_y(), _PAGE_W - self.r_margin, self.get_y())
        self.ln(4)

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 8, f"Page {self.page_no()}/{{nb}}", align="C")

    # -- reusable building blocks ---------------------------------- #

    def chapter_title(self, title: str) -> None:
        self.add_page()
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(0, 0, 0)
        self.cell(0, 14, title, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(41, 128, 185)
        self.set_line_width(0.8)
        self.line(self.l_margin, self.get_y(), _PAGE_W - self.r_margin, self.get_y())
        self.ln(6)
        self.set_line_width(0.2)

    def section_title(self, title: str) -> None:
        self._check_page_space(20)
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(41, 128, 185)
        self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(0, 0, 0)

    def severity_badge(self, score: float) -> None:
        band = severity_band(score)
        bg, fg = _SEVERITY_COLORS[band]
        label = f"{band} ({score:.1f})"
        self.set_fill_color(*bg)
        self.set_text_color(*fg)
        self.set_font("Helvetica", "B", 8)
        w = self.get_string_width(label) + 4
        self.cell(w, 5, label, fill=True)
        self.set_text_color(0, 0, 0)

    def _check_page_space(self, needed_mm: float) -> None:
        if self.get_y() + needed_mm > self.h - self.b_margin:
            self.add_page()

    def _table_header(self, cols: list[tuple[str, float]]) -> None:
        self.set_font("Helvetica", "B", 8)
        self.set_fill_color(52, 73, 94)
        self.set_text_color(255, 255, 255)
        for label, w in cols:
            self.cell(w, 7, label, border=1, fill=True, align="C")
        self.ln()
        self.set_text_color(0, 0, 0)

    def _table_row(self, cols: list[tuple[str, float]], fill: bool = False) -> None:
        self.set_font("Helvetica", "", 7)
        if fill:
            self.set_fill_color(240, 240, 240)
        h = 6
        # Calculate max row height for multi_cell wrapping
        x_start = self.get_x()
        y_start = self.get_y()
        max_h = h
        # First pass: measure
        cell_heights: list[float] = []
        for text, w in cols:
            rendered = self.multi_cell(
                w, h, text, dry_run=True, output="LINES",
            )
            n_lines = max(1, len(rendered))
            cell_heights.append(n_lines * h)
            if n_lines * h > max_h:
                max_h = n_lines * h
        # Check page space
        if y_start + max_h > self.h - self.b_margin:
            self.add_page()
            y_start = self.get_y()
            x_start = self.get_x()
        # Second pass: draw
        for i, (text, w) in enumerate(cols):
            self.set_xy(x_start + sum(cw for _, cw in cols[:i]), y_start)
            self.multi_cell(
                w, h, text, border=1, fill=fill,
                max_line_height=h, new_x="RIGHT", new_y="TOP",
            )
        self.set_xy(x_start, y_start + max_h)


# ------------------------------------------------------------------ #
# Section builders                                                     #
# ------------------------------------------------------------------ #


def _add_cover_page(pdf: _CompliancePDF, report: dict[str, Any]) -> None:
    pdf.add_page()
    pdf.ln(40)

    # Title
    pdf.set_font("Helvetica", "B", 28)
    pdf.set_text_color(41, 128, 185)
    pdf.cell(0, 16, "jibrilcon", align="C", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 16)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(
        0, 10, "Compliance Report", align="C", new_x="LMARGIN", new_y="NEXT"
    )
    pdf.cell(
        0, 8,
        "Static Container Configuration Risk Assessment",
        align="C", new_x="LMARGIN", new_y="NEXT",
    )

    pdf.ln(20)

    # Metadata block
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(0, 0, 0)
    meta = report.get("metadata", {})
    mount_path = meta.get("mount_path", "N/A")
    version = meta.get("version", "N/A")

    info_lines = [
        ("Generated", pdf._gen_time),
        ("Target", mount_path),
        ("Version", version),
    ]
    for label, value in info_lines:
        pdf.set_font("Helvetica", "B", 11)
        pdf.cell(40, 8, f"{label}:", align="R")
        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 8, f"  {value}", new_x="LMARGIN", new_y="NEXT")

    # Summary box
    summary = report.get("summary", {})
    pdf.ln(15)
    pdf.set_draw_color(41, 128, 185)
    pdf.set_line_width(0.5)
    box_y = pdf.get_y()
    pdf.rect(_MARGIN + 20, box_y, _USABLE_W - 40, 40)
    pdf.set_line_width(0.2)

    pdf.set_xy(_MARGIN + 25, box_y + 5)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Scan Summary", new_x="LMARGIN", new_y="NEXT")

    pdf.set_x(_MARGIN + 25)
    items = [
        ("Alerts", summary.get("alerts", 0), (220, 53, 69)),
        ("Warnings", summary.get("warnings", 0), (255, 152, 0)),
        ("Clean", summary.get("clean", 0), (40, 167, 69)),
        ("Violated", summary.get("violated", 0), (220, 53, 69)),
    ]
    pdf.set_font("Helvetica", "", 11)
    for label, count, color in items:
        pdf.set_text_color(*color)
        pdf.cell(35, 7, f"{label}: {count}")
    pdf.set_text_color(0, 0, 0)


def _add_executive_summary(
    pdf: _CompliancePDF,
    report: dict[str, Any],
    findings: list[Finding],
) -> None:
    pdf.chapter_title("Executive Summary")

    # -- Severity distribution ------------------------------------- #
    pdf.section_title("Severity Distribution")
    band_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for _, _, vio in findings:
        band_counts[severity_band(vio.get("severity", 0.0))] += 1

    cols = [("Severity", 40.0), ("Count", 30.0), ("Percentage", 40.0)]
    pdf._table_header(cols)
    total = max(len(findings), 1)
    for i, band in enumerate(["Critical", "High", "Medium", "Low"]):
        cnt = band_counts[band]
        pct = f"{cnt / total * 100:.1f}%"
        pdf._table_row([(band, 40.0), (str(cnt), 30.0), (pct, 40.0)], fill=i % 2 == 0)
    pdf.ln(6)

    # -- Scanner coverage ------------------------------------------ #
    pdf.section_title("Scanner Coverage")
    cols = [
        ("Scanner", 35.0),
        ("Containers", 30.0),
        ("Alerts", 30.0),
        ("Warnings", 30.0),
    ]
    pdf._table_header(cols)
    for i, block in enumerate(report.get("report", [])):
        s = block.get("summary", {})
        scanner = block.get("scanner", "unknown")
        # Try common scanner-count keys
        scanned = (
            s.get("docker_scanned")
            or s.get("podman_scanned")
            or s.get("lxc_scanned")
            or s.get("containers_scanned")
            or len(block.get("results", []))
        )
        pdf._table_row(
            [
                (scanner, 35.0),
                (str(scanned), 30.0),
                (str(s.get("alerts", 0)), 30.0),
                (str(s.get("warnings", 0)), 30.0),
            ],
            fill=i % 2 == 0,
        )
    pdf.ln(6)

    # -- Top findings ---------------------------------------------- #
    if findings:
        pdf.section_title("Top Findings by Severity")
        sorted_findings = sorted(
            findings, key=lambda f: f[2].get("severity", 0), reverse=True,
        )
        top = sorted_findings[:10]
        cols = [
            ("Sev.", 12.0),
            ("Scanner", 22.0),
            ("Container", 36.0),
            ("Rule", 35.0),
            ("Description", 85.0),
        ]
        pdf._table_header(cols)
        for i, (scanner, container, vio) in enumerate(top):
            sev = vio.get("severity", 0.0)
            pdf._table_row(
                [
                    (f"{sev:.1f}", 12.0),
                    (scanner, 22.0),
                    (_truncate(container, 30), 36.0),
                    (vio.get("id", ""), 35.0),
                    (_truncate(vio.get("description", ""), 70), 85.0),
                ],
                fill=i % 2 == 0,
            )


def _add_framework_chapter(
    pdf: _CompliancePDF,
    title: str,
    groups: dict[str, list[Finding]],
    lookup: dict[str, str],
) -> None:
    if not groups:
        return

    pdf.chapter_title(title)

    cols = [
        ("Sev.", 12.0),
        ("Scanner", 22.0),
        ("Container", 40.0),
        ("Rule", 32.0),
        ("Description", 84.0),
    ]

    for ref_id in sorted(groups.keys()):
        ref_findings = groups[ref_id]
        desc = lookup.get(ref_id, "")
        section_label = f"{ref_id}"
        if desc:
            section_label += f" - {desc}"
        pdf.section_title(section_label)

        pdf.set_font("Helvetica", "", 9)
        pdf.cell(
            0, 5,
            f"{len(ref_findings)} finding(s)",
            new_x="LMARGIN", new_y="NEXT",
        )
        pdf.ln(2)

        pdf._table_header(cols)
        for i, (scanner, container, vio) in enumerate(ref_findings):
            sev = vio.get("severity", 0.0)
            pdf._table_row(
                [
                    (f"{sev:.1f}", 12.0),
                    (scanner, 22.0),
                    (_truncate(container, 34), 40.0),
                    (vio.get("id", ""), 32.0),
                    (_truncate(vio.get("description", ""), 68), 84.0),
                ],
                fill=i % 2 == 0,
            )
        pdf.ln(4)


def _add_detailed_findings(pdf: _CompliancePDF, report: dict[str, Any]) -> None:
    pdf.chapter_title("Detailed Findings")

    finding_num = 0
    for block in report.get("report", []):
        scanner = block.get("scanner", "unknown")
        for result in block.get("results", []):
            container = result.get("container", "unknown")
            status = result.get("status", "unknown")
            violations = result.get("violations", [])

            if not violations:
                continue

            pdf.section_title(f"[{scanner}] {container}")
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(
                0, 5,
                f"Status: {status}  |  Violations: {len(violations)}",
                new_x="LMARGIN", new_y="NEXT",
            )
            pdf.ln(2)

            for vio in violations:
                finding_num += 1
                _add_finding_detail(pdf, vio, finding_num)


def _add_finding_detail(
    pdf: _CompliancePDF, vio: dict[str, Any], num: int
) -> None:
    pdf._check_page_space(50)

    # Finding header with severity badge
    pdf.set_font("Helvetica", "B", 9)
    sev = vio.get("severity", 0.0)
    rule_id = vio.get("id", "unknown")
    pdf.cell(50, 6, f"#{num}  {rule_id}")
    pdf.severity_badge(sev)
    vio_type = vio.get("type", "")
    pdf.set_font("Helvetica", "", 8)
    pdf.cell(0, 6, f"  [{vio_type}]", new_x="LMARGIN", new_y="NEXT")

    # Description
    pdf.set_font("Helvetica", "B", 8)
    pdf.cell(24, 5, "Desc:")
    pdf.set_font("Helvetica", "", 8)
    pdf.multi_cell(0, 5, vio.get("description", ""), new_x="LMARGIN", new_y="NEXT")

    # Risk
    risk = vio.get("risk", "")
    if risk:
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(24, 5, "Risk:")
        pdf.set_font("Helvetica", "", 8)
        pdf.multi_cell(0, 5, risk, new_x="LMARGIN", new_y="NEXT")

    # Remediation
    remediation = vio.get("remediation", "")
    if remediation:
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(24, 5, "Remed.:")
        pdf.set_font("Helvetica", "", 8)
        pdf.multi_cell(0, 5, remediation, new_x="LMARGIN", new_y="NEXT")

    # Source
    source = vio.get("source", "")
    if source:
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(24, 5, "Source:")
        pdf.set_font("Courier", "", 7)
        pdf.cell(0, 5, source, new_x="LMARGIN", new_y="NEXT")

    # Evidence lines
    lines = vio.get("lines", [])
    if lines:
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(24, 5, "Evidence:")
        pdf.set_font("Courier", "", 7)
        for line in lines[:5]:
            pdf.cell(0, 4, _truncate(str(line), 100), new_x="LMARGIN", new_y="NEXT")
            pdf.set_x(pdf.l_margin + 24)
        if len(lines) > 5:
            pdf.cell(
                0, 4, f"... and {len(lines) - 5} more",
                new_x="LMARGIN", new_y="NEXT",
            )

    # References
    refs = vio.get("references", {})
    if refs:
        pdf.set_font("Helvetica", "B", 8)
        pdf.cell(24, 5, "Refs:")
        pdf.set_font("Helvetica", "", 7)
        ref_parts: list[str] = []
        for fw, ids in refs.items():
            if ids:
                ref_parts.append(f"{fw}: {', '.join(str(i) for i in ids)}")
        pdf.multi_cell(0, 4, "  |  ".join(ref_parts), new_x="LMARGIN", new_y="NEXT")

    # Separator
    pdf.set_draw_color(220, 220, 220)
    y = pdf.get_y() + 2
    pdf.line(pdf.l_margin, y, _PAGE_W - pdf.r_margin, y)
    pdf.ln(5)


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #


def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


# ------------------------------------------------------------------ #
# Public API                                                           #
# ------------------------------------------------------------------ #


def generate_pdf_report(report: dict[str, Any], output_path: str | Path) -> None:
    """Generate a PDF compliance report and write it to *output_path*.

    Raises
    ------
    ImportError
        If ``fpdf2`` is not installed.
    """
    if FPDF is None:
        raise ImportError(
            "PDF report generation requires fpdf2. "
            "Install with: pip install jibrilcon[pdf]"
        )

    path = Path(output_path)
    pdf = _CompliancePDF(report)
    pdf.alias_nb_pages()

    findings = collect_findings(report)
    grouped = group_by_framework(findings)

    # Build document
    _add_cover_page(pdf, report)
    _add_executive_summary(pdf, report, findings)
    _add_framework_chapter(
        pdf,
        "MITRE ATT&CK Mapping",
        grouped["mitre_attack"],
        MITRE_TECHNIQUES,
    )
    _add_framework_chapter(
        pdf,
        "CIS Docker Benchmark Mapping",
        grouped["cis_docker_benchmark"],
        CIS_DOCKER_SECTIONS,
    )
    _add_framework_chapter(
        pdf,
        "NIST 800-190 Mapping",
        grouped["nist_800_190"],
        NIST_800_190_SECTIONS,
    )
    _add_detailed_findings(pdf, report)

    # Atomic write via report_writer helper
    from jibrilcon.util.report_writer import atomic_write

    binary = pdf.output()
    atomic_write(binary, path)

    logger.info("PDF compliance report written to %s (%d pages)", path, pdf.pages_count)
