"""Tests for jibrilcon.util.pdf_report."""

from __future__ import annotations

import pytest

from jibrilcon.util.pdf_report import (
    Finding,
    collect_findings,
    group_by_framework,
    severity_band,
)

# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #

_SAMPLE_VIOLATION = {
    "id": "privileged",
    "type": "alert",
    "severity": 9.0,
    "description": "Container is running in privileged mode",
    "risk": "Grants full access to all host devices.",
    "remediation": "Remove --privileged flag.",
    "references": {
        "mitre_attack": ["T1611"],
        "cis_docker_benchmark": ["5.4"],
        "nist_800_190": ["4.4"],
    },
    "source": "/var/lib/docker/containers/abc123/config.v2.json",
    "lines": ["HostConfig.Privileged = True"],
}

_SAMPLE_VIOLATION_2 = {
    "id": "host_network_namespace",
    "type": "alert",
    "severity": 8.0,
    "description": "Container shares the host's network namespace",
    "risk": "Bypasses network isolation.",
    "remediation": "Remove --network=host flag.",
    "references": {
        "mitre_attack": ["T1557"],
        "cis_docker_benchmark": ["5.6"],
        "nist_800_190": ["4.4"],
    },
    "source": "/var/lib/docker/containers/abc123/config.v2.json",
    "lines": ["HostConfig.NetworkMode = host"],
}

_SAMPLE_WARNING = {
    "id": "readonly_rootfs_missing",
    "type": "warning",
    "severity": 4.0,
    "description": "Readonly root filesystem is not enabled",
    "risk": "Container can write to root filesystem.",
    "remediation": "Add --read-only flag.",
    "references": {
        "mitre_attack": ["T1565.001"],
        "cis_docker_benchmark": ["5.12"],
        "nist_800_190": ["4.4"],
    },
    "source": "/var/lib/docker/containers/def456/config.v2.json",
    "lines": [],
}


def _make_report(
    violations: list[dict] | None = None,
    scanner: str = "docker",
    container: str = "test_container",
) -> dict:
    if violations is None:
        violations = [_SAMPLE_VIOLATION]
    return {
        "report": [
            {
                "scanner": scanner,
                "summary": {
                    "docker_scanned": 1,
                    "alerts": sum(1 for v in violations if v["type"] == "alert"),
                    "warnings": sum(1 for v in violations if v["type"] == "warning"),
                    "elapsed": 0.1,
                },
                "results": [
                    {
                        "container": container,
                        "status": "violated" if violations else "clean",
                        "violations": violations,
                    }
                ],
            }
        ],
        "summary": {
            "alerts": sum(1 for v in violations if v["type"] == "alert"),
            "warnings": sum(1 for v in violations if v["type"] == "warning"),
            "clean": 0 if violations else 1,
            "violated": 1 if violations else 0,
            "scanners_run": [scanner],
        },
        "metadata": {
            "mount_path": "/mnt/rootfs",
            "version": "0.1.0",
        },
    }


# ------------------------------------------------------------------ #
# Pure logic tests (no fpdf2 needed)                                   #
# ------------------------------------------------------------------ #


class TestSeverityBand:
    def test_critical(self):
        assert severity_band(9.0) == "Critical"
        assert severity_band(10.0) == "Critical"

    def test_high(self):
        assert severity_band(7.0) == "High"
        assert severity_band(8.5) == "High"

    def test_medium(self):
        assert severity_band(5.0) == "Medium"
        assert severity_band(6.9) == "Medium"

    def test_low(self):
        assert severity_band(0.0) == "Low"
        assert severity_band(4.9) == "Low"


class TestCollectFindings:
    def test_empty_report(self):
        assert collect_findings({"report": []}) == []
        assert collect_findings({}) == []

    def test_single_violation(self):
        report = _make_report([_SAMPLE_VIOLATION])
        findings = collect_findings(report)
        assert len(findings) == 1
        scanner, container, vio = findings[0]
        assert scanner == "docker"
        assert container == "test_container"
        assert vio["id"] == "privileged"

    def test_multiple_violations(self):
        report = _make_report([_SAMPLE_VIOLATION, _SAMPLE_VIOLATION_2, _SAMPLE_WARNING])
        findings = collect_findings(report)
        assert len(findings) == 3

    def test_clean_container_no_findings(self):
        report = _make_report([])
        assert collect_findings(report) == []


class TestGroupByFramework:
    def test_single_finding(self):
        findings: list[Finding] = [("docker", "c1", _SAMPLE_VIOLATION)]
        grouped = group_by_framework(findings)

        assert "T1611" in grouped["mitre_attack"]
        assert len(grouped["mitre_attack"]["T1611"]) == 1
        assert "5.4" in grouped["cis_docker_benchmark"]
        assert "4.4" in grouped["nist_800_190"]

    def test_multiple_findings_same_technique(self):
        # Both share nist_800_190 -> 4.4
        findings: list[Finding] = [
            ("docker", "c1", _SAMPLE_VIOLATION),
            ("docker", "c2", _SAMPLE_VIOLATION_2),
        ]
        grouped = group_by_framework(findings)
        assert len(grouped["nist_800_190"]["4.4"]) == 2

    def test_empty_findings(self):
        grouped = group_by_framework([])
        assert grouped["mitre_attack"] == {}
        assert grouped["cis_docker_benchmark"] == {}
        assert grouped["nist_800_190"] == {}

    def test_missing_references_key(self):
        vio_no_refs = {"id": "test", "severity": 5.0}
        findings: list[Finding] = [("docker", "c1", vio_no_refs)]
        grouped = group_by_framework(findings)
        assert grouped["mitre_attack"] == {}

    def test_unknown_framework_ignored(self):
        vio = {
            "id": "test",
            "severity": 5.0,
            "references": {"unknown_framework": ["X1"]},
        }
        findings: list[Finding] = [("docker", "c1", vio)]
        grouped = group_by_framework(findings)
        assert "unknown_framework" not in grouped


# ------------------------------------------------------------------ #
# PDF generation tests (require fpdf2)                                 #
# ------------------------------------------------------------------ #

fpdf = pytest.importorskip("fpdf")


class TestPDFGeneration:
    def test_generate_minimal_report(self, tmp_path):
        from jibrilcon.util.pdf_report import generate_pdf_report

        report = _make_report([])
        out = tmp_path / "report.pdf"
        generate_pdf_report(report, out)
        assert out.exists()
        header = out.read_bytes()[:5]
        assert header == b"%PDF-"

    def test_generate_full_report(self, tmp_path):
        from jibrilcon.util.pdf_report import generate_pdf_report

        report = _make_report(
            [_SAMPLE_VIOLATION, _SAMPLE_VIOLATION_2, _SAMPLE_WARNING]
        )
        out = tmp_path / "full_report.pdf"
        generate_pdf_report(report, out)
        assert out.exists()
        size = out.stat().st_size
        assert size > 1000  # non-trivial PDF

    def test_generate_multi_scanner_report(self, tmp_path):
        from jibrilcon.util.pdf_report import generate_pdf_report

        report = _make_report([_SAMPLE_VIOLATION])
        # Add a second scanner block
        report["report"].append(
            {
                "scanner": "podman",
                "summary": {"podman_scanned": 1, "alerts": 1, "warnings": 0},
                "results": [
                    {
                        "container": "podman_ctr",
                        "status": "violated",
                        "violations": [_SAMPLE_VIOLATION_2],
                    }
                ],
            }
        )
        out = tmp_path / "multi.pdf"
        generate_pdf_report(report, out)
        assert out.exists()

    def test_report_writer_dispatches_pdf(self, tmp_path):
        from jibrilcon.util.report_writer import write_report

        report = _make_report([_SAMPLE_VIOLATION])
        out = tmp_path / "via_writer.pdf"
        write_report(report, out)
        assert out.exists()
        assert out.read_bytes()[:5] == b"%PDF-"

    def test_json_output_still_works(self, tmp_path):
        from jibrilcon.util.report_writer import write_report

        report = _make_report([_SAMPLE_VIOLATION])
        out = tmp_path / "report.json"
        write_report(report, out)
        assert out.exists()
        import json

        data = json.loads(out.read_text())
        assert "report" in data
