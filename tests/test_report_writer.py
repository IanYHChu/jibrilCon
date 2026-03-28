"""Tests for report_writer and summary_utils."""
import gzip
import json
from pathlib import Path

import pytest

from jibrilcon.util.report_writer import write_report
from jibrilcon.util.summary_utils import generate_final_report


class TestReportWriter:
    def test_write_json(self, tmp_path):
        report = {"scanner": "test", "results": []}
        out = tmp_path / "report.json"
        write_report(report, str(out))
        assert out.exists()
        loaded = json.loads(out.read_text())
        assert loaded == report

    def test_write_gzip(self, tmp_path):
        report = {"scanner": "test", "results": []}
        out = tmp_path / "report.json.gz"
        write_report(report, str(out))
        assert out.exists()
        with gzip.open(out, "rt") as f:
            loaded = json.load(f)
        assert loaded == report


class TestSummaryUtils:
    def test_empty_scanner_results(self):
        report = generate_final_report([])
        assert report["summary"] == {}
        assert report["report"] == []

    def test_merge_multiple_scanners(self):
        results = [
            {"scanner": "docker", "summary": {"docker_scanned": 2, "alerts": 1, "warnings": 0, "elapsed": 0.1}, "results": [{"status": "violated"}, {"status": "clean"}]},
            {"scanner": "podman", "summary": {"podman_scanned": 1, "alerts": 0, "warnings": 1, "elapsed": 0.2}, "results": [{"status": "violated"}]},
        ]
        report = generate_final_report(results)
        s = report["summary"]
        assert s["alerts"] == 1
        assert s["warnings"] == 1
        assert s["clean"] == 1
        assert s["violated"] == 2
        assert s["scanners_run"] == ["docker", "podman"]

    def test_missing_status_counted_as_violated(self):
        results = [
            {"scanner": "test", "summary": {"alerts": 0}, "results": [{"status": None}]},
        ]
        report = generate_final_report(results)
        assert report["summary"]["violated"] == 1
