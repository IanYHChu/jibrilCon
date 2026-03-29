"""Tests for core.py -- run_scan orchestrator."""

from unittest.mock import patch

from jibrilcon.core import run_scan


def test_run_scan_returns_report_with_summary(make_rootfs):
    """run_scan returns a dict with 'report' and 'summary' keys."""
    r = make_rootfs
    cid = "core" * 8 + "0" * 36
    r.add_docker_container(
        cid,
        config_v2={"Name": "/coretest"},
        hostconfig={"Privileged": False, "ReadonlyRootfs": True, "Binds": []},
    )
    report = run_scan(r.path)
    assert "report" in report
    assert "summary" in report
    assert isinstance(report["report"], list)
    assert isinstance(report["summary"], dict)


def test_run_scan_summary_has_expected_keys(make_rootfs):
    """Summary should contain alert/warning counts and scanners_run."""
    r = make_rootfs
    cid = "core" * 8 + "1" * 36
    r.add_docker_container(
        cid,
        config_v2={"Name": "/sumtest"},
        hostconfig={"Privileged": True, "ReadonlyRootfs": False, "Binds": []},
    )
    report = run_scan(r.path)
    summary = report["summary"]
    assert "scanners_run" in summary
    assert isinstance(summary["scanners_run"], list)


def test_run_scan_drops_malformed_results(make_rootfs):
    """Scanner results missing the 'scanner' key are filtered out."""
    r = make_rootfs

    def fake_scanners(mount_path, **kwargs):
        return [
            {"scanner": "docker", "summary": {"alerts": 0}, "results": []},
            {"bad": "no scanner key"},
        ]

    with patch("jibrilcon.core.run_scanners", side_effect=fake_scanners):
        report = run_scan(r.path)
    assert len(report["report"]) == 1
    assert report["report"][0]["scanner"] == "docker"


def test_run_scan_detect_init_system_error(make_rootfs):
    """If detect_init_system raises RuntimeError, scan still proceeds."""
    r = make_rootfs
    cid = "core" * 8 + "2" * 36
    r.add_docker_container(
        cid,
        config_v2={"Name": "/initfailtest"},
        hostconfig={"Privileged": False, "ReadonlyRootfs": True, "Binds": []},
    )

    with patch(
        "jibrilcon.core.detect_init_system",
        side_effect=RuntimeError("corrupt ELF header"),
    ):
        report = run_scan(r.path)

    assert "report" in report
    assert "summary" in report
    assert isinstance(report["report"], list)


def test_run_scan_collect_systemd_containers_error(make_rootfs):
    """If collect_systemd_containers raises OSError, scan still proceeds."""
    r = make_rootfs

    with (
        patch(
            "jibrilcon.core.detect_init_system",
            return_value="systemd",
        ),
        patch(
            "jibrilcon.core.collect_systemd_containers",
            side_effect=OSError("permission denied reading unit files"),
        ),
    ):
        report = run_scan(r.path)

    assert "report" in report
    assert "summary" in report
    assert isinstance(report["report"], list)


def test_run_scan_empty_rootfs(make_rootfs):
    """An empty rootfs (no containers) should return an empty report."""
    r = make_rootfs
    report = run_scan(r.path)
    assert isinstance(report["report"], list)
    # Scanners run but find no containers, so every result list is empty
    assert all(r["results"] == [] for r in report["report"])
    assert isinstance(report["summary"], dict)
