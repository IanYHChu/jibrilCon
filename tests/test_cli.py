"""Tests for cli.py."""

import gzip
import json
from unittest.mock import patch

import pytest

from jibrilcon import __version__
from jibrilcon.cli import _colour, main

# ------------------------------------------------------------------ #
# --version flag
# ------------------------------------------------------------------ #


def test_version_flag(capsys):
    with patch("sys.argv", ["jibrilcon", "--version"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
    captured = capsys.readouterr()
    assert __version__ in captured.out


# ------------------------------------------------------------------ #
# _colour helper
# ------------------------------------------------------------------ #


def test_colour_enabled():
    result = _colour("42", "red", enable=True)
    assert result == "\033[31m42\033[0m"


def test_colour_disabled():
    result = _colour("42", "red", enable=False)
    assert result == "42"


# ------------------------------------------------------------------ #
# main() integration
# ------------------------------------------------------------------ #


def test_main_nonexistent_path(capsys):
    with patch("sys.argv", ["jibrilcon", "/nonexistent_rootfs_path_xyz"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code != 0


def test_main_valid_rootfs(make_rootfs, capsys):
    r = make_rootfs
    cid = "cli" * 8 + "0" * 40
    r.add_docker_container(
        cid,
        config_v2={"Name": "/clitest"},
        hostconfig={"Privileged": False, "ReadonlyRootfs": True, "Binds": []},
    )
    with patch("sys.argv", ["jibrilcon", r.path, "--no-color"]):
        main()
    captured = capsys.readouterr()
    # Should contain JSON report and summary
    assert "report" in captured.out
    assert "Scan Summary" in captured.out


def test_main_output_file(make_rootfs, tmp_path):
    r = make_rootfs
    cid = "cli" * 8 + "1" * 40
    r.add_docker_container(
        cid,
        config_v2={"Name": "/outtest"},
        hostconfig={"Privileged": False, "ReadonlyRootfs": True, "Binds": []},
    )
    out_file = tmp_path / "report.json"
    with patch("sys.argv", ["jibrilcon", r.path, "-o", str(out_file), "--no-color"]):
        main()
    assert out_file.exists()
    report = json.loads(out_file.read_text())
    assert "report" in report
    assert "summary" in report


# ------------------------------------------------------------------ #
# Argument validation
# ------------------------------------------------------------------ #


def test_main_max_workers_zero(capsys):
    """--max-workers 0 should exit with an error (validator checks < 1)."""
    with patch("sys.argv", ["jibrilcon", "/tmp", "--max-workers", "0"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code != 0


def test_main_max_workers_negative(capsys):
    """--max-workers -1 should exit with an error."""
    with patch("sys.argv", ["jibrilcon", "/tmp", "--max-workers", "-1"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code != 0


def test_main_invalid_log_level(capsys):
    """An invalid --log-level value should exit with an error."""
    with patch("sys.argv", ["jibrilcon", "/tmp", "--log-level", "banana"]):
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code != 0


def test_main_output_gzip(make_rootfs, tmp_path):
    """Output with .json.gz extension produces valid gzip content."""
    r = make_rootfs
    cid = "gzip" * 6 + "0" * 40
    r.add_docker_container(
        cid,
        config_v2={"Name": "/gztest"},
        hostconfig={"Privileged": False, "ReadonlyRootfs": True, "Binds": []},
    )
    out_file = tmp_path / "report.json.gz"
    with patch("sys.argv", ["jibrilcon", r.path, "-o", str(out_file), "--no-color"]):
        main()
    assert out_file.exists()
    raw = gzip.decompress(out_file.read_bytes())
    report = json.loads(raw)
    assert "report" in report
    assert "summary" in report


def test_main_runtime_error_handled(make_rootfs, capsys):
    """A RuntimeError from run_scan is caught and exits with code 1."""
    r = make_rootfs
    with patch("jibrilcon.cli.run_scan", side_effect=RuntimeError("boom")):
        with patch("sys.argv", ["jibrilcon", r.path]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "boom" in captured.err


def test_main_os_error_handled(make_rootfs, capsys):
    """An OSError from run_scan is caught and exits with code 1."""
    r = make_rootfs
    with patch("jibrilcon.cli.run_scan", side_effect=OSError("disk fail")):
        with patch("sys.argv", ["jibrilcon", r.path]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "disk fail" in captured.err


# ------------------------------------------------------------------ #
# __main__.py entry point
# ------------------------------------------------------------------ #


def test_dunder_main_calls_main():
    """Verify that 'python -m jibrilcon' invokes cli.main()."""
    with patch("jibrilcon.cli.main") as mock_main:
        import runpy

        runpy.run_module("jibrilcon", run_name="__main__", alter_sys=False)
    mock_main.assert_called_once()
