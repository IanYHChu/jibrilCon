"""Tests for cli.py."""

import json
from unittest.mock import patch

import pytest

from jibrilcon.cli import _colour, main


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
