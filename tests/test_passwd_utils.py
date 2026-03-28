"""Tests for util/passwd_utils.py."""

import os
from pathlib import Path

from jibrilcon.util.passwd_utils import get_user_home_dirs


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _write_passwd(rootfs: Path, content: str) -> None:
    passwd = rootfs / "etc" / "passwd"
    passwd.parent.mkdir(parents=True, exist_ok=True)
    passwd.write_text(content, encoding="utf-8")


# ------------------------------------------------------------------ #
# Tests
# ------------------------------------------------------------------ #


def test_normal_passwd_multiple_users(tmp_path):
    """Normal passwd with both system (UID < 1000) and regular users."""
    _write_passwd(
        tmp_path,
        (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
            "bob:x:1001:1001:Bob:/home/bob:/bin/zsh\n"
        ),
    )
    homes = get_user_home_dirs(str(tmp_path))
    # All 4 users have valid home directories
    assert len(homes) == 4
    assert any(h.endswith("/root") for h in homes)
    assert any(h.endswith("/home/alice") for h in homes)
    assert any(h.endswith("/home/bob") for h in homes)
    # All paths are absolute and prefixed with rootfs
    for h in homes:
        assert os.path.isabs(h)
        assert h.startswith(str(tmp_path))


def test_malformed_lines_too_few_fields(tmp_path):
    """Lines with fewer than 6 colon-separated fields are skipped."""
    _write_passwd(
        tmp_path,
        (
            "root:x:0:0:root:/root:/bin/bash\n"
            "short:x:1000\n"
            "alsoshort:x\n"
            "nofields\n"
            "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n"
        ),
    )
    homes = get_user_home_dirs(str(tmp_path))
    # Only root and alice have valid entries (>= 6 fields)
    assert len(homes) == 2


def test_missing_etc_passwd(tmp_path):
    """If /etc/passwd does not exist, return an empty list."""
    homes = get_user_home_dirs(str(tmp_path))
    assert homes == []


def test_path_traversal_rejected(tmp_path, caplog):
    """Home dirs with ../../ that would escape rootfs are rejected."""
    _write_passwd(
        tmp_path,
        (
            "legit:x:1000:1000:Legit:/home/legit:/bin/bash\n"
            "evil:x:1001:1001:Evil:/home/../../etc:/bin/bash\n"
        ),
    )
    homes = get_user_home_dirs(str(tmp_path))
    # Only legit's home should be returned
    assert len(homes) == 1
    assert any(h.endswith("/home/legit") for h in homes)
    # The traversal should have been logged as a warning
    assert any("escapes rootfs" in r.message for r in caplog.records)


def test_empty_passwd_file(tmp_path):
    """An empty /etc/passwd file returns an empty list."""
    _write_passwd(tmp_path, "")
    homes = get_user_home_dirs(str(tmp_path))
    assert homes == []


def test_empty_home_field_skipped(tmp_path):
    """A passwd line with an empty home field (field 5) is skipped."""
    _write_passwd(
        tmp_path,
        (
            "nohome:x:1000:1000:No Home::/bin/bash\n"
            "alice:x:1001:1001:Alice:/home/alice:/bin/bash\n"
        ),
    )
    homes = get_user_home_dirs(str(tmp_path))
    # nohome has empty home field, only alice returned
    assert len(homes) == 1
    assert any(h.endswith("/home/alice") for h in homes)
