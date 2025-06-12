"""
Common path helpers used by scanners.
"""
from __future__ import annotations

import os
from functools import lru_cache
from typing import Optional, Set
from pathlib import Path

# ---------------------------------------------------------------------
# Hardening constants
# ---------------------------------------------------------------------

_MAX_SYMLINK_DEPTH = 40           # prevent extremely deep chains
_MAX_COMPONENT_LENGTH = 255      # POSIX file-name limit

# ---------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------

def _is_within_rootfs(target: str, rootfs_path: str) -> bool:
    """
    Check whether *target* is located inside *rootfs_path*.

    Both paths are first converted to absolute form; os.path.commonpath
    returns the shared prefix.  If the shared prefix equals rootfs_path,
    target is considered inside the container mount.
    """
    root_abs = os.path.abspath(rootfs_path)
    tgt_abs = os.path.abspath(target)
    common = os.path.commonpath([root_abs, tgt_abs])
    return common == root_abs

def _validate_component(name: str) -> None:
    """Raise if *name* is an overlong path component (ReDoS protection)."""
    if len(name) > _MAX_COMPONENT_LENGTH:
        raise RuntimeError(f"path component too long: {name!r}")

# ---------------------------------------------------------------------
# Core resolving logic
# ---------------------------------------------------------------------

def _resolve_recursive(
    path: str,
    rootfs_path: str,
    _seen: Optional[Set[str]] = None,
    _depth: int = 0,
) -> str:
    """
    Internal recursive resolver.

    Parameters
    ----------
    path : str
        The path that may be a symlink.
    rootfs_path : str
        The root of the mounted filesystem image.
    _seen : set[str] | None
        Tracks visited paths to detect loops.
    _depth : int
        Current recursion depth, used to enforce _MAX_SYMLINK_DEPTH.

    Returns
    -------
    str
        The fully resolved absolute path located inside rootfs_path.

    Raises
    ------
    RuntimeError
        If a loop is detected, the chain exceeds _MAX_SYMLINK_DEPTH, or
        the resolution escapes rootfs_path.
    """
    if _depth > _MAX_SYMLINK_DEPTH:
        raise RuntimeError("symlink chain exceeds maximum depth")

    _seen = _seen or set()
    if path in _seen:
        raise RuntimeError(f"symlink loop detected at: {path}")

    _seen.add(path)

    if not os.path.islink(path):
        if not _is_within_rootfs(path, rootfs_path):
            raise RuntimeError("path escapes rootfs boundary")
        return path

    target = os.readlink(path)

    # Validate every component to mitigate pathological inputs
    for part in target.split(os.sep):
        if part not in ("", ".", ".."):
            _validate_component(part)

    if os.path.isabs(target):
        next_path = os.path.normpath(os.path.join(rootfs_path, target.lstrip("/")))
    else:
        next_path = os.path.normpath(os.path.join(os.path.dirname(path), target))

    if not _is_within_rootfs(next_path, rootfs_path):
        raise RuntimeError("symlink resolves outside rootfs")

    return _resolve_recursive(next_path, rootfs_path, _seen, _depth + 1)

def _resolve_symlink(path: str, rootfs_path: str) -> str:
    """
    Resolve a single path (non-cached).

    Always verifies the final result stays within rootfs_path.
    """
    abs_path = os.path.abspath(path)
    return _resolve_recursive(abs_path, rootfs_path)

# ---------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------

@lru_cache(maxsize=2048)
def resolve_path(path: str, rootfs_path: str) -> str:
    """
    Cached symlink resolver suitable for scanners.

    Caches both the positive resolution and any RuntimeError raised,
    so repeated look-ups do not hit the filesystem again.
    """
    return _resolve_symlink(path, rootfs_path)

def safe_join(rootfs: str | Path, *parts: str | Path) -> Path:
    """
    Build an absolute path anchored at *rootfs*.

    If the resulting path escapes the rootfs boundary a ValueError
    is raised.
    """
    root = Path(rootfs).resolve()
    candidate = (root / Path(*parts)).resolve()
    if root == candidate or root in candidate.parents:
        return candidate
    raise ValueError(f"Unsafe path escape: {candidate}")
