"""Filesystem helpers & small parsing utilities."""

from __future__ import annotations

import fnmatch
import os


def split_csv(value: str | None) -> tuple[str, ...] | None:
    """Split a comma-separated include/exclude list."""
    if value is None:
        return None
    parts = tuple(p.strip() for p in value.split(",") if p.strip())
    return parts or None


def matches_any(patterns: tuple[str, ...] | None, candidate: str) -> bool:
    """True if *candidate* matches any fnmatch pattern (path or basename)."""
    if not patterns:
        return False
    for pat in patterns:
        if fnmatch.fnmatch(candidate, pat) or fnmatch.fnmatch(os.path.basename(candidate), pat):
            return True
    return False


def normalize_excludes(
    exclude: tuple[str, ...] | None,
    default_exclude_dirs: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split user-supplied excludes into (extra dir names, glob list)."""
    if not exclude:
        return default_exclude_dirs, ()
    dir_names: list[str] = list(default_exclude_dirs)
    globs: list[str] = []
    for raw in exclude:
        e = raw.strip().rstrip("/")
        if not e:
            continue
        if any(ch in e for ch in "*?["):
            globs.append(e)
        else:
            dir_names.append(e)
    return tuple(dict.fromkeys(dir_names)), tuple(globs)


def should_skip_dir(name: str, exclude_dirs: tuple[str, ...]) -> bool:
    if name in exclude_dirs:
        return True
    if name.endswith(".egg-info"):
        return True
    return False
