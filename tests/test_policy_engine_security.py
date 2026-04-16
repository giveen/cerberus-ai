from __future__ import annotations

from pathlib import Path

import pytest

from cerberus.verification.policy_engine import is_path_contained


def test_is_path_contained_denies_nonexistent_outside_path(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir(parents=True, exist_ok=True)

    suspicious_path = tmp_path / "outside" / "future" / "new_file.txt"

    # Must not raise for non-existent paths and should deny outside containment.
    assert is_path_contained(workspace_root, suspicious_path) is False


def test_is_path_contained_denies_symlink_to_nonexistent_outside_path(tmp_path: Path) -> None:
    workspace_root = tmp_path / "workspace"
    workspace_root.mkdir(parents=True, exist_ok=True)

    outside_target = tmp_path / "outside" / "future" / "new_file.txt"
    symlink_path = workspace_root / "escape_link"

    try:
        symlink_path.symlink_to(outside_target)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"symlink unsupported in this environment: {exc}")

    # Must resolve the symlink target with strict=False semantics and deny access.
    assert is_path_contained(workspace_root, symlink_path) is False
