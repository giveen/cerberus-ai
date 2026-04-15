from pathlib import Path

import pytest

from cai.tools.reconnaissance.filesystem import PathGuard


def test_path_guard_write_rejects_outside_workspace(tmp_path: Path):
    workspace_root = (tmp_path / "workspace").resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)

    guard = PathGuard(workspace_root, lambda *_: None)
    outside_target = (tmp_path / "outside" / "findings.txt").resolve()

    with pytest.raises(PermissionError, match="Boundary Violation"):
        guard.validate_path(outside_target, action="write_file", mode="write")


def test_path_guard_write_rejects_tmpdir_even_when_absolute(tmp_path: Path):
    workspace_root = (tmp_path / "workspace").resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)

    guard = PathGuard(workspace_root, lambda *_: None)
    tmp_target = Path("/tmp/cerebro-write-should-fail.txt")

    with pytest.raises(PermissionError, match="Boundary Violation"):
        guard.validate_path(tmp_target, action="write_file", mode="write")


def test_path_guard_write_allows_workspace_relative_path(tmp_path: Path):
    workspace_root = (tmp_path / "workspace").resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)

    guard = PathGuard(workspace_root, lambda *_: None)

    resolved = guard.validate_path("reports/findings.txt", action="write_file", mode="write")
    assert resolved == (workspace_root / "reports" / "findings.txt").resolve()


def test_path_guard_read_allows_tmpdir_for_compatibility(tmp_path: Path):
    workspace_root = (tmp_path / "workspace").resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)

    guard = PathGuard(workspace_root, lambda *_: None)
    resolved = guard.validate_path(Path("/tmp"), action="read_file", mode="read")

    assert resolved == Path("/tmp").resolve()
