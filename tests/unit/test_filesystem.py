
"""Security tests for workspace-bound filesystem operations.

These tests verify path validation, file size restrictions,
symbolic link handling, and bounded filesystem operations.
"""

from pathlib import Path

import pytest

from secure_agent.execution.filesystem import (
    FileSizeLimitError,
    UnsafePathError,
    WorkspaceFileSystem,
)


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """Create an isolated workspace for filesystem tests."""
    root = tmp_path / "workspace"
    root.mkdir()
    return root


def test_authorized_read_and_edit(workspace: Path):
    """Read and modify a regular file inside the workspace."""
    target = workspace / "allowed.txt"
    target.write_text("Original content", encoding="utf-8")

    filesystem = WorkspaceFileSystem(workspace)

    assert filesystem.read_file("allowed.txt") == "Original content"

    filesystem.edit_file("allowed.txt", "Updated content")

    assert filesystem.read_file("allowed.txt") == "Updated content"


@pytest.mark.parametrize(
    "unsafe_path",
    [
        "../secret.txt",
        "src/../../secret.txt",
        "/etc/passwd",
        "src/../secret.txt",
        "src//file.txt",
        "C:\\secret.txt",
    ],
)
def test_path_traversal_rejected(workspace: Path, unsafe_path: str):
    """Reject unsafe and non-canonical workspace paths."""
    filesystem = WorkspaceFileSystem(workspace)

    with pytest.raises(UnsafePathError):
        filesystem.read_file(unsafe_path)


def test_oversized_file_read_rejected(workspace: Path):
    """Reject file reads exceeding the configured byte limit."""
    target = workspace / "large.txt"
    target.write_bytes(b"A" * 17)

    filesystem = WorkspaceFileSystem(
        workspace,
        max_file_bytes=16,
    )

    with pytest.raises(FileSizeLimitError):
        filesystem.read_file("large.txt")


def test_oversized_file_edit_rejected(workspace: Path):
    """Reject oversized replacements without modifying the file."""
    target = workspace / "allowed.txt"
    target.write_text("Original", encoding="utf-8")

    filesystem = WorkspaceFileSystem(
        workspace,
        max_file_bytes=16,
    )

    with pytest.raises(FileSizeLimitError):
        filesystem.edit_file("allowed.txt", "A" * 17)

    assert target.read_text(encoding="utf-8") == "Original"


def test_symlink_file_rejected(workspace: Path):
    """Prevent file access through a symbolic link."""
    outside = workspace.parent / "outside.txt"
    outside.write_text("Protected content", encoding="utf-8")

    link = workspace / "linked.txt"
    link.symlink_to(outside)

    filesystem = WorkspaceFileSystem(workspace)

    # The operating system may raise ELOOP for O_NOFOLLOW.
    with pytest.raises((OSError, UnsafePathError)):
        filesystem.read_file("linked.txt")

    assert outside.read_text(encoding="utf-8") == "Protected content"


def test_symlink_directory_rejected(workspace: Path):
    """Reject traversal through a symbolic-link directory."""
    outside = workspace.parent / "external"
    outside.mkdir()
    (outside / "secret.txt").write_text(
        "Protected", encoding="utf-8"
    )

    link = workspace / "linked_directory"
    link.symlink_to(outside, target_is_directory=True)

    filesystem = WorkspaceFileSystem(workspace)

    with pytest.raises((OSError, UnsafePathError)):
        filesystem.read_file("linked_directory/secret.txt")


def test_directory_entry_limit(workspace: Path):
    """Reject directory listings exceeding the configured limit."""
    for index in range(4):
        (workspace / f"file_{index}.txt").write_text(
            "Sample", encoding="utf-8"
        )

    filesystem = WorkspaceFileSystem(
        workspace,
        max_list_entries=3,
    )

    with pytest.raises(FileSizeLimitError):
        filesystem.list_files(".")


def test_empty_file_content_allowed(workspace: Path):
    """Allow empty replacement content for authorized regular files."""
    target = workspace / "empty.txt"
    target.write_text("Original", encoding="utf-8")

    filesystem = WorkspaceFileSystem(workspace)
    filesystem.edit_file("empty.txt", "")

    assert filesystem.read_file("empty.txt") == ""
