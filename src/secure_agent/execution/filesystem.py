
"""Workspace-bound filesystem operations for the secure executor.

This module provides bounded text-file operations and rejects unsafe
relative paths and symbolic links. Authorization is enforced by the
trusted executor, not by this module.
"""

from __future__ import annotations

import os
import secrets
import stat
from contextlib import contextmanager
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Iterator


DEFAULT_MAX_FILE_BYTES = 1024 * 1024
DEFAULT_MAX_LIST_ENTRIES = 1000

_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK


class UnsafePathError(ValueError):
    """Raised when a path violates workspace safety requirements."""


class FileSizeLimitError(ValueError):
    """Raised when a file exceeds the configured byte limit."""


def validate_relative_path(
    path: str,
    *,
    allow_root: bool = False,
) -> tuple[str, ...]:
    """Validate a canonical workspace-relative POSIX path."""
    if not isinstance(path, str) or not path:
        raise UnsafePathError("Path must be a non-empty string.")

    if path == "." and allow_root:
        return ()

    if (
        "\x00" in path
        or "\\" in path
        or PurePosixPath(path).is_absolute()
        or PureWindowsPath(path).drive
    ):
        raise UnsafePathError("Invalid workspace-relative path.")

    parts = path.split("/")

    if any(part in ("", ".", "..") for part in parts):
        raise UnsafePathError("Unsafe or non-canonical path component.")

    return tuple(parts)


class WorkspaceFileSystem:
    """Perform bounded file operations within a trusted workspace root."""

    def __init__(
        self,
        workspace_root: str | Path,
        *,
        max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
        max_list_entries: int = DEFAULT_MAX_LIST_ENTRIES,
    ) -> None:
        if max_file_bytes <= 0 or max_list_entries <= 0:
            raise ValueError("Filesystem limits must be positive.")

        self.root = Path(workspace_root).resolve(strict=True)

        if not self.root.is_dir():
            raise ValueError("Workspace root must be a directory.")

        self.max_file_bytes = max_file_bytes
        self.max_list_entries = max_list_entries

    @contextmanager
    def _directory_fd(
        self,
        parts: tuple[str, ...],
    ) -> Iterator[int]:
        """Open workspace directories without following symbolic links."""
        fd = os.open(self.root, _DIRECTORY_FLAGS)

        try:
            for component in parts:
                next_fd = os.open(
                    component,
                    _DIRECTORY_FLAGS,
                    dir_fd=fd,
                )
                os.close(fd)
                fd = next_fd

            yield fd
        finally:
            os.close(fd)

    def list_files(self, path: str = ".") -> list[str]:
        """List immediate directory entries without recursive traversal."""
        parts = validate_relative_path(path, allow_root=True)

        with self._directory_fd(parts) as directory_fd:
            entries = os.listdir(directory_fd)

        if len(entries) > self.max_list_entries:
            raise FileSizeLimitError("Directory entry limit exceeded.")

        return sorted(entries)

    def read_file(self, path: str) -> str:
        """Read a bounded regular text file as UTF-8."""
        parts = validate_relative_path(path)

        with self._directory_fd(parts[:-1]) as directory_fd:
            fd = os.open(parts[-1], _FILE_FLAGS, dir_fd=directory_fd)

            try:
                info = os.fstat(fd)

                if not stat.S_ISREG(info.st_mode):
                    raise UnsafePathError("Only regular files are supported.")

                if info.st_size > self.max_file_bytes:
                    raise FileSizeLimitError("File size limit exceeded.")

                chunks = []
                total = 0

                while True:
                    chunk = os.read(
                        fd,
                        min(65536, self.max_file_bytes + 1 - total),
                    )

                    if not chunk:
                        break

                    total += len(chunk)

                    if total > self.max_file_bytes:
                        raise FileSizeLimitError("File size limit exceeded.")

                    chunks.append(chunk)

                return b"".join(chunks).decode("utf-8")

            finally:
                os.close(fd)

    def edit_file(self, path: str, content: str) -> None:
        """Atomically replace an existing regular text file."""
        parts = validate_relative_path(path)

        if not isinstance(content, str):
            raise TypeError("File content must be a string.")

        encoded = content.encode("utf-8")

        if len(encoded) > self.max_file_bytes:
            raise FileSizeLimitError("Replacement content exceeds the limit.")

        with self._directory_fd(parts[:-1]) as directory_fd:
            existing_fd = os.open(
                parts[-1],
                _FILE_FLAGS,
                dir_fd=directory_fd,
            )

            try:
                info = os.fstat(existing_fd)

                if not stat.S_ISREG(info.st_mode):
                    raise UnsafePathError("Only regular files can be edited.")

                if info.st_size > self.max_file_bytes:
                    raise FileSizeLimitError("Existing file exceeds the limit.")
            finally:
                os.close(existing_fd)

            temporary_name = f".executor-{secrets.token_hex(16)}.tmp"
            temporary_fd = None

            try:
                temporary_fd = os.open(
                    temporary_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=directory_fd,
                )

                written = 0
                while written < len(encoded):
                    written += os.write(temporary_fd, encoded[written:])

                os.fsync(temporary_fd)
                os.close(temporary_fd)
                temporary_fd = None

                os.replace(
                    temporary_name,
                    parts[-1],
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                )
            finally:
                if temporary_fd is not None:
                    os.close(temporary_fd)

                try:
                    os.unlink(temporary_name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
