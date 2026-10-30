"""Immutable task scopes loaded by the trusted backend.

Repository location: src/secure_agent/tasks/scope.py
Permissions use exact workspace-relative paths, not globs or directory prefixes.
An empty permission set grants nothing. Grants never imply other grants.
This module validates scope configuration; it does not authorize or execute calls.
The registry binds scopes to tasks. Policy and executor checks remain mandatory.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Annotated, Self, TypeAlias

from pydantic import AfterValidator, Field, model_validator

from secure_agent.common.schemas import (
    ContractModel,
    NonEmptyText,
    ToolName,
    WorkspacePath,
)


def _canonical_scope_path(value: str) -> str:
    """Reject ambiguous path spellings and wildcard syntax in trusted grants."""
    if any(character in value for character in "*?[]"):
        raise ValueError("Scope paths must be exact paths without wildcard syntax.")
    if PurePosixPath(value).as_posix() != value:
        raise ValueError("Scope paths must use canonical POSIX spelling.")
    return value


def _file_scope_path(value: str) -> str:
    """Disallow the workspace root as a file grant without inspecting the disk."""
    if value == ".":
        raise ValueError("The workspace root cannot be used as a file grant.")
    return value


ScopePath: TypeAlias = Annotated[
    WorkspacePath,
    AfterValidator(_canonical_scope_path),
]

ScopeFilePath: TypeAlias = Annotated[
    ScopePath,
    AfterValidator(_file_scope_path),
]


class TaskScope(ContractModel):
    """Immutable permissions for one scope in one registered workspace.

    Python inputs must use frozenset; JSON inputs use arrays via
    TaskScope.model_validate_json(...). All permission sets default to empty.
    Write permission does not imply read permission. Listing is not recursive.
    A directory grant does not grant read or write access to its descendants.
    Frozen fields are not a sandbox; only trusted code may register scopes.
    """

    scope_id: NonEmptyText
    workspace_id: NonEmptyText
    allowed_tools: frozenset[ToolName] = Field(default_factory=frozenset)
    readable_files: frozenset[ScopeFilePath] = Field(default_factory=frozenset)
    writable_files: frozenset[ScopeFilePath] = Field(default_factory=frozenset)
    listable_directories: frozenset[ScopePath] = Field(default_factory=frozenset)
    allowed_test_profiles: frozenset[NonEmptyText] = Field(default_factory=frozenset)

    @model_validator(mode="after")
    def validate_grant_consistency(self) -> Self:
        """Reject resource grants whose corresponding tool is not enabled."""
        grants_by_tool = {
            "secure_list_files": self.listable_directories,
            "secure_read_file": self.readable_files,
            "secure_edit_file": self.writable_files,
            "secure_run_tests": self.allowed_test_profiles,
        }
        for tool, grants in grants_by_tool.items():
            if grants and tool not in self.allowed_tools:
                raise ValueError(f"Resource grants require '{tool}' in allowed_tools.")
        return self
