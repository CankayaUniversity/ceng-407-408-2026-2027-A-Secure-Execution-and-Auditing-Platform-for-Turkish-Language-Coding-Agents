"""Shared data contracts for Secure Coding Agent v0.1.

Target: Python 3.11+, Pydantic v2.
Repository location: src/secure_agent/common/schemas.py

ToolCall is a union of four models discriminated by the `tool` field.
Use parse_tool_call() for Python dictionaries and parse_tool_call_json()
for JSON input. Do not use ToolCall.model_validate(...).

This module validates data structure. Task ownership, registry records,
file permissions, symlink/TOCTOU checks, signature verification, and nonce
consumption belong to the respective trusted services. Validation is not
authorization.
"""

from __future__ import annotations

import base64
from pathlib import PurePosixPath, PureWindowsPath
from typing import Annotated, Literal, TypeAlias

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
)


SCHEMA_VERSION = "0.1.0"


def _non_blank(value: str) -> str:
    """Reject blank values without modifying their contents."""
    if not value.strip():
        raise ValueError("Value must not be empty or contain only whitespace.")
    return value


NonEmptyText: TypeAlias = Annotated[
    str,
    Field(min_length=1),
    AfterValidator(_non_blank),
]


def _workspace_relative_path(value: str) -> str:
    """Validate POSIX relative path syntax without accessing the filesystem.

    The executor must separately check symlinks, mounts, actual workspace
    containment, and race conditions when opening files.
    Preserve the original path argument for permit binding; do not normalize it.
    """
    if "\x00" in value:
        raise ValueError("File path must not contain NUL characters.")
    if "\\" in value:
        raise ValueError("File paths must use the POSIX '/' separator.")
    if PurePosixPath(value).is_absolute() or PureWindowsPath(value).drive:
        raise ValueError("File path must be relative to the workspace.")
    if ".." in value.split("/"):
        raise ValueError("Parent directory traversal ('..') is not allowed.")
    return value


WorkspacePath: TypeAlias = Annotated[
    NonEmptyText,
    AfterValidator(_workspace_relative_path),
]

ToolName: TypeAlias = Literal[
    "secure_list_files",
    "secure_read_file",
    "secure_edit_file",
    "secure_run_tests",
]

DecisionValue: TypeAlias = Literal["ALLOW", "DENY", "REVIEW"]
ToolResultStatus: TypeAlias = Literal["success", "error", "denied", "review"]
TrustLevel: TypeAlias = Literal["untrusted"]


class ContractModel(BaseModel):
    """Base model that rejects unknown fields and incompatible data types.

    frozen=True prevents normal field assignment; it is not an authorization
    boundary. These models also use immutable field types.
    Do not use model_construct/model_copy(update=...) with untrusted input.
    """

    model_config = ConfigDict(
        extra="forbid",
        strict=True,
        frozen=True,
        validate_default=True,
        revalidate_instances="always",
    )


class Task(ContractModel):
    """Task registered by the trusted backend; agents cannot assign permissions.

    workspace_id and scope_id reference trusted records.
    The Task Registry validates their existence and association.
    """

    task_id: NonEmptyText
    user_goal: NonEmptyText
    workspace_id: NonEmptyText
    scope_id: NonEmptyText


class ListFilesArguments(ContractModel):
    """Relative directory path. Explicitly send '.' for the workspace root."""

    path: WorkspacePath


class ReadFileArguments(ContractModel):
    """Workspace-relative path of the text file to read."""

    path: WorkspacePath


class EditFileArguments(ContractModel):
    """Complete replacement file contents, not a patch; empty text is valid.

    Preserve whitespace and line endings in content.
    The executor enforces size limits and write permissions.
    """

    path: WorkspacePath
    content: str


class RunTestsArguments(ContractModel):
    """Test profile from trusted configuration; shell commands are not accepted.

    The backend validates profile_id existence and task authorization.
    """

    profile_id: NonEmptyText


class _ToolCallBase(ContractModel):
    request_id: NonEmptyText
    task_id: NonEmptyText


class ListFilesToolCall(_ToolCallBase):
    tool: Literal["secure_list_files"]
    arguments: ListFilesArguments


class ReadFileToolCall(_ToolCallBase):
    tool: Literal["secure_read_file"]
    arguments: ReadFileArguments


class EditFileToolCall(_ToolCallBase):
    tool: Literal["secure_edit_file"]
    arguments: EditFileArguments


class RunTestsToolCall(_ToolCallBase):
    tool: Literal["secure_run_tests"]
    arguments: RunTestsArguments


ToolCall: TypeAlias = Annotated[
    ListFilesToolCall | ReadFileToolCall | EditFileToolCall | RunTestsToolCall,
    Field(discriminator="tool"),
]

TOOL_CALL_ADAPTER: TypeAdapter[ToolCall] = TypeAdapter(ToolCall)


def parse_tool_call(payload: object) -> ToolCall:
    """Validate Python input; raise ValidationError on invalid data."""
    return TOOL_CALL_ADAPTER.validate_python(payload)


def parse_tool_call_json(payload: str | bytes | bytearray) -> ToolCall:
    """Validate JSON input; raise ValidationError on invalid data."""
    return TOOL_CALL_ADAPTER.validate_json(payload)


class SecurityDecision(ContractModel):
    """Decision Engine verdict. REVIEW does not authorize execution."""

    decision: DecisionValue
    reason_code: NonEmptyText


def _ed25519_signature(value: str) -> str:
    """Check encoding and length only; this is NOT cryptographic verification."""
    raw = base64.urlsafe_b64decode(value + "==")
    canonical = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    if len(raw) != 64 or canonical != value:
        raise ValueError(
            "Signature must be the canonical unpadded Base64url encoding of 64 bytes."
        )
    return value


Sha256Hex: TypeAlias = Annotated[
    str,
    Field(min_length=64, max_length=64, pattern=r"^[0-9a-f]{64}$"),
]

Ed25519Signature: TypeAlias = Annotated[
    str,
    Field(min_length=86, max_length=86, pattern=r"^[A-Za-z0-9_-]{86}$"),
    AfterValidator(_ed25519_signature),
]


class Permit(ContractModel):
    """Signed permit contract between the issuer and verifier.

    arguments_hash: SHA-256 of canonical argument JSON bytes, lowercase hex.
    signature: 64-byte Ed25519 signature encoded as unpadded Base64url.
    expires_at: timezone required; the issuer should produce UTC timestamps.
    nonce: generated securely by the issuer and consumed atomically by the verifier.

    The signed payload includes all fields EXCEPT signature. Canonicalization,
    hashing, signature verification, expiration, and replay checks are external.
    Python input requires a timezone-aware datetime for expires_at; use
    Permit.model_validate_json(...) to parse a timestamp string from JSON.
    """

    permit_id: NonEmptyText
    task_id: NonEmptyText
    tool: ToolName
    arguments_hash: Sha256Hex
    nonce: NonEmptyText
    expires_at: AwareDatetime
    signature: Ed25519Signature


class ToolResult(ContractModel):
    """Tool result: successful results also contain untrusted content.

    output: text; empty output is valid. For structured output, the executor
    serializes JSON as text. The trusted backend generates source identifiers;
    the provenance layer maintains the relationship between sources and results.
    """

    request_id: NonEmptyText
    status: ToolResultStatus
    output: str
    source_id: NonEmptyText
    trust_level: TrustLevel
