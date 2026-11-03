
"""Scope-aware tool dispatcher for the secure execution prototype.

The executor validates tool calls and enforces trusted task scope
permissions and verifies a single-use permit before dispatch. Authentication
and process isolation remain deployment responsibilities.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path

from secure_agent.common.schemas import (
    EditFileToolCall,
    ListFilesToolCall,
    ReadFileToolCall,
    RunTestsToolCall,
    parse_tool_call,
)
from secure_agent.execution.filesystem import WorkspaceFileSystem
from secure_agent.execution.test_runner import (
    TestRunner,
    TestRunResult,
)
from secure_agent.tasks.registry import TaskRegistry
from secure_agent.security.permit_verifier import PermitVerifier


class ExecutionDenied(PermissionError):
    """Raised when an operation violates its registered task scope."""


class Executor:
    """Dispatch validated tool calls using trusted task permissions."""

    def __init__(
        self,
        *,
        registry: TaskRegistry,
        workspace_roots: Mapping[str, str | Path],
        test_runners: Mapping[str, TestRunner] | None = None,
        permit_verifier: PermitVerifier | None = None,
    ) -> None:
        """Initialize workspace resources from trusted backend inputs."""
        self._registry = registry
        self._permit_verifier = permit_verifier

        # Resolve trusted workspace roots before dispatching operations.
        self._filesystems = {
            workspace_id: WorkspaceFileSystem(root)
            for workspace_id, root in workspace_roots.items()
        }

        # Test runners must be registered by trusted backend code.
        self._test_runners = dict(test_runners or {})

        for workspace_id, runner in self._test_runners.items():
            filesystem = self._filesystems.get(workspace_id)

            if filesystem is None:
                raise ValueError(
                    "Test runner references an unknown workspace."
                )

            if runner.workspace_root != filesystem.root:
                raise ValueError(
                    "Test runner workspace mismatch."
                )

    def execute(
        self,
        payload: object, *, permit: object = None,
        on_permit_verified: Callable[[], None] | None = None,
    ) -> list[str] | str | TestRunResult | None:
        """Validate and dispatch a tool call within its registered scope."""
        call = parse_tool_call(payload)
        if self._permit_verifier is None or permit is None:
            raise ExecutionDenied("Execution requires a verified permit.")
        self._permit_verifier.verify_and_consume(call, permit)
        if on_permit_verified is not None:
            on_permit_verified()

        task = self._registry.get(call.task_id)
        scope = self._registry.get_scope(task.task_id)

        if call.tool not in scope.allowed_tools:
            raise ExecutionDenied(
                f"Tool '{call.tool}' is not allowed for this task."
            )

        filesystem = self._filesystems.get(task.workspace_id)

        if filesystem is None:
            raise ExecutionDenied(
                "No trusted filesystem is configured for this workspace."
            )

        if isinstance(call, ListFilesToolCall):
            path = call.arguments.path

            if path not in scope.listable_directories:
                raise ExecutionDenied(
                    "Directory listing is not authorized."
                )

            return filesystem.list_files(path)

        if isinstance(call, ReadFileToolCall):
            path = call.arguments.path

            if path not in scope.readable_files:
                raise ExecutionDenied(
                    "File read is not authorized."
                )

            return filesystem.read_file(path)

        if isinstance(call, EditFileToolCall):
            path = call.arguments.path

            if path not in scope.writable_files:
                raise ExecutionDenied(
                    "File modification is not authorized."
                )

            filesystem.edit_file(
                path,
                call.arguments.content,
            )
            return None

        if isinstance(call, RunTestsToolCall):
            profile_id = call.arguments.profile_id

            if profile_id not in scope.allowed_test_profiles:
                raise ExecutionDenied(
                    "Test profile is not authorized."
                )

            runner = self._test_runners.get(task.workspace_id)

            if runner is None:
                raise ExecutionDenied(
                    "No trusted test runner is configured."
                )

            return runner.run(profile_id)

        raise ExecutionDenied("Unsupported tool operation.")
