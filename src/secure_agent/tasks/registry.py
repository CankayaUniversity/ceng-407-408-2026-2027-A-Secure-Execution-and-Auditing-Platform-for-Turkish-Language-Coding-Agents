"""Trusted, in-memory task registry for the first prototype.

Repository location: src/secure_agent/tasks/registry.py
Load workspace IDs and scopes from trusted backend configuration at startup.
Expose registration only to trusted backend code, never as an agent tool.
The registry checks references, not caller identity or individual tool permissions.
Records are process-local and are lost on restart. Use one backend process.
The lock protects threads in this instance; it does not coordinate processes.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from threading import RLock
from types import MappingProxyType

from pydantic import TypeAdapter

from secure_agent.common.schemas import NonEmptyText, Task
from secure_agent.tasks.scope import TaskScope


class RegistryError(Exception):
    """Base class for registry-specific failures."""


class UnknownWorkspaceError(RegistryError):
    """The workspace ID is not present in trusted configuration."""


class UnknownScopeError(RegistryError):
    """The scope ID is not present in trusted configuration."""


class DuplicateScopeError(RegistryError):
    """Trusted configuration contains a duplicate scope ID."""


class ScopeWorkspaceMismatchError(RegistryError):
    """A task and its referenced scope belong to different workspaces."""


class DuplicateTaskError(RegistryError):
    """A task with the same ID has already been registered."""


class TaskNotFoundError(RegistryError):
    """No task with the requested ID has been registered."""


_ID_ADAPTER: TypeAdapter[NonEmptyText] = TypeAdapter(NonEmptyText)


class TaskRegistry:
    """Append-only task records with immutable startup scope configuration.

    Public methods keep storage details out of callers. A persistent backend
    can later implement register(), get(), and get_scope() with the same contract.
    Validated snapshots prevent normal callers from changing stored records
    through input or return values. This class is not a sandbox or auth service.
    """

    def __init__(
        self,
        *,
        workspace_ids: Iterable[str],
        scopes: Iterable[TaskScope],
    ) -> None:
        """Validate and snapshot trusted workspace IDs and scope definitions."""
        if isinstance(workspace_ids, (str, bytes)):
            raise TypeError("workspace_ids must be a collection, not a single string.")
        self._workspace_ids = frozenset(
            _ID_ADAPTER.validate_python(value, strict=True) for value in workspace_ids
        )
        scope_records: dict[str, TaskScope] = {}
        for candidate in scopes:
            scope = TaskScope.model_validate(candidate)
            if scope.workspace_id not in self._workspace_ids:
                raise UnknownWorkspaceError(f"Unknown workspace: {scope.workspace_id!r}")
            if scope.scope_id in scope_records:
                raise DuplicateScopeError(f"Duplicate scope ID: {scope.scope_id!r}")
            scope_records[scope.scope_id] = scope
        self._scopes: Mapping[str, TaskScope] = MappingProxyType(scope_records)
        self._tasks: dict[str, Task] = {}
        self._lock = RLock()

    def register(self, task: Task) -> Task:
        """Register a validated task once; reject invalid or conflicting references."""
        validated = Task.model_validate(task)
        with self._lock:
            if validated.task_id in self._tasks:
                raise DuplicateTaskError(f"Task already exists: {validated.task_id!r}")
            if validated.workspace_id not in self._workspace_ids:
                raise UnknownWorkspaceError(f"Unknown workspace: {validated.workspace_id!r}")
            scope = self._scopes.get(validated.scope_id)
            if scope is None:
                raise UnknownScopeError(f"Unknown scope: {validated.scope_id!r}")
            if scope.workspace_id != validated.workspace_id:
                raise ScopeWorkspaceMismatchError(
                    f"Scope {validated.scope_id!r} does not belong to "
                    f"workspace {validated.workspace_id!r}."
                )
            self._tasks[validated.task_id] = validated
            return Task.model_validate(validated)

    def get(self, task_id: str) -> Task:
        """Return a validated task snapshot; never create tasks during lookup."""
        validated_id = _ID_ADAPTER.validate_python(task_id, strict=True)
        with self._lock:
            try:
                task = self._tasks[validated_id]
            except KeyError as error:
                raise TaskNotFoundError(f"Unknown task: {validated_id!r}") from error
            return Task.model_validate(task)

    def get_scope(self, task_id: str) -> TaskScope:
        """Resolve the task's registered scope; do not accept a caller-supplied scope."""
        task = self.get(task_id)
        scope = self._scopes[task.scope_id]
        return TaskScope.model_validate(scope)
