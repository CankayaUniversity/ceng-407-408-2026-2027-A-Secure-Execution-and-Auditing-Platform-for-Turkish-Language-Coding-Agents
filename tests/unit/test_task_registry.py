"""Unit tests for immutable task scopes and the trusted in-memory registry."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from pydantic import ValidationError

from secure_agent.common.schemas import Task, parse_tool_call
from secure_agent.tasks.registry import (
    DuplicateScopeError,
    DuplicateTaskError,
    ScopeWorkspaceMismatchError,
    TaskNotFoundError,
    TaskRegistry,
    UnknownScopeError,
    UnknownWorkspaceError,
)
from secure_agent.tasks.scope import TaskScope


PERMISSION_FIELDS = (
    "allowed_tools",
    "readable_files",
    "writable_files",
    "listable_directories",
    "allowed_test_profiles",
)


@pytest.fixture
def scope_data():
    """Return fresh trusted configuration for each test."""
    return {
        "scope_id": "scope-login-fix",
        "workspace_id": "workspace-demo",
        "allowed_tools": frozenset({
            "secure_list_files", "secure_read_file", "secure_edit_file", "secure_run_tests",
        }),
        "readable_files": frozenset({"README.md", "src/login.py", "tests/test_login.py"}),
        "writable_files": frozenset({"src/login.py"}),
        "listable_directories": frozenset({".", "src", "tests"}),
        "allowed_test_profiles": frozenset({"unit"}),
    }


@pytest.fixture
def sample_scope(scope_data):
    return TaskScope.model_validate(scope_data)


@pytest.fixture
def sample_task():
    return Task(
        task_id="task-001",
        user_goal="Giriş kontrolündeki hatayı düzelt; çğıöşü İ.",
        workspace_id="workspace-demo",
        scope_id="scope-login-fix",
    )


@pytest.fixture
def registry(sample_scope):
    return TaskRegistry(
        workspace_ids={"workspace-demo", "workspace-other"},
        scopes=[sample_scope],
    )


def test_scope_defaults_grant_nothing():
    scope = TaskScope(scope_id="scope-empty", workspace_id="workspace-demo")
    for field in PERMISSION_FIELDS:
        assert getattr(scope, field) == frozenset()


def test_scope_json_round_trip_preserves_immutable_permissions(sample_scope):
    restored = TaskScope.model_validate_json(sample_scope.model_dump_json())
    assert restored == sample_scope
    for field in PERMISSION_FIELDS:
        assert isinstance(getattr(restored, field), frozenset)


@pytest.mark.parametrize("value", [[], set(), tuple()])
def test_python_permission_collections_require_frozenset(scope_data, value):
    scope_data["readable_files"] = value
    with pytest.raises(ValidationError):
        TaskScope.model_validate(scope_data)


@pytest.mark.parametrize(
    "tool",
    ["secure_list_files", "secure_read_file", "secure_edit_file", "secure_run_tests"],
)
def test_resource_grants_require_the_corresponding_tool(scope_data, tool):
    scope_data["allowed_tools"] -= frozenset({tool})
    with pytest.raises(ValidationError):
        TaskScope.model_validate(scope_data)


@pytest.mark.parametrize("field", ["readable_files", "writable_files"])
@pytest.mark.parametrize(
    "path",
    [".", "../secret.txt", "/etc/passwd", "src/./login.py", "src//login.py",
     "src/", "src/*.py", "src/login?.py", "src/[ab].py"],
)
def test_file_grants_reject_unsafe_or_ambiguous_paths(scope_data, field, path):
    scope_data[field] = frozenset({path})
    with pytest.raises(ValidationError):
        TaskScope.model_validate(scope_data)


def test_write_and_listing_grants_do_not_create_read_permissions():
    scope = TaskScope(
        scope_id="scope-limited",
        workspace_id="workspace-demo",
        allowed_tools=frozenset({"secure_edit_file", "secure_list_files"}),
        writable_files=frozenset({"src/login.py"}),
        listable_directories=frozenset({"src"}),
    )
    assert scope.readable_files == frozenset()
    assert "src/nested" not in scope.listable_directories


def test_scope_preserves_turkish_file_names(scope_data):
    scope_data["readable_files"] = frozenset({"src/giriş.py"})
    scope = TaskScope.model_validate(scope_data)
    restored = TaskScope.model_validate_json(scope.model_dump_json())
    assert restored.readable_files == frozenset({"src/giriş.py"})


@pytest.mark.parametrize("field, value", [
    ("allowed_tools", frozenset({"shell"})),
    ("allowed_test_profiles", frozenset({" "})),
    ("scope_id", ""), ("workspace_id", " "), ("admin", True),
])
def test_invalid_scope_configuration_is_rejected(scope_data, field, value):
    scope_data[field] = value
    with pytest.raises(ValidationError):
        TaskScope.model_validate(scope_data)


def test_task_registration_and_lookup_preserve_data(registry, sample_task):
    registered = registry.register(sample_task)
    fetched = registry.get(sample_task.task_id)
    assert registered == sample_task
    assert fetched == sample_task
    assert fetched.user_goal == sample_task.user_goal
    assert registered is not sample_task
    assert fetched is not registered


def test_scope_is_resolved_from_the_registered_task(registry, sample_task, sample_scope):
    registry.register(sample_task)
    call = parse_tool_call({
        "request_id": "req-001", "task_id": sample_task.task_id,
        "tool": "secure_read_file", "arguments": {"path": "src/login.py"},
    })
    resolved = registry.get_scope(call.task_id)
    assert resolved == sample_scope
    assert resolved is not sample_scope


@pytest.mark.parametrize("method", ["get", "get_scope"])
@pytest.mark.parametrize("task_id", ["task-missing", "scope-login-fix"])
def test_unknown_task_ids_are_rejected(registry, method, task_id):
    with pytest.raises(TaskNotFoundError):
        getattr(registry, method)(task_id)


def test_duplicate_task_cannot_overwrite_the_existing_record(registry, sample_task):
    registry.register(sample_task)
    replacement = Task(**{
        **sample_task.model_dump(), "user_goal": "Replace the original goal",
    })
    with pytest.raises(DuplicateTaskError):
        registry.register(replacement)
    assert registry.get(sample_task.task_id) == sample_task


@pytest.mark.parametrize("field, value, expected_error", [
    ("workspace_id", "workspace-missing", UnknownWorkspaceError),
    ("scope_id", "scope-missing", UnknownScopeError),
    ("workspace_id", "workspace-other", ScopeWorkspaceMismatchError),
])
def test_invalid_references_never_create_partial_records(
    registry, sample_task, field, value, expected_error,
):
    invalid = Task(**{**sample_task.model_dump(), field: value})
    with pytest.raises(expected_error):
        registry.register(invalid)
    with pytest.raises(TaskNotFoundError):
        registry.get(sample_task.task_id)
    registry.register(sample_task)
    assert registry.get(sample_task.task_id) == sample_task


def test_startup_rejects_scopes_for_unknown_workspaces(sample_scope):
    with pytest.raises(UnknownWorkspaceError):
        TaskRegistry(workspace_ids={"workspace-other"}, scopes=[sample_scope])


@pytest.mark.parametrize("workspace_id", ["workspace-demo", "workspace-other"])
def test_startup_rejects_duplicate_scope_ids(sample_scope, workspace_id):
    duplicate = TaskScope(**{
        **sample_scope.model_dump(), "workspace_id": workspace_id,
    })
    with pytest.raises(DuplicateScopeError):
        TaskRegistry(
            workspace_ids={"workspace-demo", "workspace-other"},
            scopes=[sample_scope, duplicate],
        )


@pytest.mark.parametrize("workspace_ids, expected_error", [
    ("workspace-demo", TypeError), (b"workspace-demo", TypeError),
    ([""], ValidationError), ([" "], ValidationError),
    ([42], ValidationError), ([None], ValidationError),
])
def test_startup_rejects_invalid_workspace_configuration(workspace_ids, expected_error):
    with pytest.raises(expected_error):
        TaskRegistry(workspace_ids=workspace_ids, scopes=[])


@pytest.mark.parametrize("method", ["get", "get_scope"])
@pytest.mark.parametrize("task_id", ["", " \t\n", 42, None])
def test_lookup_requires_non_blank_string_ids(registry, method, task_id):
    with pytest.raises(ValidationError):
        getattr(registry, method)(task_id)


def test_returned_models_reject_normal_permission_changes(registry, sample_task):
    registry.register(sample_task)
    task = registry.get(sample_task.task_id)
    scope = registry.get_scope(sample_task.task_id)
    with pytest.raises(ValidationError):
        task.scope_id = "admin"
    with pytest.raises(ValidationError):
        scope.readable_files = frozenset({".env"})
    with pytest.raises(AttributeError):
        scope.readable_files.add(".env")
    assert ".env" not in registry.get_scope(sample_task.task_id).readable_files


def test_startup_copies_caller_owned_collections(sample_scope, sample_task):
    workspace_ids = {"workspace-demo"}
    scopes = [sample_scope]
    local = TaskRegistry(workspace_ids=workspace_ids, scopes=scopes)
    workspace_ids.add("workspace-added")
    scopes.append(TaskScope(scope_id="scope-added", workspace_id="workspace-demo"))
    for changes, expected_error in [
        ({"workspace_id": "workspace-added"}, UnknownWorkspaceError),
        ({"scope_id": "scope-added"}, UnknownScopeError),
    ]:
        task = Task(**{**sample_task.model_dump(), **changes})
        with pytest.raises(expected_error):
            local.register(task)
    local.register(sample_task)
    assert local.get(sample_task.task_id) == sample_task


def test_input_models_do_not_expose_stored_records(sample_scope, sample_task):
    local = TaskRegistry(workspace_ids={"workspace-demo"}, scopes=[sample_scope])
    local.register(sample_task)
    # Deliberately bypass frozen assignment to verify defensive copies.
    object.__setattr__(sample_task, "scope_id", "admin")
    object.__setattr__(sample_scope, "readable_files", frozenset({".env"}))
    assert local.get("task-001").scope_id == "scope-login-fix"
    assert ".env" not in local.get_scope("task-001").readable_files


def test_returned_models_do_not_expose_stored_records(registry, sample_task):
    registered = registry.register(sample_task)
    fetched = registry.get(sample_task.task_id)
    scope = registry.get_scope(sample_task.task_id)
    # Mutate caller-owned snapshots, never the registry's private attributes.
    object.__setattr__(registered, "scope_id", "admin")
    object.__setattr__(fetched, "user_goal", "Changed outside the registry")
    object.__setattr__(scope, "readable_files", frozenset({".env"}))
    assert registry.get(sample_task.task_id) == sample_task
    assert ".env" not in registry.get_scope(sample_task.task_id).readable_files


def test_registry_revalidates_models_created_without_validation(sample_scope, sample_task):
    invalid_task = sample_task.model_copy(update={"task_id": ""})
    local = TaskRegistry(workspace_ids={"workspace-demo"}, scopes=[sample_scope])
    with pytest.raises(ValidationError):
        local.register(invalid_task)
    invalid_scope = sample_scope.model_copy(update={"allowed_tools": frozenset()})
    with pytest.raises(ValidationError):
        TaskRegistry(workspace_ids={"workspace-demo"}, scopes=[invalid_scope])
    local.register(sample_task)
    assert local.get(sample_task.task_id) == sample_task


def test_registry_instances_do_not_share_task_storage(sample_scope, sample_task):
    first = TaskRegistry(workspace_ids={"workspace-demo"}, scopes=[sample_scope])
    second = TaskRegistry(workspace_ids={"workspace-demo"}, scopes=[sample_scope])
    first.register(sample_task)
    with pytest.raises(TaskNotFoundError):
        second.get(sample_task.task_id)


def test_empty_registry_cannot_register_a_task(sample_task):
    empty = TaskRegistry(workspace_ids=[], scopes=[])
    with pytest.raises(UnknownWorkspaceError):
        empty.register(sample_task)


def test_concurrent_registration_of_one_task_id_has_exactly_one_winner(registry, sample_task):
    workers = 12
    barrier = Barrier(workers)

    def attempt(index):
        candidate = Task(**{
            **sample_task.model_dump(), "user_goal": f"Concurrent goal {index}",
        })
        barrier.wait(timeout=10)
        try:
            return registry.register(candidate).user_goal
        except DuplicateTaskError:
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(attempt, range(workers)))
    winners = [goal for goal in results if goal is not None]
    assert len(winners) == 1
    assert results.count(None) == workers - 1
    assert registry.get(sample_task.task_id).user_goal == winners[0]
