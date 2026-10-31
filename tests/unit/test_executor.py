
"""Unit tests for scope-aware executor behavior."""

import pytest

from secure_agent.common.schemas import Task
from secure_agent.execution.executor import Executor, ExecutionDenied
from secure_agent.tasks.registry import TaskRegistry
from secure_agent.tasks.scope import TaskScope
from pydantic import ValidationError

from secure_agent.execution.test_runner import (
    TestRunner as FixedProfileRunner,
    TestRunResult as FixedProfileResult,
)


def test_authorized_read_edit_and_scope_rejection(tmp_path):
    """Allow explicitly granted operations and reject other files."""
    (tmp_path / "allowed.txt").write_text("Original", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("Private", encoding="utf-8")

    scope = TaskScope(
        scope_id="scope-demo",
        workspace_id="workspace-demo",
        allowed_tools=frozenset({
            "secure_list_files",
            "secure_read_file",
            "secure_edit_file",
        }),
        readable_files=frozenset({"allowed.txt"}),
        writable_files=frozenset({"allowed.txt"}),
        listable_directories=frozenset({"."}),
    )

    registry = TaskRegistry(
        workspace_ids=["workspace-demo"],
        scopes=[scope],
    )

    registry.register(Task(
        task_id="task-demo",
        user_goal="Update the permitted file.",
        workspace_id="workspace-demo",
        scope_id="scope-demo",
    ))

    executor = Executor(
        registry=registry,
        workspace_roots={"workspace-demo": tmp_path},
    )

    def call(tool, arguments):
        return {
            "request_id": "req-demo",
            "task_id": "task-demo",
            "tool": tool,
            "arguments": arguments,
        }

    assert executor.execute(
        call("secure_read_file", {"path": "allowed.txt"})
    ) == "Original"

    executor.execute(
        call(
            "secure_edit_file",
            {"path": "allowed.txt", "content": "Updated"},
        )
    )

    assert executor.execute(
        call("secure_read_file", {"path": "allowed.txt"})
    ) == "Updated"

    assert "allowed.txt" in executor.execute(
        call("secure_list_files", {"path": "."})
    )

    with pytest.raises(ExecutionDenied):
        executor.execute(
            call("secure_read_file", {"path": "secret.txt"})
        )

def test_authorized_fixed_profile_dispatch(tmp_path, monkeypatch):
    """Dispatch an authorized test profile without running subprocesses."""
    config_file = tmp_path / "test_profiles.yaml"
    config_file.write_text(
        "profiles:\n"
        "  unit:\n"
        "    timeout_seconds: 30\n",
        encoding="utf-8",
    )

    scope = TaskScope(
        scope_id="scope-tests",
        workspace_id="workspace-demo",
        allowed_tools=frozenset({"secure_run_tests"}),
        allowed_test_profiles=frozenset({"unit"}),
    )

    registry = TaskRegistry(
        workspace_ids=["workspace-demo"],
        scopes=[scope],
    )

    registry.register(
        Task(
            task_id="task-tests",
            user_goal="Run the approved unit tests.",
            workspace_id="workspace-demo",
            scope_id="scope-tests",
        )
    )

    runner = FixedProfileRunner(
        workspace_root=tmp_path,
        config_path=config_file,
    )

    executed_profiles = []

    def fake_run(profile_id):
        """Record the requested profile without executing test code."""
        executed_profiles.append(profile_id)

        return FixedProfileResult(
            profile_id=profile_id,
            exit_code=0,
            output="Mocked test execution succeeded.",
        )

    monkeypatch.setattr(runner, "run", fake_run)

    executor = Executor(
        registry=registry,
        workspace_roots={"workspace-demo": tmp_path},
        test_runners={"workspace-demo": runner},
    )

    request = {
        "request_id": "req-tests",
        "task_id": "task-tests",
        "tool": "secure_run_tests",
        "arguments": {"profile_id": "unit"},
    }

    result = executor.execute(request)

    assert result.profile_id == "unit"
    assert result.exit_code == 0
    assert executed_profiles == ["unit"]

    # Reject unapproved profile identifiers before dispatch.
    with pytest.raises(ExecutionDenied):
        executor.execute({
            **request,
            "arguments": {"profile_id": "unknown"},
        })

    # Reject agent-supplied command fields at the schema boundary.
    with pytest.raises(ValidationError):
        executor.execute({
            **request,
            "arguments": {
                "profile_id": "unit",
                "command": "arbitrary-command",
            },
        })

    assert executed_profiles == ["unit"]
