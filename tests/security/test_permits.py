"""Day 4 permit checks at the executor boundary, using a recorded edit tool."""

from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import pytest

from secure_agent.common.schemas import Task, parse_tool_call
from secure_agent.execution.executor import Executor
from secure_agent.security.permit_verifier import PermitVerificationError, PermitVerifier
from secure_agent.tasks.registry import TaskRegistry
from secure_agent.tasks.scope import TaskScope


@pytest.fixture
def edit_call():
    return parse_tool_call({
        "request_id": "edit-1",
        "task_id": "task-1",
        "tool": "secure_edit_file",
        "arguments": {"path": "notes.txt", "content": "Approved text"},
    })


@pytest.fixture
def signed_edit(tmp_path, monkeypatch, permit_material, edit_call):
    key, issuer, _ = permit_material
    permit = issuer.issue(edit_call)
    clock = Mock(return_value=permit.expires_at - timedelta(microseconds=1))
    verifier = PermitVerifier(key.public_key(), tmp_path / "executor-nonces.db", clock=clock)

    scope = TaskScope(
        scope_id="edit-scope", workspace_id="workspace",
        allowed_tools=frozenset({"secure_edit_file"}),
        writable_files=frozenset({"notes.txt"}),
    )
    registry = TaskRegistry(workspace_ids=[scope.workspace_id], scopes=[scope])
    registry.register(Task(
        task_id=edit_call.task_id, user_goal="Update notes.txt",
        workspace_id=scope.workspace_id, scope_id=scope.scope_id,
    ))
    filesystem = Mock(spec=["edit_file"])
    monkeypatch.setattr(Executor, "_open_workspace", staticmethod(lambda root: filesystem))
    executor = Executor(
        registry=registry, workspace_roots={scope.workspace_id: tmp_path},
        permit_verifier=verifier,
    )
    return executor, permit, filesystem.edit_file, clock


def test_replayed_permit_dispatches_only_once(edit_call, signed_edit):
    executor, permit, edit_file, _ = signed_edit
    executor.execute(edit_call, permit=permit)
    retry = edit_call.model_copy(update={"request_id": "edit-retry"})
    with pytest.raises(PermitVerificationError, match="already used"):
        executor.execute(retry, permit=permit)
    edit_file.assert_called_once_with("notes.txt", "Approved text")


@pytest.mark.parametrize("changes", [
    pytest.param({"task_id": "other-task"}, id="task"),
    pytest.param({"tool": "secure_read_file", "arguments": {"path": "notes.txt"}}, id="tool"),
    pytest.param({"arguments": {"path": "notes.txt", "content": "Unapproved replacement"}},
                 id="edit-content"),
])
def test_permit_rejects_a_different_operation(edit_call, signed_edit, changes):
    executor, permit, edit_file, _ = signed_edit
    changed_call = {**edit_call.model_dump(), **changes}
    with pytest.raises(PermitVerificationError, match="does not match"):
        executor.execute(changed_call, permit=permit)
    edit_file.assert_not_called()
    executor.execute(edit_call, permit=permit)
    edit_file.assert_called_once_with("notes.txt", "Approved text")


@pytest.mark.parametrize("overdue", [timedelta(0), timedelta(microseconds=1)])
def test_expired_permit_blocks_dispatch(edit_call, signed_edit, overdue):
    executor, permit, edit_file, clock = signed_edit
    clock.return_value = permit.expires_at + overdue
    with pytest.raises(PermitVerificationError, match="expired"):
        executor.execute(edit_call, permit=permit)
    edit_file.assert_not_called()


@pytest.mark.parametrize("tampered_fields", [
    pytest.param({"signature": "A" * 86}, id="forged-signature"),
    pytest.param({"expires_at": datetime.max.replace(tzinfo=timezone(-timedelta(hours=1)))},
                 id="expiry-outside-utc-range"),
])
def test_invalid_permit_preserves_nonce(edit_call, signed_edit, tampered_fields):
    executor, permit, edit_file, _ = signed_edit
    tampered_permit = {**permit.model_dump(), **tampered_fields}
    with pytest.raises(PermitVerificationError, match="signature or payload"):
        executor.execute(edit_call, permit=tampered_permit)
    edit_file.assert_not_called()
    executor.execute(edit_call, permit=permit)
    edit_file.assert_called_once_with("notes.txt", "Approved text")
