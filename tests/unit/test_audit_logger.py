"""Verify logger events reach SQLite and failures remain visible."""

import sqlite3
from datetime import datetime, timezone
from uuid import UUID

import pytest
from pydantic import ValidationError



def test_logger_creates_and_persists_event(audit_repository, audit_logger, tool_call):
    before = datetime.now(timezone.utc)
    event = audit_logger.log_tool_call_received(tool_call)
    after = datetime.now(timezone.utc)
    assert UUID(event.event_id).version == 4
    assert event.request_id == tool_call.request_id
    assert event.metadata["task_id"] == tool_call.task_id
    assert event.metadata["tool"] == tool_call.tool
    assert event.event_type == "tool_call_received"
    assert event.timestamp.tzinfo == timezone.utc
    assert before <= event.timestamp <= after
    assert audit_repository.get_by_request_id(tool_call.request_id) == [event]


def test_each_receipt_gets_a_new_event_id(audit_repository, audit_logger, tool_call):
    logger = audit_logger
    first = logger.log_tool_call_received(tool_call)
    second = logger.log_tool_call_received(tool_call)
    assert first.event_id != second.event_id
    assert audit_repository.get_by_request_id(tool_call.request_id) == [first, second]


def test_invalid_call_is_not_recorded(audit_repository, audit_logger, tool_call):
    invalid = tool_call.model_copy(update={"request_id": ""})
    with pytest.raises(ValidationError):
        audit_logger.log_tool_call_received(invalid)
    assert audit_repository.get_by_request_id(tool_call.request_id) == []


def test_storage_failure_is_not_hidden(audit_repository, audit_logger, tool_call):
    with sqlite3.connect(audit_repository.database_path) as connection:
        connection.execute("DROP TABLE audit_events")
    with pytest.raises(sqlite3.OperationalError):
        audit_logger.log_tool_call_received(tool_call)


def test_existing_mock_agent_call_can_be_audited(audit_repository, audit_logger):
    from agent.agent_loop import AgentLoop, MockLLM

    run = AgentLoop(MockLLM(), task_id="task-demo").run("README.md dosyasını oku.")
    call = run.tool_calls[0]
    event = audit_logger.log_tool_call_received(call)
    assert event.metadata == {"task_id": call.task_id, "tool": call.tool}
    assert audit_repository.get_by_request_id(call.request_id) == [event]
