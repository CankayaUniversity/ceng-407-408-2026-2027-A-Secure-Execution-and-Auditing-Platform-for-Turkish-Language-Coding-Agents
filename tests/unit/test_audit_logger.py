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

    run = AgentLoop(MockLLM(), task_id="task-demo").run("README.md dosyasÄ±nÄ± oku.")
    call = run.tool_calls[0]
    event = audit_logger.log_tool_call_received(call)
    assert event.metadata == {"task_id": call.task_id, "tool": call.tool}
    assert audit_repository.get_by_request_id(call.request_id) == [event]


@pytest.mark.parametrize("verdict", ["ALLOW", "DENY", "REVIEW"])
def test_security_decision_is_persisted(audit_repository, audit_logger, tool_call, verdict):
    from secure_agent.common.schemas import SecurityDecision

    decision = SecurityDecision(decision=verdict, reason_code="POLICY_TEST")
    event = audit_logger.log_security_decision(tool_call, decision)
    assert event.request_id == tool_call.request_id
    assert event.event_type == "policy_decision"
    assert event.metadata == {
        "task_id": tool_call.task_id,
        "tool": tool_call.tool,
        "arguments": {"path": "README.md"},
        "decision": verdict,
        "reason_code": "POLICY_TEST",
    }
    assert audit_repository.get_by_request_id(tool_call.request_id) == [event]


def test_edit_contents_are_not_logged(audit_logger):
    from secure_agent.common.schemas import SecurityDecision, parse_tool_call

    call = parse_tool_call({
        "request_id": "edit-001", "task_id": "task-001",
        "tool": "secure_edit_file",
        "arguments": {"path": "src/login.py", "content": "SECRET_TOKEN=private"},
    })
    event = audit_logger.log_security_decision(
        call, SecurityDecision(decision="DENY", reason_code="POLICY_DENIED"),
    )
    assert event.metadata["arguments"] == {"path": "src/login.py"}
    assert "SECRET_TOKEN" not in event.model_dump_json()
    assert call.arguments.content == "SECRET_TOKEN=private"


def test_invalid_decision_is_not_logged(audit_repository, audit_logger, tool_call):
    from secure_agent.common.schemas import SecurityDecision

    decision = SecurityDecision(decision="DENY", reason_code="POLICY_DENIED")
    invalid = decision.model_copy(update={"decision": "unknown"})
    with pytest.raises(ValidationError):
        audit_logger.log_security_decision(tool_call, invalid)
    assert audit_repository.get_by_request_id(tool_call.request_id) == []


def test_receipt_and_decision_keep_request_order(audit_repository, audit_logger, tool_call):
    from secure_agent.common.schemas import SecurityDecision

    receipt = audit_logger.log_tool_call_received(tool_call)
    decision = audit_logger.log_security_decision(
        tool_call, SecurityDecision(decision="DENY", reason_code="POLICY_DENIED"),
    )
    assert audit_repository.get_by_request_id(tool_call.request_id) == [receipt, decision]
