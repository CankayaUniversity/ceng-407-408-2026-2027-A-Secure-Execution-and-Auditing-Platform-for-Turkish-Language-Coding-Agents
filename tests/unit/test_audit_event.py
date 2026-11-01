"""Audit contract validation; persistence is tested separately."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from secure_agent.common.schemas import AuditEvent, parse_tool_call


def event_data():
    call = parse_tool_call({
        "request_id": "req-001",
        "task_id": "task-001",
        "tool": "secure_read_file",
        "arguments": {"path": "README.md"},
    })
    return {
        "event_id": "event-001",
        "request_id": call.request_id,
        "metadata": {"task_id": call.task_id, "tool": call.tool},
        "event_type": "tool_call_received",
        "timestamp": datetime(2026, 11, 2, tzinfo=timezone.utc),
    }


def test_event_preserves_request_fields_and_json_timestamp():
    event = AuditEvent(**event_data())
    assert event.request_id == "req-001"
    assert event.metadata["task_id"] == "task-001"
    assert event.metadata["tool"] == "secure_read_file"
    assert AuditEvent.model_validate_json(event.model_dump_json()) == event


@pytest.mark.parametrize("field,value", [
    ("event_id", " "),
    ("request_id", ""),
    ("metadata", []),
    ("metadata", {"bad": object()}),
    ("event_type", " "),
    ("timestamp", datetime(2026, 11, 2)),
    ("arguments", {"path": "README.md"}),
])
def test_invalid_event_is_rejected(field, value):
    data = event_data()
    data[field] = value
    with pytest.raises(ValidationError):
        AuditEvent(**data)


@pytest.mark.parametrize("field", list(event_data()))
def test_all_event_fields_are_required(field):
    data = event_data()
    del data[field]
    with pytest.raises(ValidationError):
        AuditEvent(**data)


def test_event_supports_other_stages_and_json_metadata():
    data = event_data()
    data["event_type"] = "policy_decision"
    data["metadata"] = {"decision": "DENY", "score": 0.5,
                        "flags": ["risk", None], "details": {"allowed": False}}
    event = AuditEvent(**data)
    assert AuditEvent.model_validate_json(event.model_dump_json()) == event
