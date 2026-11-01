"""Exercise audit persistence against real temporary SQLite files."""

import sqlite3
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from secure_agent.audit.repository import AuditRepository
from secure_agent.common.schemas import AuditEvent


def make_event(event_id="event-001", request_id="req-001"):
    return AuditEvent(
        event_id=event_id,
        request_id=request_id,
        metadata={"task_id": "görev-001", "tool": "secure_read_file"},
        event_type="tool_call_received",
        timestamp=datetime(2026, 11, 2, tzinfo=timezone.utc),
    )


def test_event_survives_repository_reopening(tmp_path):
    path = tmp_path / "audit.db"
    event = make_event()
    AuditRepository(path).add(event)
    assert AuditRepository(path).get_by_request_id(event.request_id) == [event]


def test_lookup_returns_only_matching_events_in_insertion_order(audit_repository):
    first = make_event("event-002")
    second = make_event("event-001")
    audit_repository.add(first)
    audit_repository.add(make_event("other", "req-other"))
    audit_repository.add(second)
    assert audit_repository.get_by_request_id("req-001") == [first, second]


def test_unknown_request_returns_empty_list(audit_repository):
    assert audit_repository.get_by_request_id("missing") == []


def test_duplicate_event_does_not_replace_original_or_break_later_writes(audit_repository):
    original = make_event()
    audit_repository.add(original)
    with pytest.raises(sqlite3.IntegrityError):
        audit_repository.add(make_event(request_id="other"))
    second = make_event("event-002")
    audit_repository.add(second)
    assert audit_repository.get_by_request_id("req-001") == [original, second]
    assert audit_repository.get_by_request_id("other") == []


def test_request_id_is_not_sql(audit_repository):
    event = make_event(request_id="'; DROP TABLE audit_events; --")
    audit_repository.add(event)
    assert audit_repository.get_by_request_id(event.request_id) == [event]
    audit_repository.add(make_event("event-002"))
    assert len(audit_repository.get_by_request_id("req-001")) == 1


@pytest.mark.parametrize("request_id", ["", " ", 123])
def test_invalid_lookup_id_is_rejected(audit_repository, request_id):
    with pytest.raises(ValidationError):
        audit_repository.get_by_request_id(request_id)


def test_invalid_event_is_not_written(audit_repository):
    invalid = make_event().model_copy(update={"metadata": {"bad": object()}})
    with pytest.raises(ValidationError):
        audit_repository.add(invalid)
    assert audit_repository.get_by_request_id("req-001") == []
