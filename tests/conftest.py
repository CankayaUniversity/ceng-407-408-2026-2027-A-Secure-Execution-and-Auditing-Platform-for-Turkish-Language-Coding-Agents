"""Shared audit fixtures; each test gets its own temporary database."""

import pytest

from secure_agent.audit.logger import AuditLogger
from secure_agent.audit.repository import AuditRepository
from secure_agent.common.schemas import parse_tool_call


@pytest.fixture
def audit_repository(tmp_path):
    return AuditRepository(tmp_path / "audit.db")


@pytest.fixture
def audit_logger(audit_repository):
    return AuditLogger(audit_repository)


@pytest.fixture
def tool_call():
    return parse_tool_call({
        "request_id": "req-001",
        "task_id": "task-001",
        "tool": "secure_read_file",
        "arguments": {"path": "README.md"},
    })
