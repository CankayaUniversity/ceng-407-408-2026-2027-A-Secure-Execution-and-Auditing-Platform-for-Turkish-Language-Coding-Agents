"""Mock agent requests reach persistent audit storage through HTTP."""

import sqlite3

from fastapi.testclient import TestClient

from agent.agent_loop import AgentLoop, MockLLM
from secure_agent.audit.repository import AuditRepository
from secure_agent.gateway.main import create_app


def test_mock_agent_request_is_audited_and_survives_restart(tmp_path):
    path = tmp_path / "data" / "audit.db"
    call = AgentLoop(MockLLM(), task_id="task-demo").run("README oku.").tool_calls[0]
    with TestClient(create_app(path)) as client:
        assert client.get("/health").json() == {"status": "ok"}
        response = client.post("/tools/execute", json=call.model_dump(mode="json"))
        # Receipt is logged, but execution remains disabled.
        assert response.status_code == 501
    with TestClient(create_app(path)):
        events = AuditRepository(path).get_by_request_id(call.request_id)
        assert len(events) == 1
        assert events[0].metadata == {"task_id": call.task_id, "tool": call.tool}
        assert events[0].event_type == "tool_call_received"


def test_invalid_request_returns_422_without_audit(tmp_path):
    path = tmp_path / "audit.db"
    with TestClient(create_app(path)) as client:
        response = client.post("/tools/execute", json={"request_id": "bad"})
        assert response.status_code == 422
    assert AuditRepository(path).get_by_request_id("bad") == []


def test_audit_failure_returns_503_not_success(tmp_path, tool_call):
    path = tmp_path / "audit.db"
    with TestClient(create_app(path)) as client:
        with sqlite3.connect(path) as connection:
            connection.execute("DROP TABLE audit_events")
        response = client.post("/tools/execute", json=tool_call.model_dump(mode="json"))
        assert response.status_code == 503
        assert response.json() == {"detail": "Audit storage is unavailable."}
