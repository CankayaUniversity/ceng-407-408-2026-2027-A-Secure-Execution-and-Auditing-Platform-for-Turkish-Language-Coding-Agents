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


def test_mock_agent_adapter_reaches_gateway_audit(tmp_path):
    import socket
    import time
    from threading import Thread

    import uvicorn

    from agent.tool_adapter import SecureToolAdapter

    path = tmp_path / "audit.db"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(
            create_app(path), log_level="error", lifespan="on",
        ))
        thread = Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert server.started, "Gateway did not start."
            adapter = SecureToolAdapter(f"http://127.0.0.1:{port}")
            run = AgentLoop(MockLLM(), task_id="task-demo", adapter=adapter).run("README oku.")
            assert run.stop_reason == "gateway_error"
            assert run.error == "Gateway returned HTTP 501."
            assert run.tool_results == ()
            assert len(run.tool_calls) == 1
            call = run.tool_calls[0]
            events = AuditRepository(path).get_by_request_id(call.request_id)
            assert len(events) == 1
            assert events[0].event_type == "tool_call_received"
            assert events[0].metadata == {"task_id": call.task_id, "tool": call.tool}
        finally:
            server.should_exit = True
            thread.join(timeout=5)
        assert not thread.is_alive(), "Gateway did not stop."
