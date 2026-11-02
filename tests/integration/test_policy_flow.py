"""Real Policy, Audit and Executor checks on a temporary demo workspace.

Includes real HTTP adapter tests with explicit isolated demo execution.
"""

import shutil
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from secure_agent.audit.repository import AuditRepository
from secure_agent.common.schemas import Task, parse_tool_call
from secure_agent.execution.executor import Executor
from secure_agent.execution.test_runner import TestRunner as FixedTestRunner
from secure_agent.gateway.main import create_app
from secure_agent.security.policy_engine import PolicyEngine
from secure_agent.tasks.registry import TaskRegistry
from secure_agent.tasks.scope import TaskScope
from secure_agent.security.supervisor import SupervisorDecision


class AlignedSupervisor:
    def evaluate(self, **kwargs):
        return SupervisorDecision(verdict="ALIGNED", reason="Test assessment.",
                                  reason_code="SUPERVISOR_ALIGNED")


ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def policy_demo(tmp_path):
    workspace = tmp_path / "workspace"
    shutil.copytree(ROOT / "demo/sample_project", workspace)
    (workspace / ".env").write_text("DEMO_SECRET=private", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("outside", encoding="utf-8")
    scope = TaskScope(
        scope_id="login-scope", workspace_id="demo",
        allowed_tools=frozenset({"secure_read_file", "secure_edit_file",
                                 "secure_list_files", "secure_run_tests"}),
        listable_directories=frozenset({".", "src"}),
        allowed_test_profiles=frozenset({"unit"}),
        readable_files=frozenset({"README.md", "src/login.py", ".env"}),
        writable_files=frozenset({"src/login.py", ".env"}),
    )
    registry = TaskRegistry(workspace_ids={"demo"}, scopes=[scope])
    registry.register(Task(task_id="login-task", user_goal="Fix the login bug.",
                           workspace_id="demo", scope_id="login-scope"))
    policy = PolicyEngine(registry=registry,
                          model_path=ROOT / "configs/casbin_model.conf",
                          policy_path=ROOT / "configs/casbin_policy.csv")
    runner = FixedTestRunner(workspace, ROOT / "configs/test_profiles.yaml")
    executor = Executor(registry=registry, workspace_roots={"demo": workspace},
                        test_runners={"demo": runner})
    return workspace, policy, executor


@pytest.mark.parametrize("tool,path,expected", [
    ("secure_read_file", "src/login.py", "ALLOW"),
    ("secure_edit_file", "src/login.py", "ALLOW"),
    ("secure_read_file", "src/config.py", "DENY"),
    ("secure_edit_file", "src/config.py", "DENY"),
    ("secure_read_file", ".env", "DENY"),
    ("secure_edit_file", ".env", "DENY"),
])
def test_policy_decision_and_audit(policy_demo, audit_logger, audit_repository,
                                   tool, path, expected):
    workspace, policy, executor = policy_demo
    before = (workspace / path).read_bytes().decode("utf-8")
    arguments = {"path": path}
    if tool == "secure_edit_file":
        arguments["content"] = "# Demo update\n"
    call = parse_tool_call({"request_id": f"{tool}:{path}", "task_id": "login-task",
                            "tool": tool, "arguments": arguments})
    audit_logger.log_tool_call_received(call)
    decision = policy.evaluate(call)
    assert decision.decision == expected
    audit_logger.log_security_decision(call, decision)
    if expected == "ALLOW":
        output = executor.execute(call)
        if tool == "secure_read_file":
            assert output == before
        else:
            assert (workspace / path).read_bytes().decode("utf-8") == arguments["content"]
    else:
        assert (workspace / path).read_bytes().decode("utf-8") == before
    events = audit_repository.get_by_request_id(call.request_id)
    assert [event.event_type for event in events] == ["tool_call_received", "policy_decision"]
    assert events[1].metadata["decision"] == expected
    assert events[1].metadata["reason_code"] == decision.reason_code
    assert events[1].metadata["arguments"] == {"path": path}
    assert "DEMO_SECRET=private" not in events[1].model_dump_json()


def test_parent_traversal_is_rejected_before_policy(tmp_path, policy_demo):
    workspace, _, _ = policy_demo
    outside = workspace.parent / "secret.txt"
    with TestClient(create_app(tmp_path / "audit.db")) as client:
        response = client.post("/tools/execute", json={
            "request_id": "traversal", "task_id": "login-task",
            "tool": "secure_read_file", "arguments": {"path": "../secret.txt"},
        })
    assert response.status_code == 422
    assert outside.read_text(encoding="utf-8") == "outside"


@pytest.mark.parametrize("path,expected,status_code", [
    ("src/login.py", "ALLOW", 501),
    (".env", "DENY", 403),
    ("src/config.py", "DENY", 403),
])
def test_gateway_records_real_policy_verdict(tmp_path, policy_demo, path, expected, status_code):
    workspace, policy, _ = policy_demo
    database = tmp_path / "gateway-audit.db"
    before = (workspace / path).read_bytes()
    with TestClient(create_app(database, policy_engine=policy, supervisor=AlignedSupervisor())) as client:
        response = client.post("/tools/execute", json={
            "request_id": "gateway-policy", "task_id": "login-task",
            "tool": "secure_read_file", "arguments": {"path": path},
        })
    assert response.status_code == status_code
    events = AuditRepository(database).get_by_request_id("gateway-policy")
    expected_events = ["tool_call_received", "policy_decision"]
    if expected == "ALLOW":
        expected_events.append("supervisor_decision")
    assert [e.event_type for e in events] == expected_events + ["security_decision"]
    assert events[1].metadata["decision"] == expected
    assert events[1].metadata["reason_code"] == f"POLICY_{'ALLOWED' if expected == 'ALLOW' else 'DENIED'}"
    assert (workspace / path).read_bytes() == before


def test_gateway_policy_error_is_denied_and_audited(tmp_path, monkeypatch, policy_demo):
    _, policy, _ = policy_demo

    def fail(call):
        raise RuntimeError("Internal policy failure")

    monkeypatch.setattr(policy, "evaluate", fail)
    database = tmp_path / "failed-policy.db"
    with TestClient(create_app(database, policy_engine=policy, supervisor=AlignedSupervisor())) as client:
        response = client.post("/tools/execute", json={
            "request_id": "policy-error", "task_id": "login-task",
            "tool": "secure_read_file", "arguments": {"path": "src/login.py"},
        })
    assert response.status_code == 403
    event = AuditRepository(database).get_by_request_id("policy-error")[-1]
    assert event.metadata["decision"] == "DENY"
    assert event.metadata["reason_code"] == "POLICY_EVALUATION_ERROR"


@pytest.fixture
def live_demo_gateway(tmp_path, policy_demo, monkeypatch):
    import socket
    import time
    from threading import Thread
    from unittest.mock import Mock

    import uvicorn

    workspace, policy, executor = policy_demo
    execute = Mock(wraps=executor.execute)
    monkeypatch.setattr(executor, "execute", execute)
    database = tmp_path / "live-demo.db"
    app = create_app(database, policy_engine=policy, supervisor=AlignedSupervisor(), demo_executor=executor)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
        thread = Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert server.started
            yield workspace, database, execute, f"http://127.0.0.1:{port}"
        finally:
            server.should_exit = True
            thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.mark.parametrize("tool,path,allowed", [
    ("secure_read_file", "src/login.py", True),
    ("secure_edit_file", "src/login.py", True),
    ("secure_read_file", ".env", False),
    ("secure_edit_file", ".env", False),
])
def test_agent_gateway_policy_executor_flow(live_demo_gateway, tool, path, allowed):
    from agent.agent_loop import AgentLoop
    from agent.tool_adapter import SecureToolAdapter

    workspace, database, execute, url = live_demo_gateway
    before = (workspace / path).read_bytes()

    class MockModel:
        def propose(self, *, history, **kwargs):
            if history:
                return None
            arguments = {"path": path}
            if tool == "secure_edit_file":
                arguments["content"] = "# Isolated demo edit\n"
            return {"tool": tool, "arguments": arguments}

    run = AgentLoop(MockModel(), task_id="login-task",
                    adapter=SecureToolAdapter(url)).run("Fix login.")
    call = run.tool_calls[0]
    events = AuditRepository(database).get_by_request_id(call.request_id)
    assert events[1].metadata["decision"] == ("ALLOW" if allowed else "DENY")
    if allowed:
        execute.assert_called_once_with(call)
        assert run.stop_reason == "model_finished"
        assert len(run.tool_results) == 1
        result = run.tool_results[0]
        assert result.request_id == call.request_id
        assert result.status == "success"
        assert result.trust_level == "untrusted"
        assert [e.event_type for e in events] == [
            "tool_call_received", "policy_decision", "supervisor_decision",
            "security_decision", "tool_result",
        ]
        assert events[-1].metadata["source_id"] == result.source_id
        assert "output" not in events[-1].metadata
        if tool == "secure_read_file":
            assert result.output == before.decode("utf-8")
        else:
            assert (workspace / path).read_bytes() == b"# Isolated demo edit\n"
    else:
        execute.assert_not_called()
        assert run.stop_reason == "gateway_error"
        assert run.error == "Gateway returned HTTP 403."
        assert run.tool_results == ()
        assert len(events) == 3
        assert (workspace / path).read_bytes() == before


def test_demo_executor_requires_policy(tmp_path, policy_demo):
    _, _, executor = policy_demo
    with pytest.raises(ValueError, match="requires a trusted policy"):
        create_app(tmp_path / "audit.db", demo_executor=executor)


def test_audit_failure_prevents_demo_execution(tmp_path, policy_demo, monkeypatch):
    import sqlite3
    from unittest.mock import Mock

    _, policy, executor = policy_demo
    execute = Mock(wraps=executor.execute)
    monkeypatch.setattr(executor, "execute", execute)
    database = tmp_path / "audit-failure.db"
    with TestClient(create_app(database, policy_engine=policy, supervisor=AlignedSupervisor(), demo_executor=executor)) as client:
        with sqlite3.connect(database) as connection:
            connection.execute("DROP TABLE audit_events")
        response = client.post("/tools/execute", json={
            "request_id": "audit-failed", "task_id": "login-task",
            "tool": "secure_read_file", "arguments": {"path": "src/login.py"},
        })
    assert response.status_code == 503
    execute.assert_not_called()


@pytest.mark.parametrize("tool,arguments", [
    ("secure_list_files", {"path": "src"}),
    ("secure_run_tests", {"profile_id": "unit"}),
])
def test_demo_list_and_fixed_test_profile(tmp_path, policy_demo, tool, arguments):
    import json

    _, policy, executor = policy_demo
    database = tmp_path / "other-tools.db"
    with TestClient(create_app(database, policy_engine=policy, supervisor=AlignedSupervisor(), demo_executor=executor)) as client:
        response = client.post("/tools/execute", json={
            "request_id": tool, "task_id": "login-task", "tool": tool,
            "arguments": arguments,
        })
    assert response.status_code == 200
    result = response.json()
    assert result["status"] == "success"
    assert result["trust_level"] == "untrusted"
    if tool == "secure_list_files":
        assert "login.py" in json.loads(result["output"])
    else:
        assert "8 passed" in result["output"]
    assert AuditRepository(database).get_by_request_id(tool)[-1].metadata["status"] == "success"


@pytest.mark.parametrize("assessment", ["MISALIGNED", "UNCERTAIN", "missing", "timeout"])
def test_gateway_supervisor_cannot_authorize_uncertain_work(
    tmp_path, policy_demo, monkeypatch, assessment,
):
    from unittest.mock import Mock

    workspace, policy, executor = policy_demo
    execute = Mock(wraps=executor.execute)
    monkeypatch.setattr(executor, "execute", execute)
    supervisor = Mock()
    if assessment == "timeout":
        supervisor.evaluate.side_effect = TimeoutError("Private provider details")
    elif assessment != "missing":
        supervisor.evaluate.return_value = SupervisorDecision(
            verdict=assessment, reason="Example assessment.",
            reason_code=f"SUPERVISOR_{assessment}",
        )
    database = tmp_path / "supervisor-audit.db"
    before = (workspace / "src/login.py").read_bytes()
    with TestClient(create_app(database, policy_engine=policy, demo_executor=executor,
                               supervisor=None if assessment == "missing" else supervisor)) as client:
        response = client.post("/tools/execute", json={
            "request_id": "supervisor-check", "task_id": "login-task",
            "tool": "secure_edit_file", "arguments": {"path": "src/login.py", "content": "bad edit"},
        })
    assert response.status_code == 403
    execute.assert_not_called()
    assert (workspace / "src/login.py").read_bytes() == before
    events = AuditRepository(database).get_by_request_id("supervisor-check")
    assert [e.event_type for e in events] == [
        "tool_call_received", "policy_decision", "supervisor_decision", "security_decision",
    ]
    assert events[-1].metadata["decision"] == ("DENY" if assessment == "MISALIGNED" else "REVIEW")


def test_final_decision_audit_failure_prevents_execution(tmp_path, policy_demo, monkeypatch):
    import sqlite3
    from unittest.mock import Mock

    _, policy, executor = policy_demo
    execute = Mock(wraps=executor.execute)
    monkeypatch.setattr(executor, "execute", execute)
    original_add = AuditRepository.add

    def fail_final(self, event):
        if event.event_type == "security_decision":
            raise sqlite3.OperationalError("Audit write failed")
        return original_add(self, event)

    monkeypatch.setattr(AuditRepository, "add", fail_final)
    with TestClient(create_app(tmp_path / "final-audit.db", policy_engine=policy,
                               supervisor=AlignedSupervisor(), demo_executor=executor)) as client:
        response = client.post("/tools/execute", json={
            "request_id": "final-audit-failure", "task_id": "login-task",
            "tool": "secure_read_file", "arguments": {"path": "src/login.py"},
        })
    assert response.status_code == 503
    execute.assert_not_called()
