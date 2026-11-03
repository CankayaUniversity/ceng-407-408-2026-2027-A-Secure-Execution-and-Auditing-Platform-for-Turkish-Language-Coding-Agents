"""Exercise protected README results through the real HTTP agent adapter."""

import hashlib
import socket
import sqlite3
import time
from pathlib import Path
from threading import Thread

import pytest
import uvicorn

from agent.agent_loop import AgentLoop, MockLLM
from agent.tool_adapter import SecureToolAdapter
from secure_agent.audit.repository import AuditRepository
from secure_agent.common.schemas import Task
from secure_agent.execution.executor import Executor
from secure_agent.gateway.main import create_app
from secure_agent.provenance.repository import ProvenanceRepository
from secure_agent.security.policy_engine import PolicyEngine
from secure_agent.security.supervisor import SupervisorDecision
from secure_agent.tasks.registry import TaskRegistry
from secure_agent.tasks.scope import TaskScope


ROOT = Path(__file__).resolve().parents[2]
SECRET = "demo-integration-secret-987"


class AlignedSupervisor:
    """Provide a deterministic verdict without calling a model provider."""

    def evaluate(self, **kwargs):
        return SupervisorDecision(
            verdict="ALIGNED",
            reason="Isolated README protection test.",
            reason_code="SUPERVISOR_ALIGNED",
        )


@pytest.fixture
def protected_gateway(tmp_path, permit_material):
    private_key, _, verifier = permit_material
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    readme = workspace / "README.md"
    readme.write_text(
        f"# Demo\nAPI_KEY={SECRET}\nPublic explanation.\n",
        encoding="utf-8",
    )

    scope = TaskScope(
        scope_id="readme-scope",
        workspace_id="readme-workspace",
        allowed_tools=frozenset({"secure_read_file"}),
        readable_files=frozenset({"README.md"}),
    )
    registry = TaskRegistry(
        workspace_ids=["readme-workspace"],
        scopes=[scope],
    )
    registry.register(Task(
        task_id="readme-task",
        user_goal="README.md dosyasını oku.",
        workspace_id="readme-workspace",
        scope_id="readme-scope",
    ))
    policy = PolicyEngine(
        registry=registry,
        model_path=ROOT / "configs/casbin_model.conf",
        policy_path=ROOT / "configs/casbin_policy.csv",
    )
    executor = Executor(
        registry=registry,
        workspace_roots={"readme-workspace": workspace},
        permit_verifier=verifier,
    )
    database = tmp_path / "audit.db"
    graph_database = tmp_path / "audit-provenance.db"
    app = create_app(
        database,
        policy_engine=policy,
        supervisor=AlignedSupervisor(),
        demo_executor=executor,
        demo_private_key=private_key,
    )

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        server = uvicorn.Server(uvicorn.Config(
            app, log_level="error", access_log=False, lifespan="on",
        ))
        thread = Thread(
            target=server.run,
            kwargs={"sockets": [listener]},
            daemon=True,
        )
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert server.started, "Gateway did not start."
            yield readme, database, graph_database, f"http://127.0.0.1:{port}"
        finally:
            server.should_exit = True
            thread.join(timeout=5)
        assert not thread.is_alive(), "Gateway did not stop."


def read_with_agent(url, model=None):
    return AgentLoop(
        model if model is not None else MockLLM(),
        task_id="readme-task",
        adapter=SecureToolAdapter(url, acknowledge_exposure=True),
    ).run("README.md dosyasını oku.")


def test_secret_readme_reaches_agent_after_graph_update(
    protected_gateway, caplog, capsys,
):
    readme, database, graph_database, url = protected_gateway
    observed_results = []

    class InspectingModel:
        def propose(self, *, history, tool_results, **kwargs):
            if not history:
                return {
                    "tool": "secure_read_file",
                    "arguments": {"path": "README.md"},
                }

            assert len(tool_results) == 1
            result = tool_results[0]
            assert SECRET not in result.output

            # Persistence must already be complete at the next model turn.
            graph = ProvenanceRepository(graph_database).load_graph()
            node = graph.nodes[f"result:{result.request_id}"]
            assert node["output_sha256"] == hashlib.sha256(
                result.output.encode("utf-8")
            ).hexdigest()

            assert graph.edges[
                f"result:{result.request_id}",
                "agent:task:readme-task",
            ]["edge_type"] == "EXPOSED_TO_AGENT"

            observed_results.append(result)
            return None

    run = read_with_agent(url, InspectingModel())

    assert run.stop_reason == "model_finished"
    assert run.error is None
    assert len(run.tool_results) == 1
    result = run.tool_results[0]
    assert observed_results == [result]
    assert result.status == "success"
    assert result.source_id
    assert result.trust_level == "untrusted"
    assert "[REDACTED]" in result.output
    assert "Public explanation." in result.output
    assert SECRET in readme.read_text(encoding="utf-8")

    graph = ProvenanceRepository(graph_database).load_graph()
    result_node = f"result:{result.request_id}"
    source_node = f"source:{result.source_id}"
    assert graph.nodes[source_node]["path"] == "README.md"
    assert graph.nodes[result_node]["task_id"] == "readme-task"
    assert graph.edges[result_node, source_node]["edge_type"] == "DERIVED_FROM"
    assert graph.edges[
        result_node, "agent:task:readme-task",
    ]["edge_type"] == "EXPOSED_TO_AGENT"

    events = AuditRepository(database).get_by_request_id(result.request_id)
    assert [event.event_type for event in events] == [
        "tool_call_received",
        "policy_decision",
        "graph_assessment",
        "supervisor_decision",
        "security_decision",
        "permit_issued",
        "permit_verification",
        "tool_result",
        "graph_event",
        "source_exposure",
    ]
    result_event = next(event for event in events if event.event_type == "tool_result")
    assert result_event.metadata["source_id"] == result.source_id
    assert all("output" not in event.metadata for event in events)

    for path in (database, graph_database):
        with sqlite3.connect(path) as connection:
            assert SECRET not in "\n".join(connection.iterdump())

    captured = capsys.readouterr()
    assert SECRET not in caplog.text + captured.out + captured.err


def test_oversized_readme_is_limited_before_graph_and_delivery(protected_gateway):
    readme, _, graph_database, url = protected_gateway
    readme.write_text("ğ" * 20_000, encoding="utf-8")

    run = read_with_agent(url)
    assert run.stop_reason == "model_finished"
    result = run.tool_results[0]
    assert len(result.output.encode("utf-8")) <= 32 * 1024
    assert result.output.endswith("\n[TRUNCATED]")
    assert "\ufffd" not in result.output

    graph = ProvenanceRepository(graph_database).load_graph()
    assert graph.nodes[f"result:{result.request_id}"]["output_sha256"] == (
        hashlib.sha256(result.output.encode("utf-8")).hexdigest()
    )


def test_graph_failure_returns_no_tool_result(protected_gateway, monkeypatch):
    _, _, graph_database, url = protected_gateway

    def fail_save(self, graph):
        raise sqlite3.OperationalError("Synthetic graph failure.")

    monkeypatch.setattr(ProvenanceRepository, "save_graph", fail_save)
    run = read_with_agent(url)

    assert run.stop_reason == "gateway_error"
    assert run.error == "Gateway returned HTTP 503."
    assert run.tool_results == ()
    assert ProvenanceRepository(graph_database).load_graph().number_of_nodes() == 0


def test_protection_failure_stops_result_logging_and_delivery(
    protected_gateway, monkeypatch, caplog, capsys,
):
    _, database, graph_database, url = protected_gateway

    def fail_protection(result):
        raise ValueError("Synthetic failure: " + SECRET)

    monkeypatch.setattr(
        "secure_agent.gateway.orchestrator.protect_tool_result",
        fail_protection,
    )
    run = read_with_agent(url)

    assert run.stop_reason == "gateway_error"
    assert run.error == "Gateway returned HTTP 503."
    assert run.tool_results == ()
    events = AuditRepository(database).get_by_request_id(run.tool_calls[0].request_id)
    assert all(
        event.event_type not in {"tool_result", "graph_event"}
        for event in events
    )
    assert ProvenanceRepository(graph_database).load_graph().number_of_nodes() == 0
    captured = capsys.readouterr()
    assert SECRET not in caplog.text + captured.out + captured.err
