
"""Integration test for Executor, Provenance Graph, and SQLite.

The test reads a real demo file through the scoped executor,
records provenance, simulates delivery to an agent, and verifies
SQLite persistence without running untrusted code.
"""

import sqlite3
from pathlib import Path

from secure_agent.common.schemas import Task, ToolResult
from secure_agent.execution.executor import Executor
from secure_agent.provenance.constructor import ProvenanceGraphConstructor
from secure_agent.provenance.repository import ProvenanceRepository
from secure_agent.tasks.registry import TaskRegistry
from secure_agent.tasks.scope import TaskScope


def test_demo_readme_provenance_flow(tmp_path: Path) -> None:
    """Verify scoped README access and graph persistence end to end."""

    # Locate the actual demo project in the repository.
    project_root = Path(__file__).resolve().parents[2]
    workspace = project_root / "demo" / "sample_project"

    assert (workspace / "README.md").is_file()

    # Create trusted task permissions.
    scope = TaskScope(
        scope_id="scope-provenance-demo",
        workspace_id="workspace-demo",
        allowed_tools=frozenset({"secure_read_file"}),
        readable_files=frozenset({"README.md"}),
    )

    registry = TaskRegistry(
        workspace_ids=["workspace-demo"],
        scopes=[scope],
    )

    registry.register(
        Task(
            task_id="task-provenance-demo",
            user_goal="Read the demo README file.",
            workspace_id="workspace-demo",
            scope_id="scope-provenance-demo",
        )
    )

    # Execute a real file read through the Day 2 executor.
    executor = Executor(
        registry=registry,
        workspace_roots={"workspace-demo": workspace},
    )

    read_output = executor.execute({
        "request_id": "req-readme-demo",
        "task_id": "task-provenance-demo",
        "tool": "secure_read_file",
        "arguments": {"path": "README.md"},
    })

    assert isinstance(read_output, str)
    assert read_output == (
        workspace / "README.md"
    ).read_bytes().decode("utf-8")

    print("EXECUTOR README READ: OK")

    # The trusted test backend associates a source identifier.
    result = ToolResult(
        request_id="req-readme-demo",
        status="success",
        output=read_output,
        source_id="source-demo-readme",
        trust_level="untrusted",
    )

    # Construct provenance nodes and the source relationship.
    constructor = ProvenanceGraphConstructor()

    constructor.record_read_result(
        result,
        source_path="README.md",
    )

    before_exposure = constructor.get_graph()

    assert before_exposure.number_of_nodes() == 2
    assert before_exposure.number_of_edges() == 1

    assert before_exposure.nodes[
        "source:source-demo-readme"
    ]["node_type"] == "SOURCE"

    assert before_exposure.nodes[
        "result:req-readme-demo"
    ]["node_type"] == "TOOL_RESULT"

    print("SOURCE AND TOOL_RESULT: OK")

    # Simulate confirmed delivery to an agent.
    delivered_output = result.output
    assert delivered_output == read_output

    constructor.record_exposure(
        request_id=result.request_id,
        agent_id="demo-agent",
    )

    original = constructor.get_graph()

    assert original.edges[
        "result:req-readme-demo",
        "agent:demo-agent",
    ]["edge_type"] == "EXPOSED_TO_AGENT"

    print("EXPOSURE EDGE: OK")

    # Persist the graph in a real temporary SQLite database.
    database_path = tmp_path / "provenance.db"

    repository = ProvenanceRepository(database_path)
    repository.save_graph(original)

    assert database_path.is_file()

    with sqlite3.connect(database_path) as connection:
        node_count = connection.execute(
            "SELECT COUNT(*) FROM provenance_nodes"
        ).fetchone()[0]

        edge_count = connection.execute(
            "SELECT COUNT(*) FROM provenance_edges"
        ).fetchone()[0]

    assert node_count == 3
    assert edge_count == 2

    # Reopen SQLite through a completely new repository object.
    restored = ProvenanceRepository(database_path).load_graph()

    assert dict(restored.nodes(data=True)) == dict(
        original.nodes(data=True)
    )

    original_edges = {
        (source, target, data["edge_type"])
        for source, target, data in original.edges(data=True)
    }

    restored_edges = {
        (source, target, data["edge_type"])
        for source, target, data in restored.edges(data=True)
    }

    assert original_edges == restored_edges

    print("SQLITE RELOAD: OK")
    print("NODES:", node_count)
    print("EDGES:", edge_count)
    print("INTEGRATION: PASSED")
