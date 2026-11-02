
"""Negative and integrity tests for provenance graph components.

Verify that malformed nodes, conflicting identities, invalid
exposure events, and corrupted SQLite relationships are rejected.
"""

import hashlib
import sqlite3

import pytest
from pydantic import ValidationError

from secure_agent.common.schemas import ToolResult
from secure_agent.provenance.models import (
    ProvenanceEdge,
    ProvenanceNode,
)
from secure_agent.provenance.constructor import (
    ProvenanceGraphConstructor,
)
from secure_agent.provenance.repository import ProvenanceRepository


def make_result(
    request_id="req-001",
    source_id="source-001",
    output="# Demo README",
    status="success",
):
    """Create a validated tool result for an isolated test."""
    return ToolResult(
        request_id=request_id,
        status=status,
        output=output,
        source_id=source_id,
        trust_level="untrusted",
    )


def make_graph():
    """Build a valid provenance graph with a recorded exposure."""
    constructor = ProvenanceGraphConstructor()

    constructor.record_read_result(
        make_result(),
        source_path="README.md",
    )

    constructor.record_exposure(
        request_id="req-001",
        agent_id="agent-001",
    )

    return constructor.get_graph()


def test_invalid_node_type_rejected():
    """Reject node types outside the provenance contract."""
    with pytest.raises(ValidationError):
        ProvenanceNode(
            node_id="invalid-001",
            node_type="UNKNOWN",
        )


def test_invalid_edge_type_rejected():
    """Reject relationships not defined by the graph schema."""
    with pytest.raises(ValidationError):
        ProvenanceEdge(
            source_node_id="result:req-001",
            target_node_id="agent:agent-001",
            edge_type="UNAUTHORIZED_EDGE",
        )


def test_failed_read_result_not_recorded():
    """Do not treat an unsuccessful read as a successful source."""
    constructor = ProvenanceGraphConstructor()

    with pytest.raises(ValueError):
        constructor.record_read_result(
            make_result(status="denied"),
            source_path="README.md",
        )

    assert constructor.get_graph().number_of_nodes() == 0


def test_empty_source_path_rejected():
    """Reject read results without a valid source path."""
    constructor = ProvenanceGraphConstructor()

    with pytest.raises(ValueError):
        constructor.record_read_result(
            make_result(),
            source_path=" ",
        )

    assert constructor.get_graph().number_of_nodes() == 0


def test_conflicting_request_id_rejected():
    """Reject a reused request ID with different result contents."""
    constructor = ProvenanceGraphConstructor()

    constructor.record_read_result(
        make_result(),
        source_path="README.md",
    )

    with pytest.raises(ValueError, match="Conflicting"):
        constructor.record_read_result(
            make_result(output="Different content"),
            source_path="README.md",
        )

    graph = constructor.get_graph()

    assert graph.number_of_nodes() == 2
    assert graph.number_of_edges() == 1

    expected_hash = hashlib.sha256(
        b"# Demo README"
    ).hexdigest()

    assert graph.nodes[
        "result:req-001"
    ]["output_sha256"] == expected_hash


def test_conflicting_source_id_rejected():
    """Reject mapping one source identifier to different paths."""
    constructor = ProvenanceGraphConstructor()

    constructor.record_read_result(
        make_result(),
        source_path="README.md",
    )

    with pytest.raises(ValueError, match="Conflicting"):
        constructor.record_read_result(
            make_result(request_id="req-002"),
            source_path="different.txt",
        )

    graph = constructor.get_graph()

    assert graph.number_of_nodes() == 2
    assert "result:req-002" not in graph


def test_exposure_without_result_rejected():
    """Never record agent exposure for an unknown tool result."""
    constructor = ProvenanceGraphConstructor()

    with pytest.raises(ValueError, match="Tool result must exist"):
        constructor.record_exposure(
            request_id="missing-request",
            agent_id="agent-001",
        )

    assert constructor.get_graph().number_of_nodes() == 0


def test_invalid_agent_id_rejected():
    """Reject exposure events with a blank agent identifier."""
    constructor = ProvenanceGraphConstructor()

    constructor.record_read_result(
        make_result(),
        source_path="README.md",
    )

    with pytest.raises(ValueError):
        constructor.record_exposure(
            request_id="req-001",
            agent_id=" ",
        )

    assert constructor.get_graph().number_of_nodes() == 2
    assert constructor.get_graph().number_of_edges() == 1


def test_invalid_edge_does_not_replace_sqlite_graph(tmp_path):
    """Keep the previous snapshot when a new graph is invalid."""
    repository = ProvenanceRepository(
        tmp_path / "provenance.db"
    )

    valid_graph = make_graph()
    repository.save_graph(valid_graph)

    invalid_graph = valid_graph.copy()

    invalid_graph.add_edge(
        "source:source-001",
        "agent:agent-001",
        edge_type="EXPOSED_TO_AGENT",
    )

    with pytest.raises(ValueError, match="Invalid provenance edge"):
        repository.save_graph(invalid_graph)

    restored = repository.load_graph()

    assert restored.number_of_nodes() == 3
    assert restored.number_of_edges() == 2

    assert not restored.has_edge(
        "source:source-001",
        "agent:agent-001",
    )

    assert restored.has_edge(
        "result:req-001",
        "agent:agent-001",
    )


def test_corrupted_sqlite_edge_rejected(tmp_path):
    """Reject an unsupported edge type loaded from SQLite."""
    database_path = tmp_path / "provenance.db"

    repository = ProvenanceRepository(database_path)
    repository.save_graph(make_graph())

    # Simulate a corrupted record in an isolated test database.
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE provenance_edges "
            "SET edge_type = ? "
            "WHERE edge_type = ?",
            ("UNKNOWN_EDGE", "EXPOSED_TO_AGENT"),
        )

    with pytest.raises(ValidationError):
        repository.load_graph()


def test_raw_tool_output_not_stored_in_graph():
    """Store a content hash rather than the raw tool output."""
    sensitive_text = "Example untrusted README content"

    constructor = ProvenanceGraphConstructor()

    constructor.record_read_result(
        make_result(output=sensitive_text),
        source_path="README.md",
    )

    graph = constructor.get_graph()
    result_attributes = graph.nodes["result:req-001"]

    assert sensitive_text not in str(result_attributes)

    assert result_attributes["output_sha256"] == hashlib.sha256(
        sensitive_text.encode("utf-8")
    ).hexdigest()
