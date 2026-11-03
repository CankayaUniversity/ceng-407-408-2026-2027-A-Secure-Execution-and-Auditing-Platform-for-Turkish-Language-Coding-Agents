"""Task-scoped graph evidence and missing-data behavior."""

import networkx as nx
import pytest
from pydantic import ValidationError

from secure_agent.common.schemas import ToolResult, parse_tool_call
from secure_agent.provenance.constructor import ProvenanceGraphConstructor
from secure_agent.provenance.inspector import GraphInspector
from secure_agent.provenance.models import GraphAssessment


def call(path="src/login.py", task_id="task-001"):
    return parse_tool_call({"request_id": "next-request", "task_id": task_id,
                            "tool": "secure_read_file", "arguments": {"path": path}})


def history(*, exposed=True, task_id="task-001"):
    constructor = ProvenanceGraphConstructor()
    constructor.record_read_result(ToolResult(
        request_id="readme-request", status="success", output="Untrusted README text",
        source_id="source-001", trust_level="untrusted",
    ), source_path="README.md")
    constructor.graph.nodes["result:readme-request"]["task_id"] = task_id
    if exposed:
        constructor.record_exposure(request_id="readme-request", agent_id=f"task:{task_id}")
    return constructor.get_graph()


def test_empty_loaded_graph_is_valid_bootstrap_history():
    assessment = GraphInspector().inspect(call(), nx.DiGraph())
    assert assessment == GraphAssessment(risk_flags=frozenset(), source_ids=(), observed_edges=())


def test_confirmed_untrusted_exposure_is_flagged():
    assessment = GraphInspector().inspect(call(), history())
    assert assessment.risk_flags == frozenset({"UNTRUSTED_SOURCE_EXPOSURE"})
    assert assessment.source_ids == ("source-001",)
    assert {e.edge_type for e in assessment.observed_edges} == {"DERIVED_FROM", "EXPOSED_TO_AGENT"}
    assert "Untrusted README text" not in assessment.model_dump_json()
    assert GraphAssessment.model_validate_json(assessment.model_dump_json()) == assessment


@pytest.mark.parametrize("path", [".env", "config/.env.local", ".git/config"])
def test_sensitive_target_after_exposure_is_review_evidence(path):
    assessment = GraphInspector().inspect(call(path), history())
    assert "SENSITIVE_TARGET_AFTER_UNTRUSTED_INPUT" in assessment.risk_flags


def test_other_task_evidence_is_not_used_or_leaked():
    assessment = GraphInspector().inspect(call(), history(task_id="other-task"))
    assert not assessment.risk_flags
    assert not assessment.source_ids
    assert not assessment.observed_edges


def test_read_without_delivery_is_not_claimed_as_exposure():
    assessment = GraphInspector().inspect(call(), history(exposed=False))
    assert assessment.risk_flags == frozenset({"GRAPH_INCOMPLETE"})
    assert not assessment.source_ids


def test_unscoped_old_history_is_incomplete_not_clean():
    graph = history()
    del graph.nodes["result:readme-request"]["task_id"]
    assert "GRAPH_INCOMPLETE" in GraphInspector().inspect(call(), graph).risk_flags


@pytest.mark.parametrize("graph", [None, {}, nx.MultiDiGraph()])
def test_missing_or_wrong_graph_is_not_an_empty_assessment(graph):
    with pytest.raises(ValueError):
        GraphInspector().inspect(call(), graph)


def test_invalid_edge_is_rejected():
    graph = history()
    graph.edges["result:readme-request", "source:source-001"]["edge_type"] = "INVALID"
    with pytest.raises(ValidationError):
        GraphInspector().inspect(call(), graph)


def test_unknown_risk_flag_is_rejected():
    with pytest.raises(ValidationError):
        GraphAssessment(risk_flags=frozenset({"UNKNOWN"}), source_ids=(), observed_edges=())
