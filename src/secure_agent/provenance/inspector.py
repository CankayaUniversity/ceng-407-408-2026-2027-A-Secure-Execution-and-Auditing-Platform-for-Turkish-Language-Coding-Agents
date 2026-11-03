"""Inspect existing graph evidence without reading source file contents."""

from pathlib import PurePosixPath

import networkx as nx

from secure_agent.common.schemas import parse_tool_call, ToolCall
from secure_agent.provenance.models import GraphAssessment, ProvenanceEdge, ProvenanceNode


def _sensitive(path: str) -> bool:
    parts = PurePosixPath(path).parts
    return any(part == ".git" or part == ".env" or part.startswith(".env.")
               for part in parts)


class GraphInspector:
    def inspect(self, call: ToolCall, graph: nx.DiGraph) -> GraphAssessment:
        """Only explicit exposure to this task counts as source exposure.

        A valid empty graph represents no history; None or malformed input
        raises and must be handled as unavailable, never a clean assessment.
        """
        call = parse_tool_call(call)
        if type(graph) is not nx.DiGraph:
            raise ValueError("A loaded directed provenance graph is required.")
        nodes = {}
        for node_id, raw in graph.nodes(data=True):
            data = dict(raw)
            nodes[node_id] = ProvenanceNode(
                node_id=node_id, node_type=data.pop("node_type", None), attributes=data,
            )
        edges = []
        for source, target, data in graph.edges(data=True):
            if set(data) != {"edge_type"}:
                raise ValueError("Invalid graph edge attributes.")
            edge = ProvenanceEdge(source_node_id=source, target_node_id=target, **data)
            expected_target = "SOURCE" if edge.edge_type == "DERIVED_FROM" else "AGENT"
            if nodes[source].node_type != "TOOL_RESULT" or nodes[target].node_type != expected_target:
                raise ValueError("Invalid provenance edge endpoints.")
            edges.append(edge)

        flags, sources, observed = set(), set(), []
        agent_node = f"agent:task:{call.task_id}"
        for node_id, node in nodes.items():
            if node.node_type != "TOOL_RESULT":
                continue
            task_id = node.attributes.get("task_id")
            if task_id is None:
                flags.add("GRAPH_INCOMPLETE")
                continue
            if task_id != call.task_id:
                continue
            derived = [e for e in edges if e.source_node_id == node_id and e.edge_type == "DERIVED_FROM"]
            exposed = [e for e in edges if e.source_node_id == node_id
                       and e.target_node_id == agent_node and e.edge_type == "EXPOSED_TO_AGENT"]
            if len(derived) != 1 or not exposed:
                flags.add("GRAPH_INCOMPLETE")
                continue
            if node.attributes.get("trust_level") != "untrusted":
                raise ValueError("Unexpected tool-result trust level.")
            source_id = nodes[derived[0].target_node_id].attributes.get("source_id")
            if not source_id:
                raise ValueError("Source identifier is missing.")
            flags.add("UNTRUSTED_SOURCE_EXPOSURE")
            sources.add(source_id)
            observed.extend(derived + exposed)
        if sources and _sensitive(getattr(call.arguments, "path", "")):
            flags.add("SENSITIVE_TARGET_AFTER_UNTRUSTED_INPUT")
        return GraphAssessment(risk_flags=frozenset(flags), source_ids=tuple(sorted(sources)),
                               observed_edges=tuple(observed))
