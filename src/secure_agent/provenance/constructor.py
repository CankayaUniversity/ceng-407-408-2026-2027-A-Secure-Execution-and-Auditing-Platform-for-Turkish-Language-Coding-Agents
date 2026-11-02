
"""Construct provenance graphs from trusted tool-result events.

Source content remains untrusted. The graph records metadata and
content hashes rather than storing raw file contents.
"""

from __future__ import annotations

import hashlib

import networkx as nx

from secure_agent.common.schemas import ToolResult
from secure_agent.provenance.models import (
    ProvenanceEdge,
    ProvenanceNode,
)


class ProvenanceGraphConstructor:
    """Build a directed graph of sources, results, and agent exposure."""

    def __init__(self) -> None:
        self.graph = nx.DiGraph()

    def _add_node(self, node: ProvenanceNode) -> None:
        """Insert a node without overwriting conflicting metadata."""
        attributes = {
            "node_type": node.node_type,
            **node.attributes,
        }

        if node.node_id in self.graph:
            if dict(self.graph.nodes[node.node_id]) != attributes:
                raise ValueError("Conflicting provenance node metadata.")
            return

        self.graph.add_node(node.node_id, **attributes)

    def _add_edge(self, edge: ProvenanceEdge) -> None:
        """Insert a validated directed graph relationship."""
        if (
            edge.source_node_id not in self.graph
            or edge.target_node_id not in self.graph
        ):
            raise ValueError("Both edge endpoints must exist.")

        if self.graph.has_edge(
            edge.source_node_id,
            edge.target_node_id,
        ):
            existing = self.graph.edges[
                edge.source_node_id,
                edge.target_node_id,
            ]

            if existing.get("edge_type") != edge.edge_type:
                raise ValueError("Conflicting provenance edge type.")
            return

        self.graph.add_edge(
            edge.source_node_id,
            edge.target_node_id,
            edge_type=edge.edge_type,
        )

    def record_read_result(
        self,
        result: ToolResult,
        *,
        source_path: str,
    ) -> tuple[str, str]:
        """Record a successful file read and its source relationship.

        The caller must provide a backend-verified source path and a
        ToolResult containing a trusted backend-generated source ID.
        """
        result = ToolResult.model_validate(result)

        if result.status != "success":
            raise ValueError("Only successful reads can be recorded.")

        if not isinstance(source_path, str) or not source_path.strip():
            raise ValueError("A non-empty source path is required.")

        source_node_id = f"source:{result.source_id}"
        result_node_id = f"result:{result.request_id}"

        source_node = ProvenanceNode(
            node_id=source_node_id,
            node_type="SOURCE",
            attributes={
                "source_id": result.source_id,
                "path": source_path,
            },
        )

        result_node = ProvenanceNode(
            node_id=result_node_id,
            node_type="TOOL_RESULT",
            attributes={
                "request_id": result.request_id,
                "status": result.status,
                "trust_level": result.trust_level,
                "output_sha256": hashlib.sha256(
                    result.output.encode("utf-8")
                ).hexdigest(),
            },
        )

        # Check both nodes before inserting either one.
        for node in (source_node, result_node):
            if node.node_id in self.graph:
                expected = {
                    "node_type": node.node_type,
                    **node.attributes,
                }
                if dict(self.graph.nodes[node.node_id]) != expected:
                    raise ValueError(
                        "Conflicting provenance node metadata."
                    )

        self._add_node(source_node)
        self._add_node(result_node)

        self._add_edge(
            ProvenanceEdge(
                source_node_id=result_node_id,
                target_node_id=source_node_id,
                edge_type="DERIVED_FROM",
            )
        )

        return source_node_id, result_node_id

    def record_exposure(
        self,
        *,
        request_id: str,
        agent_id: str,
    ) -> None:
        """Record a tool result actually delivered to an agent."""
        if not isinstance(request_id, str) or not request_id.strip():
            raise ValueError("A non-empty request ID is required.")

        if not isinstance(agent_id, str) or not agent_id.strip():
            raise ValueError("A non-empty agent ID is required.")

        result_node_id = f"result:{request_id}"

        if result_node_id not in self.graph:
            raise ValueError(
                "Tool result must exist before recording exposure."
            )

        agent_node_id = f"agent:{agent_id}"

        self._add_node(
            ProvenanceNode(
                node_id=agent_node_id,
                node_type="AGENT",
                attributes={"agent_id": agent_id},
            )
        )

        self._add_edge(
            ProvenanceEdge(
                source_node_id=result_node_id,
                target_node_id=agent_node_id,
                edge_type="EXPOSED_TO_AGENT",
            )
        )

    def get_graph(self) -> nx.DiGraph:
        """Return a snapshot of the current provenance graph."""
        return self.graph.copy()
