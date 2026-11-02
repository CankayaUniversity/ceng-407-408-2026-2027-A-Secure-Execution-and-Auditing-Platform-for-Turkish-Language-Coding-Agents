
"""SQLite persistence for validated provenance graphs.

Graph snapshots contain metadata only, not raw tool-result contents.
Node and edge records are saved atomically.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Iterator

import networkx as nx

from secure_agent.provenance.models import (
    ProvenanceEdge,
    ProvenanceNode,
)


class ProvenanceRepository:
    """Persist and reload a directed provenance graph using SQLite."""

    def __init__(self, database_path: str | Path) -> None:
        if str(database_path) in ("", ":memory:"):
            raise ValueError("A persistent SQLite file path is required.")

        self.database_path = Path(database_path)

        if not self.database_path.parent.is_dir():
            raise ValueError("Database parent directory does not exist.")

        with self._connection() as connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS provenance_nodes (
                    node_id TEXT PRIMARY KEY,
                    node_type TEXT NOT NULL,
                    attributes TEXT NOT NULL
                )
            """)

            connection.execute("""
                CREATE TABLE IF NOT EXISTS provenance_edges (
                    source_node_id TEXT NOT NULL,
                    target_node_id TEXT NOT NULL,
                    edge_type TEXT NOT NULL,
                    PRIMARY KEY (source_node_id, target_node_id),
                    FOREIGN KEY (source_node_id)
                        REFERENCES provenance_nodes(node_id),
                    FOREIGN KEY (target_node_id)
                        REFERENCES provenance_nodes(node_id)
                )
            """)

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Open a transaction and close its SQLite connection."""
        with closing(sqlite3.connect(self.database_path)) as connection:
            connection.execute("PRAGMA foreign_keys = ON")

            with connection:
                yield connection

    def save_graph(self, graph: nx.DiGraph) -> None:
        """Validate and atomically replace the stored graph snapshot."""
        if type(graph) is not nx.DiGraph:
            raise TypeError("Expected a NetworkX DiGraph.")

        nodes = []
        node_types = {}

        for node_id, data in graph.nodes(data=True):
            attributes = dict(data)
            node_type = attributes.pop("node_type", None)

            node = ProvenanceNode(
                node_id=node_id,
                node_type=node_type,
                attributes=attributes,
            )

            node_types[node.node_id] = node.node_type

            nodes.append((
                node.node_id,
                node.node_type,
                json.dumps(node.attributes, ensure_ascii=False),
            ))

        edges = []

        for source_id, target_id, data in graph.edges(data=True):
            if set(data) != {"edge_type"}:
                raise ValueError("Invalid provenance edge attributes.")

            edge = ProvenanceEdge(
                source_node_id=source_id,
                target_node_id=target_id,
                edge_type=data["edge_type"],
            )

            expected_target = (
                "SOURCE"
                if edge.edge_type == "DERIVED_FROM"
                else "AGENT"
            )

            if (
                node_types[edge.source_node_id] != "TOOL_RESULT"
                or node_types[edge.target_node_id] != expected_target
            ):
                raise ValueError("Invalid provenance edge endpoints.")

            edges.append((
                edge.source_node_id,
                edge.target_node_id,
                edge.edge_type,
            ))

        # A transaction prevents partially saved graph snapshots.
        with self._connection() as connection:
            connection.execute("DELETE FROM provenance_edges")
            connection.execute("DELETE FROM provenance_nodes")

            connection.executemany(
                "INSERT INTO provenance_nodes "
                "(node_id, node_type, attributes) VALUES (?, ?, ?)",
                nodes,
            )

            connection.executemany(
                "INSERT INTO provenance_edges "
                "(source_node_id, target_node_id, edge_type) "
                "VALUES (?, ?, ?)",
                edges,
            )

    def load_graph(self) -> nx.DiGraph:
        """Reconstruct and validate the graph from SQLite records."""
        graph = nx.DiGraph()

        with self._connection() as connection:
            node_rows = connection.execute(
                "SELECT node_id, node_type, attributes "
                "FROM provenance_nodes"
            ).fetchall()

            edge_rows = connection.execute(
                "SELECT source_node_id, target_node_id, edge_type "
                "FROM provenance_edges"
            ).fetchall()

        for node_id, node_type, attributes_json in node_rows:
            node = ProvenanceNode(
                node_id=node_id,
                node_type=node_type,
                attributes=json.loads(attributes_json),
            )

            if "node_type" in node.attributes:
                raise ValueError("Reserved node metadata key.")

            graph.add_node(
                node.node_id,
                node_type=node.node_type,
                **node.attributes,
            )

        for source_id, target_id, edge_type in edge_rows:
            edge = ProvenanceEdge(
                source_node_id=source_id,
                target_node_id=target_id,
                edge_type=edge_type,
            )

            expected_target = (
                "SOURCE"
                if edge.edge_type == "DERIVED_FROM"
                else "AGENT"
            )

            if (
                source_id not in graph
                or target_id not in graph
                or graph.nodes[source_id]["node_type"] != "TOOL_RESULT"
                or graph.nodes[target_id]["node_type"] != expected_target
            ):
                raise ValueError("Invalid stored provenance relationship.")

            graph.add_edge(
                edge.source_node_id,
                edge.target_node_id,
                edge_type=edge.edge_type,
            )

        return graph
