
"""Validated node and edge models for provenance graphs.

The graph records the origin and exposure of untrusted tool results.
Raw file contents are not stored in node metadata.
"""

from typing import Literal, TypeAlias

from pydantic import Field

from secure_agent.common.schemas import ContractModel, NonEmptyText


NodeType: TypeAlias = Literal[
    "SOURCE",
    "TOOL_RESULT",
    "AGENT",
]

EdgeType: TypeAlias = Literal[
    "DERIVED_FROM",
    "EXPOSED_TO_AGENT",
]


class ProvenanceNode(ContractModel):
    """Represent a uniquely identified provenance graph node."""

    node_id: NonEmptyText
    node_type: NodeType
    attributes: dict[str, str] = Field(default_factory=dict)


class ProvenanceEdge(ContractModel):
    """Represent a directed relationship between two graph nodes."""

    source_node_id: NonEmptyText
    target_node_id: NonEmptyText
    edge_type: EdgeType
