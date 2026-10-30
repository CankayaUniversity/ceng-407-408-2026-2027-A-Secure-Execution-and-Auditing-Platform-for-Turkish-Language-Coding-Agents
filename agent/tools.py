"""Day 1 tool schemas and proposals using Person 1's shared ToolCall contract.

Only request data is created here. No filesystem, process, network, or database
operation is performed. The Gateway adapter is a later integration task.
"""

from typing import Any
from uuid import uuid4

from secure_agent.common.schemas import (
    ContractModel,
    EditFileArguments,
    ListFilesArguments,
    NonEmptyText,
    ReadFileArguments,
    RunTestsArguments,
    ToolCall,
    parse_tool_call,
)


_TOOL_DEFINITIONS = (
    ("secure_list_files", "List files in a workspace directory.", ListFilesArguments),
    ("secure_read_file", "Read a text file in the workspace.", ReadFileArguments),
    ("secure_edit_file", "Replace the contents of a workspace file.", EditFileArguments),
    ("secure_run_tests", "Run a registered test profile.", RunTestsArguments),
)
SUPPORTED_TOOLS = frozenset(name for name, _, _ in _TOOL_DEFINITIONS)


class UnsupportedToolError(ValueError):
    """The model proposed a tool outside the four permitted tool names."""


class _ToolProposal(ContractModel):
    """Model-controlled fields only; task and request IDs come from the caller."""

    tool: NonEmptyText
    arguments: dict[str, Any]


def get_tool_schemas() -> list[dict[str, Any]]:
    """Return fresh function schemas derived from the shared argument models.

    JSON Schema describes the structural contract. The shared models additionally
    enforce Python validators such as workspace-relative path syntax.
    """
    return [
        {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": arguments_model.model_json_schema(),
            },
        }
        for name, description, arguments_model in _TOOL_DEFINITIONS
    ]


def make_tool_call(
    proposal: object,
    *,
    task_id: str,
    request_id: str | None = None,
) -> ToolCall:
    """Reject unsupported proposals and build a validated shared ToolCall."""
    validated = _ToolProposal.model_validate(proposal)
    if validated.tool not in SUPPORTED_TOOLS:
        raise UnsupportedToolError(f"Unsupported tool: {validated.tool}")
    return parse_tool_call({
        "request_id": request_id if request_id is not None else f"req-{uuid4().hex}",
        "task_id": task_id,
        "tool": validated.tool,
        "arguments": validated.arguments,
    })
