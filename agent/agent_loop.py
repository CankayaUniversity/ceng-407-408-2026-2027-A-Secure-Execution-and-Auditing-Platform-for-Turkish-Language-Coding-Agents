"""Bounded agent loop with optional Gateway tool execution.

From the repository root, set PYTHONPATH=src and run:
    python -m agent.agent_loop
    python -m agent.agent_loop --gateway-url http://127.0.0.1:8000
"""

import argparse
from dataclasses import dataclass
import json
from typing import Any, Literal, Protocol

from pydantic import TypeAdapter

from secure_agent.common.schemas import NonEmptyText, ToolCall, ToolResult

from .tool_adapter import GatewayError, SecureToolAdapter
from .tools import get_tool_schemas, make_tool_call


class ToolCallingModel(Protocol):
    """Minimal model interface; None signals that no further call is needed."""

    def propose(
        self,
        *,
        user_goal: str,
        tool_schemas: list[dict[str, Any]],
        history: tuple[ToolCall, ...],
        tool_results: tuple[ToolResult, ...],
    ) -> dict[str, Any] | None:
        ...


@dataclass(frozen=True)
class AgentRun:
    tool_calls: tuple[ToolCall, ...]
    steps: int
    stop_reason: Literal["model_finished", "max_steps", "gateway_error"]
    tool_results: tuple[ToolResult, ...] = ()
    error: str | None = None


class AgentLoop:
    """Generate validated ToolCalls within a fixed model-invocation budget.

    Unsupported tools and invalid proposals raise validation errors immediately.
    A run has fresh history. With an adapter, calls go only through the Gateway
    and its validated results are passed to the model. Without an adapter,
    the Day 1 request-only behavior remains available.
    """

    def __init__(
        self,
        model: ToolCallingModel,
        *,
        task_id: str,
        max_steps: int = 3,
        adapter: SecureToolAdapter | None = None,
    ):
        if isinstance(max_steps, bool) or not isinstance(max_steps, int) or max_steps < 1:
            raise ValueError("max_steps must be a positive integer.")
        self.model = model
        self.task_id = TypeAdapter(NonEmptyText).validate_python(task_id, strict=True)
        self.max_steps = max_steps
        self.adapter = adapter

    def run(self, user_goal: str) -> AgentRun:
        goal = TypeAdapter(NonEmptyText).validate_python(user_goal, strict=True)
        calls: list[ToolCall] = []
        results: list[ToolResult] = []
        for step in range(1, self.max_steps + 1):
            proposal = self.model.propose(
                user_goal=goal,
                tool_schemas=get_tool_schemas(),
                history=tuple(calls),
                tool_results=tuple(results),
            )
            if proposal is None:
                return AgentRun(tuple(calls), step, "model_finished", tuple(results))
            call = make_tool_call(proposal, task_id=self.task_id)
            calls.append(call)
            if self.adapter is not None:
                try:
                    results.append(self.adapter.execute(call))
                except GatewayError as error:
                    return AgentRun(
                        tuple(calls), step, "gateway_error", tuple(results), str(error)
                    )
        return AgentRun(tuple(calls), self.max_steps, "max_steps", tuple(results))


class MockLLM:
    """Propose one read request, then stop; does not interpret the user goal."""

    def __init__(self, path: str = "README.md"):
        self.path = path

    def propose(self, *, user_goal, tool_schemas, history, tool_results):
        if history:
            return None
        return {"tool": "secure_read_file", "arguments": {"path": self.path}}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gateway-url", help="Send tool calls to this Gateway.")
    args = parser.parse_args()
    adapter = SecureToolAdapter(args.gateway_url) if args.gateway_url else None
    result = AgentLoop(MockLLM(), task_id="task-demo-001", adapter=adapter).run(
        "README.md dosyasını oku."
    )
    print(json.dumps({
        "steps": result.steps,
        "stop_reason": result.stop_reason,
        "tool_calls": [call.model_dump(mode="json") for call in result.tool_calls],
        "tool_results": [item.model_dump(mode="json") for item in result.tool_results],
        "error": result.error,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
