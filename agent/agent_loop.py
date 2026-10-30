"""Day 1 bounded mock agent loop; creates tool requests without executing them.

From the repository root, set PYTHONPATH=src and run:
    python -m agent.agent_loop
"""

from dataclasses import dataclass
import json
from typing import Any, Literal, Protocol

from pydantic import TypeAdapter

from secure_agent.common.schemas import NonEmptyText, ToolCall

from .tools import get_tool_schemas, make_tool_call


class ToolCallingModel(Protocol):
    """Minimal model interface; None signals that no further call is needed."""

    def propose(
        self,
        *,
        user_goal: str,
        tool_schemas: list[dict[str, Any]],
        history: tuple[ToolCall, ...],
    ) -> dict[str, Any] | None:
        ...


@dataclass(frozen=True)
class AgentRun:
    tool_calls: tuple[ToolCall, ...]
    steps: int
    stop_reason: Literal["model_finished", "max_steps"]


class AgentLoop:
    """Generate validated ToolCalls within a fixed model-invocation budget.

    Unsupported tools and invalid proposals raise validation errors immediately.
    A run has fresh history. The model receives previously generated requests,
    not fabricated tool results; this Day 1 loop does not execute any request.
    """

    def __init__(self, model: ToolCallingModel, *, task_id: str, max_steps: int = 3):
        if isinstance(max_steps, bool) or not isinstance(max_steps, int) or max_steps < 1:
            raise ValueError("max_steps must be a positive integer.")
        self.model = model
        self.task_id = TypeAdapter(NonEmptyText).validate_python(task_id, strict=True)
        self.max_steps = max_steps

    def run(self, user_goal: str) -> AgentRun:
        goal = TypeAdapter(NonEmptyText).validate_python(user_goal, strict=True)
        calls: list[ToolCall] = []
        for step in range(1, self.max_steps + 1):
            proposal = self.model.propose(
                user_goal=goal,
                tool_schemas=get_tool_schemas(),
                history=tuple(calls),
            )
            if proposal is None:
                return AgentRun(tuple(calls), step, "model_finished")
            calls.append(make_tool_call(proposal, task_id=self.task_id))
        return AgentRun(tuple(calls), self.max_steps, "max_steps")


class MockLLM:
    """Propose one read request, then stop; does not interpret the user goal."""

    def __init__(self, path: str = "README.md"):
        self.path = path

    def propose(self, *, user_goal, tool_schemas, history):
        if history:
            return None
        return {"tool": "secure_read_file", "arguments": {"path": self.path}}


def main() -> None:
    result = AgentLoop(MockLLM(), task_id="task-demo-001").run(
        "README.md dosyasını oku."
    )
    print(json.dumps({
        "steps": result.steps,
        "stop_reason": result.stop_reason,
        "tool_calls": [call.model_dump(mode="json") for call in result.tool_calls],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
