"""Bounded agent loop with optional Gateway tool execution.

From the repository root, set PYTHONPATH=src and run:
    python -m agent.agent_loop
    python -m agent.agent_loop --llm-mode real --max-steps 1
    python -m agent.agent_loop --gateway-url http://127.0.0.1:8000

Real mode requires LLM_BASE_URL and LLM_MODEL; LLM_API_KEY is optional.
"""

import argparse
from dataclasses import dataclass
import json
from typing import Any, Literal, Protocol

from pydantic import TypeAdapter, ValidationError

from secure_agent.common.schemas import NonEmptyText, ToolCall, ToolResult

from .llm_client import LLMClient, LLMConfig, LLMError, LLMTimeout
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
    stop_reason: Literal[
        "model_finished", "max_steps", "gateway_error", "tool_error", "tool_denied",
        "tool_review", "llm_timeout", "llm_error"
    ]
    tool_results: tuple[ToolResult, ...] = ()
    error: str | None = None


class AgentLoop:
    """Each step takes one model turn or retries one failed read-only call.

    Unsupported tools and invalid proposals from custom/mock models raise
    validation errors immediately. Real-client failures stop with llm_error or
    llm_timeout, before dispatching an invalid call.
    A run has fresh history. With an adapter, calls go only through the Gateway
    and its validated results are passed to the model. Without an adapter,
    only requests are generated; no operation is executed.
    Only an explicit error result for a read or list operation permits a retry.
    Transport failures can occur after execution and terminate the run.
    """

    def __init__(
        self,
        model: ToolCallingModel,
        *,
        task_id: str,
        max_steps: int = 3,
        max_retries: int = 1,
        adapter: SecureToolAdapter | None = None,
    ):
        if isinstance(max_steps, bool) or not isinstance(max_steps, int) or max_steps < 1:
            raise ValueError("max_steps must be a positive integer.")
        if type(max_retries) is not int or max_retries < 0:
            raise ValueError("max_retries must be a non-negative integer.")
        self.model = model
        self.task_id = TypeAdapter(NonEmptyText).validate_python(task_id, strict=True)
        self.max_steps = max_steps
        self.max_retries = max_retries
        self.adapter = adapter

    def run(self, user_goal: str) -> AgentRun:
        goal = TypeAdapter(NonEmptyText).validate_python(user_goal, strict=True)
        calls: list[ToolCall] = []
        results: list[ToolResult] = []
        retries = 0
        for step in range(1, self.max_steps + 1):
            if retries:
                # Re-authorize the same operation with a fresh request ID.
                proposal = calls[-1].model_dump(include={"tool", "arguments"})
            else:
                try:
                    proposal = self.model.propose(
                        user_goal=goal,
                        tool_schemas=get_tool_schemas(),
                        history=tuple(calls),
                        tool_results=tuple(results),
                    )
                except LLMTimeout as error:
                    return AgentRun(tuple(calls), step, "llm_timeout", tuple(results), str(error))
                except LLMError as error:
                    return AgentRun(tuple(calls), step, "llm_error", tuple(results), str(error))
                if proposal is None:
                    return AgentRun(tuple(calls), step, "model_finished", tuple(results))
            call = make_tool_call(proposal, task_id=self.task_id)
            calls.append(call)
            if self.adapter is None:
                continue
            try:
                result = ToolResult.model_validate(self.adapter.execute(call))
                if result.request_id != call.request_id:
                    raise GatewayError("Gateway response request_id does not match.")
            except ValidationError:
                return AgentRun(tuple(calls), step, "gateway_error", tuple(results),
                                "Gateway returned an invalid ToolResult.")
            except GatewayError as error:
                return AgentRun(tuple(calls), step, "gateway_error", tuple(results), str(error))

            results.append(result)
            if result.status == "success":
                retries = 0
            elif result.status == "denied":
                return AgentRun(tuple(calls), step, "tool_denied", tuple(results),
                                "Tool execution was denied.")
            elif result.status == "review":
                return AgentRun(tuple(calls), step, "tool_review", tuple(results),
                                "Tool execution requires review.")
            elif call.tool in {"secure_read_file", "secure_list_files"} and retries < self.max_retries:
                retries += 1
            else:
                return AgentRun(tuple(calls), step, "tool_error", tuple(results),
                                "Tool execution failed.")
        error = "Step limit reached after a tool failure." if retries else None
        return AgentRun(tuple(calls), self.max_steps, "max_steps", tuple(results), error)


class MockLLM:
    """Propose one read request, then stop; does not interpret the user goal."""

    def __init__(self, path: str = "README.md"):
        self.path = path

    def propose(self, *, user_goal, tool_schemas, history, tool_results):
        if history:
            return None
        return {"tool": "secure_read_file", "arguments": {"path": self.path}}


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog="Set LLM_API_KEY in the environment if the model service requires a key.",
    )
    parser.add_argument("--gateway-url", help="Send tool calls to this Gateway.")
    parser.add_argument("--acknowledge-exposure", action="store_true",
                        help="Acknowledge successful reads to the demo Gateway graph.")
    parser.add_argument("--llm-mode", choices=("mock", "real"), default="mock")
    parser.add_argument("--goal", default="README.md dosyasını oku.")
    parser.add_argument("--task-id", default="task-demo-001")
    parser.add_argument("--max-steps", type=int, default=3)
    parser.add_argument("--max-retries", type=int, default=1,
                        help="Maximum retries per failed read or list operation.")
    parser.add_argument(
        "--llm-base-url", help="Base API URL including its prefix (env: LLM_BASE_URL)."
    )
    parser.add_argument("--llm-model", help="Model supporting function tools (env: LLM_MODEL).")
    parser.add_argument(
        "--llm-timeout", type=float,
        help="Socket timeout in seconds (env: LLM_TIMEOUT_SECONDS; default: 30).",
    )
    args = parser.parse_args()
    try:
        if args.llm_mode == "real":
            model: ToolCallingModel = LLMClient(LLMConfig.from_env(
                base_url=args.llm_base_url,
                model=args.llm_model,
                timeout_seconds=args.llm_timeout,
            ))
        else:
            model = MockLLM()
        adapter = (SecureToolAdapter(args.gateway_url, acknowledge_exposure=args.acknowledge_exposure)
                   if args.gateway_url else None)
        loop = AgentLoop(model, task_id=args.task_id, max_steps=args.max_steps,
                         max_retries=args.max_retries, adapter=adapter)
        result = loop.run(args.goal)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps({
        "steps": result.steps,
        "stop_reason": result.stop_reason,
        "tool_calls": [call.model_dump(mode="json") for call in result.tool_calls],
        "tool_results": [item.model_dump(mode="json") for item in result.tool_results],
        "error": result.error,
    }, ensure_ascii=False, indent=2))
    return 1 if result.error is not None else 0


if __name__ == "__main__":
    raise SystemExit(main())
