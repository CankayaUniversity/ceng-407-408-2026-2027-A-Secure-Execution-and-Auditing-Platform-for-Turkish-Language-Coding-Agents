"""Person 2 Day 1 checks; no LLM service, Gateway, or database is needed."""

import pytest
from pydantic import ValidationError

from agent.agent_loop import AgentLoop, MockLLM
from agent.tools import UnsupportedToolError, get_tool_schemas, make_tool_call
from secure_agent.common.schemas import ReadFileToolCall, parse_tool_call_json


def test_mock_agent_generates_a_shared_read_file_tool_call():
    result = AgentLoop(MockLLM(), task_id="task-001").run("README.md dosyasını oku.")

    assert result.stop_reason == "model_finished"
    assert result.steps == 2
    assert len(result.tool_calls) == 1
    call = result.tool_calls[0]
    assert isinstance(call, ReadFileToolCall)
    assert call.task_id == "task-001"
    assert call.tool == "secure_read_file"
    assert call.arguments.path == "README.md"
    assert call.request_id
    assert parse_tool_call_json(call.model_dump_json()) == call


@pytest.mark.parametrize(
    "name, required",
    [
        ("secure_list_files", ["path"]),
        ("secure_read_file", ["path"]),
        ("secure_edit_file", ["path", "content"]),
        ("secure_run_tests", ["profile_id"]),
    ],
)
def test_four_tool_schemas_follow_shared_argument_contracts(name, required):
    schemas = get_tool_schemas()
    assert len(schemas) == 4
    functions = {schema["function"]["name"]: schema["function"] for schema in schemas}
    parameters = functions[name]["parameters"]
    assert parameters["type"] == "object"
    assert parameters["required"] == required
    assert parameters["additionalProperties"] is False


class RepeatingModel:
    def __init__(self, proposal=None):
        self.proposal = proposal if proposal is not None else {
            "tool": "secure_read_file", "arguments": {"path": "README.md"}
        }
        self.invocations = 0

    def propose(self, **kwargs):
        self.invocations += 1
        return self.proposal


def test_unsupported_tool_is_rejected_immediately():
    model = RepeatingModel({"tool": "shell", "arguments": {"command": "anything"}})
    with pytest.raises(UnsupportedToolError, match="Unsupported tool"):
        AgentLoop(model, task_id="task-001").run("Bir işlem öner.")
    assert model.invocations == 1


@pytest.mark.parametrize("max_steps", [1, 3, 5])
def test_loop_stops_at_configured_step_limit(max_steps):
    model = RepeatingModel()
    result = AgentLoop(model, task_id="task-001", max_steps=max_steps).run("Dosyayı oku.")
    assert model.invocations == max_steps
    assert result.steps == max_steps
    assert result.stop_reason == "max_steps"
    assert len(result.tool_calls) == max_steps
    assert len({call.request_id for call in result.tool_calls}) == max_steps
    assert all(call.task_id == "task-001" for call in result.tool_calls)


@pytest.mark.parametrize("max_steps", [0, -1, True, 1.5])
def test_invalid_step_limits_are_rejected(max_steps):
    with pytest.raises(ValueError, match="positive integer"):
        AgentLoop(MockLLM(), task_id="task-001", max_steps=max_steps)


def test_model_can_finish_without_requesting_a_tool():
    class FinishedModel:
        def propose(self, **kwargs):
            return None

    result = AgentLoop(FinishedModel(), task_id="task-001").run("İşlem gerekmiyor.")
    assert result.tool_calls == ()
    assert result.steps == 1
    assert result.stop_reason == "model_finished"


@pytest.mark.parametrize(
    "proposal",
    [
        {"tool": "secure_read_file", "arguments": {}},
        {"tool": "secure_read_file", "arguments": {"path": "../secret.txt"}},
        {"tool": "secure_read_file", "arguments": {"path": "README.md"}, "task_id": "admin"},
        {"tool": "secure_read_file", "arguments": []},
    ],
)
def test_invalid_proposals_are_rejected_before_a_call_is_returned(proposal):
    with pytest.raises(ValidationError):
        AgentLoop(RepeatingModel(proposal), task_id="task-001").run("Dosyayı oku.")


@pytest.mark.parametrize(
    "tool, arguments",
    [
        ("secure_list_files", {"path": "."}),
        ("secure_read_file", {"path": "notlar/çalışma.py"}),
        ("secure_edit_file", {"path": "src/example.py", "content": ""}),
        ("secure_run_tests", {"profile_id": "unit"}),
    ],
)
def test_all_four_tools_build_the_existing_flat_tool_call_contract(tool, arguments):
    call = make_tool_call(
        {"tool": tool, "arguments": arguments},
        task_id="task-001", request_id="req-001",
    )
    assert call.model_dump(mode="json") == {
        "request_id": "req-001", "task_id": "task-001",
        "tool": tool, "arguments": arguments,
    }


def test_model_receives_goal_schemas_and_history_and_runs_start_fresh():
    class ObservingModel(MockLLM):
        def propose(self, *, user_goal, tool_schemas, history):
            assert user_goal == "Dosyayı oku."
            assert len(tool_schemas) == 4
            if history:
                assert len(history) == 1
                assert history[0].tool == "secure_read_file"
            return super().propose(
                user_goal=user_goal, tool_schemas=tool_schemas, history=history
            )

    loop = AgentLoop(ObservingModel(), task_id="task-001")
    first = loop.run("Dosyayı oku.")
    second = loop.run("Dosyayı oku.")
    assert len(first.tool_calls) == len(second.tool_calls) == 1
    assert first.tool_calls[0].request_id != second.tool_calls[0].request_id
