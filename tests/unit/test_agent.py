

from http.client import IncompleteRead
from io import BytesIO
import json
from types import SimpleNamespace
from urllib.error import HTTPError, URLError

import pytest
from pydantic import ValidationError

from agent.agent_loop import AgentLoop, MockLLM
from agent.tool_adapter import GatewayError, MAX_RESPONSE_BYTES, SecureToolAdapter
from agent.tools import UnsupportedToolError, get_tool_schemas, make_tool_call
from secure_agent.common.schemas import ReadFileToolCall, parse_tool_call_json
from secure_agent.security.result_protection import DEFAULT_MAX_OUTPUT_BYTES


class GatewayResponse(BytesIO):
    status = 200

    def __init__(self, body):
        super().__init__(body)
        self.length = len(body)


@pytest.fixture
def gateway_transport(monkeypatch):
    def install(open_request):
        monkeypatch.setattr("agent.tool_adapter.build_opener",
                            lambda handler: SimpleNamespace(open=open_request))
    return install


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
        def propose(self, *, user_goal, tool_schemas, history, tool_results):
            assert user_goal == "Dosyayı oku."
            assert len(tool_schemas) == 4
            assert tool_results == ()
            if history:
                assert len(history) == 1
                assert history[0].tool == "secure_read_file"
            return super().propose(
                user_goal=user_goal, tool_schemas=tool_schemas, history=history,
                tool_results=tool_results,
            )

    loop = AgentLoop(ObservingModel(), task_id="task-001")
    first = loop.run("Dosyayı oku.")
    second = loop.run("Dosyayı oku.")
    assert len(first.tool_calls) == len(second.tool_calls) == 1
    assert first.tool_calls[0].request_id != second.tool_calls[0].request_id


@pytest.fixture
def gateway_response(gateway_transport):
    """Capture HTTP requests and return the shared Gateway result contract."""
    requests = []

    def respond(request, *, timeout):
        payload = json.loads(request.data)
        requests.append((request, payload, timeout))
        return GatewayResponse(json.dumps({
            "request_id": payload["request_id"],
            "status": "success",
            "output": "Gateway sonucu: çalışma",
            "source_id": "source-001",
            "trust_level": "untrusted",
        }, ensure_ascii=False).encode("utf-8"))

    gateway_transport(respond)
    return requests


@pytest.mark.parametrize("tool, arguments", [
    ("secure_list_files", {"path": "."}),
    ("secure_read_file", {"path": "notlar/çalışma.py"}),
    ("secure_edit_file", {"path": "src/login.py", "content": "# Türkçe\n"}),
    ("secure_run_tests", {"profile_id": "unit"}),
])
def test_all_four_tools_go_through_gateway(gateway_response, tool, arguments):
    result = AgentLoop(
        RepeatingModel({"tool": tool, "arguments": arguments}),
        task_id="task-001", max_steps=1,
        adapter=SecureToolAdapter("http://gateway:8000/", timeout=2),
    ).run("İzinli işlemi yap.")

    assert len(gateway_response) == 1
    request, payload, timeout = gateway_response[0]
    assert request.full_url == "http://gateway:8000/tools/execute"
    assert request.get_method() == "POST"
    assert request.get_header("Content-type") == "application/json"
    assert timeout == 2
    assert payload == result.tool_calls[0].model_dump(mode="json")
    assert payload["tool"] == tool
    assert payload["arguments"] == arguments
    assert result.tool_results[0].request_id == payload["request_id"]
    assert result.tool_results[0].output == "Gateway sonucu: çalışma"
    assert result.tool_results[0].trust_level == "untrusted"
    assert result.error is None


def test_gateway_results_reach_model_and_runs_start_fresh(gateway_response):
    class ObservingModel(MockLLM):
        def propose(self, *, user_goal, tool_schemas, history, tool_results):
            assert len(tool_results) == len(history)
            if history:
                assert tool_results[0].request_id == history[0].request_id
                assert tool_results[0].output == "Gateway sonucu: çalışma"
            return super().propose(
                user_goal=user_goal, tool_schemas=tool_schemas,
                history=history, tool_results=tool_results,
            )

    loop = AgentLoop(ObservingModel(), task_id="task-001", adapter=SecureToolAdapter())
    for _ in range(2):
        result = loop.run("README.md dosyasını oku.")
        assert result.stop_reason == "model_finished"
        assert len(result.tool_results) == 1


@pytest.mark.parametrize("failure, expected", [
    (TimeoutError(), "timed out"),
    (URLError(TimeoutError()), "timed out"),
    (URLError("Connection refused"), "connection failed"),
    (ConnectionResetError(), "connection failed"),
    (IncompleteRead(b"partial"), "connection failed"),
    (HTTPError("http://gateway/tools/execute", 422, "Invalid", {}, None), "HTTP 422"),
    (HTTPError("http://gateway/tools/execute", 501, "Unavailable", {}, None), "HTTP 501"),
    (HTTPError("http://gateway/tools/execute", 503, "Unavailable", {}, None), "HTTP 503"),
])
def test_gateway_failure_stops_agent_without_retry(gateway_transport, failure, expected):
    attempts = []

    def fail(request, *, timeout):
        attempts.append(request)
        raise failure

    gateway_transport(fail)
    model = RepeatingModel()
    result = AgentLoop(model, task_id="task-001", adapter=SecureToolAdapter()).run(
        "Dosyayı oku."
    )
    assert result.stop_reason == "gateway_error"
    assert expected in result.error
    assert result.steps == model.invocations == len(attempts) == 1
    assert len(result.tool_calls) == 1
    assert result.tool_results == ()


@pytest.mark.parametrize("body", [
    b"not JSON",
    b'{"status":"success"}',
    json.dumps({
        "request_id": "another-request", "status": "success", "output": "text",
        "source_id": "source-001", "trust_level": "untrusted",
    }).encode(),
])
def test_invalid_gateway_response_is_handled_by_agent(gateway_transport, body):
    gateway_transport(lambda request, timeout: GatewayResponse(body))
    result = AgentLoop(MockLLM(), task_id="task-001", adapter=SecureToolAdapter()).run(
        "Dosyayı oku."
    )
    assert result.stop_reason == "gateway_error"
    assert result.error
    assert result.tool_results == ()


def test_http_error_preserves_status_code(gateway_transport):
    def fail(request, *, timeout):
        raise HTTPError(request.full_url, 501, "Unavailable", {}, None)

    gateway_transport(fail)
    call = make_tool_call(
        {"tool": "secure_read_file", "arguments": {"path": "README.md"}},
        task_id="task-001",
    )
    with pytest.raises(GatewayError) as caught:
        SecureToolAdapter().execute(call)
    assert caught.value.status_code == 501


def test_schema_cache_is_isolated_between_model_turns():
    schemas = get_tool_schemas()
    schemas[0]["function"]["parameters"]["required"].clear()
    assert get_tool_schemas()[0]["function"]["parameters"]["required"] == ["path"]


@pytest.mark.parametrize("url", [
    "file:///tmp/data", "ftp://example.org", "http:///missing-host",
    "http://user:password@gateway", "https://gateway:bad",
    "https://gateway/path?override=1", "https://gateway/#fragment",
])
def test_invalid_gateway_endpoint_is_rejected(url):
    with pytest.raises(ValueError, match="Gateway"):
        SecureToolAdapter(url)


@pytest.mark.parametrize("fault", ["oversized_wire", "oversized_output", "short_body", "partial_status"])
def test_invalid_delivery_stops_before_exposure(gateway_transport, fault):
    requests = []

    def respond(request, *, timeout):
        requests.append(request.full_url)
        result = {
            "request_id": json.loads(request.data)["request_id"], "source_id": "source",
            "status": "success", "trust_level": "untrusted", "output": "OK",
        }
        if fault == "oversized_output":
            result["output"] = "ğ" * (DEFAULT_MAX_OUTPUT_BYTES // 2 + 1)
        body = json.dumps(result).encode()
        if fault == "oversized_wire":
            body += b" " * MAX_RESPONSE_BYTES
        response = GatewayResponse(body)
        if fault == "short_body":
            response.length += 1
        if fault == "partial_status":
            response.status = 206
        return response

    gateway_transport(respond)
    adapter = SecureToolAdapter(acknowledge_exposure=True)
    run = AgentLoop(MockLLM(), task_id="day6", adapter=adapter).run("Dosyayı oku.")
    assert requests == [adapter.url]
    assert run.stop_reason == "gateway_error" and run.steps == 1
    assert run.tool_results == ()
