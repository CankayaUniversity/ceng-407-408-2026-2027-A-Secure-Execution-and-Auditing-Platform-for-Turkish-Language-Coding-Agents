import json

import httpx
import pytest

from secure_agent.security.gemini_client import GeminiClient
from secure_agent.security.supervisor import parse_supervisor_response


def make_client(tmp_path, monkeypatch, handler):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    env = tmp_path / ".env"
    env.write_text("GEMINI_API_KEY=test-key\n", encoding="utf-8")
    client = GeminiClient(model="gemini-test", env_file=env)
    client._client.close()
    client._client = httpx.Client(transport=httpx.MockTransport(handler),
                                headers={"x-goog-api-key": "test-key"})
    return client


def test_structured_verdict_and_prompt_separation(tmp_path, monkeypatch):
    def handler(request):
        assert request.headers["x-goog-api-key"] == "test-key"
        assert "test-key" not in str(request.url)
        body = json.loads(request.content)
        assert body["systemInstruction"]["parts"][0]["text"] == "trusted rules"
        assert body["contents"][0]["parts"][0]["text"] == "untrusted input"
        assert "tools" not in body
        assert body["generationConfig"]["responseMimeType"] == "application/json"
        return httpx.Response(200, json={"candidates": [{"finishReason": "STOP", "content": {
            "parts": [{"text": '{"verdict":"ALIGNED","reason":"Relevant read."}'}]}}]})

    client = make_client(tmp_path, monkeypatch, handler)
    try:
        result = parse_supervisor_response(client.complete(system_prompt="trusted rules", user_prompt="untrusted input"))
        assert result.verdict == "ALIGNED"
    finally:
        client.close()


@pytest.mark.parametrize("status,body", [
    (429, {"error": "test-key"}),
    (200, {"candidates": []}),
    (200, {"candidates": [{"finishReason": "MAX_TOKENS"}]}),
    (200, {"candidates": [{"finishReason": "SAFETY"}]}),
])
def test_provider_failures_do_not_return_a_verdict(tmp_path, monkeypatch, status, body):
    client = make_client(tmp_path, monkeypatch, lambda request: httpx.Response(status, json=body))
    try:
        with pytest.raises(ValueError) as error:
            client.complete(system_prompt="rules", user_prompt="input")
        assert "test-key" not in str(error.value)
    finally:
        client.close()


def test_missing_key_fails_at_startup(tmp_path, monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        GeminiClient(model="gemini-test", env_file=tmp_path / "missing.env")


def test_timeout_does_not_leak_request_details(tmp_path, monkeypatch):
    def handler(request):
        raise httpx.ReadTimeout("test-key", request=request)

    client = make_client(tmp_path, monkeypatch, handler)
    try:
        with pytest.raises(ValueError) as error:
            client.complete(system_prompt="rules", user_prompt="input")
        assert "test-key" not in str(error.value)
    finally:
        client.close()
