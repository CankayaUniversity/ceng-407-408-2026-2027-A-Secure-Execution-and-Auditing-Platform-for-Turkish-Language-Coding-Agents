"""Provider selection must be explicit and preserve fail-closed startup."""

from unittest.mock import Mock

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from secure_agent.gateway import deployment
from secure_agent.security import gemini_client


def configure_factory(monkeypatch):
    captured = {}
    monkeypatch.setattr(deployment, "PolicyEngine", lambda **kwargs: object())
    monkeypatch.setattr(deployment, "load_ed25519_private_key", lambda path: object())

    def create_app(**kwargs):
        captured.update(kwargs)
        return FastAPI()

    monkeypatch.setattr(deployment, "create_app", create_app)
    return captured


def test_fixture_startup_does_not_construct_a_network_provider(monkeypatch):
    captured = configure_factory(monkeypatch)
    monkeypatch.delenv("SUPERVISOR_PROVIDER", raising=False)
    client = Mock(side_effect=AssertionError("Unexpected live provider"))
    monkeypatch.setattr(gemini_client, "GeminiClient", client)
    with TestClient(deployment.create_compose_gateway()):
        assert isinstance(captured["supervisor"], deployment.ReadmeDemoSupervisor)
    client.assert_not_called()


def test_gemini_uses_registered_task_and_closes_on_shutdown(monkeypatch):
    captured = configure_factory(monkeypatch)
    monkeypatch.setenv("SUPERVISOR_PROVIDER", "gemini")
    monkeypatch.setenv("GEMINI_MODEL", "gemini-test")
    monkeypatch.setenv("GEMINI_ENV_FILE", "/run/secrets/test.env")
    client = Mock()
    client.complete.return_value = '{"verdict":"ALIGNED","reason":"Relevant read."}'
    factory = Mock(return_value=client)
    monkeypatch.setattr(gemini_client, "GeminiClient", factory)
    with TestClient(deployment.create_compose_gateway()):
        result = captured["supervisor"].evaluate(task_id="task-demo-001", tool_call={
            "request_id": "provider-check", "task_id": "task-demo-001",
            "tool": "secure_read_file", "arguments": {"path": "README.md"},
        })
        assert result.verdict == "ALIGNED"
        client.close.assert_not_called()
    factory.assert_called_once_with(model="gemini-test", env_file="/run/secrets/test.env")
    client.close.assert_called_once_with()


def test_missing_gemini_key_fails_startup(tmp_path, monkeypatch):
    configure_factory(monkeypatch)
    monkeypatch.setenv("SUPERVISOR_PROVIDER", "gemini")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_ENV_FILE", str(tmp_path / "missing.env"))
    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        deployment.create_compose_gateway()


def test_unknown_provider_cannot_fall_back_to_fixture(monkeypatch):
    monkeypatch.setenv("SUPERVISOR_PROVIDER", "unknown")
    with pytest.raises(ValueError, match="SUPERVISOR_PROVIDER"):
        deployment.create_compose_gateway()
