"""Check the internal permit boundary and the Gateway HTTP dispatch."""

import os
import socket
import time
from pathlib import Path
from threading import Thread

import pytest
import uvicorn
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from fastapi.testclient import TestClient

from secure_agent.common.schemas import parse_tool_call
from secure_agent.execution.service import ExecutionRequest, create_compose_executor
from secure_agent.gateway.deployment import create_compose_gateway


ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(
    os.name == "nt",
    reason="The executor HTTP demo uses POSIX filesystem primitives.",
)


@pytest.fixture
def signed_demo(tmp_path, monkeypatch, permit_material):
    key, issuer, _ = permit_material
    private_path = tmp_path / "private.pem"
    private_path.write_bytes(
        key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()),
    )
    private_path.chmod(0o600)
    public_path = tmp_path / "public.pem"
    public_path.write_bytes(key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo,
    ))
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "README.md").write_text(
        "# Demo\nAPI_KEY=executor-synthetic-secret\n", encoding="utf-8",
    )
    monkeypatch.setenv("DEMO_PRIVATE_KEY_FILE", str(private_path))
    monkeypatch.setenv("DEMO_CONFIG_DIR", str(ROOT / "configs"))
    monkeypatch.setenv("EXECUTOR_PUBLIC_KEY_FILE", str(public_path))
    monkeypatch.setenv("EXECUTOR_WORKSPACE", str(workspace))
    monkeypatch.setenv("EXECUTOR_NONCE_DB", str(tmp_path / "executor-nonce.db"))
    monkeypatch.setenv("AUDIT_DB_PATH", str(tmp_path / "audit.db"))
    call = parse_tool_call({
        "request_id": "readme-request",
        "task_id": "task-demo-001",
        "tool": "secure_read_file",
        "arguments": {"path": "README.md"},
    })
    return call, issuer


def test_executor_rejects_missing_and_replayed_permits(signed_demo):
    call, issuer = signed_demo
    unsigned = ExecutionRequest(call=call).model_dump_json()
    signed = ExecutionRequest(call=call, permit=issuer.issue(call)).model_dump_json()
    with TestClient(create_compose_executor()) as client:
        assert client.post("/execute", content=unsigned).status_code == 403
        assert client.post("/execute", content=signed).status_code == 200
    with TestClient(create_compose_executor()) as restarted:
        assert restarted.post("/execute", content=signed).status_code == 403


def test_gateway_protects_result_from_http_executor(signed_demo, monkeypatch, caplog):
    call, _ = signed_demo
    executor = create_compose_executor()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        monkeypatch.setenv("EXECUTOR_URL", f"http://127.0.0.1:{port}")
        server = uvicorn.Server(uvicorn.Config(
            executor, log_level="error", access_log=False,
        ))
        thread = Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while not server.started and thread.is_alive() and time.monotonic() < deadline:
                time.sleep(0.01)
            assert server.started, "Executor HTTP service did not start."
            with TestClient(create_compose_gateway()) as gateway:
                response = gateway.post("/tools/execute", json=call.model_dump(mode="json"))
            assert response.status_code == 200
            result = response.json()
            assert result["status"] == "success"
            assert result["request_id"] == call.request_id
            assert "API_KEY=[REDACTED]" in result["output"]
            assert "executor-synthetic-secret" not in response.text
            assert "executor-synthetic-secret" not in caplog.text
        finally:
            server.should_exit = True
            thread.join(timeout=5)
        assert not thread.is_alive()
