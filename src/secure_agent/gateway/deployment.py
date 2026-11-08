"""Compose bootstrap for the signed, read-only README demo."""

from __future__ import annotations

import os
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI
from pydantic import ValidationError

from secure_agent.common.schemas import Permit, ReadFileToolCall, ToolCall
from secure_agent.execution.service import (
    MAX_EXECUTION_RESPONSE_BYTES,
    ExecutionRequest,
    ExecutionResponse,
)
from secure_agent.gateway.main import create_app
from secure_agent.security.permit_issuer import load_ed25519_private_key
from secure_agent.security.permit_verifier import PermitVerificationError
from secure_agent.security.policy_engine import PolicyEngine
from secure_agent.security.supervisor import Supervisor, SupervisorDecision
from secure_agent.tasks.registry import create_readme_demo_registry


class ReadOnlyExecutorClient:
    """Forward a signed read to the internal executor without retries."""

    def __init__(self, url: str) -> None:
        self._url = url.rstrip("/") + "/execute"

    def execute(
        self,
        payload: object,
        *,
        permit: object = None,
        on_permit_verified: Callable[[], None] | None = None,
    ) -> str:
        if permit is None:
            raise PermitVerificationError("Execution requires a signed permit.")
        request = ExecutionRequest(
            call=ReadFileToolCall.model_validate(payload),
            permit=Permit.model_validate(permit),
        )
        try:
            with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
                with client.stream(
                    "POST",
                    self._url,
                    content=request.model_dump_json().encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                ) as response:
                    if response.status_code == 403:
                        raise PermitVerificationError("Executor authorization denied.")
                    response.raise_for_status()
                    body = bytearray()
                    for chunk in response.iter_bytes(chunk_size=64 * 1024):
                        if len(body) + len(chunk) > MAX_EXECUTION_RESPONSE_BYTES:
                            raise RuntimeError("Executor response is too large.")
                        body.extend(chunk)
            result = ExecutionResponse.model_validate_json(body)
        except (httpx.HTTPError, ValidationError):
            raise RuntimeError("Executor transport failed.") from None

        if result.request_id != request.call.request_id:
            raise RuntimeError("Executor returned a mismatched request ID.")
        # Remote verification is acknowledged after the read completes.
        if on_permit_verified is not None:
            on_permit_verified()
        return result.output


class ReadmeDemoSupervisor:
    """Match the fixed demo operation without a model-provider dependency."""

    def evaluate(self, *, task_id: str, tool_call: ToolCall) -> SupervisorDecision:
        if (
            task_id == tool_call.task_id == "task-demo-001"
            and isinstance(tool_call, ReadFileToolCall)
            and tool_call.arguments.path == "README.md"
        ):
            return SupervisorDecision(
                verdict="ALIGNED",
                reason="The fixed demo task reads README.md.",
                reason_code="SUPERVISOR_ALIGNED",
            )
        return SupervisorDecision(
            verdict="MISALIGNED",
            reason="The operation falls outside the fixed demo task.",
            reason_code="SUPERVISOR_MISALIGNED",
        )


def create_compose_gateway() -> FastAPI:
    """Enable the Gateway demo using a private signing key and remote executor."""
    provider = os.environ.get("SUPERVISOR_PROVIDER", "fixture")
    if provider not in {"fixture", "gemini"}:
        raise ValueError("SUPERVISOR_PROVIDER must be fixture or gemini.")
    registry = create_readme_demo_registry()
    config_dir = Path(os.environ.get("DEMO_CONFIG_DIR", "/app/configs"))
    policy = PolicyEngine(
        registry=registry,
        model_path=config_dir / "casbin_model.conf",
        policy_path=config_dir / "casbin_policy.csv",
    )
    key = load_ed25519_private_key(os.environ.get(
        "DEMO_PRIVATE_KEY_FILE", "/app/issuer/private.pem",
    ))
    client = None
    supervisor = ReadmeDemoSupervisor()
    if provider == "gemini":
        from secure_agent.security.gemini_client import DEFAULT_MODEL, GeminiClient

        client = GeminiClient(model=os.environ.get("GEMINI_MODEL", DEFAULT_MODEL),
                              env_file=os.environ.get("GEMINI_ENV_FILE"))
        supervisor = Supervisor(registry=registry, llm_client=client)
    app = create_app(
        policy_engine=policy,
        supervisor=supervisor,
        demo_executor=ReadOnlyExecutorClient(
            os.environ.get("EXECUTOR_URL", "http://executor:8001"),
        ),
        demo_private_key=key,
    )
    if client is not None:
        original_lifespan = app.router.lifespan_context

        @asynccontextmanager
        async def lifespan(application):
            try:
                async with original_lifespan(application):
                    yield
            finally:
                client.close()

        app.router.lifespan_context = lifespan
    return app
