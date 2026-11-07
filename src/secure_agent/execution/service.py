"""Internal HTTP entry point for the permit-gated README executor."""

from __future__ import annotations

import os
from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_public_key
from fastapi import FastAPI, HTTPException, Request
from pydantic import ValidationError
from starlette.concurrency import run_in_threadpool

from secure_agent.common.schemas import (
    ContractModel,
    NonEmptyText,
    Permit,
    ReadFileToolCall,
)
from secure_agent.execution.executor import Executor
from secure_agent.security.permit_verifier import PermitVerifier
from secure_agent.tasks.registry import RegistryError, create_readme_demo_registry


MAX_EXECUTION_REQUEST_BYTES = 64 * 1024
# A 1 MiB file can expand to six bytes per byte when escaped as JSON.
MAX_EXECUTION_RESPONSE_BYTES = 7 * 1024 * 1024


class ExecutionRequest(ContractModel):
    call: ReadFileToolCall
    permit: Permit | None = None


class ExecutionResponse(ContractModel):
    request_id: NonEmptyText
    output: str


def create_executor_app(executor: Executor) -> FastAPI:
    """Dispatch reads through Executor.execute, including its permit check."""
    app = FastAPI(title="Internal README Executor", docs_url=None, redoc_url=None,
                  openapi_url=None)

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/execute", response_model=ExecutionResponse)
    async def execute(request: Request) -> ExecutionResponse:
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > MAX_EXECUTION_REQUEST_BYTES:
                raise HTTPException(413, "Executor request is too large.")
            body.extend(chunk)

        try:
            payload = ExecutionRequest.model_validate_json(body)
        except ValidationError:
            raise HTTPException(422, "Invalid executor request.") from None

        try:
            output = await run_in_threadpool(
                executor.execute, payload.call, permit=payload.permit,
            )
        except (PermissionError, RegistryError):
            raise HTTPException(403, "Executor authorization denied.") from None
        except (OSError, ValueError):
            raise HTTPException(503, "Executor read failed.") from None
        if not isinstance(output, str):
            raise HTTPException(503, "Executor returned an invalid read result.")
        return ExecutionResponse(request_id=payload.call.request_id, output=output)

    return app


def create_compose_executor() -> FastAPI:
    """Build the internal service with a public key and persistent nonce ledger."""
    public_key = Path(os.environ.get(
        "EXECUTOR_PUBLIC_KEY_FILE", "/app/verifier/public.pem",
    ))
    workspace = Path(os.environ.get("EXECUTOR_WORKSPACE", "/workspace"))
    nonce_db = Path(os.environ.get("EXECUTOR_NONCE_DB", "/app/state/nonce.db"))
    verifier = PermitVerifier(load_pem_public_key(public_key.read_bytes()), nonce_db)
    executor = Executor(
        registry=create_readme_demo_registry(),
        workspace_roots={"demo": workspace},
        permit_verifier=verifier,
    )
    return create_executor_app(executor)
