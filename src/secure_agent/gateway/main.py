"""Application entry point for the Gateway HTTP API."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI

from secure_agent.audit.logger import AuditLogger
from secure_agent.audit.repository import AuditRepository
from secure_agent.gateway.routes import router


if TYPE_CHECKING:
    from secure_agent.security.policy_engine import PolicyEngine
    from secure_agent.execution.executor import Executor


def create_app(
    database_path: str | Path | None = None, *,
    policy_engine: PolicyEngine | None = None,
    demo_executor: Executor | None = None,
) -> FastAPI:
    """Create a Gateway with file-backed audit storage."""
    if demo_executor is not None and policy_engine is None:
        raise ValueError("Demo execution requires a trusted policy engine.")
    path = Path(database_path or os.getenv("AUDIT_DB_PATH", "data/audit.db"))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        path.parent.mkdir(parents=True, exist_ok=True)
        app.state.audit_logger = AuditLogger(AuditRepository(path))
        app.state.policy_engine = policy_engine
        app.state.demo_executor = demo_executor
        yield

    app = FastAPI(
        title="Secure Coding Agent Gateway",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(router)
    return app


app = create_app()
