"""Application entry point for the Gateway HTTP API."""

import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from secure_agent.audit.logger import AuditLogger
from secure_agent.audit.repository import AuditRepository
from secure_agent.gateway.routes import router


def create_app(database_path: str | Path | None = None) -> FastAPI:
    """Create a Gateway with file-backed audit storage."""
    path = Path(database_path or os.getenv("AUDIT_DB_PATH", "data/audit.db"))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        path.parent.mkdir(parents=True, exist_ok=True)
        app.state.audit_logger = AuditLogger(AuditRepository(path))
        yield

    app = FastAPI(
        title="Secure Coding Agent Gateway",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(router)
    return app


app = create_app()
