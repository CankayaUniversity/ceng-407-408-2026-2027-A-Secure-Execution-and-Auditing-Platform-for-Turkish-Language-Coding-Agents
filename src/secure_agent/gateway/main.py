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
from secure_agent.gateway.orchestrator import SecurityOrchestrator
from secure_agent.security.supervisor import Supervisor


if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from secure_agent.gateway.deployment import ReadOnlyExecutorClient, ReadmeDemoSupervisor
    from secure_agent.security.policy_engine import PolicyEngine
    from secure_agent.execution.executor import Executor


def create_app(
    database_path: str | Path | None = None, *,
    policy_engine: PolicyEngine | None = None,
    demo_executor: Executor | ReadOnlyExecutorClient | None = None,
    supervisor: Supervisor | ReadmeDemoSupervisor | None = None,
    demo_private_key: Ed25519PrivateKey | None = None,
) -> FastAPI:
    """Create a Gateway with file-backed audit storage."""
    if demo_executor is not None and policy_engine is None:
        raise ValueError("Demo execution requires a trusted policy engine.")
    if demo_executor is not None and demo_private_key is None:
        raise ValueError("Demo execution requires a trusted signing key.")
    path = Path(database_path or os.getenv("AUDIT_DB_PATH", "data/audit.db"))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        path.parent.mkdir(parents=True, exist_ok=True)
        app.state.audit_logger = AuditLogger(AuditRepository(path))
        app.state.demo_executor = demo_executor
        app.state.demo_private_key = demo_private_key
        app.state.provenance_recorder = None
        graph_provider = None
        if policy_engine is not None:
            from secure_agent.provenance.repository import ProvenanceRepository
            from secure_agent.provenance.recorder import ProvenanceRecorder
            from secure_agent.provenance.inspector import GraphInspector

            graph_path = path.with_name(path.stem + "-provenance.db")
            recorder = ProvenanceRecorder(ProvenanceRepository(graph_path), app.state.audit_logger)
            app.state.provenance_recorder = recorder
            inspector = GraphInspector()
            graph_provider = lambda call: inspector.inspect(call, recorder.snapshot())
        app.state.orchestrator = (
            SecurityOrchestrator(policy_engine, supervisor, app.state.audit_logger, graph_provider)
            if policy_engine is not None else None
        )
        yield

    app = FastAPI(
        title="Secure Coding Agent Gateway",
        version="0.1.0",
        lifespan=lifespan,
    )
    app.include_router(router)
    return app


app = create_app()
