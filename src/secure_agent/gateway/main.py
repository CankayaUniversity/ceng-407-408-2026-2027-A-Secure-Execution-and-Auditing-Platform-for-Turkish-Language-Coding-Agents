
"""Application entry point for the Gateway HTTP API."""

from fastapi import FastAPI

from secure_agent.gateway.routes import router

app = FastAPI(
    title="Secure Coding Agent Gateway",
    version="0.1.0",
)

app.include_router(router)
