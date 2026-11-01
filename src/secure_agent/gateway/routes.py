"""HTTP route definitions for the Gateway service."""

import sqlite3

from fastapi import APIRouter, HTTPException, Request, status

from secure_agent.common.schemas import ToolCall


router = APIRouter()


@router.get("/health", status_code=status.HTTP_200_OK, tags=["Health"])
async def health_check() -> dict[str, str]:
    """Report whether the Gateway HTTP application is responsive."""
    return {"status": "ok"}


@router.post(
    "/tools/execute",
    status_code=status.HTTP_501_NOT_IMPLEMENTED,
    tags=["Tools"],
)
def execute_tool(tool_call: ToolCall, request: Request) -> None:
    """Validate the shared ToolCall contract without executing the request.

    FastAPI validates the discriminated ToolCall union before invoking this
    handler. Actual execution must remain disabled until authorization,
    permit verification, and sandbox routing are integrated.
    """
    try:
        request.app.state.audit_logger.log_tool_call_received(tool_call)
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit storage is unavailable.",
        ) from error
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Tool execution requires the authorization pipeline.",
    )
