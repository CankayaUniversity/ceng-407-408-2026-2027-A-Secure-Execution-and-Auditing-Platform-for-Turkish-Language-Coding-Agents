"""HTTP route definitions for the Gateway service."""

from fastapi import APIRouter, HTTPException, status

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
async def execute_tool(tool_call: ToolCall) -> None:
    """Validate the shared ToolCall contract without executing the request.

    FastAPI validates the discriminated ToolCall union before invoking this
    handler. Actual execution must remain disabled until authorization,
    permit verification, and sandbox routing are integrated.
    """
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Tool execution requires the authorization pipeline.",
    )
