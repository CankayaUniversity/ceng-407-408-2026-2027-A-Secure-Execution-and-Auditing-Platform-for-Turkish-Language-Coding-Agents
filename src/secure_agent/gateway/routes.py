"""HTTP route definitions for the Gateway service."""

import json
import sqlite3
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, status

from secure_agent.common.schemas import SecurityDecision, ToolCall, ToolResult


router = APIRouter()


@router.get("/health", status_code=status.HTTP_200_OK, tags=["Health"])
async def health_check() -> dict[str, str]:
    """Report whether the Gateway HTTP application is responsive."""
    return {"status": "ok"}


@router.post(
    "/tools/execute",
    response_model=ToolResult,
    tags=["Tools"],
)
def execute_tool(tool_call: ToolCall, request: Request) -> ToolResult:
    """Audit and evaluate requests; execution is explicit isolated-demo only."""
    decision = None
    try:
        logger = request.app.state.audit_logger
        logger.log_tool_call_received(tool_call)
        policy = request.app.state.policy_engine
        if policy is not None:
            try:
                decision = SecurityDecision.model_validate(policy.evaluate(tool_call))
            except Exception:
                decision = SecurityDecision(
                    decision="DENY", reason_code="POLICY_EVALUATION_ERROR",
                )
            logger.log_security_decision(tool_call, decision)
    except sqlite3.Error as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Audit storage is unavailable.",
        ) from error
    if decision is not None and decision.decision != "ALLOW":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=decision.reason_code,
        )
    executor = request.app.state.demo_executor
    if executor is None or decision is None:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Tool execution requires the authorization pipeline.",
        )

    # Default Gateway has no executor; this branch is for isolated demos only.
    from secure_agent.execution.test_runner import TestRunResult

    result_status = "success"
    try:
        output = executor.execute(tool_call)
        if isinstance(output, TestRunResult):
            result_status = "success" if output.exit_code == 0 else "error"
            output = output.output
        elif isinstance(output, list):
            output = json.dumps(output, ensure_ascii=False)
        elif output is None:
            output = ""
    except PermissionError:
        result_status, output = "denied", "Executor denied the operation."
    except Exception:
        result_status, output = "error", "Demo execution failed."
    result = ToolResult(
        request_id=tool_call.request_id, status=result_status, output=output,
        source_id=str(uuid4()), trust_level="untrusted",
    )
    try:
        logger.log_tool_result(result)
    except sqlite3.Error as error:
        raise HTTPException(status_code=503, detail="Audit storage is unavailable.") from error
    return result
