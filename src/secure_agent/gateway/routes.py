"""HTTP route definitions for the Gateway service."""

import json
import sqlite3
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request, Response, status

from secure_agent.common.schemas import ToolCall, ToolResult
from secure_agent.provenance.models import ExposureReceipt


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
        orchestrator = request.app.state.orchestrator
        if orchestrator is not None:
            decision = orchestrator.evaluate(tool_call)
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
    from secure_agent.security.permit_issuer import PermitIssuer, PermitDeniedError
    from secure_agent.security.permit_verifier import PermitVerificationError

    def authorize(candidate):
        if candidate != tool_call:
            raise PermitDeniedError("Permit must match the evaluated call.")
        return decision

    try:
        permit = PermitIssuer(private_key=request.app.state.demo_private_key,
                              decision_provider=authorize).issue(tool_call)
    except (PermissionError, ValueError, TypeError) as error:
        raise HTTPException(status_code=403, detail="Permit issuance denied.") from error

    def record_verified():
        logger.log_permit_event(tool_call, permit.permit_id, outcome="verified")

    result_status = "success"
    try:
        logger.log_permit_event(tool_call, permit.permit_id, outcome="issued")
        output = executor.execute(tool_call, permit=permit, on_permit_verified=record_verified)
        if isinstance(output, TestRunResult):
            result_status = "success" if output.exit_code == 0 else "error"
            output = output.output
        elif isinstance(output, list):
            output = json.dumps(output, ensure_ascii=False)
        elif output is None:
            output = ""
    except sqlite3.Error as error:
        raise HTTPException(status_code=503, detail="Audit storage is unavailable.") from error
    except PermitVerificationError as error:
        try:
            logger.log_permit_event(tool_call, permit.permit_id, outcome="rejected")
        except sqlite3.Error as audit_error:
            raise HTTPException(status_code=503, detail="Audit storage is unavailable.") from audit_error
        raise HTTPException(status_code=403, detail="Permit verification denied.") from error
    except PermissionError:
        result_status, output = "denied", "Executor denied the operation."
    except Exception:
        result_status, output = "error", "Demo execution failed."
    result = ToolResult(
        request_id=tool_call.request_id, status=result_status, output=output,
        source_id=str(uuid4()), trust_level="untrusted",
    )
    try:
        return orchestrator.finalize_result(
            tool_call,
            result,
            provenance_recorder=request.app.state.provenance_recorder,
        )

    except sqlite3.Error as error:
        raise HTTPException(
            status_code=503,
            detail="Result storage is unavailable.",
        ) from error

    except (ValueError, TypeError) as error:
        raise HTTPException(
            status_code=503,
            detail="Tool result processing failed.",
        ) from error


@router.post("/tools/exposure", status_code=204, response_class=Response)
def record_exposure(receipt: ExposureReceipt, request: Request) -> Response:
    """Demo-only receipt acknowledgement, not proof of trust or task ownership."""
    if request.app.state.demo_executor is None:
        raise HTTPException(status_code=501, detail="Exposure acknowledgement is demo-only.")
    try:
        request.app.state.provenance_recorder.record_exposure(receipt)
    except ValueError as error:
        raise HTTPException(status_code=409, detail="Receipt does not match a stored read.") from error
    except sqlite3.Error as error:
        raise HTTPException(status_code=503, detail="Provenance storage is unavailable.") from error
    return Response(status_code=204)
