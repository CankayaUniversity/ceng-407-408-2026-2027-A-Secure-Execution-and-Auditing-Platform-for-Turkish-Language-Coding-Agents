"""Create and persist audit events from validated tool requests."""

from datetime import datetime, timezone
from uuid import uuid4
from typing import Literal

from secure_agent.security.supervisor import SupervisorDecision
from secure_agent.provenance.models import ExposureReceipt, GraphAssessment

from secure_agent.audit.repository import AuditRepository
from secure_agent.common.schemas import AuditEvent, SecurityDecision, ToolCall, ToolResult, parse_tool_call


class AuditLogger:
    def __init__(self, repository: AuditRepository):
        self.repository = repository

    def log_tool_call_received(self, call: ToolCall) -> AuditEvent:
        """Record receipt only; storage errors propagate to the caller."""
        call = parse_tool_call(call)
        event = AuditEvent(
            event_id=str(uuid4()),
            request_id=call.request_id,
            metadata={"task_id": call.task_id, "tool": call.tool},
            event_type="tool_call_received",
            timestamp=datetime.now(timezone.utc),
        )
        self.repository.add(event)
        return event

    def log_security_decision(
        self, call: ToolCall, decision: SecurityDecision, *,
        event_type: Literal["policy_decision", "security_decision"] = "policy_decision",
    ) -> AuditEvent:
        """Record a policy verdict, not permission to execute a tool."""
        call = parse_tool_call(call)
        decision = SecurityDecision.model_validate(decision)
        arguments = call.arguments.model_dump(exclude={"content"})
        event = AuditEvent(
            event_id=str(uuid4()),
            request_id=call.request_id,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            metadata={
                "task_id": call.task_id,
                "tool": call.tool,
                "arguments": arguments,
                "decision": decision.decision,
                "reason_code": decision.reason_code,
            },
        )
        self.repository.add(event)
        return event

    def log_tool_result(self, result: ToolResult) -> AuditEvent:
        """Persist result metadata without logging untrusted output text."""
        result = ToolResult.model_validate(result)
        event = AuditEvent(
            event_id=str(uuid4()), request_id=result.request_id,
            event_type="tool_result", timestamp=datetime.now(timezone.utc),
            metadata={"status": result.status, "source_id": result.source_id,
                      "trust_level": result.trust_level},
        )
        self.repository.add(event)
        return event

    def log_supervisor_decision(
        self, call: ToolCall, decision: SupervisorDecision,
    ) -> AuditEvent:
        """Record verdict and trusted reason code, not raw LLM-generated text."""
        call = parse_tool_call(call)
        decision = SupervisorDecision.model_validate(decision)
        event = AuditEvent(
            event_id=str(uuid4()), request_id=call.request_id,
            event_type="supervisor_decision", timestamp=datetime.now(timezone.utc),
            metadata={"task_id": call.task_id, "tool": call.tool,
                      "verdict": decision.verdict, "reason_code": decision.reason_code},
        )
        self.repository.add(event)
        return event

    def log_graph_event(self, call: ToolCall, source_node_id: str,
                        result_node_id: str) -> AuditEvent:
        """Record graph identifiers without copying source contents."""
        call = parse_tool_call(call)
        event = AuditEvent(
            event_id=str(uuid4()), request_id=call.request_id,
            event_type="graph_event", timestamp=datetime.now(timezone.utc),
            metadata={"task_id": call.task_id, "tool": call.tool,
                      "source_node_id": source_node_id, "result_node_id": result_node_id,
                      "edge_type": "DERIVED_FROM"},
        )
        self.repository.add(event)
        return event

    def log_graph_assessment(self, call: ToolCall, assessment: GraphAssessment | None) -> AuditEvent:
        """Unavailable graph is explicit; no source contents are persisted."""
        call = parse_tool_call(call)
        metadata = {"task_id": call.task_id, "available": assessment is not None}
        if assessment is not None:
            metadata.update(GraphAssessment.model_validate(assessment).model_dump(mode="json"))
        event = AuditEvent(event_id=str(uuid4()), request_id=call.request_id,
                           event_type="graph_assessment", timestamp=datetime.now(timezone.utc),
                           metadata=metadata)
        self.repository.add(event)
        return event

    def log_source_exposure(self, receipt: ExposureReceipt, agent_id: str) -> AuditEvent:
        """Record a validated demo adapter receipt, not source contents."""
        receipt = ExposureReceipt.model_validate(receipt)
        event = AuditEvent(
            event_id=str(uuid4()), request_id=receipt.request_id,
            event_type="source_exposure", timestamp=datetime.now(timezone.utc),
            metadata={"task_id": receipt.task_id, "source_id": receipt.source_id,
                      "agent_id": agent_id},
        )
        self.repository.add(event)
        return event
