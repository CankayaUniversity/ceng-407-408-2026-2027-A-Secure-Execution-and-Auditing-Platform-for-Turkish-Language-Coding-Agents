"""Create and persist audit events from validated tool requests."""

from datetime import datetime, timezone
from uuid import uuid4

from secure_agent.audit.repository import AuditRepository
from secure_agent.common.schemas import AuditEvent, SecurityDecision, ToolCall, parse_tool_call


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
        self, call: ToolCall, decision: SecurityDecision,
    ) -> AuditEvent:
        """Record a policy verdict, not permission to execute a tool."""
        call = parse_tool_call(call)
        decision = SecurityDecision.model_validate(decision)
        arguments = call.arguments.model_dump(exclude={"content"})
        event = AuditEvent(
            event_id=str(uuid4()),
            request_id=call.request_id,
            event_type="policy_decision",
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
