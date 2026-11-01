"""Create and persist audit events from validated tool requests."""

from datetime import datetime, timezone
from uuid import uuid4

from secure_agent.audit.repository import AuditRepository
from secure_agent.common.schemas import AuditEvent, ToolCall, parse_tool_call


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
