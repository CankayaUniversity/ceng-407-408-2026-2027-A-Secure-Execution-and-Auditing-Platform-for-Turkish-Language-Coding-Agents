"""Run trusted policy and Supervisor checks before any demo execution."""

from __future__ import annotations

from typing import TYPE_CHECKING

from secure_agent.audit.logger import AuditLogger
from secure_agent.common.schemas import SecurityDecision, ToolCall, parse_tool_call
from secure_agent.security.decision_engine import DecisionEngine
from secure_agent.security.supervisor import Supervisor, SupervisorDecision

if TYPE_CHECKING:
    from secure_agent.security.policy_engine import PolicyEngine


class SecurityOrchestrator:
    def __init__(self, policy: PolicyEngine, supervisor: Supervisor | None,
                 audit_logger: AuditLogger):
        self.policy = policy
        self.supervisor = supervisor
        self.audit_logger = audit_logger
        self.engine = DecisionEngine()

    def evaluate(self, call: ToolCall) -> SecurityDecision:
        call = parse_tool_call(call)
        try:
            policy = SecurityDecision.model_validate(self.policy.evaluate(call))
        except Exception:
            policy = SecurityDecision(decision="DENY", reason_code="POLICY_EVALUATION_ERROR")
        self.audit_logger.log_security_decision(call, policy)

        assessment = None
        if policy.decision == "ALLOW":
            if self.supervisor is None:
                assessment = SupervisorDecision(
                    verdict="UNCERTAIN", reason="Supervisor is not configured.",
                    reason_code="SUPERVISOR_REQUIRED",
                )
            else:
                try:
                    assessment = SupervisorDecision.model_validate(self.supervisor.evaluate(
                        task_id=call.task_id, tool_call=call,
                    ))
                except Exception:
                    assessment = SupervisorDecision(
                        verdict="UNCERTAIN", reason="Supervisor evaluation failed.",
                        reason_code="SUPERVISOR_EVALUATION_ERROR",
                    )
            self.audit_logger.log_supervisor_decision(call, assessment)

        decision = self.engine.decide(policy, assessment)
        self.audit_logger.log_security_decision(call, decision, event_type="security_decision")
        return decision
