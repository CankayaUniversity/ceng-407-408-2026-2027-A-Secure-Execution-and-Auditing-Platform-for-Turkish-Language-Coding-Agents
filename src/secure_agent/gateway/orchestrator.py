"""Run trusted security checks and protect tool results."""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from secure_agent.audit.logger import AuditLogger
from secure_agent.common.schemas import (
    ReadFileToolCall,
    SecurityDecision,
    ToolCall,
    ToolResult,
    parse_tool_call,
)
from secure_agent.provenance.models import GraphAssessment
from secure_agent.security.decision_engine import DecisionEngine
from secure_agent.security.result_protection import protect_tool_result
from secure_agent.security.supervisor import Supervisor, SupervisorDecision

if TYPE_CHECKING:
    from secure_agent.provenance.recorder import ProvenanceRecorder
    from secure_agent.security.policy_engine import PolicyEngine


class SecurityOrchestrator:
    def __init__(
        self,
        policy: PolicyEngine,
        supervisor: Supervisor | None,
        audit_logger: AuditLogger,
        graph_provider: Callable[[ToolCall], GraphAssessment] | None = None,
    ):
        self.policy = policy
        self.supervisor = supervisor
        self.audit_logger = audit_logger
        self.engine = DecisionEngine()
        self.graph_provider = graph_provider

    def evaluate(self, call: ToolCall) -> SecurityDecision:
        """Evaluate policy and Supervisor verdicts before execution."""
        call = parse_tool_call(call)

        try:
            policy = SecurityDecision.model_validate(
                self.policy.evaluate(call)
            )
        except Exception:
            policy = SecurityDecision(
                decision="DENY",
                reason_code="POLICY_EVALUATION_ERROR",
            )

        self.audit_logger.log_security_decision(call, policy)

        graph = None
        assessment = None

        if policy.decision == "ALLOW":
            if self.graph_provider is not None:
                try:
                    graph = GraphAssessment.model_validate(self.graph_provider(call))
                except Exception:
                    graph = None
            self.audit_logger.log_graph_assessment(call, graph)
            if self.supervisor is None:
                assessment = SupervisorDecision(
                    verdict="UNCERTAIN",
                    reason="Supervisor is not configured.",
                    reason_code="SUPERVISOR_REQUIRED",
                )
            else:
                try:
                    assessment = SupervisorDecision.model_validate(
                        self.supervisor.evaluate(
                            task_id=call.task_id,
                            tool_call=call,
                        )
                    )
                except Exception:
                    assessment = SupervisorDecision(
                        verdict="UNCERTAIN",
                        reason="Supervisor evaluation failed.",
                        reason_code="SUPERVISOR_EVALUATION_ERROR",
                    )

            self.audit_logger.log_supervisor_decision(call, assessment)

        decision = self.engine.decide(policy, assessment, graph=graph)
        self.audit_logger.log_security_decision(
            call,
            decision,
            event_type="security_decision",
        )
        return decision

    def finalize_result(
        self,
        call: ToolCall,
        result: ToolResult,
        *,
        provenance_recorder: ProvenanceRecorder | None,
    ) -> ToolResult:
        """Protect a result before audit, graph storage, and delivery."""
        call = parse_tool_call(call)
        result = ToolResult.model_validate(result)

        if result.request_id != call.request_id:
            raise ValueError("Tool result request ID does not match.")

        protected = protect_tool_result(result)

        if isinstance(call, ReadFileToolCall) and protected.status == "success":
            if provenance_recorder is None:
                raise ValueError(
                    "Successful reads require provenance recording."
                )

            self.audit_logger.log_tool_result(protected)
            provenance_recorder.record_read(call, protected)
        else:
            self.audit_logger.log_tool_result(protected)

        return protected
