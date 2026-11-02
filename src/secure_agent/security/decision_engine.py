"""Deterministic combination of policy and supervisor decisions."""

from pydantic import ValidationError

from secure_agent.common.schemas import SecurityDecision
from secure_agent.security.supervisor import SupervisorDecision


class DecisionEngine:
    """Combine existing assessments; never call an LLM or execute a tool.

    ALLOW is this stage's verdict, not a permit. The orchestrator must skip
    Supervisor on policy DENY and enforce provider timeouts separately.
    """

    def decide(
        self, policy: SecurityDecision, supervisor: SupervisorDecision | None = None,
    ) -> SecurityDecision:
        try:
            policy = SecurityDecision.model_validate(policy)
        except ValidationError:
            return SecurityDecision(decision="DENY", reason_code="INVALID_POLICY_DECISION")

        if policy.decision != "ALLOW":
            return policy
        if supervisor is None:
            return SecurityDecision(decision="REVIEW", reason_code="SUPERVISOR_REQUIRED")
        try:
            supervisor = SupervisorDecision.model_validate(supervisor)
        except ValidationError:
            return SecurityDecision(decision="DENY", reason_code="INVALID_SUPERVISOR_DECISION")

        if supervisor.verdict == "ALIGNED":
            return SecurityDecision(decision="ALLOW", reason_code="POLICY_AND_SUPERVISOR_ALLOWED")
        if supervisor.verdict == "MISALIGNED":
            return SecurityDecision(decision="DENY", reason_code=supervisor.reason_code)
        return SecurityDecision(decision="REVIEW", reason_code=supervisor.reason_code)
