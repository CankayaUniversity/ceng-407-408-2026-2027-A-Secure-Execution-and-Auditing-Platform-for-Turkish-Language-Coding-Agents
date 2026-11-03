"""Decision matrix and non-authorizing error handling."""

import pytest

from secure_agent.common.schemas import SecurityDecision, Task
from secure_agent.security.decision_engine import DecisionEngine
from secure_agent.provenance.models import GraphAssessment
from secure_agent.security.supervisor import Supervisor, SupervisorDecision
from secure_agent.tasks.registry import TaskRegistry
from secure_agent.tasks.scope import TaskScope


@pytest.mark.parametrize("policy,verdict,expected", [
    ("DENY", "ALIGNED", "DENY"),
    ("DENY", "MISALIGNED", "DENY"),
    ("DENY", "UNCERTAIN", "DENY"),
    ("REVIEW", "ALIGNED", "REVIEW"),
    ("REVIEW", "MISALIGNED", "REVIEW"),
    ("REVIEW", "UNCERTAIN", "REVIEW"),
    ("ALLOW", "ALIGNED", "ALLOW"),
    ("ALLOW", "MISALIGNED", "DENY"),
    ("ALLOW", "UNCERTAIN", "REVIEW"),
])
def test_decision_matrix(policy, verdict, expected):
    policy_result = SecurityDecision(decision=policy, reason_code=f"POLICY_{policy}")
    supervisor = SupervisorDecision(verdict=verdict, reason="Example assessment.",
                                    reason_code=f"SUPERVISOR_{verdict}")
    result = DecisionEngine().decide(policy_result, supervisor, graph=GraphAssessment(
        risk_flags=frozenset(), source_ids=(), observed_edges=(),
    ))
    assert result.decision == expected
    if policy != "ALLOW":
        assert result.reason_code == policy_result.reason_code
    elif verdict == "ALIGNED":
        assert result.reason_code == "POLICY_SUPERVISOR_GRAPH_ALLOWED"
    else:
        assert result.reason_code == supervisor.reason_code


@pytest.mark.parametrize("policy,expected", [
    ("DENY", "DENY"), ("REVIEW", "REVIEW"), ("ALLOW", "REVIEW"),
])
def test_missing_supervisor_never_allows(policy, expected):
    result = DecisionEngine().decide(SecurityDecision(decision=policy, reason_code="TEST"))
    assert result.decision == expected
    if policy == "ALLOW":
        assert result.reason_code == "SUPERVISOR_REQUIRED"


def test_invalid_policy_cannot_be_overridden_by_aligned_supervisor():
    policy = SecurityDecision(decision="DENY", reason_code="TEST").model_copy(
        update={"decision": "INVALID"},
    )
    supervisor = SupervisorDecision(verdict="ALIGNED", reason="Example.", reason_code="TEST")
    result = DecisionEngine().decide(policy, supervisor)
    assert result == SecurityDecision(decision="DENY", reason_code="INVALID_POLICY_DECISION")


def test_invalid_supervisor_is_denied():
    supervisor = SupervisorDecision(verdict="ALIGNED", reason="Example.", reason_code="TEST")
    invalid = supervisor.model_copy(update={"verdict": "ALLOW"})
    result = DecisionEngine().decide(
        SecurityDecision(decision="ALLOW", reason_code="POLICY_ALLOWED"), invalid,
    )
    assert result == SecurityDecision(decision="DENY", reason_code="INVALID_SUPERVISOR_DECISION")


@pytest.mark.parametrize("error", [TimeoutError, ConnectionError])
def test_supervisor_client_failure_becomes_review(error, tool_call):
    class FailingClient:
        def complete(self, **kwargs):
            raise error("Sensitive provider details must not propagate.")

    scope = TaskScope(scope_id="scope", workspace_id="demo")
    registry = TaskRegistry(workspace_ids={"demo"}, scopes=[scope])
    registry.register(Task(task_id=tool_call.task_id, user_goal="Read README.",
                           workspace_id="demo", scope_id="scope"))
    assessment = Supervisor(registry=registry, llm_client=FailingClient()).evaluate(
        task_id=tool_call.task_id, tool_call=tool_call,
    )
    result = DecisionEngine().decide(
        SecurityDecision(decision="ALLOW", reason_code="POLICY_ALLOWED"), assessment,
    )
    assert assessment.verdict == "UNCERTAIN"
    assert result == SecurityDecision(decision="REVIEW", reason_code="SUPERVISOR_LLM_ERROR")


@pytest.mark.parametrize("flags,expected", [
    (frozenset(), "ALLOW"),
    (frozenset({"UNTRUSTED_SOURCE_EXPOSURE"}), "ALLOW"),
    (frozenset({"GRAPH_INCOMPLETE"}), "REVIEW"),
    (frozenset({"UNTRUSTED_SOURCE_EXPOSURE", "SENSITIVE_TARGET_AFTER_UNTRUSTED_INPUT"}), "REVIEW"),
])
def test_graph_risk_decisions(flags, expected):
    result = DecisionEngine().decide(
        SecurityDecision(decision="ALLOW", reason_code="POLICY_ALLOWED"),
        SupervisorDecision(verdict="ALIGNED", reason="Example.", reason_code="SUPERVISOR_ALIGNED"),
        graph=GraphAssessment(risk_flags=flags, source_ids=(), observed_edges=()),
    )
    assert result.decision == expected


def test_missing_graph_never_allows():
    result = DecisionEngine().decide(
        SecurityDecision(decision="ALLOW", reason_code="POLICY_ALLOWED"),
        SupervisorDecision(verdict="ALIGNED", reason="Example.", reason_code="SUPERVISOR_ALIGNED"),
    )
    assert result == SecurityDecision(decision="REVIEW", reason_code="GRAPH_REQUIRED")
