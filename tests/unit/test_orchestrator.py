"""Ordered checks, short circuits, and audit of every security verdict."""

from unittest.mock import Mock

import pytest

from secure_agent.common.schemas import SecurityDecision
from secure_agent.provenance.models import GraphAssessment
from secure_agent.gateway.orchestrator import SecurityOrchestrator
from secure_agent.security.supervisor import SupervisorDecision


@pytest.mark.parametrize("policy_verdict,supervisor_verdict,expected", [
    ("DENY", "ALIGNED", "DENY"),
    ("REVIEW", "ALIGNED", "REVIEW"),
    ("ALLOW", "ALIGNED", "ALLOW"),
    ("ALLOW", "MISALIGNED", "DENY"),
    ("ALLOW", "UNCERTAIN", "REVIEW"),
])
def test_order_and_audit(policy_verdict, supervisor_verdict, expected,
                         audit_logger, audit_repository, tool_call):
    policy = Mock()
    policy.evaluate.return_value = SecurityDecision(
        decision=policy_verdict, reason_code=f"POLICY_{policy_verdict}",
    )
    supervisor = Mock()

    def assess(**kwargs):
        # Prove policy has already run and its result has been persisted.
        policy.evaluate.assert_called_once_with(tool_call)
        events = audit_repository.get_by_request_id(tool_call.request_id)
        assert events[0].event_type == "policy_decision"
        assert events[-1].event_type == "graph_assessment"
        assert kwargs == {"task_id": tool_call.task_id, "tool_call": tool_call}
        return SupervisorDecision(verdict=supervisor_verdict,
                                  reason="Untrusted content is not logged.",
                                  reason_code=f"SUPERVISOR_{supervisor_verdict}")

    supervisor.evaluate.side_effect = assess
    result = SecurityOrchestrator(policy, supervisor, audit_logger,
        graph_provider=lambda call: GraphAssessment(risk_flags=frozenset(), source_ids=(), observed_edges=())).evaluate(tool_call)
    assert result.decision == expected
    events = audit_repository.get_by_request_id(tool_call.request_id)
    if policy_verdict == "ALLOW":
        supervisor.evaluate.assert_called_once()
        assert [e.event_type for e in events] == [
            "policy_decision", "graph_assessment", "supervisor_decision", "security_decision",
        ]
        assert "reason" not in events[2].metadata
    else:
        supervisor.evaluate.assert_not_called()
        assert [e.event_type for e in events] == ["policy_decision", "security_decision"]
    assert events[-1].metadata["decision"] == expected


@pytest.mark.parametrize("failure", [TimeoutError, RuntimeError])
def test_supervisor_failure_is_review_and_audited(failure, audit_logger,
                                                  audit_repository, tool_call):
    policy = Mock()
    policy.evaluate.return_value = SecurityDecision(decision="ALLOW", reason_code="POLICY_ALLOWED")
    supervisor = Mock()
    supervisor.evaluate.side_effect = failure("Private error text")
    result = SecurityOrchestrator(policy, supervisor, audit_logger,
        graph_provider=lambda call: GraphAssessment(risk_flags=frozenset(), source_ids=(), observed_edges=())).evaluate(tool_call)
    assert result.decision == "REVIEW"
    events = audit_repository.get_by_request_id(tool_call.request_id)
    assert events[-1].metadata["decision"] == "REVIEW"
    assert all("Private error text" not in e.model_dump_json() for e in events)


def test_missing_supervisor_never_allows(audit_logger, tool_call):
    policy = Mock()
    policy.evaluate.return_value = SecurityDecision(decision="ALLOW", reason_code="POLICY_ALLOWED")
    result = SecurityOrchestrator(policy, None, audit_logger).evaluate(tool_call)
    assert result == SecurityDecision(decision="REVIEW", reason_code="SUPERVISOR_REQUIRED")


def test_policy_failure_skips_supervisor(audit_logger, audit_repository, tool_call):
    policy = Mock()
    policy.evaluate.side_effect = RuntimeError("Private policy error")
    supervisor = Mock()
    result = SecurityOrchestrator(policy, supervisor, audit_logger,
        graph_provider=lambda call: GraphAssessment(risk_flags=frozenset(), source_ids=(), observed_edges=())).evaluate(tool_call)
    assert result.decision == "DENY"
    supervisor.evaluate.assert_not_called()
    assert audit_repository.get_by_request_id(tool_call.request_id)[-1].metadata["decision"] == "DENY"



def test_policy_deny_skips_graph_and_supervisor(audit_logger, tool_call):
    policy, supervisor, graph = Mock(), Mock(), Mock()
    policy.evaluate.return_value = SecurityDecision(decision="DENY", reason_code="POLICY_DENIED")
    result = SecurityOrchestrator(policy, supervisor, audit_logger, graph).evaluate(tool_call)
    assert result.decision == "DENY"
    graph.assert_not_called()
    supervisor.evaluate.assert_not_called()
