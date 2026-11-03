"""Shared audit fixtures; each test gets its own temporary database."""

import pytest

from secure_agent.audit.logger import AuditLogger
from secure_agent.audit.repository import AuditRepository
from secure_agent.common.schemas import parse_tool_call


@pytest.fixture
def audit_repository(tmp_path):
    return AuditRepository(tmp_path / "audit.db")


@pytest.fixture
def audit_logger(audit_repository):
    return AuditLogger(audit_repository)


@pytest.fixture
def tool_call():
    return parse_tool_call({
        "request_id": "req-001",
        "task_id": "task-001",
        "tool": "secure_read_file",
        "arguments": {"path": "README.md"},
    })


@pytest.fixture
def permit_material(tmp_path):
    """Ephemeral keys and ledger for execution tests with trusted test approval."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from secure_agent.common.schemas import SecurityDecision
    from secure_agent.security.permit_issuer import PermitIssuer
    from secure_agent.security.permit_verifier import PermitVerifier

    key = Ed25519PrivateKey.generate()
    issuer = PermitIssuer(private_key=key, decision_provider=lambda call: SecurityDecision(
        decision="ALLOW", reason_code="TEST_ALLOW",
    ))
    verifier = PermitVerifier(key.public_key(), tmp_path / "test-nonces.db")
    return key, issuer, verifier
