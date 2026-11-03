"""Exercise real signatures and persistent, atomic nonce consumption."""

import base64
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from secure_agent.common.schemas import parse_tool_call
from secure_agent.security.permit_verifier import PermitVerificationError, PermitVerifier


def test_replay_is_rejected_after_reopening_ledger(tmp_path, permit_material, tool_call):
    key, issuer, verifier = permit_material
    permit = issuer.issue(tool_call)
    verifier.verify_and_consume(tool_call, permit)
    reopened = PermitVerifier(key.public_key(), tmp_path / "test-nonces.db")
    repeated_call = tool_call.model_copy(update={"request_id": "different-request-id"})
    with pytest.raises(PermitVerificationError, match="already used"):
        reopened.verify_and_consume(repeated_call, permit)


@pytest.mark.parametrize("change", ["task", "tool", "arguments", "signature", "key"])
def test_invalid_binding_or_signature_does_not_consume_nonce(change, permit_material,
                                                               tool_call, tmp_path):
    _, issuer, verifier = permit_material
    permit = issuer.issue(tool_call)
    bad_call, bad_permit, target = tool_call, permit, verifier
    if change == "task":
        bad_call = tool_call.model_copy(update={"task_id": "another-task"})
    elif change == "tool":
        bad_call = parse_tool_call({**tool_call.model_dump(), "tool": "secure_list_files"})
    elif change == "arguments":
        bad_call = parse_tool_call({**tool_call.model_dump(), "arguments": {"path": "other.txt"}})
    elif change == "signature":
        signature = base64.urlsafe_b64encode(bytes(64)).decode("ascii").rstrip("=")
        bad_permit = permit.model_copy(update={"signature": signature})
    else:
        target = PermitVerifier(Ed25519PrivateKey.generate().public_key(), tmp_path / "test-nonces.db")
    with pytest.raises(PermitVerificationError):
        target.verify_and_consume(bad_call, bad_permit)
    verifier.verify_and_consume(tool_call, permit)


def test_permit_expires_at_deadline(tmp_path, permit_material, tool_call):
    key, issuer, _ = permit_material
    permit = issuer.issue(tool_call)
    verifier = PermitVerifier(key.public_key(), tmp_path / "expired.db", clock=lambda: permit.expires_at)
    with pytest.raises(PermitVerificationError, match="expired"):
        verifier.verify_and_consume(tool_call, permit)


def test_concurrent_replay_only_one_verifier_can_consume(tmp_path, permit_material, tool_call):
    key, issuer, verifier = permit_material
    other = PermitVerifier(key.public_key(), tmp_path / "test-nonces.db")
    permit = issuer.issue(tool_call)
    barrier = Barrier(2, timeout=5)

    def consume(candidate):
        barrier.wait()
        try:
            candidate.verify_and_consume(tool_call, permit)
        except PermitVerificationError as error:
            assert "already used" in str(error)
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(consume, [verifier, other])) == [False, True]


def test_missing_ledger_fails_closed(tmp_path, permit_material, tool_call):
    _, issuer, verifier = permit_material
    database = tmp_path / "test-nonces.db"
    database.unlink()
    with pytest.raises(PermitVerificationError, match="ledger is unavailable"):
        verifier.verify_and_consume(tool_call, issuer.issue(tool_call))
    assert not database.exists()
