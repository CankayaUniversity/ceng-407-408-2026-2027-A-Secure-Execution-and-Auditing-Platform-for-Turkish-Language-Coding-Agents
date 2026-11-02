"""Permit issuance, real Ed25519 signature, and private-key loading tests.

Repository location: tests/unit/test_permit_issuer.py
Run from the repository root with PYTHONPATH=src using pytest or unittest.
Tests run offline; no API key, Docker, database, or persistent key is required.
Temporary test keys are deleted automatically. POSIX permission checks are
skipped on Windows and do not establish agent-container key isolation.
"""

import base64
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
from pydantic import ValidationError
from secure_agent.common.canonical_json import tool_arguments_hash
from secure_agent.common.schemas import Permit, SecurityDecision
from secure_agent.security.permit_issuer import (
    KeyLoadingError,
    PermitDeniedError,
    PermitIssuer,
    load_ed25519_private_key,
    permit_signing_bytes,
)


class TestPermitIssuer(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.now = datetime(2026, 11, 2, 9, 0, 0, 123456, tzinfo=timezone.utc)
        self.clock = Mock(return_value=self.now)
        self.provider = Mock(
            return_value=SecurityDecision(decision="ALLOW", reason_code="CHECKS_PASSED")
        )
        self.issuer = PermitIssuer(
            private_key=self.key, decision_provider=self.provider, clock=self.clock
        )
        self.call = {
            "request_id": "r",
            "task_id": "t",
            "tool": "secure_edit_file",
            "arguments": {"path": "main.py", "content": "# Türkçe\n"},
        }

    def verify(self, permit, key=None):
        key = key or self.key.public_key()
        signature = base64.urlsafe_b64decode(permit.signature + "==")
        key.verify(signature, permit_signing_bytes(permit))

    def test_real_signature_and_contract(self):
        permit = self.issuer.issue(self.call)
        self.verify(permit)
        self.assertEqual(permit.task_id, "t")
        self.assertEqual(permit.tool, self.call["tool"])
        self.assertEqual(permit.arguments_hash, tool_arguments_hash(self.call))
        self.assertEqual(permit.expires_at, self.now + timedelta(seconds=60))
        self.assertEqual(len(permit.signature), 86)
        self.assertEqual(len(base64.urlsafe_b64decode(permit.signature + "==")), 64)
        self.provider.assert_called_once()
        self.assertEqual(
            self.provider.call_args.args[0].model_dump(mode="json"), self.call
        )
        self.clock.assert_called_once()

    def test_denied_and_review_never_issue(self):
        for verdict in ["DENY", "REVIEW"]:
            with self.subTest(verdict=verdict):
                self.provider.return_value = SecurityDecision(
                    decision=verdict, reason_code="BLOCKED"
                )
                with self.assertRaises(PermitDeniedError):
                    self.issuer.issue(self.call)
        self.clock.assert_not_called()

    def test_bad_decisions_fail_closed(self):
        for value in [
            None,
            {},
            True,
            {"decision": "ALIGNED", "reason_code": "x"},
            {"decision": "ALLOW", "reason_code": "x", "approved": True},
        ]:
            with self.subTest(value=value):
                self.provider.return_value = value
                with self.assertRaises(ValidationError):
                    self.issuer.issue(self.call)
        self.clock.assert_not_called()

    def test_provider_failure_fails_closed(self):
        self.provider.side_effect = RuntimeError("decision service unavailable")
        with self.assertRaises(RuntimeError):
            self.issuer.issue(self.call)
        self.clock.assert_not_called()

    def test_invalid_tool_call_precedes_decision(self):
        for value in [
            {},
            {**self.call, "approved": True},
            {**self.call, "arguments": {"path": "../secret", "content": "x"}},
        ]:
            with self.assertRaises(ValidationError):
                self.issuer.issue(value)
        self.provider.assert_not_called()

    def test_every_signed_field_is_authenticated(self):
        permit = self.issuer.issue(self.call)
        changes = {
            "permit_id": "new-id",
            "task_id": "other-task",
            "tool": "secure_read_file",
            "arguments_hash": "f" * 64,
            "nonce": "new-nonce",
            "expires_at": permit.expires_at + timedelta(seconds=1),
        }
        for name, value in changes.items():
            with self.subTest(field=name):
                changed = Permit(**{**permit.model_dump(mode="python"), name: value})
                with self.assertRaises(InvalidSignature):
                    self.verify(changed)
        self.assertEqual(
            set(json.loads(permit_signing_bytes(permit))),
            set(Permit.model_fields) - {"signature"},
        )

    def test_changed_signature_and_wrong_key_fail(self):
        permit = self.issuer.issue(self.call)
        raw = bytearray(base64.urlsafe_b64decode(permit.signature + "=="))
        raw[0] ^= 1
        sig = base64.urlsafe_b64encode(raw).decode().rstrip("=")
        changed = Permit(**{**permit.model_dump(mode="python"), "signature": sig})
        with self.assertRaises(InvalidSignature):
            self.verify(changed)
        with self.assertRaises(InvalidSignature):
            self.verify(permit, Ed25519PrivateKey.generate().public_key())

    def test_wire_round_trip_and_timezone_equivalence(self):
        permit = self.issuer.issue(self.call)
        restored = Permit.model_validate_json(permit.model_dump_json())
        self.verify(restored)
        offset = permit.expires_at.astimezone(timezone(timedelta(hours=3)))
        equivalent = Permit(
            **{**permit.model_dump(mode="python"), "expires_at": offset}
        )
        self.assertEqual(permit_signing_bytes(permit), permit_signing_bytes(equivalent))
        self.verify(equivalent)
        self.assertEqual(
            json.loads(permit_signing_bytes(permit))["expires_at"],
            "2026-11-02T09:01:00.123456Z",
        )

    def test_each_issue_has_fresh_id_nonce_and_decision(self):
        permits = [self.issuer.issue(self.call) for _ in range(20)]
        self.assertEqual(len({p.permit_id for p in permits}), 20)
        self.assertEqual(len({p.nonce for p in permits}), 20)
        self.assertEqual(self.provider.call_count, 20)
        for permit in permits:
            self.verify(permit)

    def test_approval_for_one_call_is_not_cached(self):
        self.issuer.issue(self.call)
        self.provider.return_value = SecurityDecision(
            decision="DENY", reason_code="BLOCKED"
        )
        with self.assertRaises(PermitDeniedError):
            self.issuer.issue(self.call)
        self.assertEqual(self.provider.call_count, 2)

    def test_callback_receives_separate_snapshot(self):
        # Frozen models are not a Python process boundary; still avoid sharing snapshots.
        def decide(call):
            object.__setattr__(call, "task_id", "changed")
            object.__setattr__(call.arguments, "content", "changed")
            return SecurityDecision(decision="ALLOW", reason_code="OK")

        issuer = PermitIssuer(
            private_key=self.key, decision_provider=decide, clock=self.clock
        )
        permit = issuer.issue(self.call)
        self.assertEqual(permit.task_id, "t")
        self.assertEqual(permit.arguments_hash, tool_arguments_hash(self.call))

    def test_invalid_configuration(self):
        for ttl in [0, -1, 61, True, 1.5, "60"]:
            with self.assertRaises(ValueError):
                PermitIssuer(
                    private_key=self.key,
                    decision_provider=self.provider,
                    ttl_seconds=ttl,
                )
        for kwargs in [
            dict(private_key=None, decision_provider=self.provider),
            dict(private_key=self.key, decision_provider=None),
            dict(private_key=self.key, decision_provider=self.provider, clock=None),
        ]:
            with self.assertRaises(TypeError):
                PermitIssuer(**kwargs)

    def test_short_ttl_and_naive_clock(self):
        issuer = PermitIssuer(
            private_key=self.key,
            decision_provider=self.provider,
            clock=self.clock,
            ttl_seconds=1,
        )
        self.assertEqual(
            issuer.issue(self.call).expires_at, self.now + timedelta(seconds=1)
        )
        for value in [datetime(2026, 11, 2), None]:
            self.clock.return_value = value
            with self.assertRaises(ValueError):
                issuer.issue(self.call)

    def test_pem_loading_encrypted_and_plain(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "issuer.pem"
            for password, encryption in [
                (None, serialization.NoEncryption()),
                (
                    b"test-password",
                    serialization.BestAvailableEncryption(b"test-password"),
                ),
            ]:
                path.write_bytes(
                    self.key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        encryption,
                    )
                )
                path.chmod(0o600)
                issuer = PermitIssuer.from_pem_file(
                    path,
                    password=password,
                    decision_provider=self.provider,
                    clock=self.clock,
                )
                self.verify(issuer.issue(self.call), issuer.public_key())
                if password:
                    for wrong in [None, b"wrong"]:
                        with self.assertRaises(KeyLoadingError):
                            load_ed25519_private_key(path, password=wrong)

    def test_missing_malformed_and_wrong_key_type(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "issuer.pem"
            with self.assertRaises(KeyLoadingError):
                load_ed25519_private_key(path)
            self.assertFalse(path.exists())
            ec = generate_private_key(SECP256R1())
            for content in [
                b"",
                b"bad key",
                b"x" * 16385,
                ec.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
                self.key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                ),
            ]:
                path.write_bytes(content)
                path.chmod(0o600)
                with self.assertRaises(KeyLoadingError):
                    load_ed25519_private_key(path)
            with self.assertRaises(KeyLoadingError):
                load_ed25519_private_key(path, password="wrong-type")

    @unittest.skipUnless(os.name == "posix", "POSIX permissions required")
    def test_permissions_symlinks_and_nonregular_files(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "issuer.pem"
            path.write_bytes(
                self.key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            path.chmod(0o644)
            with self.assertRaises(KeyLoadingError):
                load_ed25519_private_key(path)
            path.chmod(0o600)
            link = Path(directory) / "link.pem"
            link.symlink_to(path)
            if hasattr(os, "O_NOFOLLOW"):
                with self.assertRaises(KeyLoadingError):
                    load_ed25519_private_key(link)
            with self.assertRaises(KeyLoadingError):
                load_ed25519_private_key(Path(directory))
            fifo = Path(directory) / "fifo"
            os.mkfifo(fifo)
            with self.assertRaises(KeyLoadingError):
                load_ed25519_private_key(fifo)


if __name__ == "__main__":
    unittest.main(verbosity=2)
