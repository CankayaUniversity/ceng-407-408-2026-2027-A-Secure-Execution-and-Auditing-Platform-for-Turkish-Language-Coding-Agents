"""Ed25519 permit issuance for the Day 4 prototype.

Repository location: src/secure_agent/security/permit_issuer.py
Dependencies: cryptography, rfc8785, and the existing Pydantic v2 contracts.

Instantiate this class only inside the trusted issuer service. The injected
decision_provider must evaluate the supplied ToolCall using trusted task,
policy, supervisor, and graph state. Never expose that callback, the key path,
or caller-supplied ALLOW decisions as agent-controlled configuration.

Permit uses the existing schema unchanged: every field except signature is
signed as RFC 8785 JSON bytes. expires_at is normalized to UTC with exactly six
fractional digits and a Z suffix before signing. Issuer and verifier MUST use
permit_signing_bytes() or implement exactly the same representation.

The issuer does not execute tools or consume nonces. The verifier must check
signature, task/tool/argument binding, expiration, and atomically consume the
nonce before execution. A random nonce alone does not prevent replay.
The current schema has no request_id, audience, issued_at, or key_id fields;
these are not implicitly authenticated. Key distribution and process/container
isolation remain deployment responsibilities. Python attributes are not a
security boundary, and the key is not guaranteed to be zeroized in memory.
"""

from __future__ import annotations

import base64
import os
import secrets
import stat
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import AwareDatetime

from secure_agent.common.canonical_json import canonical_json_bytes, tool_arguments_hash
from secure_agent.common.schemas import (
    ContractModel,
    NonEmptyText,
    Permit,
    SecurityDecision,
    Sha256Hex,
    ToolCall,
    ToolName,
    parse_tool_call,
)


DEFAULT_TTL_SECONDS = 60
MAX_TTL_SECONDS = 60
MAX_KEY_FILE_BYTES = 16_384

DecisionProvider = Callable[[ToolCall], SecurityDecision]
Clock = Callable[[], datetime]


class PermitDeniedError(PermissionError):
    """The trusted decision does not authorize permit issuance."""


class KeyLoadingError(ValueError):
    """The configured private key could not be safely loaded."""


class _UnsignedPermit(ContractModel):
    """Validate unsigned fields without manufacturing a placeholder signature."""

    permit_id: NonEmptyText
    task_id: NonEmptyText
    tool: ToolName
    arguments_hash: Sha256Hex
    nonce: NonEmptyText
    expires_at: AwareDatetime


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    """Require a timezone-aware datetime; never infer the host timezone."""
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("A timezone-aware datetime is required.")
    return value.astimezone(timezone.utc)


def _unsigned_signing_bytes(payload: _UnsignedPermit) -> bytes:
    fields = payload.model_dump(mode="python")
    fields["expires_at"] = (
        _as_utc(payload.expires_at)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )
    return canonical_json_bytes(fields)


def permit_signing_bytes(permit: Permit) -> bytes:
    """Revalidate a permit and return its canonical unsigned payload.

    This helper does NOT verify a signature or check expiration. The signature
    field is excluded; every other field in the current Permit schema is bound.
    Equivalent timezone representations of the same instant sign identically.
    """
    validated = Permit.model_validate(permit)
    payload = _UnsignedPermit.model_validate(
        validated.model_dump(mode="python", exclude={"signature"})
    )
    return _unsigned_signing_bytes(payload)


def load_ed25519_private_key(
    path: str | Path, *, password: bytes | None = None
) -> Ed25519PrivateKey:
    """Load a configured PEM key; never create or replace a missing key.

    The path/password must come from trusted issuer startup configuration.
    Encrypted PEM files are supported. On POSIX, reject group/other permission
    bits and non-regular files, and refuse the final symlink where O_NOFOLLOW
    is available. Parent directories must also be protected by deployment.
    On Windows, configure restrictive ACLs separately; POSIX mode checks do not
    establish Windows access control. No key contents are written or logged.
    """
    if password is not None and type(password) is not bytes:
        raise KeyLoadingError("Key password must be bytes or None.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise KeyLoadingError("Private key must be a regular file.")
            if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
                raise KeyLoadingError("Private key permissions must exclude group/others.")
            pem = stream.read(MAX_KEY_FILE_BYTES + 1)
        if not pem or len(pem) > MAX_KEY_FILE_BYTES:
            raise KeyLoadingError("Private key file has an invalid size.")
        key = serialization.load_pem_private_key(pem, password=password)
    except KeyLoadingError:
        raise
    except (OSError, ValueError, TypeError, UnsupportedAlgorithm):
        raise KeyLoadingError("Unable to load the configured private key.") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise KeyLoadingError("The configured key must be an Ed25519 private key.")
    return key


class PermitIssuer:
    """Issue short-lived permits after a fresh trusted decision for each call.

    Load one persistent key at startup and reuse this object. Do not generate
    a new signing key per request. The callback receives a separately validated
    snapshot so normal changes to that snapshot cannot change the signed call.
    Callback/validation/signing errors propagate and produce no permit.
    """

    def __init__(
        self,
        *,
        private_key: Ed25519PrivateKey,
        decision_provider: DecisionProvider,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        clock: Clock = _utc_now,
    ) -> None:
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("private_key must be an Ed25519 private key.")
        if not callable(decision_provider) or not callable(clock):
            raise TypeError("decision_provider and clock must be callable.")
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= MAX_TTL_SECONDS:
            raise ValueError("ttl_seconds must be an integer between 1 and 60.")
        self._private_key = private_key
        self._decision_provider = decision_provider
        self._ttl_seconds = ttl_seconds
        self._clock = clock

    @classmethod
    def from_pem_file(
        cls,
        path: str | Path,
        *,
        decision_provider: DecisionProvider,
        password: bytes | None = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        clock: Clock = _utc_now,
    ) -> PermitIssuer:
        """Construct an issuer from trusted startup configuration."""
        return cls(
            private_key=load_ed25519_private_key(path, password=password),
            decision_provider=decision_provider,
            ttl_seconds=ttl_seconds,
            clock=clock,
        )

    def public_key(self) -> Ed25519PublicKey:
        """Return only the verification key for trusted distribution."""
        return self._private_key.public_key()

    def issue(self, tool_call: object) -> Permit:
        """Validate, evaluate, bind, and sign one proposal; never accept ALLOW input."""
        call = parse_tool_call(tool_call)
        decision_call = parse_tool_call(call.model_dump(mode="python"))
        decision = SecurityDecision.model_validate(self._decision_provider(decision_call))
        if decision.decision != "ALLOW":
            raise PermitDeniedError("Permit issuance requires a trusted ALLOW decision.")

        now = _as_utc(self._clock())
        payload = _UnsignedPermit(
            permit_id=str(uuid4()),
            task_id=call.task_id,
            tool=call.tool,
            arguments_hash=tool_arguments_hash(call),
            nonce=secrets.token_urlsafe(24),
            expires_at=now + timedelta(seconds=self._ttl_seconds),
        )
        signature_bytes = self._private_key.sign(_unsigned_signing_bytes(payload))
        signature = base64.urlsafe_b64encode(signature_bytes).decode("ascii").rstrip("=")
        return Permit(**payload.model_dump(mode="python"), signature=signature)
