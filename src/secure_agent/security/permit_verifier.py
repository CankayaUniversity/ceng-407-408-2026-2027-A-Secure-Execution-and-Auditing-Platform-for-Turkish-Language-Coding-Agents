"""Verify one signed permit and atomically consume its nonce before dispatch."""

import base64
import sqlite3
from collections.abc import Callable
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from secure_agent.common.canonical_json import tool_arguments_hash
from secure_agent.common.schemas import Permit, ToolCall, parse_tool_call
from secure_agent.security.permit_issuer import permit_signing_bytes


class PermitVerificationError(PermissionError):
    """A permit failed verification or could not be safely consumed."""


class PermitVerifier:
    def __init__(self, public_key: Ed25519PublicKey, nonce_database: str | Path, *,
                 clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)):
        if not isinstance(public_key, Ed25519PublicKey):
            raise TypeError("An Ed25519 public key is required.")
        if str(nonce_database) in {"", ":memory:"}:
            raise ValueError("A persistent nonce database path is required.")
        self._key = public_key
        self._database = Path(nonce_database).resolve()
        self._clock = clock
        with closing(sqlite3.connect(self._database)) as connection, connection:
            connection.execute("CREATE TABLE IF NOT EXISTS used_nonces (nonce TEXT PRIMARY KEY)")

    def verify_and_consume(self, call: ToolCall, permit: object) -> None:
        """Reject invalid or previously used permits before the tool can run."""
        try:
            call = parse_tool_call(call)
            permit = Permit.model_validate(permit)
            self._key.verify(base64.urlsafe_b64decode(permit.signature + "=="),
                             permit_signing_bytes(permit))
            bound = (permit.task_id == call.task_id and permit.tool == call.tool
                     and permit.arguments_hash == tool_arguments_hash(call))
        except (InvalidSignature, ValueError, TypeError, OverflowError) as error:
            raise PermitVerificationError("Permit signature or payload is invalid.") from error
        if not bound:
            raise PermitVerificationError("Permit does not match this operation.")

        try:
            # Open existing storage only. A missing ledger must not reset replay state.
            uri = self._database.as_uri() + "?mode=rw"
            with closing(sqlite3.connect(uri, uri=True)) as connection, connection:
                connection.execute("BEGIN IMMEDIATE")
                now = self._clock()
                if not isinstance(now, datetime) or now.utcoffset() is None:
                    raise PermitVerificationError("Permit verification clock is invalid.")
                if permit.expires_at <= now:
                    raise PermitVerificationError("Permit expired.")
                connection.execute("INSERT INTO used_nonces (nonce) VALUES (?)", (permit.nonce,))
        except sqlite3.IntegrityError as error:
            raise PermitVerificationError("Permit was already used.") from error
        except sqlite3.Error as error:
            raise PermitVerificationError("Nonce ledger is unavailable.") from error
