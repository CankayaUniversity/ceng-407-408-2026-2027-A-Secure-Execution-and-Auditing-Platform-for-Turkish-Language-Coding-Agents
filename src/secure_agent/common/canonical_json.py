"""Shared canonical JSON and argument hashing for the Day 4 prototype.

Repository location: src/secure_agent/common/canonical_json.py
Dependency: rfc8785==0.1.4 (in addition to the existing project dependencies).

Use these exact functions on both issuer and verifier sides. RFC 8785 byte
serialization is delegated to rfc8785, not emulated with json.dumps(sort_keys).
The project accepts a restricted JSON subset: no floats, integers outside the
IEEE-754 safe integer range, non-string object keys, or implicit conversions.
RFC 8785 itself supports finite floats; excluding them is a project choice.

Strings are never trimmed or Unicode-normalized. Code contents, line endings,
and array order are preserved. Caller-owned containers must not be mutated
concurrently during validation/serialization. Request byte limits belong to
the receiving service; this module additionally limits nesting depth.

This module does not authorize, sign, verify, or execute requests.
"""

from __future__ import annotations

import hashlib
import json
from typing import TypeAlias, cast

import rfc8785

from secure_agent.common.schemas import parse_tool_call


JSONValue: TypeAlias = (
    str | int | bool | None | list["JSONValue"] | dict[str, "JSONValue"]
)
MAX_SAFE_INTEGER = (1 << 53) - 1
MAX_JSON_DEPTH = 64


class CanonicalJSONError(ValueError):
    """Input is not valid JSON under this project's canonicalization rules."""


def _validate_json_value(value: object, *, depth: int, active: set[int]) -> None:
    """Reject ambiguous types and cycles without coercing or modifying input."""
    if depth > MAX_JSON_DEPTH:
        raise CanonicalJSONError("JSON nesting exceeds the allowed depth.")

    value_type = type(value)
    if value is None or value_type is bool:
        return
    if value_type is str:
        try:
            value.encode("utf-8")
        except UnicodeError:
            raise CanonicalJSONError("JSON strings must contain valid Unicode.") from None
        return
    if value_type is int:
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise CanonicalJSONError("Integer is outside the supported safe range.")
        return
    if value_type not in (dict, list):
        raise CanonicalJSONError("Unsupported JSON type; implicit conversion is forbidden.")

    identity = id(value)
    if identity in active:
        raise CanonicalJSONError("JSON containers must not contain cycles.")
    active.add(identity)
    try:
        if value_type is dict:
            for key, item in value.items():
                if type(key) is not str:
                    raise CanonicalJSONError("JSON object keys must be strings.")
                _validate_json_value(key, depth=depth + 1, active=active)
                _validate_json_value(item, depth=depth + 1, active=active)
        else:
            for item in value:
                _validate_json_value(item, depth=depth + 1, active=active)
    finally:
        active.remove(identity)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Detect duplicate keys before a JSON parser can discard them."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJSONError("Duplicate JSON object key.")
        result[key] = value
    return result


def _reject_number(_: str) -> None:
    """Reject decimal/exponent tokens, NaN, and Infinity in raw JSON."""
    raise CanonicalJSONError("Floating-point numbers are not allowed by this project.")


def canonical_json_loads(payload: str | bytes) -> JSONValue:
    """Strictly parse raw UTF-8 JSON before schema validation at service ingress.

    Duplicate keys are unrecoverable after ordinary json.loads or HTTP parsing.
    Call this on the original body if this function is used for that boundary.
    Parsed JSON still requires the relevant Task/ToolCall/Permit schema checks.
    """
    if type(payload) not in (str, bytes):
        raise CanonicalJSONError("JSON input must be text or UTF-8 bytes.")
    try:
        text = payload.decode("utf-8") if type(payload) is bytes else payload
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except CanonicalJSONError:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise CanonicalJSONError("Input is not valid UTF-8 JSON.") from None
    _validate_json_value(value, depth=0, active=set())
    return cast(JSONValue, value)


def canonical_json_bytes(value: object) -> bytes:
    """Return RFC 8785 UTF-8 bytes after strict project-subset validation.

    Pass JSON-compatible data, not a BaseModel or datetime object. Convert a
    validated Pydantic model explicitly with model_dump(mode='json') first.
    A raw JSON string is a string value here; parse it with canonical_json_loads
    first if the intended value is the object encoded inside that string.
    """
    _validate_json_value(value, depth=0, active=set())
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, RecursionError):
        raise CanonicalJSONError("Canonical JSON serialization failed.") from None


def canonical_json_text(value: object) -> str:
    """Return the same canonical representation as Unicode text for inspection."""
    return canonical_json_bytes(value).decode("utf-8")


def canonical_json_hash(value: object) -> str:
    """Return SHA-256 of canonical bytes as 64 lowercase hexadecimal characters."""
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def tool_arguments_hash(tool_call: object) -> str:
    """Validate a ToolCall and hash only its complete arguments object.

    This matches Permit.arguments_hash in common.schemas. task_id and tool must
    be bound separately by the signed permit payload. request_id is not included
    in this digest. Invalid tool calls raise Pydantic ValidationError.
    Do not normalize file paths or code text before hashing.
    """
    call = parse_tool_call(tool_call)
    return canonical_json_hash(call.arguments.model_dump(mode="json"))
