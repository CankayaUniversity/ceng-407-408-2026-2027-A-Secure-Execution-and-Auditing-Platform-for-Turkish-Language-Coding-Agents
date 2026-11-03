"""Protect tool outputs before audit, provenance recording, and delivery.

Redaction covers configured literal secrets and common credential patterns.
Source identifiers must come from the trusted backend.
"""

from __future__ import annotations

import re

from secure_agent.common.schemas import ToolResult


DEFAULT_MAX_OUTPUT_BYTES = 32 * 1024
REDACTED = "[REDACTED]"
TRUNCATION_MARKER = "\n[TRUNCATED]"

_SECRET_FIELD = (
    r"[\w-]{0,64}"
    r"(?:api[_-]?key|token|secret|password|passwd|private[_-]?key)"
    r"[\w-]{0,64}"
)

_PRIVATE_KEY = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----.*?"
    r"(?:-----END (?:[A-Z0-9]+ )?PRIVATE KEY-----|\Z)",
    re.DOTALL,
)

_AUTH_HEADER = re.compile(
    r"(\b(?:Bearer|Basic)[ \t]+)[A-Za-z0-9._~+/=-]+",
    re.IGNORECASE,
)

_SECRET_ASSIGNMENT = re.compile(
    rf"""(?P<prefix>(?<![\w-])(?:"""
    rf"""["']{_SECRET_FIELD}["'][ \t]*:\s*|"""
    rf"""["']?{_SECRET_FIELD}["']?[ \t]*=(?!=)[ \t]*|"""
    rf"""{_SECRET_FIELD}[ \t]*:\s*(?=["'])"""
    r"""))(?P<value>\[REDACTED\]|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;}\]]+)""",
    re.IGNORECASE,
)

_ENV_ASSIGNMENT = re.compile(
    rf"^(?P<prefix>[ \t]*(?:export[ \t]+)?{_SECRET_FIELD}"
    rf"[ \t]*=(?!=)[ \t]*)[^\r\n]*",
    re.IGNORECASE | re.MULTILINE,
)

def _mask_assignment(match: re.Match[str]) -> str:
    value = match.group("value")
    masked = REDACTED

    if value.startswith(("'", '"')):
        masked = value[0] + REDACTED + value[0]

    return match.group("prefix") + masked


def protect_tool_result(
    result: ToolResult,
    *,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    known_secrets: tuple[str, ...] = (),
) -> ToolResult:
    """Return a new protected result without logging or mutating raw output."""
    marker = TRUNCATION_MARKER.encode("utf-8")

    if type(max_output_bytes) is not int or max_output_bytes < len(marker):
        raise ValueError("Output limit must accommodate the truncation marker.")

    if not isinstance(known_secrets, tuple) or any(
        not isinstance(secret, str) or not secret
        for secret in known_secrets
    ):
        raise ValueError("Known secrets must be a tuple of non-empty strings.")

    result = ToolResult.model_validate(result)

    # Redact the complete output before truncating it.
    output = _PRIVATE_KEY.sub(REDACTED, result.output)

    output = _AUTH_HEADER.sub(
        lambda match: match.group(1) + REDACTED,
        output,
    )

    output = _SECRET_ASSIGNMENT.sub(_mask_assignment, output)

    output = _ENV_ASSIGNMENT.sub(
        lambda match: match.group("prefix") + REDACTED,
        output,
    )

    # Longer literals are replaced first to handle overlapping secrets.
    for secret in sorted(set(known_secrets), key=len, reverse=True):
        output = output.replace(secret, REDACTED)

    encoded = output.encode("utf-8")

    if len(encoded) > max_output_bytes:
        budget = max_output_bytes - len(marker)
        output = encoded[:budget].decode("utf-8", errors="ignore")
        output += TRUNCATION_MARKER

    # Revalidate the result and preserve trusted correlation metadata.
    return ToolResult.model_validate({
        **result.model_dump(),
        "output": output,
    })