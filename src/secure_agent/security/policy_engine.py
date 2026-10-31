"""Task-scoped authorization using the trusted Casbin model and policy.

Repository location: src/secure_agent/security/policy_engine.py
Configure one engine at backend startup with explicit, trusted config paths.
Scopes come only from TaskRegistry, never from agent-provided permission data.
SecurityDecision describes this policy stage, not the final execution verdict.
ALLOW does not bypass authentication, supervisor, permit or executor checks.
No tools are executed here. Filesystem containment, symlink/race protection,
listing filters and test-profile command resolution belong to the executor.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from threading import RLock
from typing import get_args

import casbin
from pydantic import ValidationError

from secure_agent.common.schemas import (
    RunTestsToolCall,
    SecurityDecision,
    ToolCall,
    ToolName,
    parse_tool_call,
)
from secure_agent.tasks.registry import TaskNotFoundError, TaskRegistry


_LOGGER = logging.getLogger(__name__)


class PolicyConfigurationError(RuntimeError):
    """Trusted startup configuration could not be loaded; do not serve tools."""


def _validate_policy_rows(path: Path) -> None:
    """Reject malformed records instead of silently losing intended rules."""
    known_tools = frozenset(get_args(ToolName))
    with path.open(encoding="utf-8", newline="") as policy_file:
        for line_number, row in enumerate(csv.reader(policy_file), start=1):
            fields = [field.strip() for field in row]
            if not fields or not any(fields) or fields[0].startswith("#"):
                continue
            if (
                len(fields) != 3
                or fields[0] != "p"
                or fields[1] not in known_tools
                or fields[2] not in {"allow", "deny"}
            ):
                raise ValueError(f"Invalid policy record at line {line_number}.")


class PolicyEngine:
    """Evaluate validated tool calls against registered scopes and global rules.

    Model and policy files must be controlled by the trusted backend, outside
    the agent's editable workspace. Load once; restart to apply config changes.
    An empty policy grants nothing. Initialization errors abort construction;
    evaluation errors return DENY. Never fall back to an unprotected executor.
    This class does not authenticate callers or check ownership of a task_id.
    """

    def __init__(
        self,
        *,
        registry: TaskRegistry,
        model_path: str | Path,
        policy_path: str | Path,
    ) -> None:
        self._registry = registry
        self._lock = RLock()
        try:
            model_file = Path(model_path).resolve(strict=True)
            policy_file = Path(policy_path).resolve(strict=True)
            if not model_file.is_file() or not policy_file.is_file():
                raise ValueError("Model and policy paths must point to files.")
            _validate_policy_rows(policy_file)
            self._enforcer = casbin.Enforcer(str(model_file), str(policy_file))
            self._enforcer.enable_auto_save(False)
        except Exception as error:
            raise PolicyConfigurationError(
                "Cannot initialize the trusted authorization policy."
            ) from error

    def evaluate(self, call: ToolCall) -> SecurityDecision:
        """Return ALLOW or DENY with a stable reason code; never execute a tool.

        Revalidate even an existing model instance. Normal Gateway request
        validation should reject malformed HTTP input before this stage.
        Preserve original arguments: never rewrite paths or edit contents.
        """
        try:
            validated_call = parse_tool_call(call)
        except ValidationError:
            return SecurityDecision(decision="DENY", reason_code="INVALID_TOOL_CALL")

        try:
            scope = self._registry.get_scope(validated_call.task_id)
        except TaskNotFoundError:
            return SecurityDecision(decision="DENY", reason_code="TASK_NOT_FOUND")
        except Exception:
            _LOGGER.exception("Task scope lookup failed; denying the request.")
            return SecurityDecision(decision="DENY", reason_code="TASK_CONTEXT_ERROR")

        if isinstance(validated_call, RunTestsToolCall):
            resource = validated_call.arguments.profile_id
        else:
            resource = validated_call.arguments.path

        try:
            with self._lock:
                allowed = self._enforcer.enforce(
                    scope, validated_call.tool, resource
                )
        except Exception:
            _LOGGER.exception("Policy evaluation failed; denying the request.")
            return SecurityDecision(
                decision="DENY", reason_code="POLICY_EVALUATION_ERROR"
            )

        if allowed is True:
            return SecurityDecision(decision="ALLOW", reason_code="POLICY_ALLOWED")
        return SecurityDecision(decision="DENY", reason_code="POLICY_DENIED")
