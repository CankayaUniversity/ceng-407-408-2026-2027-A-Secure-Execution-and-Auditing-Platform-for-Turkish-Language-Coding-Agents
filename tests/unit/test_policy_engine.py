"""Policy authorization tests using the real Registry, schemas and Casbin files.

Repository location: tests/unit/test_policy_engine.py
Run from the repository root with src on PYTHONPATH.
These tests do not execute tools, start containers, or test HTTP endpoints.
Protected resources are deliberately included in a trusted test scope to
verify that a mistaken grant cannot override the model's protection rules.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from secure_agent.common.schemas import (
    SecurityDecision,
    Task,
    ToolCall,
    ToolName,
    parse_tool_call,
)
from secure_agent.security.policy_engine import PolicyConfigurationError, PolicyEngine
from secure_agent.tasks.registry import TaskRegistry
from secure_agent.tasks.scope import TaskScope


PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = PROJECT_ROOT / "configs" / "casbin_model.conf"
POLICY_PATH = PROJECT_ROOT / "configs" / "casbin_policy.csv"
ALL_TOOLS: frozenset[ToolName] = frozenset(
    {
        "secure_read_file",
        "secure_edit_file",
        "secure_list_files",
        "secure_run_tests",
    }
)


@pytest.fixture
def registry() -> TaskRegistry:
    """Register independent task scopes without touching a real workspace."""
    scopes = [
        TaskScope(
            scope_id="login-fix",
            workspace_id="demo",
            allowed_tools=ALL_TOOLS,
            readable_files=frozenset(
                {
                    "src/login.py", "README.md", ".env", ".env.local",
                    ".env.example", "config/.env", ".git/config",
                    "config/.env.production", "src/.env/secret.txt",
                }
            ),
            writable_files=frozenset({"src/login.py", ".env", ".git/config"}),
            listable_directories=frozenset({".", "src", ".git", "config/.env"}),
            allowed_test_profiles=frozenset({"unit", ".env"}),
        ),
        TaskScope(scope_id="empty", workspace_id="demo"),
        TaskScope(
            scope_id="tools-only", workspace_id="demo", allowed_tools=ALL_TOOLS
        ),
        TaskScope(
            scope_id="read-only",
            workspace_id="demo",
            allowed_tools=frozenset({"secure_read_file"}),
            readable_files=frozenset({"src/login.py"}),
        ),
        TaskScope(
            scope_id="write-only",
            workspace_id="demo",
            allowed_tools=frozenset({"secure_edit_file"}),
            writable_files=frozenset({"src/login.py"}),
        ),
        TaskScope(
            scope_id="other-task",
            workspace_id="demo",
            allowed_tools=frozenset({"secure_read_file"}),
            readable_files=frozenset({"src/other.py"}),
        ),
    ]
    result = TaskRegistry(workspace_ids={"demo"}, scopes=scopes)
    for scope in scopes:
        result.register(
            Task(
                task_id=scope.scope_id,
                user_goal="Giriş kontrolündeki hatayı düzelt.",
                workspace_id="demo",
                scope_id=scope.scope_id,
            )
        )
    return result


@pytest.fixture
def engine(registry: TaskRegistry) -> PolicyEngine:
    return PolicyEngine(
        registry=registry, model_path=MODEL_PATH, policy_path=POLICY_PATH
    )


def make_call(
    tool: ToolName = "secure_read_file",
    resource: str = "src/login.py",
    *,
    task_id: str = "login-fix",
) -> ToolCall:
    """Use the shared parser, including the separate test-profile argument."""
    arguments: dict[str, str]
    if tool == "secure_run_tests":
        arguments = {"profile_id": resource}
    else:
        arguments = {"path": resource}
        if tool == "secure_edit_file":
            arguments["content"] = "def giriş():\r\n    return True\r\n"
    return parse_tool_call(
        {
            "request_id": "req-policy-test",
            "task_id": task_id,
            "tool": tool,
            "arguments": arguments,
        }
    )


def assert_decision(
    result: SecurityDecision, decision: str, reason_code: str
) -> None:
    assert isinstance(result, SecurityDecision)
    assert result.decision == decision
    assert result.reason_code == reason_code


@pytest.mark.parametrize(
    ("tool", "resource"),
    [
        ("secure_read_file", "src/login.py"),
        ("secure_read_file", "README.md"),
        ("secure_edit_file", "src/login.py"),
        ("secure_list_files", "."),
        ("secure_list_files", "src"),
        ("secure_run_tests", "unit"),
    ],
)
def test_explicitly_granted_operations_are_allowed(engine, tool, resource):
    assert_decision(engine.evaluate(make_call(tool, resource)), "ALLOW", "POLICY_ALLOWED")


@pytest.mark.parametrize(
    ("tool", "resource"),
    [
        ("secure_read_file", ".env"),
        ("secure_read_file", ".env.local"),
        ("secure_read_file", ".env.example"),
        ("secure_read_file", "config/.env"),
        ("secure_read_file", "config/.env.production"),
        ("secure_read_file", "src/.env/secret.txt"),
        ("secure_read_file", ".git/config"),
        ("secure_edit_file", ".env"),
        ("secure_edit_file", ".git/config"),
        ("secure_list_files", ".git"),
        ("secure_list_files", "config/.env"),
    ],
)
def test_protected_paths_override_explicit_grants(engine, tool, resource):
    assert_decision(engine.evaluate(make_call(tool, resource)), "DENY", "POLICY_DENIED")


@pytest.mark.parametrize(
    ("tool", "resource"),
    [
        ("secure_read_file", "src/other.py"),
        ("secure_edit_file", "README.md"),
        ("secure_read_file", "src/./login.py"),
        ("secure_read_file", "src//login.py"),
        ("secure_list_files", "src/child"),
        ("secure_run_tests", "integration"),
    ],
)
def test_ungranted_resources_and_path_aliases_are_denied(engine, tool, resource):
    assert_decision(engine.evaluate(make_call(tool, resource)), "DENY", "POLICY_DENIED")


@pytest.mark.parametrize("task_id", ["empty", "tools-only"])
@pytest.mark.parametrize(
    ("tool", "resource"),
    [
        ("secure_read_file", "src/login.py"),
        ("secure_edit_file", "src/login.py"),
        ("secure_list_files", "src"),
        ("secure_run_tests", "unit"),
    ],
)
def test_tool_availability_alone_never_grants_resources(engine, task_id, tool, resource):
    result = engine.evaluate(make_call(tool, resource, task_id=task_id))
    assert_decision(result, "DENY", "POLICY_DENIED")


@pytest.mark.parametrize(
    ("task_id", "tool", "decision"),
    [
        ("read-only", "secure_read_file", "ALLOW"),
        ("read-only", "secure_edit_file", "DENY"),
        ("write-only", "secure_edit_file", "ALLOW"),
        ("write-only", "secure_read_file", "DENY"),
    ],
)
def test_read_and_write_permissions_are_independent(engine, task_id, tool, decision):
    result = engine.evaluate(make_call(tool, task_id=task_id))
    reason = "POLICY_ALLOWED" if decision == "ALLOW" else "POLICY_DENIED"
    assert_decision(result, decision, reason)


def test_permissions_from_another_task_are_not_inherited(engine):
    allowed = engine.evaluate(make_call(resource="src/other.py", task_id="other-task"))
    denied = engine.evaluate(make_call(resource="src/other.py"))
    assert_decision(allowed, "ALLOW", "POLICY_ALLOWED")
    assert_decision(denied, "DENY", "POLICY_DENIED")


def test_test_profile_name_is_not_a_filesystem_path(engine):
    # This is a trusted profile identifier, not permission to access .env.
    result = engine.evaluate(make_call("secure_run_tests", ".env"))
    assert_decision(result, "ALLOW", "POLICY_ALLOWED")


def test_unknown_task_is_denied_without_creating_a_record(engine):
    result = engine.evaluate(make_call(task_id="missing-task"))
    assert_decision(result, "DENY", "TASK_NOT_FOUND")


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"tool": "shell", "arguments": {"command": "id"}},
        {"tool": "secure_read_file", "arguments": {"path": "../.env"}},
        {"tool": "secure_read_file", "arguments": {"path": "/etc/passwd"}},
        {"tool": "secure_read_file", "arguments": {"path": "src\\login.py"}},
        {"tool": "secure_read_file", "arguments": {"path": "C:/secret.txt"}},
        {"tool": "secure_run_tests", "arguments": {"command": "pytest"}},
        {
            "tool": "secure_read_file", "arguments": {"path": "src/login.py"},
            "scope_id": "admin",
        },
    ],
)
def test_malformed_or_forged_requests_are_denied(engine, payload):
    request = {"request_id": "invalid-req", "task_id": "login-fix", **payload}
    # Deliberately bypass normal Gateway parsing to exercise defensive validation.
    result = engine.evaluate(request)
    assert_decision(result, "DENY", "INVALID_TOOL_CALL")


def test_existing_model_instances_are_revalidated(engine):
    forged = make_call().model_copy(update={"task_id": ""})
    assert_decision(engine.evaluate(forged), "DENY", "INVALID_TOOL_CALL")


def test_enforcer_failure_denies_instead_of_allowing(engine):
    with patch.object(engine._enforcer, "enforce", side_effect=RuntimeError("failure")):
        result = engine.evaluate(make_call())
    assert_decision(result, "DENY", "POLICY_EVALUATION_ERROR")


def test_registry_failure_denies_instead_of_allowing(engine):
    with patch.object(engine._registry, "get_scope", side_effect=RuntimeError("failure")):
        result = engine.evaluate(make_call())
    assert_decision(result, "DENY", "TASK_CONTEXT_ERROR")


def test_truthy_non_boolean_enforcer_result_does_not_authorize(engine):
    with patch.object(engine._enforcer, "enforce", return_value="allow"):
        result = engine.evaluate(make_call())
    assert_decision(result, "DENY", "POLICY_DENIED")


def test_evaluation_preserves_original_edit_arguments(engine):
    request = make_call("secure_edit_file")
    before = request.model_dump_json()
    assert engine.evaluate(request).decision == "ALLOW"
    assert request.model_dump_json() == before


@pytest.mark.parametrize("missing_part", ["model", "policy"])
def test_missing_configuration_aborts_startup(registry, tmp_path, missing_part):
    missing = tmp_path / "missing.conf"
    with pytest.raises(PolicyConfigurationError):
        PolicyEngine(
            registry=registry,
            model_path=missing if missing_part == "model" else MODEL_PATH,
            policy_path=missing if missing_part == "policy" else POLICY_PATH,
        )


@pytest.mark.parametrize(
    "text",
    [
        "p, secure_read_file, alow\n",
        "p, shell, allow\n",
        "p, secure_read_file, allow, extra\n",
        "p, secure_read_file\n",
        "tool, eft\n",
    ],
)
def test_malformed_policy_records_abort_startup(registry, tmp_path, text):
    policy = tmp_path / "policy.csv"
    policy.write_text(text, encoding="utf-8")
    with pytest.raises(PolicyConfigurationError):
        PolicyEngine(registry=registry, model_path=MODEL_PATH, policy_path=policy)


def test_empty_policy_denies_every_request(registry, tmp_path):
    policy = tmp_path / "policy.csv"
    policy.write_text("", encoding="utf-8")
    engine = PolicyEngine(registry=registry, model_path=MODEL_PATH, policy_path=policy)
    assert_decision(engine.evaluate(make_call()), "DENY", "POLICY_DENIED")


def test_global_deny_overrides_allow_without_disabling_other_tools(registry, tmp_path):
    policy = tmp_path / "policy.csv"
    policy.write_text(
        POLICY_PATH.read_text(encoding="utf-8") + "\np, secure_read_file, deny\n",
        encoding="utf-8",
    )
    engine = PolicyEngine(registry=registry, model_path=MODEL_PATH, policy_path=policy)
    assert_decision(engine.evaluate(make_call()), "DENY", "POLICY_DENIED")
    assert_decision(
        engine.evaluate(make_call("secure_edit_file")), "ALLOW", "POLICY_ALLOWED"
    )
