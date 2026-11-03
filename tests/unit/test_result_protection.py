"""Security checks for protected tool results."""

import pytest

from secure_agent.common.schemas import ToolResult
from secure_agent.security.result_protection import (
    REDACTED,
    TRUNCATION_MARKER,
    protect_tool_result,
)


def make_result(output):
    return ToolResult(
        request_id="req-protection",
        status="success",
        output=output,
        source_id="source-backend-001",
        trust_level="untrusted",
    )


def test_clean_output_and_source_metadata_are_preserved():
    original = make_result("README: Türkçe açıklama.")
    protected = protect_tool_result(original)

    assert protected == original
    assert protected is not original
    assert protected.source_id == "source-backend-001"
    assert protected.request_id == "req-protection"
    assert protected.trust_level == "untrusted"


@pytest.mark.parametrize("text,secret", [
    ("API_KEY=demo-secret-123", "demo-secret-123"),
    ("DB_PASSWORD=two unquoted words", "two unquoted words"),
    ("export ACCESS_TOKEN=demo-token-123", "demo-token-123"),
    (
        '{"password": "two secret words", "ok": true}',
        "two secret words",
    ),
    ("client_secret='secret with spaces'", "secret with spaces"),
    ("Authorization: Bearer demo.token-123", "demo.token-123"),
    ("Authorization: Basic ZGVtbzpzZWNyZXQ=", "ZGVtbzpzZWNyZXQ="),
    (
        "-----BEGIN PRIVATE KEY-----\n"
        "DEMO_KEY_BODY\n"
        "-----END PRIVATE KEY-----",
        "DEMO_KEY_BODY",
    ),
    (
        "-----BEGIN RSA PRIVATE KEY-----\nUNFINISHED_BODY",
        "UNFINISHED_BODY",
    ),
])
def test_common_credentials_are_redacted(text, secret):
    original = make_result(text)
    protected = protect_tool_result(original)

    assert secret not in protected.output
    assert REDACTED in protected.output
    assert original.output == text


def test_known_literal_is_redacted_without_a_field_name():
    protected = protect_tool_result(
        make_result("Credential appears here: example-literal-credential."),
        known_secrets=("example-literal-credential",),
    )

    assert "example-literal-credential" not in protected.output
    assert REDACTED in protected.output


def test_utf8_limit_includes_marker_and_preserves_valid_text():
    protected = protect_tool_result(
        make_result("ğ" * 100),
        max_output_bytes=17,
    )

    assert len(protected.output.encode("utf-8")) <= 17
    assert protected.output.endswith(TRUNCATION_MARKER)
    assert "\ufffd" not in protected.output


def test_secret_is_redacted_before_output_is_cut():
    secret = "sensitive-credential-value-123"

    protected = protect_tool_result(
        make_result("x" * 20 + "\nAPI_KEY=" + secret),
        max_output_bytes=48,
    )

    assert secret[:10] not in protected.output
    assert REDACTED in protected.output


@pytest.mark.parametrize("limit", [True, 0, -1, 5, 32.5, "32"])
def test_invalid_output_limits_are_rejected(limit):
    with pytest.raises(ValueError):
        protect_tool_result(
            make_result("README"),
            max_output_bytes=limit,
        )


@pytest.mark.parametrize("secrets", ["secret", ("",), (123,)])
def test_invalid_known_secret_configuration_is_rejected(secrets):
    with pytest.raises(ValueError):
        protect_tool_result(
            make_result("README"),
            known_secrets=secrets,
        )


def test_protection_emits_no_output_or_logs(caplog, capsys):
    secret = "must-not-be-logged"

    protected = protect_tool_result(
        make_result("API_KEY=" + secret),
    )

    captured = capsys.readouterr()

    assert captured.out == captured.err == ""
    assert caplog.records == []
    assert secret not in protected.output

@pytest.mark.parametrize("text", [
    "def login(username: str, password: str) -> bool:\n    return True\n",
    "return username == DEMO_USERNAME and password == DEMO_PASSWORD\n",
    "if token != expected:\n    return False\n",
    ])
def test_python_annotations_and_comparisons_are_preserved(text):
    protected = protect_tool_result(make_result(text))

    assert protected.output == text