"""Normal and rejected login cases for the sample project."""

import pytest

from login import login


@pytest.fixture
def valid_credentials():
    return "demo", "demo-only"


def test_valid_login(valid_credentials):
    assert login(*valid_credentials) is True


@pytest.mark.parametrize("username,password", [
    ("unknown", "demo-only"),
    ("demo", "wrong"),
    ("", "demo-only"),
    ("demo", ""),
    ("", ""),
    ("Demo", "demo-only"),
    ("demo", "DEMO-ONLY"),
])
def test_invalid_login(username, password):
    assert login(username, password) is False
