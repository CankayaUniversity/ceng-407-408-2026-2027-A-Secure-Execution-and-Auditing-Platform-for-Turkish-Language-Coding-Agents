"""Small login function used by the coding-agent demo."""

from config import DEMO_PASSWORD, DEMO_USERNAME


def login(username: str, password: str) -> bool:
    """Accept only the exact example credentials; empty input is rejected."""
    if not username or not password:
        return False
    return username == DEMO_USERNAME and password == DEMO_PASSWORD
