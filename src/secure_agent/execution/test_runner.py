
"""Fixed-profile unit test execution for the secure executor.

Only trusted, predefined test profiles may be executed.
Arbitrary shell commands and agent-supplied arguments are not accepted.

This runner must execute inside an isolated sandbox when handling
untrusted repository content.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml


class UnknownTestProfile(ValueError):
    """Raised when the requested test profile is not configured."""


class TestRunnerError(RuntimeError):
    """Raised when the test runner configuration or execution fails."""


@dataclass(frozen=True)
class TestRunResult:
    """Immutable result of a fixed-profile test execution."""

    profile_id: str
    exit_code: int
    output: str


class TestRunner:
    """Execute predefined unit tests in a trusted workspace."""

    def __init__(
        self,
        workspace_root: str | Path,
        config_path: str | Path,
    ) -> None:
        self.workspace_root = Path(workspace_root).resolve(strict=True)

        if not self.workspace_root.is_dir():
            raise TestRunnerError("Workspace root must be a directory.")

        config_file = Path(config_path).resolve(strict=True)

        # Configuration must be supplied by the trusted backend.
        # Production deployments must keep it outside agent-writable paths.
        config = yaml.safe_load(config_file.read_text(encoding="utf-8"))

        if not isinstance(config, dict):
            raise TestRunnerError("Invalid test profile configuration.")

        profiles = config.get("profiles")

        if not isinstance(profiles, dict) or set(profiles) != {"unit"}:
            raise TestRunnerError("Only the fixed 'unit' profile is supported.")

        unit_config = profiles["unit"]

        if (
            not isinstance(unit_config, dict)
            or set(unit_config) != {"timeout_seconds"}
        ):
            raise TestRunnerError("Invalid unit test profile definition.")

        timeout = unit_config["timeout_seconds"]

        if type(timeout) is not int or not 1 <= timeout <= 60:
            raise TestRunnerError("Invalid test execution timeout.")

        self.timeout_seconds = timeout

    def run(self, profile_id: str) -> TestRunResult:
        """Execute the fixed unit test profile without invoking a shell."""
        if profile_id != "unit":
            raise UnknownTestProfile(
                f"Unknown or unauthorized test profile: {profile_id}"
            )

        test_directory = self.workspace_root / "tests" / "unit"

        if (
            not test_directory.is_dir()
            or (self.workspace_root / "tests").is_symlink()
            or test_directory.is_symlink()
            or not test_directory.resolve().is_relative_to(self.workspace_root)
        ):
            raise TestRunnerError("Invalid unit test directory.")

        # The executable and arguments are fixed by trusted code.
        command = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "tests/unit",
        ]

        try:
            completed = subprocess.run(
                command,
                cwd=self.workspace_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
            )

        except subprocess.TimeoutExpired as error:
            raise TestRunnerError(
                "Unit test execution exceeded the timeout."
            ) from error

        return TestRunResult(
            profile_id=profile_id,
            exit_code=completed.returncode,
            output=completed.stdout[-10000:],
        )
