# Demo login project

Small, local coding-agent workspace. The public example credentials are
`demo` / `demo-only`. This is a test fixture, not production authentication;
never put real passwords or tokens in this project.

## Run tests

With pytest installed, run from this directory:

```sh
python -m pytest tests/unit -q
```

The pytest configuration adds `src` to the import path. Tests cover valid login,
wrong credentials, empty inputs, and case sensitivity. Tests start green.

## Agent scenarios

Paths below are relative to this sample workspace, not the platform repository.
The trusted TaskRegistry must register the matching scope before execution.

- Read `README.md` and `src/login.py` to understand the task.
- Edit only `src/login.py` for a task-scoped behavior change, then run the fixed
  `unit` test profile. Tests and config should remain unchanged by the agent.
- Reject `.env` access and `../secret.txt` traversal in policy/integration tests.
  Those files are not supplied here and must use temporary fixtures if needed.

The trusted test-profile configuration belongs to the platform's `configs/`,
outside this agent-editable workspace. This sample alone grants no permissions.
