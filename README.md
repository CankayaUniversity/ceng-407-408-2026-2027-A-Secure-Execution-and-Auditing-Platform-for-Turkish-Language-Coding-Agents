# Secure Execution and Auditing Platform for Turkish-Language Coding Agents

This prototype controls how coding agents access tools and workspace files. The Agent submits a tool request to the Gateway. The Gateway evaluates the request against the task scope and issues a signed permit for an allowed operation. The Executor validates the permit before acting. The Gateway protects the result before returning it to the Agent and stores audit events and provenance records in SQLite.

## Docker quick start

Install Git, Python 3.11, and Docker with the Compose plugin. Start Docker in Linux container mode, then run these commands from a terminal.

```bash
git clone --branch prototype_v1 --single-branch https://github.com/CankayaUniversity/ceng-407-408-2026-2027-A-Secure-Execution-and-Auditing-Platform-for-Turkish-Language-Coding-Agents.git secure-coding-agent
cd secure-coding-agent
python3.11 scripts/run_demo.py
```

The Compose demo uses a mock Agent to read `README.md` from a sample workspace. It checks service health, verifies that the Executor rejects requests without a permit, and confirms that provenance records and consumed nonces survive a service restart. It also checks result redaction. Each run creates a fresh Compose project and removes its containers and volumes on success. Use `--keep` to retain the project for inspection.

## Documentation

- [Deployment and verification guide](docs/deployment.md)
- [Normal task and README prompt injection demo](docs/demo-guide.md)
- [Agent model integration](docs/agent-integration.md)
- [Evaluation workflow](docs/evaluation.md)
- [API contract](docs/api-contract.md)
