# Evaluation

Final release evaluation: [reports/docs/evaluation.md](../reports/docs/evaluation.md).

## Run again

Use Linux/Docker so the real `WorkspaceFileSystem` is exercised. Install
`requirements.txt` and `.[dev]`, then run from the project root:

```bash
python -m demo.evaluate --output reports/new-run --env-file /run/secrets/gemini.env
```

Mount the local `.env` read-only at `/run/secrets/gemini.env`. Never copy it into
an image. Use a new output directory for each run. The model defaults to
`gemini-3.1-flash-lite`; `--model` explicitly overrides it. Offline regression:

```bash
python -m demo.evaluate --supervisor fixture --output reports/new-offline-run
python -m pytest tests -q
```

The harness uses six checked-in benign and six teammate-authored attack JSONs.
Each scenario receives its own trusted task goal and fresh fixture workspace.
The normal edit reads the original login module before proposing replacement.
Only protected tool results actually returned to that task are supplied to the
Supervisor as untrusted context. Workspaces are discarded after the run.

## Evidence and scope

The November 7 run is under `reports/evaluation/`. `fixture/` is deterministic;
`gemini/` uses a real Gemini Supervisor. Both use scripted agent proposals,
real loopback HTTP, Casbin, graph inspection, SQLite audit, Ed25519 issuance,
single-use verification and the actual Linux Executor. All 12 cases passed in
both runs. Raw ledgers remain local and Git-ignored under each `ledgers/` folder.

This is a controlled pipeline evaluation, not a measurement of a generative
agent's susceptibility to injection. The six attack targets violate task scope
and are rejected by Policy before Supervisor; no model call is needed for those
targets. Successful source reads are recorded in graph and audit. Permit
issuance and verification are recorded for allowed execution; blocked requests
have no permit. The report validates these relationships by request ID.

Separate real-model smoke checks also exercised task alignment and a synthetic
injected source. These do not establish universal injection resistance.

## Added Latency

For each benign scenario the same scripted task runs against a security-enabled
Gateway and a loopback fixture-only baseline. Each gets an identical fresh copy
of the project. Both use the same HTTP adapter, AgentLoop, filesystem operations,
test profile, result serialization and read acknowledgement round trips.
The baseline omits Policy, Supervisor, graph, permit and audit processing. Its
fixed-step guard accepts only unchanged checked-in benign scenarios; attacks
are never run through this endpoint.

Only pairs that complete the same benign task enter Added Latency. Per pair:
`secured latency_ms - baseline latency_ms`. The mean, pair count and both
component means are reported. `baseline.jsonl` and `evaluation.jsonl` preserve
the measurements. Gemini mode includes real Supervisor/network time; fixture
mode measures the remaining controlled pipeline overhead. These are one-pass
descriptive measurements, with security-enabled measured first, not a statistical
benchmark. Test-process startup and machine/network variation affect them.

## Deliverables

- `evaluation.jsonl`: all 12 scenario outcomes and measured durations.
- `scenario_results.json`: expected/observed decisions and classifications.
- `metrics_report.json`: ASR/TCR/FBR numerators, denominators, unknown counts and latency.
- `audit_graph_validation.json`: request-level graph/audit/permit matches.
- `baseline.jsonl`: six measured benign baseline durations.
- `methodology.json` and `summary.md`: experiment scope and readable results.
- `test_summary.json` in the parent folder: final deterministic test verification.

## Team deployment boundary

The November 7 evaluation container exercised the real Executor on disposable
workspaces. That historical run did not activate the separate executor service.
The team has since added the read-only Compose service and verification runner
in `scripts/run_demo.py`; see [deployment](deployment.md). The final release
report records its independently observed verification result. The default
Gateway still deliberately requires explicit trusted dependency injection.
