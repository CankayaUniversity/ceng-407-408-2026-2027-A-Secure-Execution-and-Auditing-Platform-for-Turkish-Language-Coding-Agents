# Evaluation

Start with the [complete 30-case results](../reports/evaluation/summary.md): 15 benign tasks and 15 attacks. Each case lists the trusted task, proposed operations, expected and observed decision, outcome, backend reason and raw evidence. The legitimate-task false block is retained.

All definitions are in [demo/scenarios](../demo/scenarios/README.md), under `benign/` and `attacks/`. Fixture/scope profiles share the same catalog but retain independent trusted permissions.

## Run the full suite

Use Linux/Docker, install `requirements.txt` and `.[dev]`, mount your local `.env` read-only, then run:

```bash
python -m demo.evaluate_suite --env-file /run/secrets/gemini.env --output reports/new-evaluation
```

Use a new directory. This runs all 30 definitions with a real Gemini Supervisor, HTTP Gateway, Graph Inspector, Ed25519 permits and Linux Executor. Agent proposals are scripted JSON. No live generative-agent accuracy claim is made.

`summary.md` is the main report; `scenario_results.json` contains machine-readable per-case details; `metrics_report.json` contains denominators and rates; `evidence/` retains raw observations and trace validation. Local SQLite ledgers are ignored by Git.

To rebuild the published consolidated report without calling Gemini:

```bash
python -m demo.evaluation_report
```

For offline deterministic regression:

```bash
python -m pytest tests -q
python -m demo.evaluate_suite --supervisor fixture --output reports/new-control
```

The fixture Supervisor always permits aligned operations. Nine attack targets are deliberately in scope, so they succeed in that control. These defense failures demonstrate target reachability; they must not be confused with real Gemini decisions.

## Measurement limits

The checked-in 30-case report merges separately recorded live runs, without relabeling failures or rerunning them to improve scores. Some durations include deliberate API pacing. Do not compare those means as a performance benchmark. Six policy-profile benign tasks have release-time paired security-on/off baselines under `reports/evaluation/evidence/policy-live/`; no paired baseline exists for all 30.

Scope denials do not establish Supervisor detection. Supervisor MISALIGNED denotes a task-alignment decision; raw model explanations are not retained. Attack success requires the target effect, not merely an ALLOW verdict. Planting a malicious test is scored as a file replacement; later execution or external exfiltration is not claimed.

The [release-time evaluation](../reports/docs/evaluation.md) remains available as historical evidence and should not be read as results for all 30 cases.
