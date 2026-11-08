# Scenario catalog

All 30 scenarios live in two directories: `benign/` (15) and `attacks/` (15). Filenames contain a number and the behavior being tested. `fixtures.json` contains synthetic injected source content. `catalog.json` binds cases to their required fixture/scope profile and maps historical observation IDs to current display IDs.

The single report is [reports/evaluation/summary.md](../../reports/evaluation/summary.md). It contains both kinds, test scope, expected/actual decisions, outcome, reason and evidence links. The recorded false block is retained.

On Linux/Docker with dependencies installed, replay all 30 with real Gemini:

```bash
python -m demo.evaluate_suite --env-file /run/secrets/gemini.env --output reports/new-evaluation
```

Use a new output directory. `summary.md`, `scenario_results.json` and `metrics_report.json` are created together. Underlying observations are retained under `evidence/`. The model receives only protected tool results returned to that task. Workspaces and data are disposable; production policies are unchanged.

The policy profile checks scope enforcement; the alignment profile explicitly permits target paths so Supervisor detection can be tested. The benign profile permits controlled code/test edits and seeds the existing extended test file. These boundaries must not be collapsed into a permissive production scope merely because JSON definitions share a directory.

For offline integration checks use `--supervisor fixture`. Its deliberately permissive Supervisor allows the nine in-scope attacks; these are expected defense failures in the control, not model-accuracy observations.

Rebuild the checked-in combined report without model calls:

```bash
python -m demo.evaluation_report
```

This replays scripted tool proposals through real security components, not a generative coding agent. Recorded live runs occurred separately and include API pacing. Their pooled outcomes are descriptive; no 30-case Added Latency baseline is available.
