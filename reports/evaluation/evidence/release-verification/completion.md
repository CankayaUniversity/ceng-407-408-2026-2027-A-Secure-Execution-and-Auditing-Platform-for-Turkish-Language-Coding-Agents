# Contributor 4 - Days 1-6 Delivery Summary

Historical verification dated November 7, 2026. For the November 8 separate
Executor and release verification, see `reports/docs/evaluation.md`.

| Day | Deliverable | Verification |
| --- | --- | --- |
| 1 | SQLite audit, logger, pytest, and CI infrastructure | Repository/logger/Gateway tests and real SQLite records |
| 2 | Demo login, Policy scenarios, Gateway-Executor-Audit integration | Linux Executor integration and demo login tests |
| 3 | Decision Engine, Policy-Supervisor ordering, audited decisions | Real Gemini calls and offline ALLOW/DENY/REVIEW/error tests |
| 4 | NetworkX Graph Inspector, Decision Engine and audit integration | Risk/missing-graph tests and graph/audit/permit traces |
| 5 | Six benign and six team attack scenarios, runner and metrics | Twelve JSON scenarios loaded and recorded in both runs |
| 6 | Twelve-case execution, paired latency and reports | Fixture/Gemini results, six measured pairs, 12/12 trace matches |

## Real-Supervisor results

- Model: `gemini-3.1-flash-lite`.
- Six benign tasks completed; Policy blocked all six attack targets.
- ASR: 0/6 (0%). TCR: 6/6 (100%). FBR: 0/6 (0%).
- Graph/audit/permit correlation: 12/12 scenarios.
- Secured mean over six benign tasks: 4277.10 ms.
- Mean matched baseline: 96.91 ms.
- Mean added latency: 4180.19 ms, approximately 4.18 seconds.

Durations are single-pass observations including model/network time. Agent
proposals were scripted; a live generative agent's injection susceptibility was
not measured by this dataset. Policy rejects the attack targets before they
reach Supervisor, so these results do not show that Gemini detected every attack.

The historical test counts are in `test_summary.json`. The reproduction method
is described in `docs/evaluation.md`.

## Deployment status at the time of measurement

On November 7, the separate Executor entry point was still disabled. These
measurements exercised the real Executor in a test container with disposable
workspaces, not the later separate-service deployment. That deployment has
since been added and verified; consult the final report for current evidence.

API credentials and raw SQLite ledgers remain outside Git. Local verification
is distinct from GitHub Actions verification of a published commit.
