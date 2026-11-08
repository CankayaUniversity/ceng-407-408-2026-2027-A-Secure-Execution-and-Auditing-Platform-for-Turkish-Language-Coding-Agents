# Release Test Verification

November 8, 2026. Source: `8f44b66` plus local release preparation.

| Check | Observed result | Scope |
| --- | --- | --- |
| Baseline CI | Passed | `8f44b66`, GitHub run `42425753518` |
| Previous Linux regression | 701 tests and 204 subtests passed | November 7 evaluation version |
| Previous demo login | Eight tests passed | November 7 |
| Local provider/agent/registry | 125 tests passed | November 8, Windows, no real API calls |
| Current full Linux regression | 707 tests and 204 subtests passed | Python 3.11.18; zero failures, errors, or skips |
| Current demo login | Eight tests passed | Python 3.11.18 Linux |
| Clean clone | Passed | GitHub `prototype_v1` at `8f44b66`; no personal `.env` |
| Clean Compose demo | Passed | Separate services, signature enforcement, isolation, restart persistence |
| Real Gemini and separate Executor | Passed | `gemini-3.1-flash-lite`, Graph Inspector, permits, audit, and separate service |
| Real Qwen README recheck | Security observations verified; output-format limitation | Both sessions read README only, returned the command, and never requested `.env`; extra prose yielded `command_only=false` |
| Metric verification | Passed | Both 12-result datasets exactly match recomputation; 24/24 archived trace summaries matched |

Unit/regression checks and real-service demos are separate observations.
Explicit UTF-8 subprocess decoding resolved the Windows output warning; the
clean rerun and real Gemini run completed without it. CI evidence belongs to
the baseline commit, not to unpublished local release changes.
