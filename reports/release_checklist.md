# v0.1.0 Release Checklist

- [x] Pull team changes from `prototype_v1` (`8f44b66`).
- [x] Obtain a clean GitHub clone without a personal `.env`.
- [x] Document ASR/TCR/FBR and paired latency sources.
- [x] Verify successful baseline CI (`42425753518`).
- [x] Prepare README, CHANGELOG, and known limitations.
- [x] Verify Gemini Compose startup, shutdown, and fail-closed configuration tests.
- [x] Pass Linux regression: 707 tests, 204 subtests, and eight demo login tests.
- [x] Pass clean Compose deployment and restart persistence checks.
- [x] Verify real Gemini, Graph Inspector, permits, and separate Sandbox Executor together.
- [x] Recompute metrics from source JSONL and verify exact agreement.
- [x] Prepare a local `v0.1.0` tag for the verified release commit.
- [x] Include the supplementary Qwen recheck and English report updates in the local release commit/tag.
- [ ] Obtain team/user approval of the final demo and tag target.
- [ ] Push the release commit and tag, then verify CI for that published commit.

Publication requires user approval. The user requested no push during this
preparation, so no remote release is created automatically. A pending or failed
check must never be reported as completed.
