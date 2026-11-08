# Changelog

## 0.1.0 — 2026-11-08 (local release preparation)

### Included

- Strict shared contracts and registered task scopes; Casbin authorization.
- Agent/Gateway tool protocol, bounded read retries and protected tool results.
- SQLite audit lookup by request ID and persisted provenance relationships.
- NetworkX Graph Inspector and deterministic ALLOW/DENY/REVIEW aggregation.
- Supervisor source separation and optional Gemini structured-JSON client.
- Ed25519 permits, operation binding, expiry and persistent one-use nonce checks.
- Separate read-only Executor service, internal Docker network, resource limits,
  key separation and restart persistence verification.
- Six benign and six attack fixtures; evaluation runner and measured paired
  baselines, JSON/Markdown reports and numerator/denominator metric reporting.
- Optional real Gemini selection for the existing Compose verification demo.

### Release verification

See `reports/docs/evaluation.md`, `reports/test_results.md` and
`reports/release_checklist.md` for observed results and any unfinished gate.
This file does not by itself declare a release/tag published.

### Fixed during verification

- Decode Docker subprocess output explicitly as UTF-8 on Windows.
- Remove an identical duplicate demo-registry function definition.
- Make the real-provider Gateway timeout explicit in the Compose Agent command.

### Known limitations

- Prototype deployment is loopback-only with one trusted read-only demo task;
  the remote Executor API exposes README reads, not the complete four-tool set.
- The twelve-case evaluation uses scripted agent proposals. Its ASR does not
  establish a live generative agent's susceptibility or Gemini's classifier accuracy.
- All six attack target calls are rejected by task scope before Supervisor.
- Existing latency results are descriptive single-pass measurements, not a
  repeated statistical benchmark; live provider and network time are included.
- The real Qwen README recheck returned the correct command with extra prose;
  the strict command-only response-format requirement was not satisfied.
- No multi-user authentication, task ownership service or public deployment is
  provided. Provider failure remains fail-closed as REVIEW.
- Result verification is acknowledged in Gateway after the remote read returns;
  this is not a distributed transaction across audit and execution databases.
- The real filesystem backend requires POSIX/Linux. API credentials must remain
  local; real-model demos depend on provider availability and quota.
