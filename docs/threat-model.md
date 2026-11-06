# Threat Model and Security Limitations

**Project:** A Secure Execution and Auditing Platform for Turkish Language Coding Agents  
**Document revision:** 0.1.0 — Day 7 documentation  
**Prepared:** 2026-11-06  
**Repository location:** `docs/threat-model.md`  
**Evidence scope:** Inspected Day 1–6 security components and the test results listed in Section 8. No release commit SHA or complete deployed-system assessment is attached to this document.

## 1. Purpose and scope

The platform aims to let a coding agent perform a Turkish-language user task while preventing repository content, tool output or agent proposals from granting additional authority. This document identifies protected assets, trust boundaries, attack scenarios, implemented controls and unresolved security requirements.

The review follows an asset-and-boundary approach: identify what is protected, how an attacker could cross a boundary, the available control and the evidence needed to validate it. OWASP's threat-modeling guidance provides the review structure [R1]. Threat priorities below are project judgments, not measured exploit probabilities or CVSS scores.

The inspected scope includes:

- `src/secure_agent/common/schemas.py` and `common/canonical_json.py`.
- `src/secure_agent/tasks/scope.py` and `tasks/registry.py`.
- `src/secure_agent/security/policy_engine.py`, `security/supervisor.py` and `security/permit_issuer.py`.
- `configs/casbin_model.conf` and `configs/casbin_policy.csv`.
- `tests/unit/test_supervisor.py`, `tests/security/test_alignment.py` and `tests/security/test_security_pipeline.py`.
- Earlier inspected Permit Issuer unit tests and the CI configuration supplied by the developer.

Authentication endpoints, the production decision provider, Graph Inspector, permit verifier, executor, Docker/gVisor configuration and audit/database implementation were not fully inspected for this document. Their status is **not verified here**, which does not establish that they are absent from the team's repository. An observed Windows import failure in `execution/filesystem.py` is not a review of that module's security behavior.

## 2. Protected assets and security objectives

| Asset | What must be protected | Security objective |
| --- | --- | --- |
| A1 — Original task and ownership | Registered `user_goal`, task-to-workspace/scope association and authenticated owner | Source content and another user's identifiers cannot replace the task or its authority. |
| A2 — Workspace and host data | Authorized source files, protected configuration, environment secrets and files outside the workspace | Only explicitly granted operations occur; data is not disclosed through another path or tool. |
| A3 — Authorization configuration | Casbin model/policy, task scopes, test-profile command mappings and decision-provider configuration | The agent cannot modify the rules that authorize its own actions. |
| A4 — Signing authority | Ed25519 private key and trusted verifier public-key configuration | Only the trusted issuer can sign; an attacker cannot substitute the verification key. |
| A5 — Operation integrity and freshness | Exact tool, task, arguments, permit expiration and nonce state | A permit applies to its intended operation and cannot be reused beyond its allowed lifetime/use. |
| A6 — Evidence and audit data | Decision records, tool outcomes, correlation identifiers and stored sensitive content | Records remain attributable and protected from unauthorized disclosure or modification. |
| A7 — Service availability | Model budget, execution resources, backend capacity and database access | Invalid or expensive requests cannot cause unbounded work or trigger a default-allow fallback. |

Model explanations and source labels are evidence to examine, not credentials. A hash supplies an integrity comparison, not confidentiality. A valid signature authenticates the signed fields under a trusted key; it does not establish task ownership, harmlessness, freshness or actual execution safety.

## 3. Attacker model and assumptions

### 3.1 Attacker capabilities

The primary attacker can author or alter README content, code comments, other workspace text or text returned by a tool that the agent processes. The attacker can use Turkish, Turkish without diacritics, misspellings, mixed-language text, forged role messages and fabricated approval statements.

A compromised or manipulated agent may propose any request body, including a syntactically valid but unrelated edit, a protected path, another task ID or extra fields claiming permission. The system must therefore validate every proposal at the tool boundary even when the agent normally follows instructions.

Threats also include attempts to modify or replay a captured permit and failures of external model/graph services. These scenarios do not require an attacker to break Ed25519. A validly signed but incorrectly authorized request is a separate failure from signature forgery.

Indirect injection through code comments and documentation, together with a separation between model output and tool authorization, is described in OWASP's prompt-injection guidance [R2]. The specific threat analysis below is based on this project's interfaces.

### 3.2 Required deployment assumptions

These assumptions require deployment evidence; they are not guarantees provided by Python classes:

1. The trusted backend authenticates callers and checks ownership before selecting a task ID. Task registration and scope configuration are not agent tools.
2. Policy files, issuer configuration and test-profile mappings are outside agent-writable paths. A Git repository containing trusted backend code is distinct from the workspace that an agent may edit and execute.
3. Agent code cannot access issuer memory, private-key files, administrative credentials or the Docker control socket. Untrusted tests also execute on the restricted side of this boundary.
4. The verifier obtains its public key from trusted configuration. Keys, transport and hosts are managed by the deployment, not by repository instructions.
5. Every route that can create a side effect enforces the security chain. An alternative file-write endpoint or unrestricted shell cannot bypass it.
6. The decision provider evaluates fresh backend results for the exact same operation and source snapshot. Results from separate calls are not mixed or cached as reusable approvals.

A compromised administrator, host kernel, issuer process or trusted dependency can invalidate these assumptions. Such compromise is outside the assurance demonstrated by the current component tests. Supply-chain exposure remains a deployment risk to manage, not an assumption that repository content is safe.

## 4. Trust boundaries

The intended authorization path is authenticated task resolution → validated proposal → Policy/Supervisor/Graph checks → trusted aggregation → permit issuance → permit verification and nonce consumption → restricted execution. This is the required path; the Day 6 test composes part of it inside a test fixture.

| Boundary | Data crossing it | Required enforcement | Evidence and remaining limit |
| --- | --- | --- | --- |
| B1 — Caller to task registry | User task and task ID | Backend authentication, ownership checks and trusted scope selection | Registry validates references and immutable snapshots; it does not authenticate callers. Production ownership checks are not verified here. |
| B2 — Source content to Supervisor | README, comments, file text, tool output and source labels | Keep observations separate from the registry-backed task; never infer permissions from text | Day 5 payload construction is inspected/tested. Labels do not authenticate provenance or force a model to obey the boundary. |
| B3 — Agent to authorization backend | Tool name, arguments and identifiers | Strict schema validation plus trusted registry/Casbin evaluation | Shared contracts and Policy Engine are implemented. Caller-controlled `approved`, scope or replacement-task fields do not authorize anything. |
| B4 — Model/Graph to decision code | Structured verdict, explanation and graph suspicion | Validate types; aggregate outside the model; withhold approval on uncertainty/failure | Supervisor/resolver are implemented. Graph Inspector is replaced by a test double in the inspected integration tests. |
| B5 — Decision provider to issuer | Exact call and aggregate `SecurityDecision` | Only a fresh trusted `ALLOW` may reach signing | Issuer validates the returned decision. It cannot establish whether the callback actually ran every required check. |
| B6 — Issuer to verifier/executor | Signed permit and proposed operation | Trusted-key verification, binding, expiry and atomic one-time nonce consumption | Issuance/signature primitives are tested. Production consumption and execution are not verified by those tests. |
| B7 — Sandbox to host/network | File operations, tests, subprocesses and outbound traffic | Containment, mount/permission checks, resource limits and egress policy | Executor/container controls need separate inspection and runtime tests. A test-profile name alone does not make test code harmless. |
| B8 — Runtime to audit store/UI | Decisions, reasons, source excerpts and tool outcomes | Access control, sensitive-data handling, safe rendering and evidence integrity | Audit/database/UI implementation is not assessed here. Logs and model reasons remain potentially attacker-controlled text. |

## 5. Inspected controls and precise limits

### 5.1 Request validation and scoped policy

`ContractModel` rejects extra fields and incompatible types and revalidates existing model instances. A `ToolCall` selects one of four tools: `secure_read_file`, `secure_edit_file`, `secure_list_files` or `secure_run_tests`. The last tool accepts a configured `profile_id`, not an arbitrary shell command.

Paths are workspace-relative POSIX strings. The schema rejects traversal components, absolute/drive paths, backslashes and NUL. Scopes grant exact resources; reading, writing, listing and test execution are independent permissions. Casbin denies file-tool access to protected `.env`, `.env.*` and `.git` path components, including when a trusted scope mistakenly grants them. A global deny overrides an allow.

These are lexical/policy controls. They do not resolve symlinks, inspect mounts, make file opening race-free or filter the contents of directory listings. Listing the workspace root still requires executor filtering of protected entries. The reviewed model uses case-sensitive matching; filesystem aliases and case-insensitive volumes require executor checks before cross-platform support is claimed.

### 5.2 Supervisor source isolation

The trusted task is loaded from `TaskRegistry`; proposed tool arguments and optional `untrusted_sources` occupy separate JSON fields. `UntrustedSource.kind` accepts `readme`, `code_comment`, `file` or `tool_output`. Source IDs/kinds remain untrusted labels. The source collection is bounded to 16 entries; the full serialized input is limited to 65,536 UTF-8 bytes, without silent truncation.

The prompt version is `supervisor-tr-v2`. The model may return only `ALIGNED`, `MISALIGNED` or `UNCERTAIN` with a non-blank reason of at most 1,000 characters. The raw response limit is 8,192 UTF-8 bytes. Duplicate JSON keys, extra fields, malformed output and invalid verdicts are rejected. Trusted Python code assigns `reason_code`.

Unknown/mismatched tasks, invalid requests/sources, excessive input, provider failures and invalid responses produce `UNCERTAIN` in the handled paths. A real adapter supplies a timeout and makes no agent tool available to the Supervisor. Other injected clients must enforce their own timeouts.

An `ALIGNED` answer is a model judgment, not a permit. A correctly formatted answer can still be wrong or manipulated. The module does not prove that supplied source observations are complete/current, compare them with a verified repository revision, or guarantee Turkish-language injection resistance. Quotes of attacks can be legitimate task data; keyword presence alone is not a security verdict.

### 5.3 Deterministic aggregation

`resolve_security_decision()` has the following contract for validated stage results:

| Policy | Supervisor | Graph flag | Aggregate result |
| --- | --- | --- | --- |
| `DENY` | Any or missing | Any | `DENY` |
| `ALLOW` or `REVIEW` | `MISALIGNED` | Any | `DENY` |
| `REVIEW` | `ALIGNED` or `UNCERTAIN` | Any | `REVIEW` |
| `ALLOW` | `UNCERTAIN` | Any | `REVIEW` |
| `ALLOW` | `ALIGNED` | `False` as a strict boolean | Stage `ALLOW` |
| `ALLOW` | `ALIGNED` | `True` | `REVIEW` |
| `ALLOW` | `ALIGNED` | Missing or invalid type | `REVIEW` |

Invalid policy input returns `REVIEW`; invalid Supervisor input returns `REVIEW` unless a valid policy denial already determines the result. Therefore a definitive Supervisor rejection combined with an invalid policy object may also result in `REVIEW`; both remain non-authorizing. Integer `0` and string `"false"` are not accepted as graph clearance.

A graph suspicion alone does not establish an attack, but it withholds automatic approval. No human-review/resumption workflow is implemented by this resolver. `REVIEW` must remain blocked until a separately authorized backend process resolves it. The resolver validates object structure, not the origin, request binding or authenticity of supplied results.

### 5.4 Permit integrity and freshness requirements

`PermitIssuer.issue()` validates a call, passes a separate validated snapshot to the decision provider and requires its result to be `ALLOW`. Denial/review raises `PermitDeniedError`; provider, validation and signing failures do not return a permit. Issuance is checked afresh for each call.

The issuer binds `permit_id`, `task_id`, `tool`, `arguments_hash`, `nonce` and `expires_at` in an Ed25519 signature. RFC 8785 canonicalization is delegated to `rfc8785`; timestamp signing uses UTC with six fractional digits and `Z`. The argument hash covers the complete argument object without rewriting source text or line endings. RFC 8785 defines the canonical JSON representation [R3]; RFC 8032 specifies Ed25519/EdDSA [R4].

The default/max TTL is 60 seconds; configured TTL must be an integer from 1 to 60. The nonce uses `secrets.token_urlsafe(24)`. Neither a short TTL nor a random nonce independently prevents replay: the consumer must enforce expiration and atomically consume the nonce before a side effect.

The current permit has no `request_id`, audience, issuance timestamp, key ID or source/workspace snapshot digest. Task/workspace association is external registry context. Request-ID correlation is not cryptographic binding. Source changes, key rotation, revocation and cross-service permit reuse need explicit protocol/deployment decisions; they are not implicitly solved by the signature.

The private-key loader supports configured PEM keys and checks file type/size, POSIX permission bits and the final symlink where supported. It does not isolate issuer memory or enforce Windows ACLs. The agent and issuer must not share a trust domain merely because a Python attribute is named private.

## 6. Threat register

**High** priority means a boundary failure could allow unauthorized execution, sensitive-data disclosure or forged/reused authority. **Medium** means availability or evidence could be degraded, with impact depending on deployment. Priorities do not imply that a specific exploit was reproduced.

| ID / priority | Threat and attacker route | Current response | Residual risk / required verification |
| --- | --- | --- | --- |
| T01 — High | Indirect injection in README/comments replaces the goal or claims administrator approval. | Separate source/task fields, Turkish Supervisor prompt and independent scoped policy. | Mocked verdicts do not measure resistance. Evaluate real models using held-out Turkish, transliterated, mixed-language and benign cases. |
| T02 — High | A manipulated model emits `ALLOW`, extra approval fields, duplicate keys or malformed JSON. | Strict response parsing; handled failures become `UNCERTAIN`; issuer requires an aggregate decision. | Schema-valid but incorrect `ALIGNED` remains possible. Policy and execution controls must remain independent. |
| T03 — High | An agent supplies another registered task ID to inherit another user's scope. | Registry consistency and Supervisor task-ID mismatch checks. | These checks do not prove caller ownership. Test authenticated cross-user requests against every real endpoint. |
| T04 — High | Scope/permission escalation or an unrelated edit is approved through a permissive layer. | Exact grants, protected-path rules and deny precedence. | The real provider must not pass policy-only `ALLOW` directly to the issuer or expose an alternative path to signing/execution. |
| T05 — High | Traversal, symlink replacement, mount tricks, case aliases or a race bypass lexical policy. | Request path validation and protected-path matching. | Inspect/test the real filesystem boundary, including check/open races and listing filters. POSIX flags cannot be silently removed for Windows compatibility. |
| T06 — High | An attacker modifies signed fields or substitutes a verification key. | Canonical signing and real signature-tampering tests. | Verify the production consumer uses the same signing bytes and a pinned trusted public-key source. |
| T07 — High | A captured valid permit is replayed, used after expiry or used at another consumer. | Random nonce and signed expiration are emitted. | Atomic nonce consumption, expiry enforcement and consumer separation are not demonstrated by issuer tests. Concurrent replay must be tested at the real verifier. |
| T08 — High | An agent obtains the issuer key through a mount, environment, editable config or shared process. | Key-loading checks cover part of startup handling. | Verify process/container separation, restrictive key storage and absence of issuer credentials from the agent's view. |
| T09 — High | Results are mixed across proposals, cached, forged as Python dictionaries or recomputed for different arguments. | Issuer snapshot validation and per-call provider invocation; resolver checks shapes. | Results are not self-authenticating. Backend context must bind the exact call, task, source snapshot and stage results without a time-of-check gap. |
| T10 — High | A valid-looking edit inserts exfiltration code or a permitted test profile executes malicious project tests. | Supervisor alignment layer and limited tool/profile interface. | An allowed file path is not proof of safe code. Execute all untrusted code/tests in the restricted environment with controlled mounts and egress. |
| T11 — High | Secrets in source, tool output, prompts or logs reach a model provider or unauthorized viewer. | Scope restrictions and sanitized fallback errors cover some routes. | Source content is sent to the configured LLM; `store=False` is not a complete retention or confidentiality guarantee. Review data minimization, provider terms, egress, logs and UI access. |
| T12 — Medium | Large/repeated inputs, hanging services or costly tools exhaust resources. | Supervisor byte/count limits and real-adapter request timeout. | Add/test request-rate limits, end-to-end deadlines, bounded concurrency, execution limits and size controls at other service boundaries. Never fall back to approval. |
| T13 — Medium | Attacker-controlled source/reason text forges audit records or unsafe UI output; records are altered/deleted. | Some fallback errors omit raw provider exception text. | Audit integrity, authenticated writes, retention, safe rendering, access control and encryption/key management require independent review. |
| T14 — High | Repository/dependency changes execute trusted-side code, alter policy or compromise CI secrets. | Supplied CI runs tests with read-only repository-content permissions. | Review dependency/action updates, branch changes and workflow privilege. Running code from a pull request does not make that code trusted. Production keys must remain outside tests/CI. |

## 7. Known security limitations and unresolved evidence

These items describe the limits of the inspected implementation or its evidence. They are not a claim that every item is an exploitable defect in the complete repository.

| ID | Known limitation | Consequence / follow-up |
| --- | --- | --- |
| L01 | No real-model attack-success or false-positive measurement is supplied. | Do not report a detection percentage, complete Turkish coverage or guaranteed prompt-injection prevention. |
| L02 | Day 6 wiring is in `_trusted_decision()` inside the test file. | A passing composition test does not prove the deployed Gateway supplies an equivalent provider or blocks all bypass routes. |
| L03 | Graph signals are mocked in the reviewed tests. | Source attribution, graph accuracy, graph availability and runtime correlation are unverified here. |
| L04 | Issuance is not verification or nonce consumption. | Signature validity alone cannot stop replay, expired permits or wrong-operation use at the consumer. |
| L05 | Permits do not bind a workspace/source revision or consumer audience. | Define how changes between assessment and execution and cross-consumer use are prevented. |
| L06 | A Python process is not a private-key isolation boundary. | Frozen models and private attributes cannot protect keys from hostile code in the same process. |
| L07 | Registry storage is process-local and in memory. | Restart loses records; multiple backend workers do not automatically share consistent tasks/scopes. Operational topology must match this constraint. |
| L08 | Windows full-suite collection failed on `os.O_DIRECTORY` in `execution/filesystem.py`. | Linux/WSL runtime verification is necessary for Linux-dependent execution code. The Windows security subset passing does not establish full Windows support. |
| L09 | Case-sensitive/exact policy matching does not establish physical filesystem containment. | Test executor behavior on the actual volume/platform; do not replace unavailable security flags with zero as a portability fix. |
| L10 | `REVIEW` is a result, not an implemented approval workflow. | Keep the action blocked; a user-facing review process must have explicit authorization and fresh checks before resuming. |
| L11 | Prompt separation provides a model-facing instruction, not a hard semantic barrier. | A compromised agent or incorrect Supervisor must still face deterministic authorization and restricted execution. |
| L12 | Complete audit, network, sandbox and deployment controls are not assessed here. | Do not claim encrypted/tamper-proof audit storage, blocked exfiltration or verified container isolation solely from these tests. |

## 8. Validation evidence and acceptance criteria

### 8.1 Recorded results

| Evidence | Recorded result | Scope and limit |
| --- | --- | --- |
| Day 3 `tests/unit/test_supervisor.py` | 22 tests passed against the Day 5 Supervisor during its preparation. | Offline request/response and adapter-contract checks; no live model evaluation. |
| Day 5 `tests/security/test_alignment.py` | 25 tests passed; includes three scripted attack scenarios, three scripted normal scenarios and a 27-combination aggregation table. | The 27 combinations are subcases within one test, not 27 additional test methods. Policy/Graph outputs are fixtures. |
| Day 6 `tests/security/test_security_pipeline.py` | 24 tests passed. | Real Casbin, Supervisor, canonical hashing, issuer and Ed25519 signing. LLM/Graph are doubles; downstream execution is a Mock sentinel. |
| Combined Day 5–6 recheck on 2026-11-06 | 49 test methods passed in the isolated inspected-source environment. | Python 3.12.14; Pydantic 2.14.1; casbin 1.43.0; cryptography 50.0.2; rfc8785 0.1.4. This is not a clean clone of the team's latest merged commit or its pinned CI environment. |
| Developer's Windows `pytest tests/security -q` run | Developer reported all selected security tests passed. | No exact output/count or commit SHA was provided; record no larger total than the available evidence supports. |
| Developer's demo test run | Developer reported the demo tests passed. | A separate complete hosted CI run log/URL was not supplied for this review. |
| Developer's Windows `pytest tests -q` run | Collection failed at `execution/filesystem.py`: `os.O_DIRECTORY` unavailable. | Full-suite success on Windows is not established. The FastAPI deprecation warning was separate from this error. |
| Existing CI configuration | Runs on Ubuntu/Python 3.11; executes `python -m pytest tests -q`, then demo tests. | This selection includes security tests. Configuration inspection is not evidence that a specific hosted run passed. The separately drafted alternative CI file was not adopted. |

No real detection accuracy, attack success rate, false-positive rate, latency benchmark or sandbox escape result is inferred from these counts. Passing source-isolation tests means the data was constructed separately; it does not show that a real model classified it correctly.

### 8.2 Critical acceptance mapping

| Required behavior | Representative check | Result supported here |
| --- | --- | --- |
| Source text cannot overwrite the registered task in the constructed prompt. | `test_source_text_cannot_be_promoted_to_a_trusted_goal`; pipeline source-injection test | Passed for the inspected source/payload construction. |
| Policy `DENY` cannot be overridden by a would-be model approval. | `test_policy_deny_stops_before_supervisor_even_if_llm_would_align` | Passed in the composition fixture; production path still needs direct verification. |
| Protected file paths remain denied despite explicit test grants. | `test_protected_paths_cannot_be_permitted_even_with_explicit_scope_grants` | Passed with the real Casbin configuration. |
| Supervisor timeout/malformed answer cannot produce a permit. | `test_supervisor_timeout_never_reaches_signing_or_execution_sentinel`; malformed-response tests | Passed; issuer returned no permit and the fixture's downstream sentinel was not reached. |
| Graph suspicion is not labeled a definitive attack and does not authorize issuance. | `test_graph_flag_alone_requests_review_without_declaring_attack`; pipeline flag tests | Passed for mocked graph signals. |
| An authorized, aligned call can receive a valid bound permit. | `test_aligned_authorized_call_receives_a_real_bound_signature` | Passed using real Ed25519 signing and verification. |
| Changed signed fields invalidate the signature. | `test_tampering_with_a_permit_from_the_chain_breaks_its_real_signature` | Passed cryptographic checks; not an endpoint rejection test. |
| The same permit cannot execute twice. | Concurrent replay against the real verifier/executor | Not demonstrated by the inspected tests. |
| User/task ownership and sandbox boundaries hold in deployment. | Cross-user endpoint and restricted-runtime acceptance tests | Not verified in this review. |

### 8.3 Reproduction commands

From the repository root on Windows PowerShell, with the project environment activated:

```powershell
$env:PYTHONPATH = (Join-Path $PWD "src")
python -m pytest tests/security/test_alignment.py tests/security/test_security_pipeline.py -q
```

The two files also support standard-library unittest:

```powershell
python -m unittest discover -s tests/security -p test_alignment.py -v
python -m unittest discover -s tests/security -p test_security_pipeline.py -v
```

For the complete suite, use a correctly installed Linux/WSL environment or the existing Ubuntu CI job:

```bash
PYTHONPATH="$PWD/src" python -m pytest tests -q
```

Record the commit SHA, Python/dependency versions, selected tests and complete results for the final reviewed release. A failed or skipped test must remain visible in the evidence; do not label a selected-subset pass as a complete-suite pass.

## 9. Remaining validation and improvement priorities

| Priority | Required work | Completion evidence |
| --- | --- | --- |
| P0 — Before claiming end-to-end enforcement | Inspect the real Gateway/provider wiring and all side-effect routes; verify caller ownership and fresh same-call/same-source checks. | Endpoint tests show denied, uncertain and mismatched requests cannot issue or execute, with the release commit identified. |
| P0 | Test permit signature/binding/expiry checks and atomic nonce consumption at the real verifier. | Tampering, wrong-operation, expired and concurrent replay cases are rejected before side effects. |
| P0 | Verify issuer/agent isolation and restricted execution of project code and tests. | Runtime mount, credential, socket, containment, resource and egress checks on the intended Linux deployment. |
| P1 — Before model-performance claims | Evaluate real Turkish-language attacks and benign tasks with fixed model/prompt versions and held-out cases. | Per-case outcomes, sample counts, repeated-run settings, attack success/false positives and limitations are recorded. |
| P1 | Assess Graph provenance and failure handling against actual tool/source snapshots. | Real Graph Inspector tests and correlated runtime results, including missing/unavailable service behavior. |
| P1 | Review audit/database/UI data handling and access controls. | Sensitive-data, record-integrity, access and safe-rendering tests with explicit retention/key-management decisions. |
| P1 | Reconcile the final documents with the latest merged branch and complete Ubuntu CI. | A reproducible install, commit identifier and successful hosted workflow link/artifacts. |
| P2 — Further development | Specify key rotation/revocation, consumer binding, durable shared task/nonce state and policy-change handling. | Reviewed protocol/schema changes and migration/regression evidence before these features are advertised. |

The controlled educational prototype may document unresolved items, but they are not automatically accepted risks. Any decision to use the system with real secrets, multiple users or less trusted code must account for the unresolved boundaries explicitly.

## 10. Maintenance and references

Update this document when a tool, source channel, model/prompt, task scope, aggregation rule, permit field, verifier, runtime boundary, audit flow or deployment topology changes. Review it again after integration merges; a report written against earlier generated files cannot certify later team changes.

The repository's source modules and tests are the authority for implementation details. [api-contract.md](api-contract.md) defines the shared contracts and is scheduled for a Day 5–7 update; any earlier statement there about aggregation status must be reconciled with the Day 5 resolver. The separate `docs/architecture.md` deliverable will describe component relationships rather than duplicate this risk register.

External references explain methods/mechanisms, not the security of this deployment:

- **[R1]** [OWASP Threat Modeling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html) — system boundaries, threats, responses and validation.
- **[R2]** [OWASP LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html) — indirect injection and layered enforcement beyond model instructions.
- **[R3]** [RFC 8785 — JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785) — canonical representation used by the hashing/signing codec.
- **[R4]** [RFC 8032 — Edwards-Curve Digital Signature Algorithm](https://www.rfc-editor.org/rfc/rfc8032) — Ed25519/EdDSA specification.

References checked on 2026-11-06. This document is a prototype threat assessment, not a penetration-test certificate or a guarantee that every attack is prevented.
