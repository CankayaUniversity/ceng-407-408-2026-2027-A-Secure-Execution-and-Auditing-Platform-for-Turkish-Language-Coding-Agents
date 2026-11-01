# Shared API Contract

**Contract version:** `0.1.0`
**Target runtime:** Python 3.11 and Pydantic v2  
**Repository location:** `docs/api-contract.md`

## 1. Scope and implementation status

This document defines the shared data structures and task registry interface for the first prototype of the Secure Execution and Auditing Platform for Turkish Language Coding Agents.

| Component | Source | Status covered by this contract |
| --- | --- | --- |
| Shared schemas and parsing helpers | `src/secure_agent/common/schemas.py` | Implemented and unit tested |
| Immutable task scope | `src/secure_agent/tasks/scope.py` | Implemented and unit tested |
| Trusted task registry | `src/secure_agent/tasks/registry.py` | Implemented and unit tested |
| Gateway HTTP endpoints | Gateway integration | Day 1 integration target; implementation was not inspected for this document |
| Mock agent to Gateway to Audit flow | Agent, Gateway, and Audit integration | Must be demonstrated separately; schema tests do not establish completion |
| Policy evaluation, permit signing, and sandbox execution | Security and executor modules | Not implemented by the three modules documented above |

Source models determine the behavior of the implemented interfaces. Integration targets below describe required consumer behavior, not evidence that those consumers already implement it.

`SCHEMA_VERSION` is a module constant. There is no `schema_version` field in the current payloads and no automatic version negotiation. Do not add such a field to requests: unknown fields are rejected.

## 2. Shared validation rules

All models derived from `ContractModel` use these settings:

| Setting | Value | Behavior |
| --- | --- | --- |
| `extra` | `forbid` | Reject fields not declared by the selected model, including nested argument models |
| `strict` | `True` | Enforce strict type validation; JSON has type-specific exceptions such as timestamp strings |
| `frozen` | `True` | Reject normal assignment to model fields after construction |
| `validate_default` | `True` | Validate declared default values |
| `revalidate_instances` | `always` | Revalidate existing model instances when passed through model validation |

Every declared field is required unless this document specifies a default. Models do not generate identifiers automatically.

### 2.1 Text and identifiers

`NonEmptyText` is a string of at least one character that must not consist entirely of whitespace. Validation preserves the original text; it does not trim, lowercase, transliterate, or normalize Unicode.

Identifiers are opaque, case-sensitive strings. The schema does not require UUIDs, enforce a naming pattern, or establish uniqueness. The registry enforces task and scope ID uniqueness within its instance.

Code identifiers, protocol values, and error messages are English. Turkish user goals, source contents, filenames, and attack examples are valid Unicode data and must be preserved.

### 2.2 Workspace-relative request paths

`WorkspacePath` requires non-blank relative POSIX path syntax:

- Use `/`, not a backslash, as the separator.
- Reject NUL characters, absolute paths, Windows drive specifications, and path components equal to `..`.
- Preserve the supplied spelling; the shared request schema does not normalize paths.
- Explicitly send `.` to list the workspace root.

For example, `src/login.py` and `notes..txt` pass lexical validation. `src/./login.py` also passes the request schema, but scope configuration has stricter spelling rules described in Section 7.

Passing lexical validation does not establish file existence, file type, workspace containment, or permission. `.env` is syntactically valid and must still be checked by policy. The executor must enforce actual containment, symlink handling, safe file access, and race-condition protection.

### 2.3 Safe model usage

Use constructors, `model_validate()`, `model_validate_json()`, or the parsing helpers below. Do not use `model_construct()` or `model_copy(update=...)` as validation of untrusted data. Frozen models and Python private-name conventions are not isolation or authentication boundaries.

## 3. Task

**Model:** `Task`  
**Producer:** Trusted backend task registration code  
**Consumer:** Task Registry and backend orchestration

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `task_id` | `NonEmptyText` | Yes | Task identifier |
| `user_goal` | `NonEmptyText` | Yes | Original user goal; Turkish text is supported |
| `workspace_id` | `NonEmptyText` | Yes | Reference to a trusted workspace definition, not a filesystem path |
| `scope_id` | `NonEmptyText` | Yes | Reference to a trusted scope definition |

Valid example:

```json
{
  "task_id": "task-001",
  "user_goal": "GiriÅŸ kontrolÃ¼ndeki hatayÄ± dÃ¼zelt.",
  "workspace_id": "workspace-demo",
  "scope_id": "scope-login-fix"
}
```

The schema validates structure. The registry checks referenced records and workspace association. A `task_id` is not a credential: caller authentication and task ownership must be enforced separately by the backend.

## 4. ToolCall and tool arguments

**Type:** `ToolCall`  
**Producer:** Coding agent through its secure tool adapter  
**Consumer:** Gateway request validation

The JSON body is a flat object with four required fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `request_id` | `NonEmptyText` | Correlation identifier for one tool request |
| `task_id` | `NonEmptyText` | Reference to the registered task |
| `tool` | One exact tool name below | Discriminator selecting the request model |
| `arguments` | Selected argument model | Arguments appropriate for that tool |

`ToolCall` is a discriminated union, not a model class with a `model_validate()` method.

| `tool` | Concrete model | Required `arguments` fields |
| --- | --- | --- |
| `secure_list_files` | `ListFilesToolCall` | `path: WorkspacePath` |
| `secure_read_file` | `ReadFileToolCall` | `path: WorkspacePath` |
| `secure_edit_file` | `EditFileToolCall` | `path: WorkspacePath`, `content: str` |
| `secure_run_tests` | `RunTestsToolCall` | `profile_id: NonEmptyText` |

No argument field has a default. In particular, the list operation requires an explicit path.

### 4.1 List files

```json
{
  "request_id": "req-001",
  "task_id": "task-001",
  "tool": "secure_list_files",
  "arguments": {"path": "."}
}
```

### 4.2 Read a file

```json
{
  "request_id": "req-002",
  "task_id": "task-001",
  "tool": "secure_read_file",
  "arguments": {"path": "src/login.py"}
}
```

### 4.3 Replace file contents

```json
{
  "request_id": "req-003",
  "task_id": "task-001",
  "tool": "secure_edit_file",
  "arguments": {"path": "src/login.py", "content": "def login():\n    return False\n"}
}
```

`content` is the complete replacement text, not a patch. Empty text, whitespace, Unicode, and original line endings are valid and must be preserved. The schema does not enforce a byte limit; the executor must enforce configured size limits and write permissions.

### 4.4 Run a trusted test profile

```json
{
  "request_id": "req-004",
  "task_id": "task-001",
  "tool": "secure_run_tests",
  "arguments": {"profile_id": "unit"}
}
```

`profile_id` identifies a backend-configured test command. The agent cannot provide a `command`, executable, or arbitrary shell arguments through this model. Profile existence and task authorization require backend checks.

### 4.5 Python parsing interface

```python
from secure_agent.common.schemas import parse_tool_call, parse_tool_call_json

payload = {
    "request_id": "req-002",
    "task_id": "task-001",
    "tool": "secure_read_file",
    "arguments": {"path": "src/login.py"},
}
call = parse_tool_call(payload)
restored = parse_tool_call_json(call.model_dump_json())
assert restored == call
assert call.arguments.path == "src/login.py"
```

`parse_tool_call()` accepts Python input. `parse_tool_call_json()` accepts JSON as `str`, `bytes`, or `bytearray`. Invalid data raises Pydantic `ValidationError`.

Use `model_dump(mode="json")` for a JSON-compatible Python dictionary, and `model_dump_json()` for JSON text. These are different return types.

## 5. SecurityDecision

**Model:** `SecurityDecision`  
**Producer:** Decision Engine  
**Consumer:** Gateway orchestration and later permit issuance

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `decision` | `ALLOW`, `DENY`, or `REVIEW` | Yes | Final security verdict |
| `reason_code` | `NonEmptyText` | Yes | Machine-readable explanation code |

```json
{
  "decision": "DENY",
  "reason_code": "TASK_SCOPE_VIOLATION"
}
```

Verdict values are case-sensitive. `reason_code` is currently free non-blank text; no enum or complete reason-code catalog is enforced.

Consumer requirement: `DENY` and `REVIEW` must not execute the tool. `ALLOW` only permits continuation of the remaining security checks; it does not bypass permit verification or executor checks. The schema alone does not implement this control flow.

## 6. Permit

**Model:** `Permit`  
**Producer:** Permit Issuer  
**Consumer:** Permit Verifier in the executor boundary

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `permit_id` | `NonEmptyText` | Yes | Permit identifier |
| `task_id` | `NonEmptyText` | Yes | Bound task |
| `tool` | `ToolName` | Yes | Bound tool |
| `arguments_hash` | `Sha256Hex` | Yes | SHA-256 of canonical argument JSON bytes |
| `nonce` | `NonEmptyText` | Yes | Value for replay prevention |
| `expires_at` | `AwareDatetime` | Yes | Expiration timestamp with a timezone |
| `signature` | `Ed25519Signature` | Yes | Encoded Ed25519 signature |

### 6.1 Encodings

- `arguments_hash`: exactly 64 lowercase hexadecimal characters, matching `^[0-9a-f]{64}$`.
- `signature`: exactly 86 Base64url characters without `=` padding, matching `^[A-Za-z0-9_-]{86}$`. Decoding must yield 64 bytes and re-encoding must reproduce the same canonical text.
- `expires_at`: a timezone-aware timestamp. Issuers should produce UTC. Python validation requires an aware `datetime`; JSON timestamp strings are parsed with `Permit.model_validate_json()`.

The signed payload includes all declared permit fields except `signature`. There is no `request_id`, `workspace_id`, or `scope_id` field in this permit schema. Task context must come from trusted registration rather than extra caller-supplied fields.

### 6.2 Schema checks versus verification

The current model checks structure and encoding only. It does not compute the argument hash, sign or verify a signature, generate a secure nonce, reject expired permits, or consume nonces.

The issuer and verifier must share a reviewed canonical JSON codec, timestamp representation for signing, and matching hash/signature test vectors before execution is enabled. Those byte-level algorithms are not implemented by the current schema modules and are not established by this document. Never use ordinary JSON output ordering as an assumed signing specification.

Verifier integration must independently check the signature, bound task/tool/arguments, expiration, and atomic one-time nonce consumption before execution. A correctly formatted signature can still be invalid cryptographically. A correctly formatted timestamp can already be expired.

## 7. TaskScope

**Model:** `TaskScope`  
**Producer:** Trusted backend configuration  
**Consumer:** Task Registry and later policy evaluation

| Field | Python type | Required | Default |
| --- | --- | --- | --- |
| `scope_id` | `NonEmptyText` | Yes | None |
| `workspace_id` | `NonEmptyText` | Yes | None |
| `allowed_tools` | `frozenset[ToolName]` | No | Empty frozenset |
| `readable_files` | `frozenset[ScopeFilePath]` | No | Empty frozenset |
| `writable_files` | `frozenset[ScopeFilePath]` | No | Empty frozenset |
| `listable_directories` | `frozenset[ScopePath]` | No | Empty frozenset |
| `allowed_test_profiles` | `frozenset[NonEmptyText]` | No | Empty frozenset |

"None" in the default column for required IDs means no default is defined; null is not accepted.

Python inputs must use frozensets, not lists, sets, or tuples. JSON arrays are accepted through `TaskScope.model_validate_json()` and become frozensets. Sets have no ordering guarantee.

Valid JSON configuration example, intended for trusted loading rather than agent submission:

```json
{
  "scope_id": "scope-login-fix",
  "workspace_id": "workspace-demo",
  "allowed_tools": ["secure_list_files", "secure_read_file", "secure_edit_file", "secure_run_tests"],
  "readable_files": ["README.md", "src/login.py", "tests/test_login.py"],
  "writable_files": ["src/login.py"],
  "listable_directories": [".", "src", "tests"],
  "allowed_test_profiles": ["unit"]
}
```

### 7.1 Scope validation and permission interpretation

- Resource grants require the corresponding tool in `allowed_tools`; otherwise model validation fails.
- An enabled tool may have an empty resource set. That grants no resource access.
- Read, write, list, and test permissions are separate. No permission implies another.
- Paths are exact entries, not glob patterns or directory prefixes. Scope paths reject `*`, `?`, `[`, and `]`, including literal filenames containing those characters.
- Scope paths must satisfy `WorkspacePath` and match their `PurePosixPath(...).as_posix()` spelling. For example, `src/./login.py`, `src//login.py`, and `src/` are rejected in scope configuration.
- `.` is allowed in `listable_directories`, but not in file grants.
- Directory grants are not recursive and do not grant read/write access to descendants.
- Profile identifiers must be non-blank strings. This model does not establish whether a profile exists.

These are configuration and consumer rules. `TaskScope` has no tool-authorization method. Policy and executor code must enforce grants against actual requests and securely accessed resources; lexical equality alone is not a filesystem security boundary.

## 8. Trusted Task Registry

**Class:** `TaskRegistry`  
**Storage:** In-memory, instance-local, append-only through the public API

### 8.1 Initialization

Constructor signature:

```text
TaskRegistry(*, workspace_ids: Iterable[str], scopes: Iterable[TaskScope])
```

- Parameters are keyword-only.
- Workspace IDs must be a collection of non-blank strings; a single `str` or `bytes` is rejected.
- Every configured scope must reference a known workspace.
- Scope IDs must be unique across the entire registry, including different workspaces.
- Workspace IDs and scopes are snapshotted. Modifying caller-owned collections or model objects afterward must not alter stored configuration.
- Empty configuration is valid, but cannot register a task referring to an unknown workspace or scope.

### 8.2 Public methods

| Method | Returns | Contract |
| --- | --- | --- |
| `register(task: Task)` | `Task` | Revalidate, reject duplicate task ID, validate workspace and scope references, require the scope's workspace to match, then store |
| `get(task_id: str)` | `Task` | Validate the ID and return a registered task; never create one during lookup |
| `get_scope(task_id: str)` | `TaskScope` | Resolve the scope from the registered task; its argument is a task ID, not a scope ID |

Failed registration must not leave a task record. Task IDs cannot be reused to overwrite the original goal or scope. Returned models are validated snapshots rather than references to stored model objects. There is no public update/delete operation or runtime scope-registration method.

### 8.3 Registry errors

| Error | Condition |
| --- | --- |
| `UnknownWorkspaceError` | Configured scope or submitted task references an unknown workspace |
| `UnknownScopeError` | A submitted task references an unknown scope |
| `DuplicateScopeError` | Startup configuration repeats a scope ID |
| `ScopeWorkspaceMismatchError` | Task and scope belong to different known workspaces |
| `DuplicateTaskError` | A task ID already exists; the record remains unchanged |
| `TaskNotFoundError` | A well-formed task ID has no record |

All errors above derive from `RegistryError`. Invalid model fields and malformed lookup IDs raise Pydantic `ValidationError`. Passing a single string/bytes as `workspace_ids` raises `TypeError`. HTTP mappings are not implemented by the registry.

### 8.4 Trusted startup example

```python
from secure_agent.common.schemas import Task
from secure_agent.tasks.registry import TaskRegistry
from secure_agent.tasks.scope import TaskScope

scope = TaskScope(
    scope_id="scope-login-fix",
    workspace_id="workspace-demo",
    allowed_tools=frozenset({"secure_read_file", "secure_edit_file"}),
    readable_files=frozenset({"src/login.py"}),
    writable_files=frozenset({"src/login.py"}),
)
registry = TaskRegistry(workspace_ids={"workspace-demo"}, scopes=[scope])
task = Task(
    task_id="task-001",
    user_goal="GiriÅŸ kontrolÃ¼ndeki hatayÄ± dÃ¼zelt.",
    workspace_id="workspace-demo",
    scope_id="scope-login-fix",
)
registry.register(task)
assert registry.get("task-001") == task
assert registry.get_scope("task-001").scope_id == "scope-login-fix"
```

Create one registry during backend startup and reuse it across requests. Its `RLock` protects operations on that instance across threads, including the duplicate-check/insertion sequence. It provides no cross-process coordination. Use one backend process for this storage implementation; restarting it requires trusted re-registration of tasks. A shared persistent registry is a later implementation task.

Do not expose `register()` as an agent tool or an unauthenticated registration endpoint. The class itself does not authenticate callers.

## 9. ToolResult

**Model:** `ToolResult`  
**Producer:** Trusted executor/result wrapper  
**Consumer:** Gateway, agent adapter, and provenance integration

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `request_id` | `NonEmptyText` | Yes | Corresponding request identifier |
| `status` | `success`, `error`, `denied`, or `review` | Yes | Operation outcome |
| `output` | `str` | Yes | Text output; empty text is valid |
| `source_id` | `NonEmptyText` | Yes | Trusted source identifier for provenance association |
| `trust_level` | Literal `untrusted` | Yes | Content trust classification |

```json
{
  "request_id": "req-002",
  "status": "success",
  "output": "def login():\n    return False\n",
  "source_id": "source-001",
  "trust_level": "untrusted"
}
```

Every status still requires all fields, including `source_id` and `trust_level`. If there is no file-derived source, the trusted wrapper must provide an appropriate result/source record rather than omit the field. Structured output must be serialized into text; a raw dictionary is invalid.

A successful operation does not make its content trusted. Preserve original content, including Turkish text and suspected injection instructions, as untrusted data. This schema does not detect, sanitize, or obey instructions in output.

The wrapper must preserve the originating `request_id` and create/associate the `source_id` in trusted code. The model validates their structure, not cross-record identity or actual provenance.

## 10. Invalid request examples

All examples in this section must raise `ValidationError` when passed to a ToolCall parsing helper.

### 10.1 Unknown tool

```json
{
  "request_id": "req-invalid-001",
  "task_id": "task-001",
  "tool": "shell",
  "arguments": {"command": "pytest"}
}
```

### 10.2 Missing required tool argument

```json
{
  "request_id": "req-invalid-002",
  "task_id": "task-001",
  "tool": "secure_read_file",
  "arguments": {}
}
```

### 10.3 Caller-supplied authority

```json
{
  "request_id": "req-invalid-003",
  "task_id": "task-001",
  "tool": "secure_read_file",
  "arguments": {"path": "src/login.py"},
  "scope_id": "admin"
}
```

Scope, workspace, permissions, and permit state must not be inferred from extra fields in an agent request. Resolve task context through trusted registration.

## 11. Gateway and Audit integration targets

These are Day 1 integration requirements. Their implementation must be checked with the Gateway and Audit owners; the current unit tests exercise Python contracts rather than HTTP endpoints or audit storage.

| Interface | Required Day 1 behavior | Verification still required |
| --- | --- | --- |
| `GET /health` | Return HTTP 200 | Confirm actual route and response body with the Gateway owner |
| `POST /tools/execute` | Validate a flat ToolCall body using the shared contract; invalid schema input must return HTTP 422 | Confirm concrete request annotation, response model, and exception handling |
| Valid mock request | Reach the Gateway and produce an audit event correlated with its request ID | Demonstrate Mock Agent to Gateway to Audit; real execution is not implied |
| Audit lookup | Retrieve the recorded event by the same `request_id` | Confirm repository method and persistence test with the Audit owner |

The normal tool-result data contract is `ToolResult`. The actual HTTP response envelope, domain-error status mappings, authentication mechanism, and validation-error body must be agreed with the Gateway owner and documented here when integrated. Do not infer them from Registry exceptions.

The broader plan includes `PolicyDecision`, `GraphAssessment`, and `SupervisorDecision`. They are not defined in the current `schemas.py`. Their owners must agree and implement shared definitions before consumers depend on them. `AuditEvent` is defined in Section 13; SQLite storage and Gateway receipt logging are implemented; tool execution remains disabled.

In an integrated backend, validation and task-context resolution precede policy evaluation. Schema acceptance and registry lookup never grant execution on their own. Authentication, task ownership, policy, supervisor/graph decisions, permit checks, and sandbox controls remain the responsibilities of their respective components.

## 12. Validation commands and Day 1 completion

The current files provide 112 shared-schema test cases and 69 scope/registry test cases: 181 in total. These counts describe the supplied test versions, not future additions by other owners.

Run from the repository root in Windows PowerShell using the already installed Python launcher and uv:

```powershell
$env:PYTHONPATH = "src"
py -m uv run --no-project --python 3.11 --with pytest --with "pydantic>=2,<3" python -m pytest tests/unit/test_schemas.py tests/unit/test_task_registry.py -q
```

Expected result for these file versions: `181 passed`.

This command uses an invocation-specific environment and is useful before the shared project setup is complete. It does not validate the team's lockfile or replace agreed dependency declarations. Once project dependencies are configured, use the team's normal project environment for CI and integration.

Day 1 completion requires all of the following:

- The shared schemas, scope model, registry, and their unit tests are available on `prototype_v1`.
- The agent and Gateway use the shared ToolCall contract rather than independent copies.
- The Gateway's health and invalid-request HTTP behaviors are demonstrated.
- A valid mock request reaches audit storage and is retrieved by its original request ID.
- The Gateway/Audit owners reconcile the open integration details in Section 11.

Changes to required fields, tool names, argument semantics, permit encoding, or permission interpretation require team coordination and matching updates to source, tests, this document, and consumers. Update `SCHEMA_VERSION` when the shared data contract changes. Adding a field is not automatically backward-compatible because existing models reject unknown fields.


## 13. AuditEvent

**Model:** `AuditEvent` in `src/secure_agent/common/schemas.py`

The Gateway creates this event after validating a ToolCall. The audit logger and
repository stores it and looks it up by `request_id`.

| Field | Type | Meaning |
| --- | --- | --- |
| `event_id` | `NonEmptyText` | Backend-generated event identifier |
| `request_id` | `NonEmptyText` | Request identifier copied from ToolCall |
| `event_type` | `NonEmptyText` | Event name; receipt uses `tool_call_received` |
| `timestamp` | `AwareDatetime` | Backend-generated time; use UTC |
| `metadata` | `dict[str, JsonValue]` | JSON-compatible event details; receipt stores `task_id` and `tool` |

All fields are required and follow the shared validation rules. The backend generates
IDs and timestamps; the schema does not check uniqueness or request correlation.
Use an aware datetime in Python or `AuditEvent.model_validate_json()` for JSON.
Multiple events may share a request ID.

The receipt event records no authorization or execution result. Its metadata contains
only `task_id` and `tool` from the validated ToolCall, not arguments or file contents.
Other stages may use other non-blank event names and JSON metadata. Nested metadata
is mutable despite the frozen model. Gateway records validated requests before returning HTTP 501; tool execution remains disabled.

### SQLite repository

`AuditRepository(database_path)` in `src/secure_agent/audit/repository.py` creates
`audit_events` in a SQLite file. The parent directory must exist; `:memory:` is not supported.

- `add(event: AuditEvent) -> None`: validate and commit an event.
- `get_by_request_id(request_id: str) -> list[AuditEvent]`: return matching events
  in insertion order, or an empty list.

`event_id` is the primary key; `request_id` has a non-unique index. Timestamps are
stored as ISO 8601 text with their timezone; metadata is stored as JSON text. Connections close after each operation.
Duplicate event IDs raise `sqlite3.IntegrityError` without replacing existing events.
Other SQLite errors propagate to the caller.


### Audit logger

`AuditLogger(repository)` in `src/secure_agent/audit/logger.py` provides
`log_tool_call_received(call: ToolCall) -> AuditEvent`. It revalidates the call,
generates a UUID event ID and UTC timestamp, copies request_id and places task_id/tool in metadata, and saves
the event through `AuditRepository.add()`. It returns the saved event and propagates
storage errors. Each invocation creates a separate event; it does not execute tools.


### Gateway audit integration

`create_app(database_path)` initializes audit storage during application startup.
The default database is `data/audit.db`; override it with `AUDIT_DB_PATH`.
Docker Compose persists `/app/data` in the `audit_data` volume.

- Valid `POST /tools/execute`: record receipt, then return HTTP 501 (execution disabled).
- Invalid body: HTTP 422; no receipt event is created.
- SQLite write failure: HTTP 503; no successful tool result is returned.

Query events using `AuditRepository.get_by_request_id()`; no public lookup endpoint
is exposed. The agent adapter still treats HTTP 501 as an error. The Day 1 flow
proves request receipt and persistence, not successful tool execution.
