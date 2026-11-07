# Gemini Supervisor

Create `.env` at the project root with `GEMINI_API_KEY=your-key`.
The file is ignored by Git. Never include the key in reports or screenshots.
Install dependencies with `uv sync --extra dev`.

`GeminiClient` implements the existing Supervisor client protocol. The project
`.env` is read explicitly; a process-level `GEMINI_API_KEY` takes precedence.
No environment variables are changed globally. The default model is
`gemini-3.1-flash-lite`. An explicit model argument overrides it; failures never
silently trigger a switch to a different model.

```python
from secure_agent.security.gemini_client import GeminiClient
from secure_agent.security.supervisor import Supervisor

client = GeminiClient()
supervisor = Supervisor(registry=registry, llm_client=client)
# Pass supervisor to the existing create_app(..., supervisor=supervisor).
# Close client during shutdown.
```

The adapter requests JSON matching the existing verdict schema and exposes no
tools. The Supervisor retains its strict validation. Provider errors, incomplete
responses and timeouts yield UNCERTAIN through the existing Supervisor logic.
Decision Engine therefore does not authorize execution on provider failure.

Run three real assessments without executing any tool:

```powershell
uv run python scripts/check_gemini_supervisor.py
```

This command uses real Policy, Supervisor, Decision Engine and SQLite audit.
Its empty graph is a fixture. It does not verify Gateway HTTP transport,
Executor sandboxing or complete prompt-injection resistance. Evidence is saved
under ignored `data/gemini-supervisor/audit.db`. Model verdicts are observations,
not assertions that every example must receive a predetermined answer.

For the complete twelve-scenario run and paired latency measurements, see
[Evaluation](evaluation.md). The dedicated harness passes this
Supervisor explicitly to the existing Gateway; the default application is not
silently switched to paid network calls.
