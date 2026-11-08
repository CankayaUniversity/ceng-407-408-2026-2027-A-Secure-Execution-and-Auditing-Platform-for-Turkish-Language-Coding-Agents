"""Six advanced benign replays against real Gateway/Executor and optional Gemini.

Uses disposable Linux workspaces. The original twelve-case dataset is unchanged.
Agent steps are scripted; Supervisor calls and protected file operations are real.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from demo.evaluate import ROOT, ContextSupervisor, FixtureSupervisor, ObservingAdapter, copy_workspace, serve
from secure_agent.audit.repository import AuditRepository
from secure_agent.common.schemas import Task
from secure_agent.evaluation.report import generate_reports
from secure_agent.evaluation.runner import evaluate, load_scenarios
from secure_agent.execution.executor import Executor
from secure_agent.execution.test_runner import TestRunner
from secure_agent.gateway.main import create_app
from secure_agent.provenance.repository import ProvenanceRepository
from secure_agent.security.gemini_client import DEFAULT_MODEL, GeminiClient
from secure_agent.security.permit_verifier import PermitVerifier
from secure_agent.security.policy_engine import PolicyEngine
from secure_agent.tasks.registry import TaskRegistry
from secure_agent.tasks.scope import TaskScope


class PacedProvider:
    """Space live calls without retrying or changing a security decision."""

    def __init__(self, client, interval):
        self.client, self.interval, self.next_call = client, interval, 0.0

    def complete(self, **kwargs):
        time.sleep(max(0, self.next_call - time.monotonic()))
        try:
            return self.client.complete(**kwargs)
        finally:
            self.next_call = time.monotonic() + self.interval


def snapshot(workspace):
    return {path.relative_to(workspace).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in workspace.rglob("*") if path.is_file()
            and not {"__pycache__", ".pytest_cache"}.intersection(path.parts)}


def run(output: Path, *, provider=None, interval=4.0):
    if os.name != "posix":
        raise RuntimeError("Use Linux/Docker for real Executor file operations.")
    if output.exists():
        raise ValueError("Choose a new output directory.")
    scenarios = load_scenarios(ROOT / "demo/scenarios/advanced")
    if len(scenarios) != 6 or any(s.kind != "benign" for s in scenarios):
        raise ValueError("Expected six advanced benign cases.")
    output.mkdir(parents=True)
    ledger = output / "ledgers"
    ledger.mkdir()
    database = ledger / "audit.db"
    audit = AuditRepository(database)
    paced = PacedProvider(provider, interval) if provider else None
    records = []
    with TemporaryDirectory(prefix="advanced-benign-") as temp:
        for index, scenario in enumerate(scenarios):
            workspace = Path(temp) / f"workspace-{index}"
            copy_workspace(workspace, "benign", "advanced-fixture-not-a-real-key")
            # Executor edits existing files only. This test-owned empty file is
            # deliberately seeded; the system is not claimed to create files.
            (workspace / "tests/unit/test_extended_login.py").write_text("", encoding="utf-8")
            scope = TaskScope(
                scope_id="advanced", workspace_id="demo",
                allowed_tools=frozenset({"secure_read_file", "secure_edit_file", "secure_list_files", "secure_run_tests"}),
                readable_files=frozenset({"README.md", "src/login.py", "tests/unit/test_login.py", "tests/unit/test_extended_login.py"}),
                writable_files=frozenset({"src/login.py", "tests/unit/test_extended_login.py"}),
                listable_directories=frozenset({".", "src"}), allowed_test_profiles=frozenset({"unit"}),
            )
            registry = TaskRegistry(workspace_ids={"demo"}, scopes=[scope])
            registry.register(Task(task_id=scenario.task_id, user_goal=scenario.goal,
                                   workspace_id="demo", scope_id=scope.scope_id))
            policy = PolicyEngine(registry=registry, model_path=ROOT / "configs/casbin_model.conf",
                                  policy_path=ROOT / "configs/casbin_policy.csv")
            key = Ed25519PrivateKey.generate()
            executor = Executor(registry=registry, workspace_roots={"demo": workspace},
                                test_runners={"demo": TestRunner(workspace, ROOT / "configs/test_profiles.yaml")},
                                permit_verifier=PermitVerifier(key.public_key(), ledger / "nonces.db"))
            observations = {}
            supervisor = ContextSupervisor(registry, paced, observations) if paced else FixtureSupervisor()
            app = create_app(database, policy_engine=policy, supervisor=supervisor,
                             demo_executor=executor, demo_private_key=key)
            before = snapshot(workspace)
            with serve(app) as adapter:
                record = evaluate(scenario, ObservingAdapter(adapter, observations), audit)
            after = snapshot(workspace)
            changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
            planned = {step.arguments["path"] for step in scenario.steps if step.tool == "secure_edit_file"}
            protected = [".env", "src/config.py", "tests/unit/test_login.py"]
            if not set(changed).issubset(planned) or any(before.get(name) != after.get(name) for name in protected):
                raise RuntimeError("Unexpected or protected fixture modification.")
            record.update(changed_files=changed, protected_files_unchanged=True,
                          supervisor_model=provider._model if provider else "fixture")
            records.append(record)
            with (output / "evaluation.jsonl").open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
            print(f"{scenario.id}: decision={record['decision']}, completed={record['task_completed']}, changes={changed}", flush=True)
    graph = ProvenanceRepository(ledger / "audit-provenance.db").load_graph()
    summary = generate_reports(records, audit, graph, output, label="Advanced benign evaluation")
    methodology = {
        "agent": "scripted multi-step proposals", "supervisor": provider._model if provider else "fixture",
        "execution": "real HTTP Gateway and Linux Executor in an evaluation container, not the read-only remote service",
        "dataset": "six additional benign cases; original twelve-case reports unchanged",
        "safety": "fresh per-case workspaces, explicit grants, signed one-use permits; original tests/config/fake secret unchanged",
        "seeded_file": "existing empty tests/unit/test_extended_login.py; no new-file capability implied",
        "latency": "includes intentional API pacing; not a performance benchmark or Added Latency measurement",
        "api_interval_seconds": interval if provider else 0, "attack_success_rate": "not measured: no attacks in this dataset",
        "summary": summary,
    }
    (output / "methodology.json").write_text(json.dumps(methodology, indent=2) + "\n", encoding="utf-8")
    with (output / "summary.md").open("a", encoding="utf-8") as stream:
        stream.write("\nScripted Agent steps; " + methodology["supervisor"] + " Supervisor. "
                     "Real Gateway/Linux Executor on disposable fixtures; separate remote read-only service not exercised.\n"
                     "All cases are benign. ASR and Added Latency are unmeasured. Live timings include deliberate API pacing.\n")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--supervisor", choices=["gemini", "fixture"], default="gemini")
    parser.add_argument("--env-file", type=Path)
    args = parser.parse_args()
    provider = GeminiClient(env_file=args.env_file) if args.supervisor == "gemini" else None
    try:
        print(json.dumps(run(args.output, provider=provider)), flush=True)
    finally:
        if provider:
            provider.close()


if __name__ == "__main__":
    main()
