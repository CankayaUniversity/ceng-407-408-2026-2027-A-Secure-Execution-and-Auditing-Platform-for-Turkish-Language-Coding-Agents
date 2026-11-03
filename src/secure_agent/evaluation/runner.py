"""Run scripted scenarios against a configured demo Gateway and its audit ledger."""

import argparse
import json
from pathlib import Path
from time import perf_counter
from typing import Literal

from pydantic import Field, JsonValue

from agent.agent_loop import AgentLoop
from agent.tool_adapter import SecureToolAdapter
from secure_agent.audit.repository import AuditRepository
from secure_agent.common.schemas import ContractModel, DecisionValue, NonEmptyText, ToolName
from secure_agent.evaluation.metrics import compute_metrics


class Proposal(ContractModel):
    tool: ToolName
    arguments: dict[str, JsonValue]


class ExpectedEffect(Proposal):
    output_contains: NonEmptyText | None = None


class Scenario(ContractModel):
    id: NonEmptyText
    kind: Literal["benign", "attack"]
    task_id: NonEmptyText
    goal: NonEmptyText
    expected_decision: DecisionValue
    steps: tuple[Proposal, ...] = Field(min_length=1)
    expected_effect: ExpectedEffect


def load_scenarios(root: Path) -> list[Scenario]:
    scenarios = []
    seen = set()
    for folder, kind in (("benign", "benign"), ("attacks", "attack")):
        for path in sorted((root / folder).glob("*.json")):
            scenario = Scenario.model_validate_json(path.read_bytes())
            if scenario.kind != kind or scenario.id in seen:
                raise ValueError(f"Wrong kind or duplicate scenario ID: {path}")
            effect = scenario.expected_effect.model_dump(exclude={"output_contains"})
            if not any(step.model_dump() == effect for step in scenario.steps):
                raise ValueError(f"Expected effect must match a scripted step: {path}")
            seen.add(scenario.id)
            scenarios.append(scenario)
    return scenarios


class ScriptedModel:
    def __init__(self, scenario: Scenario):
        self.steps = scenario.steps

    def propose(self, *, history, **kwargs):
        if len(history) < len(self.steps):
            return self.steps[len(history)].model_dump(mode="json")
        return None


def evaluate(scenario: Scenario, adapter: SecureToolAdapter, audit: AuditRepository) -> dict:
    started = perf_counter()
    run = None
    error = None
    try:
        run = AgentLoop(ScriptedModel(scenario), task_id=scenario.task_id,
                       max_steps=len(scenario.steps) + 1, adapter=adapter).run(scenario.goal)
    except Exception as exc:
        error = type(exc).__name__
    latency_ms = (perf_counter() - started) * 1000

    effect = scenario.expected_effect
    target_ids = set()
    traces = []
    decisions = {}
    audit_error = None
    for call in run.tool_calls if run else ():
        if call.tool == effect.tool and call.arguments.model_dump(mode="json") == effect.arguments:
            target_ids.add(call.request_id)
        try:
            events = audit.get_by_request_id(call.request_id)
        except Exception as exc:
            audit_error = type(exc).__name__
            continue
        for event in events:
            if event.event_type == "security_decision":
                decisions[call.request_id] = event.metadata.get("decision")
            if event.event_type in {"security_decision", "graph_assessment", "graph_event", "source_exposure"}:
                traces.append({"request_id": event.request_id, "event_id": event.event_id,
                               "event_type": event.event_type, "metadata": event.metadata})

    results = run.tool_results if run else ()
    observed = [result for result in results if result.request_id in target_ids]
    reached = any(result.status == "success" and
                  (effect.output_contains is None or effect.output_contains in result.output)
                  for result in observed)
    target_blocked = any(decisions.get(request_id) in {"DENY", "REVIEW"}
                         for request_id in target_ids)
    # An infrastructure error or unattempted target gives no attack outcome.
    attack_success = (True if reached else False if target_blocked or
                      any(result.status in {"success", "denied"} for result in observed)
                      else None)
    if run and run.error:
        error = run.stop_reason
    return {
        "id": scenario.id, "kind": scenario.kind, "expected_decision": scenario.expected_decision,
        "stop_reason": run.stop_reason if run else None, "error": error, "audit_error": audit_error,
        "latency_ms": latency_ms, "decision": next(reversed(decisions.values()), None),
        "blocked": (any(value in {"DENY", "REVIEW"} for value in decisions.values())
                    if decisions else None),
        "task_completed": reached and all(result.status == "success" for result in results)
                          and run.stop_reason == "model_finished" if scenario.kind == "benign" else None,
        "attack_succeeded": attack_success if scenario.kind == "attack" else None,
        "tool_results": [{"request_id": result.request_id, "status": result.status,
                          "source_id": result.source_id} for result in results],
        "request_ids": [call.request_id for call in run.tool_calls] if run else [],
        "audit": traces,
    }


def run_evaluation(scenarios: list[Scenario], adapter: SecureToolAdapter,
                   audit: AuditRepository, output: Path) -> list[dict]:
    output.parent.mkdir(parents=True, exist_ok=True)
    records = []
    with output.open("x", encoding="utf-8") as stream:
        for scenario in scenarios:
            record = evaluate(scenario, adapter, audit)
            stream.write(json.dumps(record, ensure_ascii=False, allow_nan=False) + "\n")
            stream.flush()
            records.append(record)
    return records


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenarios", type=Path, default=Path("demo/scenarios"))
    parser.add_argument("--gateway-url", required=True)
    parser.add_argument("--audit-db", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    scenarios = load_scenarios(args.scenarios)
    if not scenarios:
        parser.error("No scenarios found.")
    if not args.audit_db.is_file():
        parser.error("Use the configured demo Gateway's existing audit database.")
    adapter = SecureToolAdapter(args.gateway_url, timeout=args.timeout, acknowledge_exposure=True)
    records = run_evaluation(scenarios, adapter, AuditRepository(args.audit_db), args.output)
    print(json.dumps(compute_metrics(records), indent=2, allow_nan=False))


if __name__ == "__main__":
    main()
