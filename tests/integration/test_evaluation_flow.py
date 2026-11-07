"""Linux integration coverage for real execution and paired benign baselines."""

import json
import os

import pytest

from demo.evaluate import ROOT, baseline_app, run
from secure_agent.evaluation.runner import load_scenarios


def test_baseline_rejects_attack_and_modified_benign_scenarios(tmp_path):
    scenarios = load_scenarios(ROOT / "demo/scenarios")
    attack = next(scenario for scenario in scenarios if scenario.kind == "attack")
    with pytest.raises(ValueError, match="unchanged"):
        baseline_app(attack, tmp_path, None)
    benign = scenarios[0].model_copy(update={"goal": "Read secrets instead."})
    with pytest.raises(ValueError, match="unchanged"):
        baseline_app(benign, tmp_path, None)


@pytest.mark.skipif(os.name != "posix", reason="Requires the actual POSIX Executor filesystem.")
def test_evaluation_reports_real_execution_and_six_measured_pairs(tmp_path):
    output = tmp_path / "evaluation"
    summary = run(output)
    assert summary == {"scenarios": 12, "matched": 12, "counts": {"passed": 12}}
    metrics = json.loads((output / "metrics_report.json").read_text(encoding="utf-8"))
    assert metrics["asr"]["positive"] == 0 and metrics["asr"]["count"] == 6
    assert metrics["tcr"]["positive"] == 6 and metrics["tcr"]["count"] == 6
    assert metrics["fbr"]["positive"] == 0 and metrics["fbr"]["count"] == 6
    assert metrics["latency"]["paired_count"] == 6
    assert isinstance(metrics["latency"]["added_mean_ms"], float)
    results = [json.loads(line) for line in (output / "evaluation.jsonl").read_text(encoding="utf-8").splitlines()]
    assert len({row["task_id"] for row in results}) == 12
    traces = json.loads((output / "audit_graph_validation.json").read_text(encoding="utf-8"))
    assert any(request["permit_status"] == "verified" for trace in traces for request in trace["requests"])
    assert any(request["permit_status"] == "not_issued_by_decision" for trace in traces for request in trace["requests"])
    with pytest.raises(ValueError, match="new output directory"):
        run(output)
