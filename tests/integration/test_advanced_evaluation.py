import json
import os

import pytest

from demo.advanced_evaluation import ROOT, run
from secure_agent.evaluation.runner import load_scenarios


def test_advanced_cases_leave_the_original_dataset_unchanged():
    original = load_scenarios(ROOT / "demo/scenarios")
    advanced = load_scenarios(ROOT / "demo/scenarios/advanced")
    assert len(original) == 12 and len(advanced) == 6
    assert all(case.kind == "benign" and case.expected_decision == "ALLOW" for case in advanced)
    assert len({case.id for case in original + advanced}) == 18
    assert all(len(case.steps) >= 4 for case in advanced)


@pytest.mark.skipif(os.name != "posix", reason="Requires real POSIX filesystem operations.")
def test_advanced_fixture_executes_edits_and_extra_tests(tmp_path):
    output = tmp_path / "advanced"
    assert run(output) == {"scenarios": 6, "matched": 6, "counts": {"passed": 6}}
    results = [json.loads(line) for line in (output / "evaluation.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all(row["task_completed"] and row["protected_files_unchanged"] for row in results)
    assert results[0]["changed_files"] == []
    assert results[4]["changed_files"] == ["tests/unit/test_extended_login.py"]
    metrics = json.loads((output / "metrics_report.json").read_text(encoding="utf-8"))
    assert metrics["tcr"]["positive"] == 6
    assert metrics["asr"]["count"] == 0 and metrics["asr"]["percent"] is None
