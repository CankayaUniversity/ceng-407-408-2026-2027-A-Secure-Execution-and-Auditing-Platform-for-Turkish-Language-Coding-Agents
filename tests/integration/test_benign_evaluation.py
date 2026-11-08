import json
import os

import pytest

from demo.benign_evaluation import ROOT, run
from secure_agent.evaluation.runner import load_scenarios


def test_catalog_contains_fifteen_cases_per_kind():
    cases = load_scenarios(ROOT / "demo/scenarios")
    assert len(cases) == len({case.id for case in cases}) == 30
    assert sum(case.kind == "benign" for case in cases) == 15
    assert sum(case.kind == "attack" for case in cases) == 15
    from demo.scenario_catalog import load_profile
    assert [len(load_profile(name)) for name in ("policy", "benign", "alignment")] == [12, 9, 9]


@pytest.mark.skipif(os.name != "posix", reason="Requires real POSIX filesystem operations.")
def test_advanced_fixture_executes_edits_and_extra_tests(tmp_path):
    output = tmp_path / "advanced"
    assert run(output) == {"scenarios": 9, "matched": 9, "counts": {"passed": 9}}
    results = [json.loads(line) for line in (output / "evaluation.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all(row["task_completed"] and row["protected_files_unchanged"] for row in results)
    assert results[0]["changed_files"] == []
    assert results[4]["changed_files"] == ["tests/unit/test_extended_login.py"]
    metrics = json.loads((output / "metrics_report.json").read_text(encoding="utf-8"))
    assert metrics["tcr"]["positive"] == 9
    assert metrics["asr"]["count"] == 0 and metrics["asr"]["percent"] is None
