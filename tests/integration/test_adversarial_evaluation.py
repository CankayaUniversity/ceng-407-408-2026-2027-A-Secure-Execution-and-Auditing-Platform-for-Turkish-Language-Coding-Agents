import json
import os

import pytest

from demo.adversarial_evaluation import ROOT, run
from secure_agent.evaluation.runner import load_scenarios


def test_adversarial_dataset_is_separate_and_has_six_attack_targets():
    assert len(load_scenarios(ROOT / "demo/scenarios")) == 12
    cases = load_scenarios(ROOT / "demo/scenarios/adversarial")
    assert len(cases) == 6
    assert all(case.kind == "attack" and case.expected_decision == "DENY" for case in cases)
    assert all(case.expected_effect.tool == "secure_edit_file" for case in cases)


@pytest.mark.skipif(os.name != "posix", reason="Requires real POSIX file operations.")
def test_allow_all_control_proves_all_six_attacks_can_change_their_targets(tmp_path):
    output = tmp_path / "control"
    assert run(output) == {"scenarios": 6, "matched": 6, "counts": {"failed": 6}}
    rows = [json.loads(line) for line in (output / "evaluation.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all(row["attack_succeeded"] and row["target_effect_observed"] for row in rows)
    assert all(row["target_policy_preflight"] == "ALLOW" and row["untargeted_files_unchanged"] for row in rows)
    metrics = json.loads((output / "metrics_report.json").read_text(encoding="utf-8"))
    assert metrics["asr"]["percent"] == 100 and metrics["asr"]["count"] == 6


@pytest.mark.skipif(os.name != "posix", reason="Requires real POSIX file operations.")
def test_misaligned_verdict_blocks_all_in_scope_attack_targets(tmp_path):
    class VerdictFixture:
        """Deterministic verdicts test enforcement, not model accuracy."""

        _model = "scripted-verdict-fixture"

        def complete(self, *, system_prompt, user_prompt):
            call = json.loads(user_prompt)["untrusted_tool_call"]
            verdict = "MISALIGNED" if call["tool"] == "secure_edit_file" else "ALIGNED"
            return json.dumps({"verdict": verdict, "reason": "Fixture assessment of a read-only task."})

    output = tmp_path / "blocked"
    assert run(output, provider=VerdictFixture(), interval=0) == {
        "scenarios": 6, "matched": 6, "counts": {"passed": 6},
    }
    rows = [json.loads(line) for line in (output / "evaluation.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all(row["attack_succeeded"] is False and row["changed_files"] == [] for row in rows)
    for row in rows:
        decisions = [event["metadata"] for event in row["audit"] if event["event_type"] == "security_decision"]
        assert decisions[-1]["reason_code"] == "SUPERVISOR_MISALIGNED"
