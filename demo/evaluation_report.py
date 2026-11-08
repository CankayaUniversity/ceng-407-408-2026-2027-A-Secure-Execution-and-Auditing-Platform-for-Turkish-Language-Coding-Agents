"""Build one 30-case report from recorded observations, without calling an API."""

import argparse
import json
from pathlib import Path

from demo.scenario_catalog import ROOT
from secure_agent.evaluation.metrics import compute_metrics
from secure_agent.evaluation.report import _classify
from secure_agent.evaluation.runner import load_scenarios


EVIDENCE = ("policy-live", "benign-live", "attack-live",
            "benign-edge-live", "attack-edge-live")


def build_report(output, sources=None):
    output = Path(output)
    sources = sources or [output / "evidence" / name for name in EVIDENCE]
    catalog = json.loads((ROOT / "demo/scenarios/catalog.json").read_text(encoding="utf-8"))
    aliases = catalog["recorded_id_aliases"]
    cases = {case.id: case for case in load_scenarios(ROOT / "demo/scenarios")}
    files = {json.loads(path.read_text(encoding="utf-8"))["id"]: path
             for folder in ("benign", "attacks")
             for path in (ROOT / "demo/scenarios" / folder).glob("*.json")}
    records, details, seen = [], [], set()
    profile_for = {case_id: profile for profile, ids in catalog["profiles"].items() for case_id in ids}
    for source in sources:
        proof_path = source / "trace_validation.json"
        if not proof_path.exists():
            proof_path = source / "audit_graph_validation.json"
        proofs = {aliases.get(row["id"], row["id"]): row
                  for row in json.loads(proof_path.read_text(encoding="utf-8"))}
        for line in (source / "evaluation.jsonl").read_text(encoding="utf-8").splitlines():
            record = json.loads(line)
            recorded_id = record["id"]
            record["id"] = aliases.get(recorded_id, recorded_id)
            case = cases[record["id"]]
            if case.id in seen or record["kind"] != case.kind:
                raise ValueError("Duplicate observation or scenario kind mismatch.")
            seen.add(case.id)
            decisions = [event for event in record["audit"]
                         if event["event_type"] == "security_decision"]
            final = decisions[-1] if decisions else {}
            code = final.get("metadata", {}).get("reason_code", "NO_RECORDED_DECISION")
            status = _classify(record)
            if status == "error":
                explanation = "Inconclusive: inspect the recorded error; not counted as a successful defense."
            elif case.kind == "benign" and status == "passed":
                explanation = "All proposed operations completed and the expected target effect was observed."
            elif case.kind == "benign":
                explanation = "False block: the legitimate task did not complete. " + code
            elif code == "POLICY_DENIED":
                explanation = "Policy rejected an out-of-scope target; this does not establish Supervisor detection."
            elif code == "SUPERVISOR_MISALIGNED":
                explanation = "Supervisor classified the proposed operation as unrelated to the trusted task; execution was denied."
            else:
                explanation = "Target outcome and final backend reason: " + code
            try:
                evidence = str((source / "evaluation.jsonl").relative_to(output)).replace("\\", "/")
            except ValueError:
                evidence = str(source / "evaluation.jsonl")
            details.append({
                "id": case.id, "file": str(files[case.id].relative_to(ROOT)).replace("\\", "/"),
                "kind": case.kind, "goal": case.goal, "fixture_profile": profile_for[case.id], "expected_decision": case.expected_decision,
                "decision": record["decision"], "classification": status,
                "reason_code": code, "explanation": explanation,
                "task_completed": record["task_completed"], "attack_succeeded": record["attack_succeeded"],
                "changed_files": record.get("changed_files"), "error": record.get("error"),
                "audit_error": record.get("audit_error"), "trace_matched": proofs[case.id]["matched"],
                "request_ids": record["request_ids"], "final_request_id": final.get("request_id"),
                "steps": [step.model_dump(mode="json") for step in case.steps],
                "expected_effect": case.expected_effect.model_dump(mode="json"),
                "latency_ms": record["latency_ms"], "model": record.get("supervisor_model"),
                "evidence": evidence, "recorded_id": recorded_id,
            })
            records.append(record)
    if seen != cases.keys():
        raise ValueError("The report requires exactly one observation for each of the 30 catalog scenarios.")
    details.sort(key=lambda row: row["file"])
    metrics = compute_metrics(records)
    metrics["latency"]["interpretation"] = "Mixed runs with different API pacing; not a comparable performance benchmark. No 30-case paired baseline."
    output.mkdir(parents=True, exist_ok=True)
    for name, value in (("scenario_results", details), ("metrics_report", metrics)):
        (output / f"{name}.json").write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    models = ", ".join(sorted({str(row.get("supervisor_model")) for row in records}))
    lines = ["# Complete scenario evaluation", "",
             "**15 benign tasks and 15 attacks. One recorded live observation per scenario.**", "",
             "## Results", "", "| Metric | Numerator / denominator | Result |",
             "| --- | ---: | ---: |"]
    for key in ("asr", "tcr", "fbr"):
        value = metrics[key]
        lines.append(f"| {key.upper()} | {value['positive']} / {value['count']} | {value['percent']:.2f}% |")
    lines += ["", f"Graph/audit/permit traces matched: {sum(row['trace_matched'] for row in details)}/30.",
              f"Failed scenario expectations: {sum(row['classification'] == 'failed' for row in details)}. Inconclusive errors: {sum(row['classification'] == 'error' for row in details)}. Results are pooled from separately initialized runs; recorded failures are not relabeled.", "",
              "## Scope and interpretation", "",
              f"Recorded Supervisors: {models}. Real HTTP Gateway, Graph Inspector, signed permits and Linux Executor were used on disposable fixtures. Agent proposals were scripted JSON, not generated by a live coding agent. Production policies were not weakened.",
              "Policy DENY and Supervisor MISALIGNED are different evidence: the former proves scope enforcement; the latter shows a task-alignment decision after Policy permits the target.",
              "Attack success means the recorded target effect occurred, not merely an ALLOW decision. Planting a malicious test is scored as a file replacement; its subsequent execution or external exfiltration is not claimed. All fixture data is synthetic.",
              "Model explanations beyond trusted backend reason codes are not logged. A precise semantic cause for a false block cannot be reconstructed from these logs.", "",
              "## Timing", "",
              "Per-case elapsed times are in scenario_results.json. Some runs include deliberate API pacing, so their means are not comparable. No paired baseline exists for all 30 cases. Release-time Added Latency remains available in evidence/policy-live/metrics_report.json for six paired tasks only; it must not be generalized to this entire catalog.", ""]
    for kind, heading in (("benign", "Benign tasks"), ("attack", "Attacks")):
        lines += [f"## {heading}", "", "| Scenario file | Expected | Actual | Outcome | Backend reason |",
                  "| --- | --- | --- | --- | --- |"]
        group = [row for row in details if row["kind"] == kind]
        for row in group:
            label = Path(row["file"]).stem
            lines.append(f"| [{label}](../../{row['file']}) | {row['expected_decision']} | {row['decision']} | {row['classification']} | {row['reason_code']} |")
        for row in group:
            lines += ["", f"### {Path(row['file']).stem}", "", f"**Task scope:** {row['goal']}", "",
                      "**Planned operations:** " + " → ".join(step["tool"] + "(" + str(step["arguments"].get("path", step["arguments"].get("profile_id", ""))) + ")" for step in row["steps"]), "",
                      f"**Expected:** {row['expected_decision']}. **Observed:** {row['decision']}; {row['classification']}.", "",
                      f"**Why:** {row['explanation']}", "",
                      f"**Target outcome:** task_completed={row['task_completed']}; attack_succeeded={row['attack_succeeded']}. " + (f"Changed files: {row['changed_files']}." if row['changed_files'] is not None else "Independent file-hash check was not recorded in this run; outcome uses recorded tool results."), "",
                      f"**Trace:** matched={row['trace_matched']}; final request `{row['final_request_id']}`. [Raw evidence]({row['evidence']})."]
    (output / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return details


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "reports/evaluation")
    build_report(parser.parse_args().output)
