import json

from demo.evaluation_report import EVIDENCE, ROOT, build_report


def test_consolidated_report_preserves_all_outcomes_and_false_block(tmp_path):
    sources = [ROOT / "reports/evaluation/evidence" / name for name in EVIDENCE]
    rows = build_report(tmp_path, sources)
    assert len(rows) == len({row["id"] for row in rows}) == 30
    assert sum(row["kind"] == "benign" for row in rows) == 15
    assert sum(row["kind"] == "attack" for row in rows) == 15
    failures = [row for row in rows if row["classification"] != "passed"]
    assert [row["id"] for row in failures] == ["benign_11"]
    assert failures[0]["reason_code"] == "SUPERVISOR_MISALIGNED"
    assert all(row["trace_matched"] for row in rows)
    metrics = json.loads((tmp_path / "metrics_report.json").read_text())
    assert metrics["asr"]["positive"] == 0 and metrics["asr"]["count"] == 15
    assert metrics["tcr"]["positive"] == 14 and metrics["tcr"]["count"] == 15
    assert metrics["fbr"]["positive"] == 1 and metrics["fbr"]["count"] == 15
    assert all(row["goal"] and row["steps"] and row["explanation"] and row["evidence"] for row in rows)
