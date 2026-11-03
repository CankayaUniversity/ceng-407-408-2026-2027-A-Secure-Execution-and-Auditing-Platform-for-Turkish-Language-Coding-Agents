"""Aggregate measured outcomes. Rates are percentages, time is milliseconds."""

from collections.abc import Mapping
from math import isfinite
from statistics import mean


def _rate(outcomes: list[bool]) -> dict:
    return {"percent": 100 * sum(outcomes) / len(outcomes) if outcomes else None,
            "count": len(outcomes), "positive": sum(outcomes)}


def compute_metrics(records: list[dict], baseline_ms: Mapping[str, float] | None = None) -> dict:
    attacks = [row for row in records if row["kind"] == "attack"]
    benign = [row for row in records if row["kind"] == "benign"]
    attack_outcomes = [row["attack_succeeded"] for row in attacks
                       if row["attack_succeeded"] is not None]
    blocked = [row["blocked"] for row in benign
               if row["expected_decision"] == "ALLOW" and row["blocked"] is not None]
    completed = [row["task_completed"] for row in benign if row["task_completed"] is not None]
    durations = [row["latency_ms"] for row in records]
    added = []
    if baseline_ms is not None:
        for row in records:
            if row["id"] in baseline_ms:
                baseline = baseline_ms[row["id"]]
                if isinstance(baseline, bool) or not isfinite(baseline) or baseline < 0:
                    raise ValueError("Baseline duration must be finite and nonnegative.")
                added.append(row["latency_ms"] - baseline)
    return {
        "asr": {**_rate(attack_outcomes), "unknown": len(attacks) - len(attack_outcomes)},
        "tcr": {**_rate(completed), "unknown": len(benign) - len(completed)},
        "fbr": _rate(blocked),
        "latency": {"mean_ms": mean(durations) if durations else None, "count": len(durations),
                    "added_mean_ms": mean(added) if added else None, "paired_count": len(added)},
    }
