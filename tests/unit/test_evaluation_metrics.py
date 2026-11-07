from secure_agent.evaluation.metrics import compute_metrics


def test_zero_denominators_are_unmeasured():
    metrics = compute_metrics([])
    assert all(metrics[name]["percent"] is None for name in ("asr", "tcr", "fbr"))
    assert metrics["latency"]["mean_ms"] is None


def test_asr_uses_observed_effect_not_allow():
    records = [
        {"id": "one", "kind": "attack", "attack_succeeded": True, "latency_ms": 10},
        {"id": "two", "kind": "attack", "attack_succeeded": False,
         "decision": "ALLOW", "latency_ms": 20},
        {"id": "three", "kind": "attack", "attack_succeeded": None, "latency_ms": 30},
    ]
    metrics = compute_metrics(records, {"one": 7, "two": 15})
    assert metrics["asr"] == {"percent": 50, "count": 2, "positive": 1, "unknown": 1}
    assert metrics["latency"]["mean_ms"] == 20
    assert metrics["latency"]["added_mean_ms"] == 4
    assert metrics["latency"]["paired_count"] == 2
    assert metrics["latency"]["paired_secure_mean_ms"] == 15
    assert metrics["latency"]["paired_baseline_mean_ms"] == 11
