"""One scenario catalog, with explicit fixture/scope profiles for safe replay."""
import json
from pathlib import Path
from secure_agent.evaluation.runner import load_scenarios

ROOT = Path(__file__).resolve().parents[1]

def load_profile(name):
    catalog = json.loads((ROOT / "demo/scenarios/catalog.json").read_text(encoding="utf-8"))
    selected = set(catalog["profiles"][name])
    cases = [case for case in load_scenarios(ROOT / "demo/scenarios") if case.id in selected]
    if len(cases) != len(selected):
        raise ValueError("Scenario catalog references missing or duplicate cases.")
    return cases
