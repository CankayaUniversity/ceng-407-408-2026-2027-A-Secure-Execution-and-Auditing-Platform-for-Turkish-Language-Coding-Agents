"""Replay the complete 30-case catalog and write one combined report."""

import argparse
from pathlib import Path

from demo.attack_evaluation import run as run_attacks
from demo.benign_evaluation import run as run_benign
from demo.evaluate import run as run_policy
from demo.evaluation_report import build_report
from secure_agent.security.gemini_client import GeminiClient


def run(output, *, provider=None):
    output = Path(output)
    if output.exists():
        raise ValueError("Choose a new output directory to preserve recorded evidence.")
    sources = [output / "evidence" / name for name in ("policy", "benign", "alignment")]
    run_policy(sources[0], provider=provider)
    run_benign(sources[1], provider=provider)
    run_attacks(sources[2], provider=provider)
    return build_report(output, sources)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--supervisor", choices=("gemini", "fixture"), default="gemini")
    args = parser.parse_args()
    provider = GeminiClient(env_file=args.env_file) if args.supervisor == "gemini" else None
    try:
        run(args.output, provider=provider)
    finally:
        if provider:
            provider.close()
