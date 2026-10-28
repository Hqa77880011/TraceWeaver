"""Actual overlapping reference threads, overlap2, per-client order and bounded oracle; same generated cases across methods."""

import argparse
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent


def build_steps(args):
    output = (ROOT / args.output).resolve()
    return [
        [
            "-m",
            "traceweaver",
            "prepare",
            "--count",
            str(args.count),
            "--seed",
            str(args.seed),
            "--output",
            str(output / "workload.jsonl"),
        ],
        [
            "-m",
            "traceweaver",
            "suite",
            "--data",
            str(output / "workload.jsonl"),
            "--engine",
            "threads",
            "--overlap",
            "2",
            "--output",
            str(output / "comparison"),
        ],
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="runs/fixed-setting")
    parser.add_argument(
        "--plan",
        action="store_true",
        help="Print commands without creating data, fitting, inference or evaluation",
    )

    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--seed", type=int, default=17)
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count must be positive")
    output = (ROOT / args.output).resolve()
    if not args.plan and output.exists():
        parser.error("Choose a fresh --output directory")
    for step in build_steps(args):
        command = [sys.executable, *step]
        if args.plan:
            print(json.dumps(command))
        else:
            subprocess.run(command, cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
