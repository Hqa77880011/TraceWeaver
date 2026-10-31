import argparse
import csv
import json
import random
import math
import platform
import sys
import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import psutil

from . import core


def read_jsonl(path):
    with Path(path).open(encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("Each JSONL line must be an object")
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("Case IDs must be unique within an input")
    return rows


def write_jsonl(path, rows):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        raise FileExistsError(str(path))
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, allow_nan=False) + "\n")


def summarize(rows, wall_seconds=None):
    report = {}
    keys = sorted(
        {
            key
            for row in rows
            for key, value in row["metrics"].items()
            if value is None or isinstance(value, (int, float, bool))
        }
    )
    for key in keys:
        values = np.array(
            [
                float(row["metrics"][key])
                for row in rows
                if row["metrics"].get(key) is not None
            ],
            dtype=float,
        )
        values = values[np.isfinite(values)]
        if not len(values):
            report[key] = {"count": 0, "mean": None}
            continue
        report[key] = {
            "count": len(values),
            "mean": float(values.mean()),
            "std": float(values.std(ddof=1)) if len(values) > 1 else None,
            "p50": float(np.quantile(values, 0.5)),
            "p95": float(np.quantile(values, 0.95)),
            "p99": float(np.quantile(values, 0.99)),
        }
    for key in keys:
        counts = [
            row["metric_counts"][key]
            for row in rows
            if key in row.get("metric_counts", {})
        ]
        if counts:
            numerator = sum(value[0] for value in counts)
            denominator = sum(value[1] for value in counts)
            report[key]["micro"] = dict(
                numerator=numerator,
                denominator=denominator,
                rate=numerator / denominator if denominator else None,
            )
    elapsed = sum(row["metrics"].get("latency_ms", 0) for row in rows) / 1000
    legal = sum(row["metrics"].get("legal_effects", 0) for row in rows)
    report["legal_throughput_per_second"] = (
        legal / elapsed
        if elapsed and any("legal_effects" in row["metrics"] for row in rows)
        else None
    )
    observations = [
        (
            row["metrics"]["discovery_observed_seconds"],
            not row["metrics"].get("right_censored", 1),
        )
        for row in rows
        if row["metrics"].get("discovery_observed_seconds") is not None
    ]
    if observations:
        from .survival import kaplan_meier

        report["discovery_survival"] = kaplan_meier(observations)
        confirmed = {
            row.get("cluster", row["id"])
            for row in rows
            if row.get("result", {}).get("confirmed")
        }
        report["confirmed_families"] = len(confirmed)
        report["confirmed_families_per_second"] = (
            len(confirmed) / wall_seconds if wall_seconds else None
        )
        report["discovery_rmst_seconds"] = report["discovery_survival"]["mean"]
        report["cpu_seconds_per_confirmed_family"] = (
            sum(row["metrics"].get("cpu_seconds", 0) for row in rows) / len(confirmed)
            if confirmed
            and all(row["metrics"].get("cpu_seconds") is not None for row in rows)
            else None
        )
    return report


def execute(cases, method, output, target=None, engine="finite"):
    output = Path(output)
    if output.exists() and any(output.iterdir()):
        raise FileExistsError("Choose an empty output directory: " + str(output))
    run_start = time.perf_counter()
    rows = []
    process = psutil.Process()
    for case in cases:
        start_cpu = time.process_time()
        start = time.perf_counter()
        result = core.run_case(case, method, target=target)
        result["target_backend"] = engine
        elapsed = time.perf_counter() - start
        cpu = time.process_time() - start_cpu
        metrics = core.score(case, result)
        metrics.update(
            latency_ms=elapsed * 1000,
            cpu_seconds=cpu,
            rss_mib=process.memory_info().rss / 2**20,
            output_bytes=len(json.dumps(result).encode()),
        )
        rows.append(
            {
                "id": case["id"],
                "family": case.get("family", case["id"]),
                "method": method,
                "cluster": case.get("cluster", case.get("family", case["id"])),
                "generation_seed": case.get("generation_seed"),
                "metric_counts": core.metric_counts(case, result)
                if hasattr(core, "metric_counts")
                else {},
                "result": result,
                "metrics": metrics,
            }
        )
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    write_jsonl(output / "records.jsonl", rows)
    wall_seconds = time.perf_counter() - run_start
    (output / "metrics.json").write_text(
        json.dumps(summarize(rows, wall_seconds), indent=2, allow_nan=False),
        encoding="utf-8",
    )
    (output / "config.json").write_text(
        json.dumps(
            dict(
                method=method,
                wall_seconds=wall_seconds,
                python=sys.version.split()[0],
                platform=platform.system(),
                arguments=sys.argv[1:],
                generation_seeds=sorted(
                    {
                        row["generation_seed"]
                        for row in rows
                        if row["generation_seed"] is not None
                    }
                ),
                timing="whole finite-model case; inspect stage metrics for online/offline separation",
            ),
            indent=2,
        ),
        encoding="utf-8",
    )
    return rows


def retained_wall(records):
    path = Path(records).parent / "config.json"
    value = (
        json.loads(path.read_text(encoding="utf-8")).get("wall_seconds")
        if path.exists()
        else None
    )
    if value is not None and (
        type(value) not in (int, float) or not math.isfinite(value) or value <= 0
    ):
        raise ValueError("Retained wall_seconds must be a finite positive measurement")
    return value


def evaluate(records, output):
    """Aggregate numerical measurements from retained or externally recorded JSONL."""
    rows = read_jsonl(records)
    for row in rows:
        for value in row["metrics"].values():
            if value is not None and (
                not isinstance(value, (int, float)) or not math.isfinite(value)
            ):
                raise ValueError("Metrics must be finite numbers or null")
        for numerator, denominator in row.get("metric_counts", {}).values():
            if not (
                math.isfinite(numerator)
                and math.isfinite(denominator)
                and 0 <= numerator <= denominator
            ):
                raise ValueError("Rate counts require 0 <= numerator <= denominator")
    output = Path(output)
    if output.exists():
        raise FileExistsError(str(output))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(summarize(rows, retained_wall(records)), indent=2, allow_nan=False),
        encoding="utf-8",
    )


def plot(paths, output, metrics=None):
    """Render per-case, pooled-rate, family-cost and censored-discovery endpoints."""
    records = []
    durations = {}
    for path in paths:
        rows = read_jsonl(Path(path) / "records.jsonl")
        records.extend(rows)
        methods = {row["method"] for row in rows}
        for method in methods:
            durations.setdefault(method, []).append(
                retained_wall(Path(path) / "records.jsonl")
                if len(methods) == 1
                else None
            )
    methods = sorted({row["method"] for row in records})
    summaries = {}
    for method in methods:
        times = durations[method]
        summary = summarize(
            [row for row in records if row["method"] == method],
            sum(times) if all(value is not None for value in times) else None,
        )
        for key, value in list(summary.items()):
            if isinstance(value, dict) and "micro" in value:
                micro = value["micro"]
                summary[key + "_micro"] = dict(
                    count=micro["denominator"], mean=micro["rate"]
                )
        summaries[method] = summary
    keys = sorted({key for summary in summaries.values() for key in summary})
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    with (output / "summary.csv").open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["method", "metric", "n", "mean", "std", "p50", "p95", "p99"])
        for method, summary in summaries.items():
            for key, value in summary.items():
                item = (
                    value
                    if isinstance(value, dict)
                    else dict(
                        count=sum(row["method"] == method for row in records),
                        mean=value,
                    )
                )
                writer.writerow(
                    [
                        method,
                        key,
                        item["count"],
                        item["mean"],
                        *(item.get(field) for field in ("std", "p50", "p95", "p99")),
                    ]
                )
    for key in keys:
        if metrics is not None and key not in metrics:
            continue
        if key == "discovery_survival":
            curves = {
                method: summaries[method].get(key, {}).get("curve", [])
                for method in methods
            }
            if not any(curves.values()):
                continue
            fig, ax = plt.subplots(figsize=(6, 4))
            for method, curve in curves.items():
                if curve:
                    ax.step(
                        [0] + [item["time"] for item in curve],
                        [1] + [item["survival"] for item in curve],
                        where="post",
                        label=method,
                    )
            ax.set(
                xlabel="Observed seconds",
                ylabel="Probability of no confirmed witness",
                ylim=(0, 1.02),
            )
            ax.legend()
        else:
            values = [summaries[method].get(key) for method in methods]
            means = [
                value.get("mean") if isinstance(value, dict) else value
                for value in values
            ]
            if not any(value is not None for value in means):
                continue
            fig, ax = plt.subplots(figsize=(max(6, len(methods)), 4))
            ax.bar(
                methods,
                [np.nan if value is None else value for value in means],
                color="#527c91",
            )
            ax.set_ylabel(key)
            ax.tick_params(axis="x", rotation=35)
        fig.tight_layout()
        fig.savefig(output / (key + ".png"), dpi=180)
        plt.close(fig)


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("--output", required=True)
    prepare.add_argument("--count", type=int, default=200)
    prepare.add_argument("--seed", type=int, default=17)
    prepare.add_argument(
        "--fragment",
        choices=["flat", "relations", "attributes", "execute", "mixed"],
        default="flat",
    )
    prepare.add_argument("--depth", type=int, default=3)
    prepare.add_argument("--native-profile", choices=["cedar", "openfga"])
    for name in ("run", "suite"):
        item = sub.add_parser(name)
        item.add_argument("--data", required=True)
        item.add_argument("--output", required=True)
        item.add_argument(
            "--engine",
            choices=["finite", "threads", "command", "cedar", "openfga"],
            default="finite",
        )
        item.add_argument("--native-url", default="http://127.0.0.1:8080")
        item.add_argument("--cedar-executable", default="cedar")
        item.add_argument("--overlap", type=int, default=2)
        item.add_argument("--adapter-command", nargs="+")
        item.add_argument("--adapter-timeout", type=float, default=60.0)
        item.add_argument(
            "--methods",
            nargs="+",
            choices=core.METHODS,
            default=[core.METHODS[0]] if name == "run" else core.METHODS,
        )
    item = sub.add_parser("evaluate")
    item.add_argument("--records", required=True)
    item.add_argument("--output", required=True)
    item = sub.add_parser("plot")
    item.add_argument("--inputs", nargs="+", required=True)
    item.add_argument(
        "--metrics",
        nargs="+",
        help="Render selected metric PNGs; CSV retains all metrics",
    )
    item.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        if args.count < 1:
            parser.error("--count must be positive")
        if args.fragment == "flat":
            rows = list(core.generate(random.Random(args.seed), args.count))
        else:
            from .workloads import generate

            rows = list(
                generate(
                    random.Random(args.seed), args.count, args.fragment, args.depth
                )
            )
        for row in rows:
            if args.native_profile:
                if args.native_profile == "openfga" and args.fragment != "flat":
                    parser.error(
                        "The automatic OpenFGA profile requires --fragment flat; import reviewed models for other fragments"
                    )
                row["contract"] = (
                    "UNKNOWN" if args.native_profile == "openfga" else "LIN"
                )
                row["mutant"] = "native"
                row["non_equivalent_mutant"] = False
                row["stratum"] = "native_unmodified"
                row["family"] = "native-" + row["family"].split("-")[0]
                row["native"] = {
                    "effect_command": [
                        "{python}",
                        "examples/durable_effect.py",
                        "--database",
                        "{episode}/effects.sqlite",
                    ]
                }
            row["id"] = str(args.seed) + ":" + row["id"]
            row["generation_seed"] = args.seed
            row.setdefault("cluster", row.get("family", row["id"]))
        write_jsonl(args.output, rows)
    elif args.command in ("run", "suite"):
        from .runtime import command_target, threaded_target

        if args.engine == "command" and not args.adapter_command:
            parser.error("--engine command requires --adapter-command")
        if args.overlap < 1 or args.adapter_timeout <= 0:
            parser.error("overlap and adapter-timeout must be positive")
        target = (
            threaded_target(args.overlap)
            if args.engine == "threads"
            else command_target(args.adapter_command, args.adapter_timeout)
            if args.engine == "command"
            else None
        )
        if args.engine in ("cedar", "openfga"):
            from .native import cedar_target, openfga_target

            target = (
                cedar_target(
                    args.cedar_executable,
                    str(Path(args.output) / "native-inputs"),
                    overlap=args.overlap,
                )
                if args.engine == "cedar"
                else openfga_target(args.native_url, overlap=args.overlap)
            )
        cases = read_jsonl(args.data)
        for method in args.methods:
            execute(cases, method, Path(args.output) / method, target, args.engine)
    elif args.command == "evaluate":
        evaluate(args.records, args.output)
    else:
        plot(args.inputs, args.output, args.metrics)


if __name__ == "__main__":
    main()
