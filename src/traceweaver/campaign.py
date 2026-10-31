"""Equal-information schedule, wall-time and shared-worker-pool campaigns."""

import argparse
import copy
import json
import multiprocessing as mp
import os
from pathlib import Path
import queue
import time


def _stop(process):
    """Stop only this campaign's worker and descendants, including native calls."""
    import psutil

    if process.is_alive():
        try:
            children = psutil.Process(process.pid).children(recursive=True)
        except psutil.NoSuchProcess:
            children = []
        for child in children:
            try:
                child.kill()
            except psutil.NoSuchProcess:
                pass
        process.terminate()
    process.join()


def _worker(case, method, engine, options, channel):
    from . import core
    from .runtime import threaded_target

    start, cpu = time.perf_counter(), time.process_time()
    target = None
    if engine == "threads":
        target = threaded_target(options["overlap"])
    elif engine == "cedar":
        from .native import cedar_target

        target = cedar_target(
            options["cedar"], options["native_output"], overlap=options["overlap"]
        )
    elif engine == "openfga":
        from .native import openfga_target

        target = openfga_target(options["url"], overlap=options["overlap"])
    result = core.run_case(case, method, target)
    metrics = core.score(case, result)
    metrics.update(
        latency_ms=(time.perf_counter() - start) * 1000,
        cpu_seconds=time.process_time() - cpu,
        timeouts=0,
    )
    import psutil

    info = psutil.Process().memory_info()
    peak = getattr(info, "peak_wset", None)
    if peak is None:
        import resource
        import sys

        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (
            1 if sys.platform == "darwin" else 1024
        )
    metrics["peak_rss_mib"] = peak / 2**20
    row = dict(
        id=case["id"],
        method=method,
        cluster=case.get("cluster", case.get("family", case["id"])),
        metrics=metrics,
        result=result,
        metric_counts=core.metric_counts(case, result),
    )
    channel.put(row)


def run(
    cases,
    method,
    output,
    workers=4,
    horizon=None,
    engine="finite",
    options=None,
    per_case_horizon=None,
):
    """Share one wall horizon across a complete pool, retaining killed-job censoring."""
    if workers < 1 or horizon is not None and horizon <= 0:
        raise ValueError("Use positive workers and horizon")
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    path = output / "records.jsonl"
    if path.exists():
        raise FileExistsError(str(path))
    context = mp.get_context("spawn")
    channel = context.Queue()
    options = options or dict(overlap=2)
    started = time.perf_counter()
    pending = list(copy.deepcopy(cases))
    active = {}
    rows = []

    def retain(row):
        rows.append(row)
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(row, allow_nan=False) + "\n")

    try:
        while pending or active:
            elapsed = time.perf_counter() - started
            if horizon is not None and elapsed >= horizon:
                break
            if per_case_horizon is not None:
                expired = [
                    identifier
                    for identifier, (_, _, assigned) in active.items()
                    if time.perf_counter() - assigned >= per_case_horizon
                ]
                for identifier in expired:
                    process, case, assigned = active.pop(identifier)
                    _stop(process)
                    retain(
                        dict(
                            id=identifier,
                            method=method,
                            cluster=case.get("cluster", case.get("family", identifier)),
                            result=dict(
                                confirmed=False,
                                censored=True,
                                termination="per_case_wall_budget",
                            ),
                            metrics=dict(
                                confirmed_mutation=0
                                if case.get("non_equivalent_mutant")
                                else None,
                                first_witness_seconds=None,
                                discovery_observed_seconds=time.perf_counter()
                                - assigned,
                                right_censored=1,
                                timeouts=1,
                                cpu_seconds=None,
                            ),
                        )
                    )
            while pending and len(active) < workers:
                case = pending.pop(0)
                process = context.Process(
                    target=_worker, args=(case, method, engine, options, channel)
                )
                process.start()
                active[case["id"]] = (process, case, time.perf_counter())
            try:
                row = channel.get(timeout=0.05)
            except queue.Empty:
                for identifier, (process, _, _) in active.items():
                    if process.exitcode is not None and process.exitcode != 0:
                        raise RuntimeError(
                            f"Campaign worker failed for {identifier} with exit {process.exitcode}"
                        )
                continue
            if row["id"] not in active:
                continue
            process, _, _ = active.pop(row["id"])
            if horizon is not None:
                row["metrics"]["discovery_observed_seconds"] = (
                    time.perf_counter() - started
                )
                if row["result"]["confirmed"]:
                    row["metrics"]["first_witness_seconds"] = (
                        time.perf_counter() - started
                    )
            process.join()
            retain(row)
    finally:
        for process, _, _ in active.values():
            _stop(process)
        channel.close()
    for identifier, (_, case, assigned) in active.items():
        observed = time.perf_counter() - started
        retain(
            dict(
                id=identifier,
                method=method,
                cluster=case.get("cluster", case.get("family", identifier)),
                result=dict(
                    confirmed=False, censored=True, termination="shared_wall_budget"
                ),
                metrics=dict(
                    confirmed_mutation=0 if case.get("non_equivalent_mutant") else None,
                    first_witness_seconds=None,
                    discovery_observed_seconds=observed,
                    right_censored=1,
                    timeouts=1,
                    cpu_seconds=None,
                ),
            )
        )
    for case in pending:
        retain(
            dict(
                id=case["id"],
                method=method,
                cluster=case.get("cluster", case.get("family", case["id"])),
                result=dict(
                    confirmed=False,
                    censored=True,
                    termination="unstarted_at_shared_horizon",
                ),
                metrics=dict(
                    confirmed_mutation=0 if case.get("non_equivalent_mutant") else None,
                    first_witness_seconds=None,
                    discovery_observed_seconds=time.perf_counter() - started,
                    right_censored=1,
                    timeouts=0,
                    cpu_seconds=None,
                ),
            )
        )
    config = dict(
        workers=workers,
        shared_horizon=horizon,
        wall_seconds=time.perf_counter() - started,
        per_case_horizon=per_case_horizon,
        engine=engine,
        cases=len(cases),
        completed=sum(not row["result"].get("censored", False) for row in rows),
    )
    (output / "config.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--methods", nargs="+", default=["traceweaver"])
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--protocol",
        choices=["target_schedules", "wall", "whole_pool"],
        default="target_schedules",
    )
    parser.add_argument("--schedules", type=int, default=1000)
    parser.add_argument("--seconds", type=float, default=300)
    parser.add_argument("--seeds", nargs="+", type=int, default=[17, 29, 43, 71, 101])
    parser.add_argument(
        "--visibility", choices=["black", "gray", "white"], default="white"
    )
    parser.add_argument(
        "--engine", choices=["finite", "threads", "cedar", "openfga"], default="finite"
    )
    parser.add_argument("--overlap", type=int, default=2)
    parser.add_argument("--cedar", default="cedar")
    parser.add_argument("--url", default="http://127.0.0.1:8080")
    args = parser.parse_args()
    os.environ.setdefault("OMP_NUM_THREADS", "1")
    from . import core

    if set(args.methods) - set(core.METHODS) or args.schedules < 1:
        parser.error("Unknown method or invalid schedule budget")
    raw = [
        json.loads(line)
        for line in Path(args.data).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    cases = []
    for seed in args.seeds:
        for original in raw:
            case = copy.deepcopy(original)
            case.update(
                id=str(original["id"]) + ":scheduler:" + str(seed),
                scheduler_seed=seed,
                budget=args.schedules,
                generator_visibility=args.visibility,
            )
            cases.append(case)
    options = dict(
        overlap=args.overlap,
        cedar=args.cedar,
        url=args.url,
        native_output=str(Path(args.output) / "native"),
    )
    for method in args.methods:
        run(
            cases,
            method,
            Path(args.output) / method,
            args.workers,
            args.seconds if args.protocol == "whole_pool" else None,
            args.engine,
            options,
            args.seconds if args.protocol == "wall" else None,
        )

        config_path = Path(args.output) / method / "config.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config.update(
            data=args.data,
            scheduler_seeds=args.seeds,
            visibility=args.visibility,
            target_schedule_budget=args.schedules,
            protocol=args.protocol,
        )
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
