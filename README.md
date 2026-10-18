# TraceWeaver

Implementation of **Contract-aware concurrency exploration for authorization histories**.

Implements finite decision-separating policy states, scheduled concurrent operations, LIN/SNAP/AT_LEAST history checking, violation minimization and independent contract rechecking.

## Install

Use Python 3.11 or newer.

```bash
git clone https://github.com/Hqa77880011/TraceWeaver.git
cd TraceWeaver
python -m venv .venv
```

Activate with `source .venv/bin/activate` on Linux/macOS or `.venv\Scripts\Activate.ps1` in PowerShell.

```bash
python -m pip install -e .
```

## Prepare the workload

```bash
python -m traceweaver prepare --count 200 --seed 17 --output data/workload.jsonl
```

The seeded generator constructs finite scenarios from the formal problem. Independently generated or recorded cases may be imported with the same JSONL schema.

`allow` and `deny` are principal/resource relations. Operations insert/delete relations or check a request, and carry ID, client and client sequence. Histories include invocation/return bounds and observed revisions. The generator supplies correct and stale-reader configurations with declared consistency contracts.

## Execute and compare

```bash
python -m traceweaver run --data data/workload.jsonl --output runs/main
python -m traceweaver suite --data data/workload.jsonl --output runs/comparison
```

Use actual overlapping client invocations against the versioned reference service:

```bash
python -m traceweaver suite --data data/workload.jsonl --output runs/threads --engine threads --overlap 2
```

The threaded target records invocation and response timestamps from one monotonic clock. A barrier overlaps calls from distinct clients, while each client's sequence remains ordered. The reference service serializes policy updates and reads under a lock; it is a local concurrency target, not a measurement of a distributed authorization engine. `--overlap 1` gives sequential calls and exposes a stale read following a completed write under LIN.

To execute an external engine, provide a local command adapter:

```bash
python -m traceweaver run --data data/workload.jsonl --output runs/engine --engine command --adapter-command python adapters/engine.py
```

Supply your engine wrapper at that path. Each invocation receives one JSON object on stdin with `case` and `schedule` (the ordered operation IDs). It must reset the engine to the case's `allow`/`deny` initial state, execute those operations through its real client interface, and return `{"history": [...]}` on stdout. Diagnostic logging belongs on stderr. Each history item must include `id`, `start`, `end` and, for checks, Boolean `result` plus the observed `revision` when available. All timestamps share one monotonic clock and unit, and every requested operation must occur exactly once. The adapter must preserve each client's sequence. Map engine version tokens to this case's zero-based write revisions; SNAP requires a named revision. Do not derive returned decisions from the checker or the case's mutant label. The adapter may declare check dependencies in `requires`; versioned external checks conservatively pin case writes during witness minimization to preserve revision meaning. `--adapter-timeout` limits each command invocation. Command startup and execution count toward witness and elapsed time; CPU/RSS fields measure the controller process and exclude external child/server resource usage.

The `finite` engine remains the default deterministic model. Every result records `target_backend`, so finite, threaded and external measurements can be kept separate. Controlled mutation coverage still requires cases whose `mutant` label identifies an independently configured engine; do not interpret labels from the example generator as ground truth for an arbitrary external service.

`--methods` selects one or more method names. There are no learned parameters or model training in these finite algorithms.

`traceweaver` prioritizes update/check separation; `bounded` enumerates schedules; `random` shuffles them; `no_negative_cone` removes negative-dependency targeting; `no_por` retains unreduced schedule exploration; `forced_lin` deliberately checks every history against LIN.

## Metrics and plots

Confirmed mutation coverage on non-equivalent mutants, false reports, first-witness time with right censoring, histories explored and minimized witness length, together with CPU and memory measurements.

Each method writes `records.jsonl` and `metrics.json` under its output subdirectory. Conditional rates omit cases outside their denominator. Summary fields include means, sample standard deviations, P50/P95/P99 and usable sample counts. Independent scoring runs after the method timer. RSS includes the process runtime; serialized sizes measure JSON bytes.

```bash
python -m traceweaver plot --inputs runs/comparison/traceweaver --output figures
```

Supply multiple method directories after `--inputs` for comparison. Plotting writes `summary.csv` and metric PNGs.

## Implementation conventions

The checker exhaustively searches sequential explanations for at most 12 operations and returns INCONCLUSIVE above that bound. SNAP reads use a reachable named revision; AT_LEAST admits any reachable version at or above its nonnegative lower bound. The finite target executes sequential atomic operations; the threaded and command targets supply measured invocation/response histories to the same checker.


## Uncertainty and paired comparisons

```bash
python -m traceweaver.statistics --records runs/main/traceweaver/records.jsonl --output results/intervals.json
```

Supply --reference with a matched record file for paired differences. Resampling uses independent case IDs, or explicit cluster IDs when provided. Repeated observations from one source unit must share cluster. Zero-event bounds refer to an event in an independent cluster.
