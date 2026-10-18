# TraceWeaver

Implementation of **Contract-aware concurrency exploration for authorization histories**.

## Installation

Requires Python `>=3.11`. Run from the repository root in an activated environment.

```bash
python -m pip install -e .
```

Inspection environment: Python 3.13.5; numpy 2.1.3, matplotlib 3.10.0. Checks: Python syntax, configuration parsing and CLI/source argument matching. Training and full evaluation were not run.

## Data

The seeded generator constructs finite scenarios from the formal problem. Independently generated or recorded cases may be imported with the same JSONL schema.

The bundled generator writes synthetic finite-model scenarios as JSONL. Fix the seed and keep the generated input for paired comparisons.

```bash
python -m traceweaver prepare --count 200 --seed 17 --output data/generated.jsonl
```

## Execution and evaluation

```bash
python -m traceweaver run --data data/generated.jsonl --engine threads --overlap 2 --output runs/main
```

## Comparisons and ablations

```bash
python -m traceweaver suite --data data/generated.jsonl --engine threads --overlap 2 --output runs/comparison
```

Use `--methods` to select: `traceweaver`, `bounded`, `random`, `no_negative_cone`, `no_por`, `forced_lin`.

## Outputs

`runs/main/traceweaver/records.jsonl` stores per-case results; `metrics.json` stores aggregate measurements. Comparison outputs use one directory per method.

```bash
python -m traceweaver plot --inputs runs/comparison/traceweaver --output figures
```

Plotting writes `figures/summary.csv` and metric PNGs. Statistical intervals can be computed from a retained record file:

```bash
python -m traceweaver.statistics --records runs/main/traceweaver/records.jsonl --output results/intervals.json
```
