# TraceWeaver implementation

Implementation of **Contract-aware concurrency exploration for authorization histories**.

The existing finite-model algorithms are retained. This revision adds causal-edge preservation, explicit incomplete-evidence verdicts, an independent permutation oracle, fresh witness replay, right-censor records, and an executable external JSON command adapter. These are implementation and functional-validation artifacts; they are not the raw experimental code or evidence behind the manuscript's reported numbers.

## Installation

Requires Python >=3.11. From the repository root in an activated environment:

```bash
python -m pip install -e .
python -m unittest discover -s tests
```

Installed validation environment: Windows, Python 3.13.5, numpy 2.1.3, scipy 1.15.3, matplotlib 3.10.0, psutil 7.1.0. Existing CI installs dependencies and runs the regression checks on Python 3.11.

## Data

The bundled generator produces synthetic finite-model scenarios for functional checks. It does not download a native benchmark, reproduce manuscript result tables or fit any parameters. Retain one generated input for paired comparisons:

```bash
python -m traceweaver prepare --count 6 --seed 17 --output data/generated.jsonl
```

Each UTF-8 JSONL line has a unique `id`, optional `family`, and `cluster` identifying the actual independent policy/history family. The generator records `generation_seed` and conservatively clusters repeated examples by family. Imported independent data should supply its reviewed cluster IDs. Input fields are:

`allow` and `deny`: principal/resource pairs; `operations`: insert/delete/check events with unique `id`, `client` and `sequence`; optional `requires` supplies causal parents. `contract` is LIN, SNAP or AT_LEAST, and `budget` bounds attempted schedules. Evaluation labels use `mutant` or explicit `non_equivalent_mutant`; external native findings need independent adjudication rather than an invented label.

`core.generate` is an executable complete schema example. Use the same schema for reviewed recorded cases; keep native, mutation-derived and synthetic strata separate. No private data, manuscript, pretrained weights or original server logs are distributed. The algorithms use explicit policy/configuration inputs rather than learned models, and do not tune on test labels.

## Execution

```bash
python -m traceweaver run --data data/generated.jsonl --output runs/main
```

The default `finite` backend is deterministic. The following commands also execute real local threads or the supplied stdin/stdout command protocol example:

```bash
python -m traceweaver run --data data/generated.jsonl --engine threads --overlap 2 --output runs/threads
python -m traceweaver run --data data/generated.jsonl --engine command --adapter-command python examples/reference_target.py --output runs/command
```

A command consumes one JSON object containing `case` and an ordered list of operation IDs `schedule`; it returns `{"history": [...]}` with complete monotonic invocation/response observations. The runtime validates Boolean check results, named snapshot revisions, causal parents and per-client timing. Replace the example only with a locally authorized adapter whose contract is registered.

## Evaluation

```bash
python -m traceweaver evaluate --records runs/main/traceweaver/records.jsonl --output runs/evaluated.json
```

`confirmed_mutation` conditions on adjudicated non-equivalent mutants. `false_report` uses histories executed on correct controls, with explicit micro numerator/denominator; `inconclusive_rate` uses all checked histories. `first_witness_seconds` is conditional on confirmed discovery; `discovery_observed_seconds` and `right_censored` retain non-discoveries. `replay_success` is one fresh replay per reported witness in this implementation, not the paper campaign of ten restarts. Repeated witnesses share their fault-family `cluster`.

Rates are fractions in [0,1]. `null` means an inapplicable or unresolved denominator, not zero failures. `metrics.json` gives conditional per-case means, SD and quantiles; rate fields with explicit `metric_counts` also contain pooled `micro` numerator/denominator/rate. Whole-case `latency_ms` includes local construction and audits; stage metrics identify the narrower compilation/runtime path. `rss_mib` is a sampled resident value, not a measured peak. Throughput is local finite-model useful effects per whole-case wall second, not the manuscript's server throughput.

The same `evaluate` command accepts independently recorded JSONL with `id`, `method`, `cluster`, numerical-or-null `metrics`, and optional `metric_counts` mapping each rate name to `[numerator, denominator]`. Thus backend-only paper measurements can be aggregated when genuinely collected; missing lock waits, network latency, maintenance, attacker recovery or native task outcomes are not assigned invented values.

## Comparisons and ablations

```bash
python -m traceweaver suite --data data/generated.jsonl --output runs/comparison
python -m traceweaver.statistics --records runs/comparison/traceweaver/records.jsonl --reference runs/comparison/bounded/records.jsonl --resamples 10000 --seed 17 --primary confirmed_mutation --output runs/paired.json
```

Select a subset with `--methods`. Implemented configurations: `traceweaver`, `bounded`, `random`, `no_negative_cone`, `no_por`, `forced_lin`. Deliberately lossy, unbound, feasibility-disabled and race variants are sandbox diagnostic controls, not safe deployments. The comparison implementations use this repository's declared finite semantics; they are not unmodified upstream systems.

Statistics first aggregate within each independent family and then bootstrap whole families. Paired analysis requires identical case IDs and excludes metrics undefined on either side. One eligible family yields no bootstrap interval. The zero-event bound concerns an event in an independent eligible cluster, not an iid per-request rate. McNemar is used only for independent single-record binary pairs; other paired summaries use Wilcoxon. Holm correction applies only to explicitly selected `--primary` endpoints. Small synthetic examples are not a source of experimental confidence intervals.

## Outputs and visualizations

```bash
python -m traceweaver plot --inputs runs/comparison/traceweaver runs/comparison/bounded --metrics confirmed_mutation latency_ms --output runs/figures
```

Each method directory contains `records.jsonl` (actual outcomes and conditional metrics), `metrics.json`, and `config.json` (command, environment and seeds). Plotting writes `summary.csv` plus selected metric PNGs; undefined metrics produce no misleading empty plot. All paths are configurable. Choose fresh output directories for reruns; generation/evaluation do not silently overwrite retained inputs or records.

## Paper-to-code map

| Paper module or metric | Code entry | Configuration / command |
|---|---|---|
| Positive/negative finite state semantics | `core.decision / update / generate` | finite allow/deny mutation cases |
| Contract-aware schedule reduction | `core.independent / representative / run_case` | traceweaver / bounded / no_por |
| LIN, SNAP and AT_LEAST explanations | `core.check_history; oracle.check` | contract and observed revisions |
| Actual overlapping target and command transport | `runtime.threaded_target / command_target` | --engine threads / command |
| Minimization, independent confirmation and replay | `core.shrink / run_case / score` | records.jsonl; observed_seconds |
| Aggregation, paired intervals and visualization | `cli.summarize; statistics.analyze; cli.plot` | evaluate / statistics / plot |

## Validation and implementation scope

Validated locally: editable installation, syntax/import and regression checks, six seed-17 cases through every suite configuration, retained-record re-evaluation, 10,000-resample paired analysis, selected metric PNG/CSV output, and wheel/source-distribution builds. No full paper campaign was run. Local functional records are retained under `runs/smoke/` (Git-ignored).

Regression checks cover hand-computable rates and eligible denominators, the algorithm's safety boundary, and applicable replay/serialization paths. The documented small-data preparation, execution, suite, evaluation, statistics and plotting commands are the validation entry points. No complete training or large experimental campaign is required for these checks.

The main checker bounds histories at 12 operations; the independent permutation cross-check bounds them at 8 and otherwise cannot confirm a finding. The built-in generator uses small allow/deny stale-read examples; it does not implement the full symbolic negative-cone/separating-state generator, Go/Porcupine stack, or native multi-engine campaign. The command example is a real local process running the reference threaded service. Local schedule-count smoke tests do not constitute a 300-second discovery campaign. Preserve censoring when analyzing discovery times.

The source retains its existing MIT license. Data and external systems remain subject to their own licenses and access rules.
