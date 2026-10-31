# TraceWeaver implementation

Implementation of **Contract-aware concurrency exploration for authorization histories**.
The source implements the registered finite policy/history semantics, symbolic seed synthesis,
conservative reduction, independent confirmation, and the paper's concurrent comparison
configurations. Generated checks and newly collected native-wrapper records are implementation
validation; they are not the manuscript's original experiment evidence.

## Install

Python >=3.11:

```bash
python -m pip install -e .
python -m unittest discover -s tests
```

Runtime dependencies include Z3. Native profiles additionally use the Cedar CLI or a local
OpenFGA server. Existing MIT licensing is retained; dependencies and native engines retain
their own licenses. No third-party implementation source is vendored.

## Data and reference semantics

```bash
python -m traceweaver prepare --count 6 --seed 71 --fragment mixed --depth 3 --output data/cases.jsonl
```

`--fragment` selects `flat`, `relations`, `attributes`, `execute`, or `mixed`. These are synthetic
fixtures. Injected faults are adjudicated with the independent interpreter before comparing
generators. Reviewed imported records use the same UTF-8 JSONL schema and must supply independent
`cluster` IDs; renaming nodes does not create a new independent family. Native, mutation-derived,
and synthetic strata should be analyzed separately. Original policy corpora/server logs are not
bundled or represented by generated performance numbers.

Each case declares `id`, `contract`, initial `allow`/`deny` or `relations`, `operations`, and a
target-schedule `budget`. The finite AST supports `and`, `or`, `not`, binary `atom`, transitive
`reach`, typed `attribute` comparisons, and fixed-request/action/context predicates. Relation
universes declare string node IDs. Attribute domains live under `universe.__attributes__`, with
concrete values in `attributes`; supported attributes are total over that declared domain.
`fixed` binds initial Boolean relation facts; AST `invariants` hold before and after symbolic updates.
Administrative operations are fixture-authorized by default; `admin_allowed=false` excludes
unauthorized separating updates.

Operations have unique `id`, `client`, `sequence`, `principal`, `resource`, optional `action`
and `context`, and causal `requires`. Updates are `insert`, `delete`, or atomic `attribute`.
Checks record Boolean decisions. Execute records a nonce, a registered `revalidate` or named
`snapshot` gate, and whether an effect committed; operational failure is not treated as an
unauthorized effect. Duplicate committed nonces violate the once-only promise. Unknown gate or
consistency promises remain inconclusive. `frontends.ngac` additionally compiles the typed NGAC-style
assignment/association/prohibition fragment, enforcing policy-class conjunction, type validity,
acyclicity and dynamic association/prohibition facts. Supply it as a case's `ngac` object.

LIN, SNAP and AT_LEAST retain client, real-time and explicit causal constraints. Data revisions
index policy-state updates; executing a nonce does not invent a data revision. If a LIN deployment
makes revision values observable, set `revision_observable=true`; conservative POR then protects
those observations. SNAP requires a named revision, and AT_LEAST also checks the lower bound.
Shrinking preserves causal parents and named-snapshot provenance. Pending calls use the registered
`pending_rule`: `linearize` searches legal drops/completions, `drop` follows an explicit no-effect
contract, and the default `unknown` returns inconclusive. Hypothetical completion outcomes stay
inside the checker and are never written as observed results.

## Run and compare

```bash
python -m traceweaver run --data data/cases.jsonl --output runs/main
python -m traceweaver suite --data data/cases.jsonl --output runs/comparison
python -m traceweaver run --data data/cases.jsonl --engine threads --overlap 2 --output runs/threads
```

| Paper configuration | Method | Actual generation/reduction mechanism |
|---|---|---|
| Full | `traceweaver` | Positive/negative AST cones, SMT decision-separating fixtures, proved semantic commutation |
| Random | `random` | Random valid finite fixtures and random client/causality-respecting orders |
| KeyPOR | `keypor` | Random valid fixtures plus physical-key candidate reduction and semantic proof before pruning unsupported cases |
| PX+ | `px_plus` | Iterative single-fact/attribute differential mutation within the valid policy-state grammar |
| VGD+ | `vgd_plus` | Typed permit/nonpermit property construction under invariants, with separate concrete-policy cross-checks |
| Cover+ | `cover_plus` | Greedy action/obligation/transition, enabledness and reference-outcome coverage over legal linear extensions |
| Bounded | `bounded` | Blocking-clause enumeration of valid finite states and unreduced legal linear extensions; explicit completeness/UNKNOWN status |
| No negative cones | `no_negative_cone` | Exclude negative read cones from directed seed construction |
| Unsafe key-only POR | `no_semantic_independence` | Physical-key pruning without the semantic proof; diagnostic only |
| Forced LIN | `forced_lin` | Register LIN in the variant's checker even for a different actual contract; diagnostic only |
| Random seed state | `random_seed` | Random valid seed states with the directed ordering strategy |
| No POR / no shrinking | `no_por`, `no_shrink` | Disable the corresponding component |

PX+/VGD+/Cover+ are concurrent mechanism adaptations under this repository's common policy IR,
contracts, permissions, observations and oracle, as specified by the manuscript comparison.
They do not claim to be unmodified ProfessorX, Cedar VGD, or an upstream NGAC testing tool.
`bounded` enumerates complete finite-state models lazily and records whether all valid states/orders
finished; budget-limited runs do not claim exhaustive coverage. The bounded event model uses legal linear extensions and proven adjacent commutations; it does
not assume physical-key disjointness implies semantic independence. Independence includes absent
negative facts, inheritance, enabledness, attributes, nonce gates and observable revisions.

## Native engines and actual effects

```bash
python -m traceweaver prepare --count 6 --seed 71 --fragment mixed --native-profile cedar --output data/cedar.jsonl
python -m traceweaver prepare --count 6 --seed 71 --native-profile openfga --output data/native.jsonl
python -m traceweaver run --data data/cedar.jsonl --engine cedar --cedar-executable cedar --overlap 2 --output runs/cedar
python -m traceweaver run --data data/native.jsonl --engine openfga --native-url http://127.0.0.1:8080 --output runs/openfga
python -m traceweaver run --data data/cases.jsonl --engine command --adapter-command python examples/reference_target.py --output runs/command
```

The Cedar target compiles the declared relational/attribute AST into Cedar policy/entity inputs,
then invokes the actual CLI. Inheritance closure attributes belong to the tested shared-state
wrapper. Reads really overlap; atomic updates and revalidating effects share its gate. The
OpenFGA HTTP profile creates fresh local sandbox stores/models, writes the fixture and records
actual Check responses. The built-in model is direct allow/deny difference; other OpenFGA models
must be supplied with their reviewed reference mapping. The wrapper normalizes set-like tuple
updates and mediates its own effects. External writers are outside that local wrapper gate.

OpenFGA's `HIGHER_CONSISTENCY` option is not declared to imply LIN. Use `contract=UNKNOWN` unless
`contract_registration` records the reviewed deployment mode and its provenance. This adapter
cannot invent SNAP tokens that the server did not return. Authentication reads
`OPENFGA_API_TOKEN` from the environment and does not log it.

A native Execute additionally requires `native.effect_command`, a list of command arguments.
The adapter sends the event as JSON stdin and requires a JSON `committed` Boolean and receipt.
`{python}` selects the current interpreter; `{episode}` in an argument expands to that fresh episode's retained output directory. For
example, configure `python examples/durable_effect.py --database {episode}/effects.sqlite`;
the supplied adapter performs an actual atomic SQLite effect with nonce/plan binding. Ten fresh
restarts use fresh episode directories. Command transport remains available for other reviewed
native-engine adapters and validates observed IDs, times, revisions and causal parents.

API references: [Cedar CLI](https://github.com/cedar-policy/cedar/tree/main/cedar-policy-cli),
[OpenFGA consistency contract](https://openfga.dev/blog/query-consistency-options-announcement).

## Budgets, evaluation and outputs

```bash
python -m traceweaver.campaign --data data/cases.jsonl --output runs/schedules --protocol target_schedules --schedules 1000 --workers 4 --seeds 17 29 43 71 101
python -m traceweaver.campaign --data data/cases.jsonl --output runs/wall --protocol wall --seconds 300 --workers 4
python -m traceweaver.campaign --data data/cases.jsonl --output runs/pool --protocol whole_pool --seconds 300 --workers 4
python -m traceweaver evaluate --records runs/main/traceweaver/records.jsonl --output runs/evaluated.json
python -m traceweaver.statistics --records runs/comparison/traceweaver/records.jsonl --reference runs/comparison/bounded/records.jsonl --resamples 10000 --seed 71 --primary confirmed_mutation --output runs/paired.json
python -m traceweaver plot --inputs runs/comparison/traceweaver runs/comparison/bounded --metrics confirmed_mutation latency_ms checking_seconds --output runs/figures
```

A target-schedule budget counts executed histories, not discarded permutations. Generation,
solving, confirmation and ten fresh replays consume real time. Wall campaigns supervise each
case; whole-pool campaigns share one horizon across all families and retain unfinished and
unstarted mutants in coverage. Expired workers and only their descendants are stopped; their
observations remain censored, with unknown CPU rather than a fabricated zero. `--visibility`
selects black/gray/white generator information; black-box histories omit named revision evidence.
The trusted oracle retains the registered reference model in every condition.

`records.jsonl`, `metrics.json`, and `config.json` retain actual outcomes, seeds and environment.
Metrics include independently confirmed mutation coverage, emitted false reports on correct
controls (including legal old snapshots), inconclusive histories, ten-start replay success, minimized length, discovery exposure,
right censoring, measured stage times, latency quantiles, productive families per measured wall
second, and CPU per confirmed family. Prefix DFS,
independent exhaustive interpretation and rank/state SMT supply distinct history checks; larger
histories use timeout-bounded SMT and UNKNOWN stays inconclusive. `discovery_survival` contains
Kaplan闂備胶鍋ㄩ崕鑼躲亹閸у獢er and restricted-mean summaries without dropping non-discoveries. Conditional discovery
means are kept distinct. Generation includes dependency/seed subtimes; these nested times should
not be summed twice. Fresh campaign workers additionally record OS peak RSS for the Python/Z3
process; native engine/server memory is a separate measurement scope. Native findings require
independent adjudication, not a generated mutant label.

All rates retain explicit eligible denominators; undefined values are null. Paired statistics
first aggregate independent families, preserve repeated-run clustering, use 10,000 resamples,
and apply Holm correction only to selected endpoints. The metric hand checks include 3/8 pooled
rates and a censored discovery example with restricted mean 2. A generated fixture is not an
experimental confidence interval. Plotting produces selected PNGs and all-metric CSV. Inputs
and retained records are not silently overwritten.

## Paper-to-code map

| Module / metric | Entry | Configuration / command |
|---|---|---|
| Cones, inheritance, separation | `policy.cones / separating; frontends.ngac` | universe / fixed / invariants; prepare fragments |
| LIN/SNAP/AT_LEAST and enabledness | `core.check_history; oracle.check; smt.check` | contract / revisions / timeout |
| Generation, POR and ablations | `strategies.fixtures / schedules / representative` | suite / --methods |
| Native history and actual effects | `runtime; native; examples/durable_effect.py` | --engine / effect_command |
| Shrink and ten-start replay | `core.shrink / run_case` | replay_attempts=10 |
| Budgets, censoring, metrics and figures | `campaign; cli; survival; statistics` | campaign / evaluate / statistics / plot |

## Validation

Local environment: Windows, Python 3.13.5, numpy 2.1.3, scipy 1.15.3, matplotlib 3.10.0,
psutil 7.1.0, Z3 5.3.3.0; native checks used Cedar CLI 4.14.0 and OpenFGA 1.22.1.
Tests cover negative/nonlocal inheritance, typed attribute revocation, symbolic separation from
non-separating fixtures, three-checker agreement, 14-operation histories, action-scoped NGAC
association changes, conservative POR class preservation, actual Cedar attribute evaluation,
actual OpenFGA revoke/Check transport, real local threads, command replay, metrics and censoring.
Native tests activate when Cedar is installed or `CEDAR_EXECUTABLE` is set, and when
`TRACEWEAVER_OPENFGA_URL` points to the local sandbox.

No full manuscript campaign or original raw-result reconstruction was run. Native validation
establishes these configured wrapper/API paths; it does not establish a universal consistency
contract for all external deployments. Retained functional runs are Git-ignored under `runs/`.
