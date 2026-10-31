"""Information-matched concurrent generation and reduction configurations.

PX+/VGD+/Cover+ are the paper's concurrent mechanism adaptations, not calls to
the upstream projects. All invoke the same registered contract checker.
"""

import copy
import itertools
import json
import random
import time

from . import policy


def linearizations(events, rng=None):
    """Enumerate only client/causality-respecting orders, not invalid permutations."""
    by_id = {event["id"]: event for event in events}
    parents = {
        event["id"]: set(event.get("requires", []))
        | {
            other["id"]
            for other in events
            if other["client"] == event["client"]
            and other["sequence"] < event["sequence"]
        }
        for event in events
    }
    if len(by_id) != len(events) or any(
        not values <= set(by_id) for values in parents.values()
    ):
        raise ValueError("Schedule IDs and causal parents must be complete and unique")

    def visit(prefix, done):
        if len(done) == len(events):
            yield tuple(prefix)
            return
        ready = [
            event
            for event in events
            if event["id"] not in done and parents[event["id"]] <= done
        ]
        if not ready:
            raise ValueError("Cyclic client/causal schedule constraints")
        if rng is not None:
            rng.shuffle(ready)
            ready = ready[:1]
        for event in ready:
            yield from visit(prefix + [event], done | {event["id"]})

    yield from visit([], set())


def representative(schedule, case, method):
    ordered = list(schedule)
    changed = True
    while changed:
        changed = False
        for index in range(len(ordered) - 1):
            a, b = ordered[index : index + 2]
            if (
                case.get("revision_observable")
                and method != "no_semantic_independence"
                and (a["kind"] != "check" or b["kind"] != "check")
            ):
                independent = False
            elif "universe" in case and method != "no_semantic_independence":
                independent = policy.independent(a, b, case)
                if method == "keypor":
                    independent &= (a["principal"], a["resource"]) != (
                        b["principal"],
                        b["resource"],
                    )
            else:
                from .core import independent as physical

                independent = physical(a, b, case["contract"])
            if a["id"] > b["id"] and independent:
                ordered[index : index + 2] = [b, a]
                changed = True
    return tuple(event["id"] for event in ordered)


def _valid_fixture(case, relations):
    request = {
        "action": "read",
        "context": {},
        **next((e for e in case["operations"] if e["kind"] == "check"), {}),
    }
    return all(
        policy.evaluate(expr, relations, request) for expr in case.get("invariants", [])
    ) and all(
        (
            (tuple(fixed["atom"][1:]) in relations.get(fixed["atom"][0], set()))
            == fixed["value"]
        )
        for fixed in case.get("fixed", [])
    )


def _construct(expr, desired, state, case, request, rng):
    """Construct a typed policy-property witness without using fault outcomes."""
    fixed = {tuple(row["atom"]): row["value"] for row in case.get("fixed", [])}
    if isinstance(expr, bool):
        return expr == desired
    if "not" in expr:
        return _construct(expr["not"], not desired, state, case, request, rng)
    if "and" in expr or "or" in expr:
        conjunction = "and" in expr
        children = expr["and" if conjunction else "or"]
        if desired == conjunction:
            return all(
                _construct(child, desired, state, case, request, rng)
                for child in children
            )
        return bool(children) and _construct(
            rng.choice(children), desired, state, case, request, rng
        )
    if "request" in expr:
        return policy.evaluate(expr, state, request) == desired
    if "attribute" in expr:
        entity, name, operation, value = expr["attribute"]
        entity = policy.term(entity, request)
        options = [
            item
            for item in case["universe"]["__attributes__"][entity][name]
            if policy.compare(item, operation, policy.term(value, request)) == desired
        ]
        if not options:
            return False
        state["attributes"].setdefault(entity, {})[name] = rng.choice(options)
        return True
    if "atom" in expr:
        relation, *values = expr["atom"]
        values = tuple(policy.term(value, request) for value in values)
        if (relation, *values) in fixed and fixed[relation, *values] != desired:
            return False
        (state[relation].add if desired else state[relation].discard)(values)
        return True
    if "reach" in expr:
        relation, left, right = expr["reach"]
        left, right = policy.term(left, request), policy.term(right, request)
        if not desired:
            state[relation] = {
                pair for pair in state[relation] if fixed.get((relation, *pair)) is True
            }
            return not policy.evaluate(expr, state, request)
        if policy.evaluate(expr, state, request):
            return True
        frontier = [(left, [])]
        seen = {left}
        while frontier:
            node, path = frontier.pop(0)
            targets = list(case["universe"][relation])
            rng.shuffle(targets)
            for target in targets:
                if fixed.get((relation, node, target)) is False:
                    continue
                following = path + [(node, target)]
                if target == right:
                    state[relation].update(following)
                    return True
                if target not in seen:
                    seen.add(target)
                    frontier.append((target, following))
        return False
    raise ValueError("Unsupported property-generation AST")


def verification_guided(case, rng):
    """Generate permit/nonpermit properties and cross-check a separate interpreter."""
    from .core import initial_state
    from .oracle import check

    request = {
        "action": "read",
        "context": {},
        **next(
            (e for e in case["operations"] if e["kind"] in ("check", "execute")), {}
        ),
    }
    positive, negative = policy.cones(
        case.get("policy", policy.DEFAULT), case["universe"], request
    )
    fixed = {tuple(row["atom"]): row["value"] for row in case.get("fixed", [])}
    for index in range(case.get("fixture_budget", 32)):
        desired = index % 2 == 0
        state = {name: set() for name in case["universe"] if name != "__attributes__"}
        state["attributes"] = {
            entity: {name: rng.choice(values) for name, values in fields.items()}
            for entity, fields in case["universe"].get("__attributes__", {}).items()
        }
        for (name, left, right), value in fixed.items():
            if value:
                state[name].add((left, right))
        for atom in policy.keys(case["universe"]):
            if (
                atom[0] != "__attr__"
                and atom not in fixed
                and atom not in positive | negative
                and rng.random() < 0.25
            ):
                state[atom[0]].add(atom[1:])
        if not _construct(
            case.get("policy", policy.DEFAULT), desired, state, case, request, rng
        ):
            continue
        if (
            not _valid_fixture(case, state)
            or policy.evaluate(case.get("policy", policy.DEFAULT), state, request)
            != desired
        ):
            continue
        fixture = {
            **case,
            "relations": {
                name: sorted(values)
                for name, values in state.items()
                if name != "attributes"
            },
            "attributes": state["attributes"],
            "property_expected": desired,
        }
        event = {
            **request,
            "id": "property",
            "kind": "check",
            "client": 0,
            "sequence": 0,
            "requires": [],
            "enabled": True,
            "start": 0,
            "end": 1,
            "result": desired,
            "revision": 0,
        }
        if check(initial_state(fixture), [event], "LIN") != "CONFORMING":
            raise RuntimeError(
                "Property generator disagrees with independent policy interpretation"
            )
        yield fixture


def reference_coverage(fixture, order):
    """Cover actions, obligations, transitions, enabledness and reference outcomes."""
    from .core import simulate

    _, history = simulate({**fixture, "mutant": "correct"}, order)
    result = {
        (
            "call",
            event["kind"],
            event.get("relation", event.get("attribute")),
            event.get("action", "read"),
            event.get("gate"),
            event["principal"],
            event["resource"],
        )
        for event in order
    }
    result |= {
        (
            "transition",
            a["kind"],
            a.get("relation", a.get("attribute")),
            b["kind"],
            b.get("relation", b.get("attribute")),
        )
        for a, b in zip(order, order[1:])
    }
    result |= {
        (
            "outcome",
            event["kind"],
            event["principal"],
            event["resource"],
            event.get("result"),
            event.get("error"),
        )
        for event in history
        if event["kind"] in ("check", "execute") or event.get("error")
    }
    result |= {
        ("obligation", tag) for event in order for tag in event.get("coverage_tags", [])
    }
    return result


def _ngac_order(case, rng):
    nodes = case["universe"]["assignment"]
    parents = {node: set() for node in nodes}
    for fixed in case.get("fixed", []):
        relation, left, right = fixed["atom"]
        if relation == "assignment" and fixed["value"]:
            parents[right].add(left)
    ranks = {}
    while len(ranks) < len(nodes):
        ready = [
            node
            for node in nodes
            if node not in ranks and parents[node] <= ranks.keys()
        ]
        if not ready:
            raise ValueError("Cyclic fixed NGAC assignment constraints")
        ranks[rng.choice(ready)] = len(ranks)
    return ranks


def fixtures(case, method, timings=None, diagnostics=None):
    from .core import initial_state

    if not _valid_fixture(case, initial_state(case)):
        raise ValueError("Initial fixture violates its fixed facts or state invariants")
    for entity, attributes in (
        case.get("universe", {}).get("__attributes__", {}).items()
    ):
        for name, domain in attributes.items():
            if not any(
                policy.compare(case["attributes"][entity][name], "eq", value)
                for value in domain
            ):
                raise ValueError(
                    "Initial attribute lies outside its declared finite domain"
                )
    yield case
    if "universe" not in case or method in ("no_semantic_independence",):
        return
    if method == "bounded":
        request = {
            "action": "read",
            "context": {},
            **next(
                (e for e in case["operations"] if e["kind"] in ("check", "execute")), {}
            ),
        }
        original = json.dumps(
            dict(
                relations={
                    name: sorted(
                        case.get("relations", {}).get(name, case.get(name, []))
                    )
                    for name in case["universe"]
                    if name != "__attributes__"
                },
                attributes=case.get("attributes", {}),
            ),
            sort_keys=True,
        )
        for state in policy.models(case, request):
            if state["status"] == "UNKNOWN":
                if diagnostics is not None:
                    diagnostics["state_enumeration_unknown"] = True
                return
            if (
                json.dumps(
                    dict(
                        relations={
                            name: sorted(values)
                            for name, values in state["relations"].items()
                        },
                        attributes=state["attributes"],
                    ),
                    sort_keys=True,
                )
                == original
            ):
                continue
            yield {
                **case,
                "relations": state["relations"],
                "attributes": state["attributes"],
            }
        return
    rng = random.Random(
        str(case.get("scheduler_seed", case.get("generation_seed", 17)))
        + str(case["id"])
    )
    if method == "vgd_plus":
        yield from verification_guided(case, rng)
        return
    if method in (
        "traceweaver",
        "no_por",
        "no_shrink",
        "forced_lin",
        "no_negative_cone",
    ):
        for write in case["operations"]:
            if write["kind"] in ("check", "execute"):
                continue
            for original in (e for e in case["operations"] if e["kind"] == "check"):
                request = {"action": "read", "context": {}, **original}
                stamp = time.perf_counter()
                positive, negative = policy.cones(
                    case.get("policy", policy.DEFAULT), case["universe"], request
                )
                if timings is not None:
                    timings["dependency_analysis"] += time.perf_counter() - stamp
                atom = (
                    (
                        "__attr__",
                        write.get("entity", write["principal"]),
                        write["attribute"],
                    )
                    if write["kind"] == "attribute"
                    else (write["relation"], write["principal"], write["resource"])
                )
                if atom not in positive | (
                    set() if method == "no_negative_cone" else negative
                ):
                    continue
                stamp = time.perf_counter()
                seed = policy.separating(
                    case, write, request, case.get("solver_timeout_ms", 1000)
                )
                if timings is not None:
                    timings["seed_solving"] += time.perf_counter() - stamp
                if seed["status"] == "SAT":
                    yield {
                        **case,
                        "relations": seed["relations"],
                        "attributes": seed["attributes"],
                        "separating_seed": seed,
                    }
        return
    fixed = {tuple(row["atom"]) for row in case.get("fixed", [])}
    keys = [key for key in policy.keys(case["universe"]) if key not in fixed]
    if not keys:
        return
    state = {
        name: {tuple(x) for x in values}
        for name, values in case.get("relations", {}).items()
    }
    for name in case["universe"]:
        if name == "__attributes__":
            continue
        state.setdefault(name, {tuple(x) for x in case.get(name, [])})
    state["attributes"] = copy.deepcopy(case.get("attributes", {}))
    for entity, attributes in case["universe"].get("__attributes__", {}).items():
        for name, values in attributes.items():
            state["attributes"].setdefault(entity, {}).setdefault(name, values[0])
    for _ in range(case.get("fixture_budget", 32)):
        candidate = copy.deepcopy(state)
        changed = False
        ranks = (
            _ngac_order(case, rng) if "ngac" in case and method != "px_plus" else None
        )
        # Differential mutation changes one policy-state atom per step. VGD+
        # samples valid complete environments and checks concrete AST properties.
        chosen = [rng.choice(keys)] if method == "px_plus" and keys else keys
        for name, a, b in chosen:
            if ranks is not None and name == "assignment":
                (
                    candidate[name].add
                    if ranks[a] < ranks[b] and rng.getrandbits(1)
                    else candidate[name].discard
                )((a, b))
                continue
            if name == "__attr__":
                options = case["universe"]["__attributes__"][a][b]
                if method == "px_plus":
                    options = [
                        value
                        for value in options
                        if not policy.compare(
                            value, "eq", candidate["attributes"][a][b]
                        )
                    ]
                if options:
                    candidate["attributes"][a][b] = rng.choice(options)
                    changed = True
                continue
            if method == "px_plus" or rng.getrandbits(1):
                (
                    candidate[name].discard
                    if (a, b) in candidate[name]
                    else candidate[name].add
                )((a, b))
                changed = True
        if method == "px_plus" and not changed:
            continue
        if not _valid_fixture(case, candidate):
            continue
        if method == "px_plus":
            state = candidate
        yield {
            **case,
            "relations": {
                k: sorted(v) for k, v in candidate.items() if k != "attributes"
            },
            "attributes": candidate["attributes"],
        }


def schedules(case, method, timings=None, diagnostics=None):
    """Interleave fixture exploration under one total schedule budget."""
    rng = random.Random(str(case["id"]))
    if "universe" not in case:
        nodes = sorted(
            {
                event[k]
                for event in case["operations"]
                for k in ("principal", "resource")
            }
        )
        case = {
            **case,
            "universe": {
                name: nodes
                for name in sorted(
                    {"allow", "deny"}
                    | {e["relation"] for e in case["operations"] if "relation" in e}
                )
            },
        }
    visibility = case.get("generator_visibility", "white")
    source = iter(
        [case]
        if visibility in ("black", "gray")
        else fixtures(case, method, timings, diagnostics)
    )

    def candidate_orders(fixture):
        events = fixture["operations"]
        if method in ("random", "vgd_plus") or visibility in ("black", "gray"):
            candidates = (
                order
                for _ in range(case["budget"])
                for order in linearizations(events, rng)
            )
        else:
            ordered = (
                sorted(events, key=lambda e: e["kind"] == "check")
                if method
                in (
                    "traceweaver",
                    "px_plus",
                    "no_por",
                    "no_shrink",
                    "random_seed",
                )
                else events
            )
            candidates = linearizations(ordered)
        if method == "cover_plus":
            candidates = list(
                itertools.islice(candidates, fixture.get("coverage_pool", 10000))
            )
            covered = set()
            ranked = []
            coverage_cache = {}
            while candidates and len(ranked) < case["budget"]:

                def coverage(order):
                    key = tuple(event["id"] for event in order)
                    if key not in coverage_cache:
                        coverage_cache[key] = reference_coverage(fixture, order)
                    return coverage_cache[key]

                chosen = max(
                    candidates, key=lambda order: len(coverage(order) - covered)
                )
                covered |= coverage(chosen)
                candidates.remove(chosen)
                ranked.append(chosen)
            candidates = iter(ranked)
        return iter(candidates)

    iterators = []
    exhausted = False
    while iterators or not exhausted:
        if not exhausted:
            fixture = next(source, None)
            if fixture is None:
                exhausted = True
            else:
                iterators.append((fixture, candidate_orders(fixture)))
        following = []
        for fixture, iterator in iterators:
            candidate = next(iterator, None)
            if candidate is not None:
                yield fixture, candidate
                following.append((fixture, iterator))
        iterators = following
    if diagnostics is not None:
        diagnostics["orders_complete"] = not diagnostics.get(
            "state_enumeration_unknown", False
        )
