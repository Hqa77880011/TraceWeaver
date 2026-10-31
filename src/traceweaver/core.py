import copy
import itertools
import json
import random
import time

from .oracle import check as independent_check
from . import policy as relational


METHODS = [
    "traceweaver",
    "bounded",
    "random",
    "no_negative_cone",
    "no_por",
    "forced_lin",
    "keypor",
    "px_plus",
    "vgd_plus",
    "cover_plus",
    "no_semantic_independence",
    "no_shrink",
    "random_seed",
]


def decision(state, principal, resource, action="read", context=None):
    if "policy" in state:
        return relational.evaluate(
            state["policy"],
            state,
            dict(
                principal=principal,
                resource=resource,
                action=action,
                context=context or {},
            ),
        )
    return (principal, resource) in state["allow"] and (
        principal,
        resource,
    ) not in state["deny"]


def update(state, event):
    after = copy.deepcopy(state)
    if event["kind"] == "attribute":
        after["attributes"][event.get("entity", event["principal"])][
            event["attribute"]
        ] = event["value"]
        return after
    if event["kind"] == "execute":
        after.setdefault("consumed", set()).add(event["nonce"])
        return after
    relation = event["relation"]
    atom = (event["principal"], event["resource"])
    if event["kind"] == "insert":
        after[relation].add(atom)
    else:
        after[relation].discard(atom)
    return after


def check_history(initial, events, contract):
    """Search only explanations consistent with real-time, clients and causal edges."""
    if contract == "UNKNOWN":
        return "INCONCLUSIVE"
    from . import pending

    if pending.present(events):
        return pending.check(initial, events, contract, check_history)
    if any(event.get("error") not in (None, "disabled") for event in events):
        return "INCONCLUSIVE"
    if contract not in ("LIN", "SNAP", "AT_LEAST"):
        raise ValueError("Unknown consistency contract")
    operations = events[:]
    identifiers = {event["id"] for event in operations}
    if len(identifiers) != len(operations) or any(
        not set(event.get("requires", [])) <= identifiers
        or event["kind"] in ("check", "execute")
        and not event.get("error")
        and ("result" not in event or contract == "SNAP" and "revision" not in event)
        for event in operations
    ):
        return "INCONCLUSIVE"
    if any(
        e["kind"] == "execute" and e.get("gate") not in ("revalidate", "snapshot")
        for e in operations
    ):
        return "INCONCLUSIVE"
    if contract == "AT_LEAST" and any(
        isinstance(e.get("min_revision", 0), bool)
        or not isinstance(e.get("min_revision", 0), int)
        or e.get("min_revision", 0) < 0
        for e in operations
        if e["kind"] == "check"
    ):
        raise ValueError("Minimum revision must be a nonnegative integer")
    if len(operations) > 12:
        from .smt import check

        return check(initial, events, contract)
    real_edges = {
        (a["id"], b["id"])
        for a in operations
        for b in operations
        if a["end"] < b["start"]
        or (a["client"] == b["client"] and a["sequence"] < b["sequence"])
    }
    real_edges.update(
        (parent, event["id"])
        for event in operations
        for parent in event.get("requires", [])
    )
    predecessors = {
        e["id"]: {a for a, b in real_edges if b == e["id"]} for e in operations
    }

    def search(done, state, revisions):
        if len(done) == len(operations):
            return True
        for event in operations:
            key = event["id"]
            if key in done or not predecessors[key] <= done:
                continue
            enabled = relational.evaluate(event.get("enabled", True), state, event)
            if event.get("error") == "disabled":
                if not enabled and search(done | {key}, state, revisions):
                    return True
                continue
            if not enabled:
                continue
            if event["kind"] == "execute":
                snapshot = (
                    state
                    if event["gate"] == "revalidate"
                    else revisions[event["revision"]]
                    if type(event.get("revision")) is int
                    and 0 <= event["revision"] < len(revisions)
                    else None
                )
                allowed = (
                    snapshot is not None
                    and decision(
                        snapshot,
                        event["principal"],
                        event["resource"],
                        event.get("action", "read"),
                        event.get("context", {}),
                    )
                    and event["nonce"] not in state.get("consumed", set())
                )
                if (not event["result"] or allowed) and search(
                    done | {key},
                    update(state, event) if event["result"] else state,
                    revisions,
                ):
                    return True
            elif event["kind"] == "check":
                if contract == "LIN":
                    valid = (
                        decision(
                            state,
                            event["principal"],
                            event["resource"],
                            event.get("action", "read"),
                            event.get("context", {}),
                        )
                        == event["result"]
                    )
                elif contract == "SNAP":
                    revision = event["revision"]
                    valid = (
                        0 <= revision < len(revisions)
                        and decision(
                            revisions[revision],
                            event["principal"],
                            event["resource"],
                            event.get("action", "read"),
                            event.get("context", {}),
                        )
                        == event["result"]
                    )
                elif contract == "AT_LEAST":
                    minimum = event.get("min_revision", 0)
                    revision = event.get("revision")
                    valid = (
                        (
                            revision is not None
                            and minimum <= revision < len(revisions)
                            and decision(
                                revisions[revision],
                                event["principal"],
                                event["resource"],
                                event.get("action", "read"),
                                event.get("context", {}),
                            )
                            == event["result"]
                        )
                        if revision is not None
                        else any(
                            decision(
                                snapshot,
                                event["principal"],
                                event["resource"],
                                event.get("action", "read"),
                                event.get("context", {}),
                            )
                            == event["result"]
                            for snapshot in revisions[minimum:]
                        )
                    )
                else:
                    raise ValueError("Unknown consistency contract")
                if initial.get("_revision_observable") and contract == "LIN":
                    valid = valid and event.get("revision") == len(revisions) - 1
                if "policy_revision" in event:
                    valid = valid and event["policy_revision"] == initial.get(
                        "_policy_revision", 1
                    )
                if valid and search(done | {key}, state, revisions):
                    return True
            else:
                after = update(state, event)
                if search(done | {key}, after, revisions + [after]):
                    return True
        return False

    return "CONFORMING" if search(set(), initial, [initial]) else "VIOLATION"


def shrink(initial, history, contract):
    current = history[:]
    changed = True
    while changed:
        changed = False
        for i in range(len(current)):
            if (
                current[i]["kind"] in ("insert", "delete", "attribute")
                and (
                    contract != "LIN"
                    or any(e.get("gate") == "snapshot" for e in current)
                )
                and any(
                    e.get("revision", 0) > 0 or e.get("min_revision", 0) > 0
                    for e in current
                )
            ):
                continue
            candidate = current[:i] + current[i + 1 :]
            identifiers = {event["id"] for event in candidate}
            if any(
                not set(event.get("requires", [])) <= identifiers for event in candidate
            ):
                continue
            if any(
                e["kind"] == "check"
                and e.get("revision", 0) > sum(x["kind"] != "check" for x in candidate)
                for e in candidate
            ):
                continue
            if check_history(initial, candidate, contract) == "VIOLATION":
                current = candidate
                changed = True
                break
    return current


def initial_state(case):
    if any(
        event.get("admin_allowed", True) is not True
        for event in case.get("operations", [])
        if event["kind"] not in ("check", "execute")
    ):
        raise ValueError("Campaign updates require fixture administrative permission")
    initial = {
        name: {tuple(x) for x in values}
        for name, values in case.get("relations", {}).items()
    }
    for name in ("allow", "deny"):
        initial.setdefault(name, {tuple(x) for x in case.get(name, [])})
    initial["_revision_observable"] = case.get("revision_observable", False)
    initial["_policy_revision"] = case.get("policy_revision", 1)
    initial["_pending_rule"] = case.get("pending_rule", "unknown")
    initial["attributes"] = copy.deepcopy(case.get("attributes", {}))
    initial["consumed"] = set(case.get("consumed", []))
    if "policy" in case:
        initial["policy"] = case["policy"]
    if "universe" in case:
        initial["_universe"] = case["universe"]
        for name in case["universe"]:
            if name != "__attributes__":
                initial.setdefault(name, set())
    return initial


def simulate(case, schedule):
    initial = initial_state(case)
    state = copy.deepcopy(initial)
    revisions = [copy.deepcopy(initial)]
    history = []
    stale = case.get("mutant") == "stale"
    for tick, spec in enumerate(schedule):
        event = copy.deepcopy(spec)
        event.update(start=tick * 2, end=tick * 2 + 1)
        if not relational.evaluate(event.get("enabled", True), state, event):
            event["error"] = "disabled"
            history.append(event)
            continue
        if event["kind"] == "execute":
            observed = initial if stale or event.get("gate") == "snapshot" else state
            event["revision"] = 0 if observed is initial else len(revisions) - 1
            event["result"] = decision(
                observed,
                event["principal"],
                event["resource"],
                event.get("action", "read"),
                event.get("context", {}),
            ) and (
                case.get("mutant") == "duplicate_nonce"
                or event["nonce"] not in state["consumed"]
            )
            if event["result"]:
                state = update(state, event)
        elif event["kind"] == "check":
            observed = initial if stale else state
            event["result"] = decision(
                observed,
                event["principal"],
                event["resource"],
                event.get("action", "read"),
                event.get("context", {}),
            )
            event["revision"] = 0 if stale else len(revisions) - 1
            event["min_revision"] = event.get(
                "min_revision", case.get("minimum_revision", 0)
            )
            visibility_parents = (
                []
                if event["revision"] == 0
                else [e["id"] for e in history if e["kind"] != "check"]
            )
            event["requires"] = list(
                dict.fromkeys(event.get("requires", []) + visibility_parents)
            )
        else:
            state = update(state, event)
            revisions.append(copy.deepcopy(state))
        history.append(event)
    return initial, history


def independent(a, b, contract):
    if a["client"] == b["client"]:
        return False
    if a["id"] in b.get("requires", []) or b["id"] in a.get("requires", []):
        return False
    if contract != "LIN" and (a["kind"] != "check" or b["kind"] != "check"):
        return False
    return (a["principal"], a["resource"]) != (b["principal"], b["resource"]) or a[
        "kind"
    ] == b["kind"] == "check"


def representative(schedule, contract):
    ordered = list(schedule)
    changed = True
    while changed:
        changed = False
        for i in range(len(ordered) - 1):
            if ordered[i]["id"] > ordered[i + 1]["id"] and independent(
                ordered[i], ordered[i + 1], contract
            ):
                ordered[i], ordered[i + 1] = ordered[i + 1], ordered[i]
                changed = True
    return tuple(e["id"] for e in ordered)


def generate(rng, count):
    for index in range(count):
        mutant = rng.choice(["correct", "stale"])
        relation = rng.choice(["allow", "deny"])
        yield {
            "id": str(index),
            "family": f"{relation}-{mutant}",
            "allow": [["u", "o"]],
            "deny": [],
            "mutant": mutant,
            "contract": rng.choice(["LIN", "SNAP", "AT_LEAST"]),
            "operations": [
                {
                    "id": "w",
                    "client": 0,
                    "sequence": 0,
                    "kind": "delete" if relation == "allow" else "insert",
                    "relation": relation,
                    "principal": "u",
                    "resource": "o",
                },
                {
                    "id": "r",
                    "client": 1,
                    "sequence": 0,
                    "kind": "check",
                    "principal": "u",
                    "resource": "o",
                },
            ],
            "budget": 20,
        }


def timed_proposals(iterator, timings):
    while True:
        stamp = time.perf_counter()
        try:
            proposal = next(iterator)
        except StopIteration:
            timings["generation"] += time.perf_counter() - stamp
            return
        timings["generation"] += time.perf_counter() - stamp
        yield proposal


def run_case(case, method, target=None):
    start = time.perf_counter()
    from .frontends import normalize

    case = copy.deepcopy(normalize(case))
    for operation in case["operations"]:
        operation.setdefault("action", "read")
        operation.setdefault("context", {})
    from .strategies import schedules as propose

    operations = case["operations"]
    timings = {
        name: 0.0
        for name in (
            "generation",
            "dependency_analysis",
            "seed_solving",
            "target",
            "checking",
            "shrinking",
            "independent",
            "replay",
        )
    }
    diagnostics = {"orders_complete": False, "state_enumeration_unknown": False}
    schedules = timed_proposals(
        iter(propose(case, method, timings, diagnostics)), timings
    )
    checked = 0
    inconclusive = 0
    visited = set()
    for fixture, schedule in schedules:
        if checked >= case["budget"] or time.perf_counter() - start >= case.get(
            "wall_budget_seconds", float("inf")
        ):
            break
        positions = {event["id"]: i for i, event in enumerate(schedule)}
        if any(
            parent not in positions or positions[parent] >= positions[event["id"]]
            for event in schedule
            for parent in event.get("requires", [])
        ):
            continue
        if any(
            a["client"] == b["client"] and a["sequence"] > b["sequence"]
            for i, a in enumerate(schedule)
            for b in schedule[i + 1 :]
        ):
            continue
        if method in ("traceweaver", "keypor", "no_semantic_independence"):
            from .strategies import representative as reduction_key

            key = (
                json.dumps(
                    {
                        "relations": fixture.get(
                            "relations",
                            {name: fixture.get(name, []) for name in ("allow", "deny")},
                        ),
                        "attributes": fixture.get("attributes", {}),
                        "policy": fixture.get("policy"),
                        "contract": fixture["contract"],
                    },
                    sort_keys=True,
                ),
                reduction_key(schedule, fixture, method),
            )
            if key in visited:
                continue
            visited.add(key)
        stamp = time.perf_counter()
        initial, history = (simulate if target is None else target)(fixture, schedule)
        timings["target"] += time.perf_counter() - stamp
        if fixture.get("generator_visibility") == "black":
            for observation in history:
                if observation["kind"] == "check":
                    observation.pop("revision", None)
                    observation.pop("policy_revision", None)
        stamp = time.perf_counter()
        verdict = check_history(
            initial, history, "LIN" if method == "forced_lin" else case["contract"]
        )
        timings["checking"] += time.perf_counter() - stamp
        checked += 1
        inconclusive += verdict == "INCONCLUSIVE"
        if verdict == "VIOLATION":
            stamp = time.perf_counter()
            reduced = (
                history
                if method == "no_shrink"
                else shrink(
                    initial,
                    history,
                    "LIN" if method == "forced_lin" else case["contract"],
                )
            )
            timings["shrinking"] += time.perf_counter() - stamp
            stamp = time.perf_counter()
            verified = (
                independent_check(initial, reduced, case["contract"]) == "VIOLATION"
            )
            method_verified = (
                verified
                if method != "forced_lin"
                else independent_check(initial, reduced, "LIN") == "VIOLATION"
            )
            timings["independent"] += time.perf_counter() - stamp
            stamp = time.perf_counter()
            replay_attempts = case.get("replay_attempts", 10)
            if type(replay_attempts) is not int or replay_attempts < 1:
                raise ValueError("replay_attempts must be a positive integer")
            successes = 0
            for _ in range(replay_attempts):
                replay_initial, replay_history = (
                    simulate if target is None else target
                )(fixture, schedule)
                successes += (
                    independent_check(replay_initial, replay_history, case["contract"])
                    == "VIOLATION"
                )
            timings["replay"] += time.perf_counter() - stamp
            reproduced = successes > 0
            return {
                "search_status": diagnostics,
                "stage_seconds": timings,
                "found": True,
                "confirmed": verified,
                "reported": method_verified,
                "confirmation_contract": "LIN"
                if method == "forced_lin"
                else case["contract"],
                "history": reduced,
                "first_witness_seconds": time.perf_counter() - start,
                "observed_seconds": time.perf_counter() - start,
                "checked": checked,
                "inconclusive": inconclusive,
                "reproduced": reproduced,
                "replay_successes": successes,
                "replay_attempts": replay_attempts,
                "fixture": fixture,
                "original_history": history,
            }
    return {
        "search_status": diagnostics,
        "stage_seconds": timings,
        "found": False,
        "confirmed": False,
        "history": [],
        "first_witness_seconds": None,
        "observed_seconds": time.perf_counter() - start,
        "checked": checked,
        "inconclusive": inconclusive,
        "reproduced": None,
    }


def correct_control(case):
    """Identify declared correct wrappers, including protocol-permitted staleness."""
    if "correct_control" in case:
        return case["correct_control"] is True
    if case.get("mutant") == "correct":
        return True
    if case.get("mutant") != "stale" or any(
        e["kind"] == "execute" for e in case.get("operations", [])
    ):
        return False
    return (
        case["contract"] == "SNAP"
        or case["contract"] == "AT_LEAST"
        and all(
            e.get("min_revision", case.get("minimum_revision", 0)) == 0
            for e in case.get("operations", [])
            if e["kind"] == "check"
        )
    )


def score(case, result):
    discoverable = case.get(
        "non_equivalent_mutant",
        case.get("mutant") == "stale" and case["contract"] == "LIN",
    )
    return {
        **{
            name + "_seconds": value
            for name, value in result.get("stage_seconds", {}).items()
        },
        "confirmed_mutation": int(result["confirmed"]) if discoverable else None,
        "false_report": int(result.get("reported", result["found"])) / result["checked"]
        if correct_control(case) and result["checked"]
        else None,
        "replay_success": result.get("replay_successes", int(result["reproduced"]))
        / result.get("replay_attempts", 1)
        if result["reproduced"] is not None
        else None,
        "first_witness_seconds": result["first_witness_seconds"]
        if result["confirmed"]
        else None,
        "discovery_observed_seconds": result["observed_seconds"],
        "right_censored": int(not result["confirmed"]),
        "histories_checked": result["checked"],
        "inconclusive_rate": result["inconclusive"] / result["checked"]
        if result["checked"]
        else None,
        "minimized_length": len(result["history"]) if result["found"] else None,
    }


def metric_counts(case, result):
    return {
        "replay_success": [
            result.get("replay_successes", 0),
            result.get("replay_attempts", 0),
        ],
        "false_report": [
            int(correct_control(case) and result.get("reported", result["found"])),
            result["checked"] if correct_control(case) else 0,
        ],
        "inconclusive_rate": [result["inconclusive"], result["checked"]],
    }
