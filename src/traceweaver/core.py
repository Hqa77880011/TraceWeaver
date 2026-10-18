import copy
import itertools
import random
import time


METHODS = ["traceweaver", "bounded", "random", "no_negative_cone", "no_por", "forced_lin"]


def decision(state, principal, resource):
    return (principal, resource) in state["allow"] and (principal, resource) not in state["deny"]


def update(state, event):
    after = copy.deepcopy(state)
    relation = event["relation"]
    atom = (event["principal"], event["resource"])
    if event["kind"] == "insert":
        after[relation].add(atom)
    else:
        after[relation].discard(atom)
    return after


def check_history(initial, events, contract):
    operations = events[:]
    if contract == "AT_LEAST" and any(
        isinstance(e.get("min_revision", 0), bool)
        or not isinstance(e.get("min_revision", 0), int)
        or e.get("min_revision", 0) < 0
        for e in operations if e["kind"] == "check"
    ):
        raise ValueError("Minimum revision must be a nonnegative integer")
    if len(operations) > 12:
        return "INCONCLUSIVE"
    real_edges = {
        (a["id"], b["id"])
        for a in operations
        for b in operations
        if a["end"] < b["start"] or (a["client"] == b["client"] and a["sequence"] < b["sequence"])
    }
    predecessors = {e["id"]: {a for a, b in real_edges if b == e["id"]} for e in operations}

    def search(done, state, revisions):
        if len(done) == len(operations):
            return True
        for event in operations:
            key = event["id"]
            if key in done or not predecessors[key] <= done:
                continue
            if event["kind"] == "check":
                if contract == "LIN":
                    valid = (
                        decision(state, event["principal"], event["resource"]) == event["result"]
                    )
                elif contract == "SNAP":
                    revision = event["revision"]
                    valid = (
                        0 <= revision < len(revisions)
                        and decision(revisions[revision], event["principal"], event["resource"])
                        == event["result"]
                    )
                elif contract == "AT_LEAST":
                    minimum = event.get("min_revision", 0)
                    revision = event.get("revision")
                    valid = (
                        (
                            revision is not None
                            and minimum <= revision < len(revisions)
                            and decision(revisions[revision], event["principal"], event["resource"])
                            == event["result"]
                        )
                        if revision is not None
                        else any(
                            decision(snapshot, event["principal"], event["resource"])
                            == event["result"]
                            for snapshot in revisions[minimum:]
                        )
                    )
                else:
                    raise ValueError("Unknown consistency contract")
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
            candidate = current[:i] + current[i + 1 :]
            identifiers = {event["id"] for event in candidate}
            if any(not set(event.get("requires", [])) <= identifiers for event in candidate):
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


def simulate(case, schedule):
    initial = {"allow": {tuple(x) for x in case["allow"]}, "deny": {tuple(x) for x in case["deny"]}}
    state = copy.deepcopy(initial)
    revisions = [copy.deepcopy(initial)]
    history = []
    stale = case["mutant"] == "stale"
    for tick, spec in enumerate(schedule):
        event = copy.deepcopy(spec)
        event.update(start=tick * 2, end=tick * 2 + 1)
        if event["kind"] == "check":
            observed = initial if stale else state
            event["result"] = decision(observed, event["principal"], event["resource"])
            event["revision"] = 0 if stale else len(revisions) - 1
            event["min_revision"] = case.get("minimum_revision", 0)
            event["requires"] = (
                [] if event["revision"] == 0 else [e["id"] for e in history if e["kind"] != "check"]
            )
        else:
            state = update(state, event)
            revisions.append(copy.deepcopy(state))
        history.append(event)
    return initial, history


def independent(a, b, contract):
    if a["client"] == b["client"]:
        return False
    if contract != "LIN" and (a["kind"] != "check" or b["kind"] != "check"):
        return False
    return (a["principal"], a["resource"]) != (b["principal"], b["resource"]) or a["kind"] == b[
        "kind"
    ] == "check"


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


def run_case(case, method, target=None):
    start = time.perf_counter()
    operations = case["operations"]
    if method == "random":
        rng = random.Random(case["id"])
        schedules = (
            tuple(rng.sample(operations, len(operations))) for _ in range(case["budget"])
        )
    elif method == "no_negative_cone" and any(e.get("relation") == "deny" for e in operations):
        schedules = iter([tuple(operations[::-1])])
    else:
        ordered = (
            sorted(operations, key=lambda event: event["kind"] == "check")
            if method == "traceweaver" else operations
        )
        schedules = itertools.permutations(ordered)
    checked = 0
    inconclusive = 0
    visited = set()
    for schedule in itertools.islice(schedules, case["budget"]):
        if any(
            a["client"] == b["client"] and a["sequence"] > b["sequence"]
            for i, a in enumerate(schedule)
            for b in schedule[i + 1 :]
        ):
            continue
        if method == "traceweaver":
            key = representative(schedule, case["contract"])
            if key in visited:
                continue
            visited.add(key)
        initial, history = (simulate if target is None else target)(case, schedule)
        verdict = check_history(
            initial, history, "LIN" if method == "forced_lin" else case["contract"]
        )
        checked += 1
        inconclusive += verdict == "INCONCLUSIVE"
        if verdict == "VIOLATION":
            reduced = shrink(
                initial, history, "LIN" if method == "forced_lin" else case["contract"]
            )
            verified = check_history(initial, reduced, case["contract"]) == "VIOLATION"
            return {
                "found": True,
                "confirmed": verified,
                "history": reduced,
                "first_witness_seconds": time.perf_counter() - start,
                "checked": checked,
                "inconclusive": inconclusive,
            }
    return {
        "found": False,
        "confirmed": False,
        "history": [],
        "first_witness_seconds": None,
        "checked": checked,
        "inconclusive": inconclusive,
    }


def score(case, result):
    discoverable = case["mutant"] == "stale" and case["contract"] == "LIN"
    return {
        "confirmed_mutation": int(result["confirmed"]) if discoverable else None,
        "false_report": int(result["found"] and not result["confirmed"]),
        "first_witness_seconds": result["first_witness_seconds"],
        "right_censored": int(not result["found"]),
        "histories_checked": result["checked"],
        "inconclusive_rate": result["inconclusive"] / result["checked"]
        if result["checked"]
        else None,
        "minimized_length": len(result["history"]) if result["found"] else None,
        "legal_effects": int(result["confirmed"]),
    }
