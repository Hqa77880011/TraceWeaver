"""Small-history permutation oracle, independent of the prefix-search checker."""

import itertools
import copy


def check(initial, history, contract):
    """Return a contract verdict by complete admissible-order replay (at most 8 calls)."""
    if contract == "UNKNOWN":
        return "INCONCLUSIVE"
    from . import pending

    if pending.present(history):
        return pending.check(initial, history, contract, check)
    if any(event.get("error") not in (None, "disabled") for event in history):
        return "INCONCLUSIVE"
    if contract not in ("LIN", "SNAP", "AT_LEAST"):
        raise ValueError("Unknown consistency contract")
    if len(history) > 8:
        from .smt import check as smt_check

        return smt_check(initial, history, contract)
    if any(
        event["kind"] == "check"
        and not event.get("error")
        and ("result" not in event or contract == "SNAP" and "revision" not in event)
        for event in history
    ):
        return "INCONCLUSIVE"
    ids = {event["id"] for event in history}
    if len(ids) != len(history) or any(
        not set(e.get("requires", [])) <= ids for e in history
    ):
        return "INCONCLUSIVE"
    edges = {
        (a["id"], b["id"])
        for a in history
        for b in history
        if a["end"] < b["start"]
        or a["client"] == b["client"]
        and a["sequence"] < b["sequence"]
    }
    edges.update(
        (parent, event["id"])
        for event in history
        for parent in event.get("requires", [])
    )

    def interpret(expr, state, event):
        if isinstance(expr, bool):
            return expr
        if "and" in expr:
            return all(interpret(x, state, event) for x in expr["and"])
        if "or" in expr:
            return any(interpret(x, state, event) for x in expr["or"])
        if "not" in expr:
            return not interpret(expr["not"], state, event)
        if "request" in expr:
            name, op, value = expr["request"]
            actual = event
            for component in name.split("."):
                actual = (
                    actual[component]
                    if component in actual
                    else "read"
                    if component == "action"
                    else {}
                )
            return (
                type(actual) is type(value) and actual == value
                if op == "eq"
                else {
                    "ge": actual >= value,
                    "gt": actual > value,
                    "le": actual <= value,
                    "lt": actual < value,
                }[op]
            )
        if "attribute" in expr:
            entity, name, operation, value = expr["attribute"]
            entity = (
                event[entity[1:]]
                if isinstance(entity, str) and entity.startswith("$")
                else entity
            )
            actual = state["attributes"][entity][name]
            if operation == "eq":
                return type(actual) is type(value) and actual == value
            if type(actual) not in (int, float) or type(value) not in (int, float):
                return False
            return {
                "ge": actual >= value,
                "gt": actual > value,
                "le": actual <= value,
                "lt": actual < value,
            }[operation]
        name, *values = expr.get("atom", expr.get("reach"))
        values = [
            event[x[1:]] if isinstance(x, str) and x.startswith("$") else x
            for x in values
        ]
        if "atom" in expr:
            return tuple(values) in state.get(name, set())
        edges = set(state.get(name, set()))
        while True:
            expanded = edges | {(a, d) for a, b in edges for c, d in edges if b == c}
            if expanded == edges:
                return tuple(values) in edges
            edges = expanded

    def allowed(state, event):
        if "policy" in state:
            return interpret(state["policy"], state, event)
        pair = (event["principal"], event["resource"])
        return pair in state["allow"] and pair not in state["deny"]

    for order in itertools.permutations(history):
        position = {e["id"]: i for i, e in enumerate(order)}
        if any(position[a] >= position[b] for a, b in edges):
            continue
        versions = [copy.deepcopy(initial)]
        current = copy.deepcopy(initial)
        valid = True
        for event in order:
            enabled = interpret(event.get("enabled", True), current, event)
            if event.get("error") == "disabled":
                if enabled:
                    valid = False
                    break
                continue
            if not enabled:
                valid = False
                break
            if event["kind"] == "execute":
                if (
                    event.get("gate") not in ("snapshot", "revalidate")
                    or "result" not in event
                ):
                    return "INCONCLUSIVE"
                revision = event.get("revision")
                snapshot = (
                    current
                    if event["gate"] == "revalidate"
                    else versions[revision]
                    if type(revision) is int and 0 <= revision < len(versions)
                    else None
                )
                if event["result"]:
                    if (
                        snapshot is None
                        or not allowed(snapshot, event)
                        or event["nonce"] in current.get("consumed", set())
                    ):
                        valid = False
                        break
                    current.setdefault("consumed", set()).add(event["nonce"])
                continue
            if event["kind"] != "check":
                following = copy.deepcopy(current)
                if event["kind"] == "attribute":
                    following["attributes"][event.get("entity", event["principal"])][
                        event["attribute"]
                    ] = event["value"]
                    current = following
                    versions.append(copy.deepcopy(following))
                    continue
                pair = (event["principal"], event["resource"])
                if event["kind"] == "insert":
                    following[event["relation"]].add(pair)
                else:
                    following[event["relation"]].discard(pair)
                current = following
                versions.append(copy.deepcopy(following))
                continue
            if contract == "LIN":
                candidates = [current]
            elif "revision" in event:
                revision = event["revision"]
                minimum = event.get("min_revision", 0) if contract == "AT_LEAST" else 0
                candidates = (
                    [versions[revision]]
                    if type(revision) is int and minimum <= revision < len(versions)
                    else []
                )
            else:
                candidates = versions[event.get("min_revision", 0) :]
            if (
                (
                    initial.get("_revision_observable")
                    and contract == "LIN"
                    and event.get("revision") != len(versions) - 1
                )
                or (
                    "policy_revision" in event
                    and event["policy_revision"] != initial.get("_policy_revision", 1)
                )
                or not any(
                    allowed(version, event) == event["result"] for version in candidates
                )
            ):
                valid = False
                break
        if valid:
            return "CONFORMING"
    return "VIOLATION"
