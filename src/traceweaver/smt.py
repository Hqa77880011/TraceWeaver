"""Rank-and-state SMT history checking, separate from prefix-order DFS."""

from . import policy


def check(initial, history, contract, timeout_ms=1000):
    """Search all admissible linearizations and read revisions within a timeout."""
    import z3
    from . import pending

    if pending.present(history):
        return pending.check(
            initial,
            history,
            contract,
            lambda state, events, mode: check(state, events, mode, timeout_ms),
        )

    if contract not in ("LIN", "SNAP", "AT_LEAST"):
        return "INCONCLUSIVE"
    identifiers = [e["id"] for e in history]
    if len(identifiers) != len(set(identifiers)) or any(
        not set(e.get("requires", [])) <= set(identifiers) for e in history
    ):
        return "INCONCLUSIVE"
    for e in history:
        if e["kind"] == "check" and not e.get("error"):
            if (
                type(e.get("result")) is not bool
                or contract == "SNAP"
                and type(e.get("revision")) is not int
            ):
                return "INCONCLUSIVE"
    relations = {
        k: v for k, v in initial.items() if isinstance(v, set) and k != "consumed"
    }
    relations["__nonce__"] = {(n, n) for n in initial.get("consumed", set())}
    universe = dict(initial["_universe"]) if "_universe" in initial else None
    if universe is None:
        nodes = {v for values in relations.values() for atom in values for v in atom}
        nodes |= {e[k] for e in history for k in ("principal", "resource")}
        universe = {name: sorted(nodes) for name in relations}
    universe["__nonce__"] = sorted(
        {e["nonce"] for e in history if e["kind"] == "execute"}
        | set(initial.get("consumed", set()))
    )
    keys = policy.keys(universe)
    count = len(history)
    if not count:
        return "CONFORMING"
    ranks = [z3.Int("rank_" + str(i)) for i in range(count)]
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    solver.add(z3.Distinct(ranks), *(z3.And(0 <= rank, rank < count) for rank in ranks))
    for i, a in enumerate(history):
        for j, b in enumerate(history):
            if (
                a["end"] < b["start"]
                or a["client"] == b["client"]
                and a["sequence"] < b["sequence"]
                or a["id"] in b.get("requires", [])
            ):
                solver.add(ranks[i] < ranks[j])

    def initial_value(key):
        if key[0] == "__attr__":
            values = universe["__attributes__"][key[1]][key[2]]
            return z3.IntVal(
                next(
                    i
                    for i, v in enumerate(values)
                    if policy.compare(v, "eq", initial["attributes"][key[1]][key[2]])
                )
            )
        return z3.BoolVal(key[1:] in relations.get(key[0], set()))

    states = [{key: initial_value(key) for key in keys}]
    versions = [z3.IntVal(0)]
    writes = [
        i
        for i, e in enumerate(history)
        if e["kind"] not in ("check", "execute") and not e.get("error")
    ]
    commits = [
        i
        for i, e in enumerate(history)
        if e["kind"] == "execute" and e.get("result") is True
    ]
    expression = initial.get("policy", policy.DEFAULT)
    for position in range(count):
        previous = states[-1]
        following = dict(previous)
        is_write = z3.Or(*(ranks[i] == position for i in writes))
        versions.append(versions[-1] + z3.If(is_write, 1, 0))
        for i in writes:
            event = history[i]
            if event["kind"] == "attribute":
                key = (
                    "__attr__",
                    event.get("entity", event["principal"]),
                    event["attribute"],
                )
                domain = universe["__attributes__"][key[1]][key[2]]
                value = next(
                    j
                    for j, v in enumerate(domain)
                    if policy.compare(v, "eq", event["value"])
                )
            else:
                key = (event["relation"], event["principal"], event["resource"])
                value = event["kind"] == "insert"
            following[key] = z3.If(ranks[i] == position, value, following[key])
        for i in commits:
            key = ("__nonce__", history[i]["nonce"], history[i]["nonce"])
            following[key] = z3.If(ranks[i] == position, True, following[key])
        states.append(following)
    snapshots = [states[0]]
    for revision in range(1, len(writes) + 1):
        snapshot = dict(states[0])
        for position in range(count):
            condition = z3.And(
                versions[position + 1] == revision, versions[position] == revision - 1
            )
            snapshot = {
                key: z3.If(condition, states[position + 1][key], snapshot[key])
                for key in keys
            }
        snapshots.append(snapshot)
    for i, event in enumerate(history):
        request = dict(
            principal=event["principal"],
            resource=event["resource"],
            action=event.get("action", "read"),
            context=event.get("context", {}),
        )
        for position in range(count):
            enabled = policy.symbolic(
                event.get("enabled", True), states[position], universe, request
            )
            if event.get("error"):
                if event["error"] != "disabled":
                    return "INCONCLUSIVE"
                solver.add(z3.Implies(ranks[i] == position, z3.Not(enabled)))
                continue
            solver.add(z3.Implies(ranks[i] == position, enabled))
            if event["kind"] == "execute":
                if (
                    event.get("gate") not in ("revalidate", "snapshot")
                    or type(event.get("result")) is not bool
                ):
                    return "INCONCLUSIVE"
                if not event["result"]:
                    continue
                if event["gate"] == "revalidate":
                    permits = policy.symbolic(
                        expression, states[position], universe, request
                    )
                else:
                    revision = event.get("revision")
                    if type(revision) is not int or not 0 <= revision < len(snapshots):
                        return "INCONCLUSIVE"
                    permits = z3.And(
                        revision <= versions[position],
                        policy.symbolic(
                            expression, snapshots[revision], universe, request
                        ),
                    )
                valid = z3.And(
                    permits,
                    z3.Not(
                        states[position]["__nonce__", event["nonce"], event["nonce"]]
                    ),
                )
                solver.add(z3.Implies(ranks[i] == position, valid))
                continue
            if event["kind"] != "check":
                continue
            if contract == "LIN":
                valid = (
                    policy.symbolic(expression, states[position], universe, request)
                    == event["result"]
                )
            else:
                revision = event.get("revision")
                minimum = event.get("min_revision", 0) if contract == "AT_LEAST" else 0
                eligible = [
                    r
                    for r in range(len(snapshots))
                    if r >= minimum and (revision is None or r == revision)
                ]
                valid = z3.Or(
                    *(
                        z3.And(
                            r <= versions[position],
                            policy.symbolic(expression, snapshots[r], universe, request)
                            == event["result"],
                        )
                        for r in eligible
                    )
                )
            if initial.get("_revision_observable") and contract == "LIN":
                if type(event.get("revision")) is not int:
                    return "INCONCLUSIVE"
                valid = z3.And(valid, event["revision"] == versions[position])
            if "policy_revision" in event:
                valid = z3.And(
                    valid,
                    event["policy_revision"] == initial.get("_policy_revision", 1),
                )
            solver.add(z3.Implies(ranks[i] == position, valid))
    status = solver.check()
    return (
        "CONFORMING"
        if status == z3.sat
        else "VIOLATION"
        if status == z3.unsat
        else "INCONCLUSIVE"
    )
