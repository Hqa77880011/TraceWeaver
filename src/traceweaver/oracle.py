"""Small-history permutation oracle, independent of the prefix-search checker."""

import itertools


def check(initial, history, contract):
    """Return a contract verdict by complete admissible-order replay (at most 8 calls)."""
    if contract not in ("LIN", "SNAP", "AT_LEAST"):
        raise ValueError("Unknown consistency contract")
    if len(history) > 8 or any(
        event["kind"] == "check"
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

    def allowed(state, event):
        pair = (event["principal"], event["resource"])
        return pair in state["allow"] and pair not in state["deny"]

    for order in itertools.permutations(history):
        position = {e["id"]: i for i, e in enumerate(order)}
        if any(position[a] >= position[b] for a, b in edges):
            continue
        versions = [{name: set(values) for name, values in initial.items()}]
        valid = True
        for event in order:
            if event["kind"] != "check":
                following = {key: set(values) for key, values in versions[-1].items()}
                pair = (event["principal"], event["resource"])
                if event["kind"] == "insert":
                    following[event["relation"]].add(pair)
                else:
                    following[event["relation"]].discard(pair)
                versions.append(following)
                continue
            if contract == "LIN":
                candidates = [versions[-1]]
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
            if not any(
                allowed(version, event) == event["result"] for version in candidates
            ):
                valid = False
                break
        if valid:
            return "CONFORMING"
    return "VIOLATION"
