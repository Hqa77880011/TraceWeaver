"""Registered pending-call completion semantics, without inventing observations."""

import copy
import itertools
import time


def present(history):
    return any(event.get("pending") or event.get("end") is None for event in history)


def check(initial, history, contract, checker, timeout_seconds=1):
    """Check admissible drops/completions; hypothetical results stay internal."""
    rule = initial.get("_pending_rule", "unknown")
    if rule not in ("drop", "linearize"):
        return "INCONCLUSIVE"
    if any(type(event.get("start")) not in (int, float) for event in history):
        return "INCONCLUSIVE"
    horizon = (
        max(
            [event["start"] for event in history]
            + [event["end"] for event in history if event.get("end") is not None]
            + [0]
        )
        + 1
    )
    options = []
    for original in history:
        if not original.get("pending") and original.get("end") is not None:
            options.append([original])
            continue
        if original.get("effect_committed") is True:
            outcomes = [True]
            droppable = False
        else:
            outcomes = (
                [original["result"]]
                if type(original.get("result")) is bool
                else [False, True]
            )
            droppable = True
        alternatives = [None] if droppable else []
        if rule == "linearize":
            for outcome in (
                outcomes if original["kind"] in ("check", "execute") else [None]
            ):
                completed = copy.deepcopy(original)
                completed.pop("pending", None)
                completed["end"] = horizon
                if outcome is not None:
                    completed["result"] = outcome
                alternatives.append(completed)
        if not alternatives:
            return "INCONCLUSIVE"
        options.append(alternatives)
    stamp = time.perf_counter()
    unknown = False
    checked = False
    for completion in itertools.product(*options):
        if time.perf_counter() - stamp >= timeout_seconds:
            return "INCONCLUSIVE"
        events = [event for event in completion if event is not None]
        ids = {event["id"] for event in events}
        if any(not set(event.get("requires", [])) <= ids for event in events):
            continue
        checked = True
        verdict = checker(initial, events, contract)
        if verdict == "CONFORMING":
            return verdict
        unknown |= verdict == "INCONCLUSIVE"
    return "INCONCLUSIVE" if unknown or not checked else "VIOLATION"
