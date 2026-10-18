"""Executable concurrent reference target and JSON command adapter."""
import copy
import json
import math
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from .core import decision, update


def initial_state(case):
    return {key: {tuple(atom) for atom in case[key]} for key in ("allow", "deny")}


def command_target(command, timeout=60):
    """Wrap an engine command accepting one case/schedule JSON on stdin."""
    def execute(case, schedule):
        request = {"case": case, "schedule": [event["id"] for event in schedule]}
        completed = subprocess.run(command, input=json.dumps(request), text=True,
                                   capture_output=True, check=True, timeout=timeout)
        observed = json.loads(completed.stdout)["history"]
        by_id = {event["id"]: event for event in schedule}
        if len(by_id) != len(schedule) or {event["id"] for event in observed} != set(by_id) or len(observed) != len(schedule):
            raise ValueError("Adapter must return each requested operation exactly once")
        history = []
        write_ids = {event["id"] for event in schedule if event["kind"] != "check"}
        for record in observed:
            event = copy.deepcopy(by_id[record["id"]])
            for key in ("start", "end"):
                value = record[key]
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                    raise ValueError("Adapter timestamps must be finite nonnegative numbers")
                event[key] = value
            if event["end"] < event["start"]:
                raise ValueError("Adapter response precedes its invocation")
            if event["kind"] == "check":
                if not isinstance(record["result"], bool):
                    raise ValueError("Adapter check result must be Boolean")
                event["result"] = record["result"]
                revision = record.get("revision")
                if revision is not None:
                    if isinstance(revision, bool) or not isinstance(revision, int) or not 0 <= revision <= len(write_ids):
                        raise ValueError("Adapter revisions must index this case's write history")
                    event["revision"] = revision
                if case["contract"] == "SNAP" and revision is None:
                    raise ValueError("SNAP observations require a named revision")
                event["min_revision"] = event.get("min_revision", case.get("minimum_revision", 0))
                minimum = event["min_revision"]
                if isinstance(minimum, bool) or not isinstance(minimum, int) or minimum < 0:
                    raise ValueError("Minimum revision must be a nonnegative integer")
                dependencies = set(record.get("requires", []))
                if not dependencies <= write_ids:
                    raise ValueError("Adapter dependencies must name writes in this case")
                # Keep the revision's meaning when shrinking an external history.
                if (revision or 0) > 0 or minimum > 0:
                    dependencies |= write_ids
                event["requires"] = sorted(dependencies)
            history.append(event)
        ordered = sorted(history, key=lambda e: (e["client"], e["sequence"]))
        for first, second in zip(ordered, ordered[1:]):
            if first["client"] == second["client"] and first["end"] > second["start"]:
                raise ValueError("One client's sequential calls must not overlap")
        return initial_state(case), history
    return execute


def threaded_target(overlap=2):
    """Use real overlapping client calls to a locked versioned policy service."""
    if overlap < 1:
        raise ValueError("overlap must be positive")

    def execute(case, schedule):
        initial = initial_state(case)
        state = copy.deepcopy(initial)
        writes = []
        history = []
        lock = threading.Lock()
        start_time = time.perf_counter_ns()
        batches, current, clients = [], [], set()
        for event in schedule:
            if len(current) == overlap or event["client"] in clients:
                batches.append(current)
                current, clients = [], set()
            current.append(event)
            clients.add(event["client"])
        if current:
            batches.append(current)

        def invoke(specification, barrier):
            nonlocal state
            event = copy.deepcopy(specification)
            event["start"] = time.perf_counter_ns() - start_time
            # All invocations in this batch are visible before any response.
            barrier.wait()
            with lock:
                if event["kind"] == "check":
                    stale = case.get("mutant") == "stale"
                    event["result"] = decision(initial if stale else state, event["principal"], event["resource"])
                    event["revision"] = 0 if stale else len(writes)
                    event["min_revision"] = event.get("min_revision", case.get("minimum_revision", 0))
                    event["requires"] = [] if stale else list(writes)
                else:
                    state = update(state, event)
                    writes.append(event["id"])
                event["end"] = time.perf_counter_ns() - start_time
            return event

        with ThreadPoolExecutor(max_workers=overlap) as pool:
            for batch in batches:
                barrier = threading.Barrier(len(batch))
                futures = [pool.submit(invoke, event, barrier) for event in batch]
                history.extend(future.result() for future in futures)
        return initial, history
    return execute
