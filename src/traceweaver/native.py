"""Cedar shared-state wrapper and OpenFGA HTTP targets for registered sandboxes."""

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import threading
import urllib.parse
import urllib.request
import uuid

from . import policy
from .core import initial_state, update
from .runtime import concurrent_history


def _uid(value):
    return "Entity::" + json.dumps(str(value))


def cedar_inputs(case, state, request):
    """Compile the relational AST to Cedar attributes and Boolean expressions.

    Closure-valued attributes belong to this explicitly tested shared-state
    wrapper. They are not a claim about the concurrency of the pure Cedar PDP.
    """
    relations = {
        k: v for k, v in state.items() if isinstance(v, set) and k != "consumed"
    }
    names = {name: "r" + str(i) for i, name in enumerate(sorted(relations))}
    nodes = {x for values in relations.values() for pair in values for x in pair}
    nodes |= {request["principal"], request["resource"]}
    for values in case.get("universe", {}).values():
        if isinstance(values, list):
            nodes.update(values)
    attribute_names = {
        name: "a" + str(i)
        for i, name in enumerate(
            sorted(
                {
                    name
                    for values in state.get("attributes", {}).values()
                    for name in values
                }
            )
        )
    }

    def expression(expr):
        if isinstance(expr, bool):
            return "true" if expr else "false"
        if "and" in expr or "or" in expr:
            key = "and" if "and" in expr else "or"
            values = [expression(x) for x in expr[key]]
            return (
                "(" + (" && " if key == "and" else " || ").join(values) + ")"
                if values
                else ("true" if key == "and" else "false")
            )
        if "not" in expr:
            return "!(" + expression(expr["not"]) + ")"
        if "request" in expr:
            name, operation, value = expr["request"]
            actual = {
                "action": request.get("action", "read"),
                "context": request.get("context", {}),
                **request,
            }
            for component in name.split("."):
                actual = actual[component]
            return "true" if policy.compare(actual, operation, value) else "false"
        if "attribute" in expr:
            entity, name, operation, value = expr["attribute"]
            left = entity[1:] if entity in ("$principal", "$resource") else _uid(entity)
            right = (
                value[1:]
                if isinstance(value, str) and value.startswith("$")
                else json.dumps(value)
            )
            return (
                left
                + "."
                + attribute_names[name]
                + {"eq": " == ", "ge": " >= ", "gt": " > ", "le": " <= ", "lt": " < "}[
                    operation
                ]
                + right
            )
        relation, left, right = expr.get("atom", expr.get("reach"))

        def operand(value):
            return value[1:] if value in ("$principal", "$resource") else _uid(value)

        attribute = ("closure_" if "reach" in expr else "") + names[relation]
        return f"{operand(left)}.{attribute}.contains({operand(right)})"

    entities = []
    for node in sorted(nodes):
        attrs = {}
        attrs.update(
            {
                attribute_names[name]: value
                for name, value in state.get("attributes", {}).get(node, {}).items()
            }
        )
        for name, values in relations.items():
            direct = {b for a, b in values if a == node}
            reached, queue = set(), list(direct)
            while queue:
                value = queue.pop()
                if value in reached:
                    continue
                reached.add(value)
                queue.extend(b for a, b in values if a == value)
            for field, selected in (
                (names[name], direct),
                ("closure_" + names[name], reached),
            ):
                attrs[field] = [
                    {"__entity": {"type": "Entity", "id": str(v)}}
                    for v in sorted(selected)
                ]
        entities.append(
            dict(uid={"type": "Entity", "id": str(node)}, attrs=attrs, parents=[])
        )
    text = (
        "permit(principal, action, resource) when { "
        + expression(case.get("policy", policy.DEFAULT))
        + " };\n"
    )
    query = dict(
        principal=_uid(request["principal"]),
        action="Action::" + json.dumps(request.get("action", "read")),
        resource=_uid(request["resource"]),
        context=request.get("context", {}),
    )
    return text, entities, query


def cedar_target(executable="cedar", output="runs/native-cedar", timeout=30, overlap=2):
    """Invoke actual Cedar reads and mediated effects on a versioned state wrapper."""

    def target(case, schedule):
        initial = initial_state(case)
        state = copy.deepcopy(initial)
        writes, lock = [], threading.RLock()
        root = Path(output) / uuid.uuid4().hex
        root.mkdir(parents=True)

        def authorize(snapshot, event):
            text, entities, query = cedar_inputs(case, snapshot, event)
            prefix = uuid.uuid4().hex
            paths = [
                root / (prefix + suffix)
                for suffix in (".cedar", ".entities.json", ".request.json")
            ]
            paths[0].write_text(text, encoding="utf-8")
            paths[1].write_text(json.dumps(entities), encoding="utf-8")
            paths[2].write_text(json.dumps(query), encoding="utf-8")
            completed = subprocess.run(
                [
                    executable,
                    "authorize",
                    "--policies",
                    str(paths[0]),
                    "--entities",
                    str(paths[1]),
                    "--request-json",
                    str(paths[2]),
                ],
                text=True,
                capture_output=True,
                timeout=timeout,
            )
            lines = completed.stdout.split()
            if completed.returncode not in (0, 2) or not (
                "ALLOW" in lines or "DENY" in lines
            ):
                raise RuntimeError(
                    "Cedar authorization failed: " + completed.stderr + completed.stdout
                )
            return "ALLOW" in lines

        def invoke(event):
            nonlocal state
            with lock:
                if not policy.evaluate(event.get("enabled", True), state, event):
                    return dict(event, error="disabled")
                if event["kind"] == "execute":
                    if event.get("gate") not in ("revalidate", "snapshot"):
                        raise ValueError("Register the execution gate before effects")
                    command = case.get("native", {}).get("effect_command")
                    if not command:
                        raise ValueError(
                            "Native Execute needs an actual effect_command JSON adapter"
                        )
                    snapshot = initial if event["gate"] == "snapshot" else state
                    event["revision"] = 0 if snapshot is initial else len(writes)
                    allowed = event["nonce"] not in state["consumed"] and authorize(
                        snapshot, event
                    )
                    event["result"] = False
                    if allowed:
                        completed = subprocess.run(
                            [
                                arg.replace("{episode}", str(root)).replace(
                                    "{python}", sys.executable
                                )
                                for arg in command
                            ],
                            input=json.dumps(event),
                            text=True,
                            capture_output=True,
                            check=True,
                            timeout=timeout,
                        )
                        receipt = json.loads(completed.stdout)
                        if type(receipt.get("committed")) is not bool:
                            raise ValueError(
                                "Effect adapter must return a Boolean committed and its receipt"
                            )
                        event["result"], event["effect_receipt"] = (
                            receipt["committed"],
                            receipt,
                        )
                        if event["result"]:
                            state = update(state, event)
                    return event
                if event["kind"] != "check":
                    state = update(state, event)
                    writes.append(event["id"])
                    return event
                snapshot = copy.deepcopy(
                    initial if case.get("mutant") == "stale" else state
                )
                revision = 0 if case.get("mutant") == "stale" else len(writes)
                parents = list(event.get("requires", []))
                if revision:
                    parents += writes
            event.update(
                result=authorize(snapshot, event),
                revision=revision,
                min_revision=event.get("min_revision", case.get("minimum_revision", 0)),
                requires=list(dict.fromkeys(parents)),
            )
            return event

        history = concurrent_history(schedule, invoke, overlap)
        (root / "history.json").write_text(json.dumps(history), encoding="utf-8")
        return initial, history

    return target


def openfga_target(url, timeout=30, overlap=2):
    """Use fresh stores on a local OpenFGA server; never infer LIN from API flags."""
    if urllib.parse.urlparse(url).hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError(
            "The native campaign is restricted to the authorized local sandbox"
        )

    def post(path, payload):
        headers = {"Content-Type": "application/json"}
        token = os.environ.get("OPENFGA_API_TOKEN")
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(
            url.rstrip("/") + path, json.dumps(payload).encode(), headers
        )
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read()
            return json.loads(data) if data else {}

    def target(case, schedule):
        registration = case.get("contract_registration", {})
        if case["contract"] != "UNKNOWN" and not (
            registration.get("mode") == case["contract"]
            and registration.get("provenance")
        ):
            raise ValueError(
                "Register the deployment's reviewed contract before native judgments"
            )
        if case["contract"] not in ("LIN", "UNKNOWN"):
            raise ValueError(
                "OpenFGA Check does not supply this adapter's named snapshot revisions"
            )
        config = case.get("native", {})
        if "policy" in case and "model" not in config:
            raise ValueError(
                "A relational AST requires an independently reviewed matching OpenFGA model"
            )
        store = post("/stores", {"name": "traceweaver-" + uuid.uuid4().hex})["id"]
        direct = {
            "schema_version": "1.1",
            "type_definitions": [
                {"type": "user"},
                {
                    "type": "document",
                    "relations": {
                        "allow": {"this": {}},
                        "deny": {"this": {}},
                        "viewer": {
                            "difference": {
                                "base": {"computedUserset": {"relation": "allow"}},
                                "subtract": {"computedUserset": {"relation": "deny"}},
                            }
                        },
                    },
                    "metadata": {
                        "relations": {
                            name: {"directly_related_user_types": [{"type": "user"}]}
                            for name in ("allow", "deny")
                        }
                    },
                },
            ],
        }
        model = post(
            f"/stores/{store}/authorization-models", config.get("model", direct)
        )["authorization_model_id"]
        initial = initial_state(case)
        gate_lock, consumed = threading.RLock(), set(case.get("consumed", []))
        shadow = {
            name: set(values)
            for name, values in initial.items()
            if isinstance(values, set) and name != "consumed"
        }
        root = Path(config.get("output", "runs/native-openfga")) / uuid.uuid4().hex
        root.mkdir(parents=True)
        (root / "target.json").write_text(
            json.dumps(
                dict(store=store, model=model, url=url, registration=registration)
            ),
            encoding="utf-8",
        )

        def tuple_key(relation, left, right):
            return dict(
                user=config.get("user_type", "user") + ":" + left,
                relation=config.get("relation_map", {}).get(relation, relation),
                object=config.get("object_type", "document") + ":" + right,
            )

        tuples = [
            tuple_key(name, a, b)
            for name, values in initial.items()
            if isinstance(values, set) and name != "consumed"
            for a, b in values
        ]
        for offset in range(0, len(tuples), 100):
            post(
                f"/stores/{store}/write",
                dict(
                    authorization_model_id=model,
                    writes={"tuple_keys": tuples[offset : offset + 100]},
                ),
            )

        def invoke(event):
            if event["kind"] == "execute":
                if event.get("gate") != "revalidate" or not config.get(
                    "effect_command"
                ):
                    raise ValueError(
                        "OpenFGA wrapper Execute requires revalidate and an effect_command"
                    )
                with gate_lock:
                    key = tuple_key(
                        config.get("check_relation", "viewer"),
                        event["principal"],
                        event["resource"],
                    )
                    allowed = post(
                        f"/stores/{store}/check",
                        dict(
                            tuple_key=key,
                            authorization_model_id=model,
                            consistency="HIGHER_CONSISTENCY",
                        ),
                    )["allowed"]
                    event["result"] = False
                    if allowed and event["nonce"] not in consumed:
                        command = [
                            arg.replace("{episode}", str(root)).replace(
                                "{python}", sys.executable
                            )
                            for arg in config["effect_command"]
                        ]
                        receipt = json.loads(
                            subprocess.run(
                                command,
                                input=json.dumps(event),
                                text=True,
                                capture_output=True,
                                check=True,
                                timeout=timeout,
                            ).stdout
                        )
                        if type(receipt.get("committed")) is not bool:
                            raise ValueError(
                                "Effect adapter needs a committed Boolean receipt"
                            )
                        event["result"], event["effect_receipt"] = (
                            receipt["committed"],
                            receipt,
                        )
                        if event["result"]:
                            consumed.add(event["nonce"])
                return event
            if event["kind"] == "check":
                key = tuple_key(
                    config.get("check_relation", "viewer"),
                    event["principal"],
                    event["resource"],
                )
                answer = post(
                    f"/stores/{store}/check",
                    dict(
                        tuple_key=key,
                        authorization_model_id=model,
                        consistency=config.get("consistency", "HIGHER_CONSISTENCY"),
                    ),
                )
                if type(answer.get("allowed")) is not bool:
                    raise ValueError("OpenFGA returned no Boolean Check decision")
                event["result"] = answer["allowed"]
            else:
                key = tuple_key(
                    event["relation"], event["principal"], event["resource"]
                )
                field = "writes" if event["kind"] == "insert" else "deletes"
                with gate_lock:
                    atom = (event["principal"], event["resource"])
                    values = shadow.setdefault(event["relation"], set())
                    changes = (
                        (atom not in values) if field == "writes" else atom in values
                    )
                    if changes:
                        post(
                            f"/stores/{store}/write",
                            {
                                "authorization_model_id": model,
                                field: {"tuple_keys": [key]},
                            },
                        )
                        (values.add if field == "writes" else values.discard)(atom)
            return event

        history = concurrent_history(schedule, invoke, overlap)
        (root / "history.json").write_text(json.dumps(history), encoding="utf-8")
        return initial, history

    return target
