"""Typed policy/history templates with explicit, pre-adjudicated injected faults."""

import copy


def generate(rng, count, fragment="mixed", depth=3):
    """Prepare relation, inheritance, attribute and execution-gate experiments."""
    if depth < 1:
        raise ValueError("Inheritance depth must be positive")
    for index in range(count):
        kind = (
            ["relations", "attributes", "execute"][index % 3]
            if fragment == "mixed"
            else fragment
        )
        mutant = rng.choice(["correct", "stale"])
        write = dict(
            id="w",
            kind="insert",
            relation="deny",
            principal="u",
            resource="o",
            client=0,
            sequence=0,
        )
        read = dict(
            id="r",
            kind="check",
            principal="u",
            resource="o",
            client=1,
            sequence=0,
            requires=["w"],
        )
        case = dict(
            id=str(index),
            family=kind + "-" + mutant,
            contract="LIN",
            mutant=mutant,
            budget=100,
            replay_attempts=10,
            operations=[write, read],
            non_equivalent_mutant=mutant != "correct",
        )
        if kind == "relations":
            groups = ["g" + str(i) for i in range(depth)]
            nodes = ["u", "o", *groups]
            chain = list(zip(["u", *groups[:-1]], groups))
            case.update(
                universe={"member": nodes, "deny": nodes},
                relations={"member": [list(pair) for pair in chain], "deny": []},
                policy={
                    "and": [
                        {"reach": ["member", "$principal", groups[-1]]},
                        {"not": {"atom": ["deny", "$principal", "$resource"]}},
                    ]
                },
            )
        elif kind == "attributes":
            case.update(
                universe={"__attributes__": {"u": {"clearance": [0, 1, 2, 3]}}},
                attributes={"u": {"clearance": 3}},
                policy={"attribute": ["$principal", "clearance", "ge", 2]},
            )
            write.update(kind="attribute", entity="u", attribute="clearance", value=0)
            del write["relation"]
        elif kind == "execute":
            case.update(
                allow=[["u", "o"]],
                deny=[],
                universe={"allow": ["u", "o"], "deny": ["u", "o"]},
            )
            if rng.getrandbits(1):
                write.update(kind="delete", relation="allow")
                execute = dict(
                    id="e",
                    kind="execute",
                    gate="revalidate",
                    nonce="task",
                    principal="u",
                    resource="o",
                    client=2,
                    sequence=0,
                    requires=["r"],
                )
                case["operations"].append(execute)
            else:
                case["mutant"] = "duplicate_nonce" if mutant != "correct" else "correct"
                first = dict(
                    id="e0",
                    kind="execute",
                    gate="revalidate",
                    nonce="task",
                    principal="u",
                    resource="o",
                    client=0,
                    sequence=0,
                )
                second = dict(first, id="e1", sequence=1)
                case["operations"] = [first, second]
        else:
            raise ValueError("Unknown workload fragment")
        # Adjudication precedes generator outcomes and uses the independent checker.
        from .core import simulate
        from .oracle import check

        initial, history = simulate(case, case["operations"])
        case["non_equivalent_mutant"] = (
            check(initial, history, case["contract"]) == "VIOLATION"
        )
        yield copy.deepcopy(case)
