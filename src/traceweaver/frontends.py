"""Typed NGAC association/prohibition fragment to the relational reference AST."""

import copy


def ngac(model):
    """Compile assignments, per-policy-class grants and scoped prohibitions.

    This accepts a finite NGAC-style IR, not arbitrary NIST server objects.
    Assignments are directed from an entity to its containing attribute/class.
    Prohibition object sets explicitly declare union/intersection and complement.
    """
    kinds = (
        "users",
        "objects",
        "user_attributes",
        "object_attributes",
        "policy_classes",
    )
    nodes = [node for kind in kinds for node in model[kind]]
    if (
        any(type(node) is not str for node in nodes)
        or len(nodes) != len(set(nodes))
        or not model["policy_classes"]
    ):
        raise ValueError("NGAC node IDs must be distinct and policy classes nonempty")
    known = set(nodes)
    assignments = model["assignments"]
    if any(len(pair) != 2 or not set(pair) <= known for pair in assignments):
        raise ValueError("Unknown NGAC assignment node")
    category = {node: kind for kind in kinds for node in model[kind]}
    legal = {
        "users": {"user_attributes"},
        "objects": {"object_attributes"},
        "user_attributes": {"user_attributes", "policy_classes"},
        "object_attributes": {"object_attributes", "policy_classes"},
        "policy_classes": set(),
    }
    if any(category[b] not in legal[category[a]] for a, b in assignments):
        raise ValueError("NGAC assignments must preserve user/object types")
    closure = set(map(tuple, assignments))
    while True:
        following = closure | {(a, d) for a, b in closure for c, d in closure if b == c}
        if following == closure:
            break
        closure = following
    if any(a == b for a, b in closure):
        raise ValueError("NGAC assignment graph must be acyclic")
    actions = sorted(
        set(model.get("operations", []))
        | {action for a in model["associations"] for action in a["operations"]}
    )
    relations = {
        "assignment": copy.deepcopy(assignments),
        **{"association:" + action: [] for action in actions},
    }
    for association in model["associations"]:
        ua, oa = association["user_attribute"], association["object_attribute"]
        if ua not in model["user_attributes"] or oa not in model["object_attributes"]:
            raise ValueError("Associations require typed user/object attributes")
        for action in association["operations"]:
            relations["association:" + action].append([ua, oa])

    def member(source, target):
        return {
            "or": [
                {"request": ["principal", "eq", target]}
                if source == "$principal"
                else {"request": ["resource", "eq", target]}
                if source == "$resource"
                else source == target,
                {"reach": ["assignment", source, target]},
            ]
        }

    class_checks, any_class = [], []
    for pc in model["policy_classes"]:
        object_in_class = member("$resource", pc)
        any_class.append(object_in_class)
        grants = []
        for ua in model["user_attributes"]:
            for oa in model["object_attributes"]:
                grants.append(
                    {
                        "and": [
                            member("$principal", ua),
                            member("$resource", oa),
                            member(oa, pc),
                            {
                                "or": [
                                    {
                                        "and": [
                                            {"request": ["action", "eq", action]},
                                            {"atom": ["association:" + action, ua, oa]},
                                        ]
                                    }
                                    for action in actions
                                ]
                            },
                        ]
                    }
                )
        class_checks.append({"or": [{"not": object_in_class}, {"or": grants}]})
    forbidden = []
    for index, prohibition in enumerate(model.get("prohibitions", [])):
        if prohibition["subject"] not in set(model["users"]) | set(
            model["user_attributes"]
        ):
            raise ValueError("Unknown prohibition subject")
        if not set(prohibition["objects"]) <= set(model["object_attributes"]) | set(
            model["objects"]
        ):
            raise ValueError("Unknown prohibition object scope")
        terms = [member("$resource", node) for node in prohibition["objects"]]
        if prohibition["mode"] not in ("union", "intersection"):
            raise ValueError("Declare prohibition union or intersection")
        scope = {"or" if prohibition["mode"] == "union" else "and": terms}
        if prohibition.get("complement", False):
            scope = {"not": scope}
        identifier = "__prohibition_" + str(index)
        if identifier in known:
            raise ValueError("Reserved prohibition identifier")
        nodes.append(identifier)
        relations.setdefault("prohibition", []).append([identifier, identifier])
        forbidden.append(
            {
                "and": [
                    {"atom": ["prohibition", identifier, identifier]},
                    member("$principal", prohibition["subject"]),
                    scope,
                    {
                        "or": [
                            {"request": ["action", "eq", action]}
                            for action in prohibition["operations"]
                        ]
                    },
                ]
            }
        )
    expression = {"and": [{"or": any_class}, *class_checks, {"not": {"or": forbidden}}]}
    fixed = []
    for name in relations:
        for left in nodes:
            for right in nodes:
                if name == "assignment":
                    valid = (
                        left in category
                        and right in category
                        and category[right] in legal[category[left]]
                    )
                elif name.startswith("association:"):
                    valid = (
                        left in model["user_attributes"]
                        and right in model["object_attributes"]
                    )
                else:
                    valid = left.startswith("__prohibition_") and left == right
                if not valid:
                    fixed.append(dict(atom=[name, left, right], value=False))
    invariants = [{"not": {"reach": ["assignment", node, node]}} for node in nodes]
    return dict(
        universe={name: nodes for name in relations},
        policy=expression,
        relations=relations,
        fixed=fixed,
        invariants=invariants,
    )


def normalize(case):
    return {**case, **ngac(case["ngac"])} if "ngac" in case else case
