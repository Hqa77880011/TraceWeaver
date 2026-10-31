"""Finite relational policy AST, conservative cones and SMT separating states."""

import copy
import itertools
import json


def keys(universe):
    atoms = [
        (name, a, b)
        for name, nodes in universe.items()
        if name != "__attributes__"
        for a in nodes
        for b in nodes
    ]
    atoms += [
        ("__attr__", entity, name)
        for entity, attributes in universe.get("__attributes__", {}).items()
        for name in attributes
    ]
    return atoms


def compare(left, operation, right):
    if operation == "eq":
        return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)
    if type(left) not in (int, float) or type(right) not in (int, float):
        return False
    return {
        "ge": left >= right,
        "gt": left > right,
        "le": left <= right,
        "lt": left < right,
    }[operation]


DEFAULT = {
    "and": [
        {"atom": ["allow", "$principal", "$resource"]},
        {"not": {"atom": ["deny", "$principal", "$resource"]}},
    ]
}


def term(value, request):
    if isinstance(value, str) and value.startswith("$"):
        actual = request
        for component in value[1:].split("."):
            actual = actual[component]
        return actual
    return value


def evaluate(expr, relations, request):
    """Interpret Boolean relation predicates and bounded transitive inheritance."""
    if isinstance(expr, bool):
        return expr
    if "and" in expr:
        return all(evaluate(item, relations, request) for item in expr["and"])
    if "or" in expr:
        return any(evaluate(item, relations, request) for item in expr["or"])
    if "not" in expr:
        return not evaluate(expr["not"], relations, request)
    if "request" in expr:
        name, operation, value = expr["request"]
        return compare(term("$" + name, request), operation, term(value, request))
    if "attribute" in expr:
        entity, name, operation, value = expr["attribute"]
        entity = term(entity, request)
        if (
            entity not in relations.get("attributes", {})
            or name not in relations["attributes"][entity]
        ):
            raise ValueError("Attribute outside the declared total finite state")
        return compare(
            relations["attributes"][entity][name], operation, term(value, request)
        )
    if "atom" in expr:
        name, *args = expr["atom"]
        return tuple(term(x, request) for x in args) in relations.get(name, set())
    if "reach" in expr:
        name, source, target = expr["reach"]
        source, target = term(source, request), term(target, request)
        seen, queue = set(), [source]
        while queue:
            node = queue.pop()
            for left, right in relations.get(name, set()):
                if left == node:
                    if right == target:
                        return True
                    if right not in seen:
                        seen.add(right)
                        queue.append(right)
        return False
    raise ValueError("Policy AST supports and/or/not/atom/reach")


def cones(expr, universe, request, negative=False):
    """Include absent relation atoms and every possible inheritance edge."""
    positive, excluded = set(), set()
    if isinstance(expr, bool):
        return positive, excluded
    if "request" in expr:
        return positive, excluded
    if "not" in expr:
        return cones(expr["not"], universe, request, not negative)
    if "attribute" in expr:
        entity, name, _, _ = expr["attribute"]
        (excluded if negative else positive).add(
            ("__attr__", term(entity, request), name)
        )
        return positive, excluded
    if "and" in expr or "or" in expr:
        for child in expr.get("and", expr.get("or")):
            p, n = cones(child, universe, request, negative)
            positive |= p
            excluded |= n
    else:
        relation = expr.get("atom", expr.get("reach"))
        if relation is None:
            raise ValueError("Unsupported policy dependency")
        name, *args = relation
        atoms = {
            (name, *values)
            for values in itertools.product(universe[name], repeat=len(args))
        }
        if "atom" in expr:
            atoms = {(name, *(term(x, request) for x in args))}
        (excluded if negative else positive).update(atoms)
    return positive, excluded


def symbolic(expr, atoms, universe, request):
    """Encode the same declared finite AST directly, including transitive closure."""
    import z3

    if isinstance(expr, bool):
        return z3.BoolVal(expr)
    if "request" in expr:
        name, operation, value = expr["request"]
        return z3.BoolVal(
            compare(term("$" + name, request), operation, term(value, request))
        )
    if "and" in expr:
        return z3.And(*(symbolic(x, atoms, universe, request) for x in expr["and"]))
    if "or" in expr:
        return z3.Or(*(symbolic(x, atoms, universe, request) for x in expr["or"]))
    if "not" in expr:
        return z3.Not(symbolic(expr["not"], atoms, universe, request))
    if "attribute" in expr:
        entity, name, operation, value = expr["attribute"]
        entity, value = term(entity, request), term(value, request)
        domain = universe["__attributes__"][entity][name]
        return z3.Or(
            *(
                atoms["__attr__", entity, name] == index
                for index, actual in enumerate(domain)
                if compare(actual, operation, value)
            )
        )
    name, *args = expr.get("atom", expr.get("reach"))
    args = [term(x, request) for x in args]
    if "atom" in expr:
        return atoms[(name, *args)]
    nodes = universe[name]
    closure = {(a, b): atoms[(name, a, b)] for a in nodes for b in nodes}
    for middle in nodes:
        previous = closure
        closure = {
            (a, b): z3.Or(
                previous[a, b], z3.And(previous[a, middle], previous[middle, b])
            )
            for a in nodes
            for b in nodes
        }
    return closure[tuple(args)]


def separating(case, write, request, timeout_ms=1000):
    """Solve a legal decision-changing update over a finite relational universe.

    `fixed` atoms bind fixture requirements; `invariants` and `enabled` are AST
    constraints. SAT returns a concrete independently replayable state; UNKNOWN
    remains explicit. The caller supplies authorized administrative updates.
    """
    import z3

    request = {"action": "read", "context": {}, **request}
    universe = case["universe"]
    atom_keys = keys(universe)
    atoms = {
        key: (z3.Int if key[0] == "__attr__" else z3.Bool)("atom_" + str(i))
        for i, key in enumerate(atom_keys)
    }
    solver = z3.Solver()
    solver.set(timeout=timeout_ms)
    for key, variable in atoms.items():
        if key[0] == "__attr__":
            solver.add(
                variable >= 0,
                variable < len(universe["__attributes__"][key[1]][key[2]]),
            )
    for expression in case.get("invariants", []):
        solver.add(symbolic(expression, atoms, universe, request))
    for fixed in case.get("fixed", []):
        solver.add(atoms[tuple(fixed["atom"])] == fixed["value"])
    if write.get("admin_allowed", True) is not True:
        return {"status": "UNAUTHORIZED"}
    solver.add(symbolic(write.get("enabled", True), atoms, universe, request))
    key = (
        ("__attr__", write.get("entity", write["principal"]), write["attribute"])
        if write["kind"] == "attribute"
        else (write["relation"], write["principal"], write["resource"])
    )
    after = dict(atoms)
    if key[0] == "__attr__":
        domain = universe["__attributes__"][key[1]][key[2]]
        after[key] = z3.IntVal(
            next(
                i
                for i, value in enumerate(domain)
                if compare(value, "eq", write["value"])
            )
        )
    else:
        after[key] = z3.BoolVal(write["kind"] == "insert")
    for expression in case.get("invariants", []):
        solver.add(symbolic(expression, after, universe, request))
    expression = case.get("policy", DEFAULT)
    solver.add(
        symbolic(expression, atoms, universe, request)
        != symbolic(expression, after, universe, request)
    )
    status = solver.check()
    if status != z3.sat:
        return {
            "status": "UNSAT" if status == z3.unsat else "UNKNOWN",
            "reason": solver.reason_unknown(),
        }
    model = solver.model()
    state = {name: set() for name in universe if name != "__attributes__"}
    state["attributes"] = {}
    for name, left, right in atom_keys:
        if name == "__attr__":
            state["attributes"].setdefault(left, {})[right] = universe[
                "__attributes__"
            ][left][right][
                model.eval(atoms[name, left, right], model_completion=True).as_long()
            ]
        elif z3.is_true(model.eval(atoms[name, left, right], model_completion=True)):
            state[name].add((left, right))
    following = copy.deepcopy(state)
    if key[0] == "__attr__":
        following["attributes"][key[1]][key[2]] = write["value"]
    else:
        (
            following[key[0]].add
            if write["kind"] == "insert"
            else following[key[0]].discard
        )(key[1:])
    before_value = evaluate(expression, state, request)
    after_value = evaluate(expression, following, request)
    if before_value == after_value:
        raise RuntimeError("SMT separation disagrees with the concrete interpreter")
    return {
        "status": "SAT",
        "relations": {k: sorted(v) for k, v in state.items() if k != "attributes"},
        "attributes": state["attributes"],
        "before": before_value,
        "after": after_value,
    }


def models(case, request):
    """Enumerate all valid finite states with blocking clauses; retain UNKNOWN."""
    import z3

    universe = case["universe"]
    atom_keys = keys(universe)
    atoms = {
        key: (z3.Int if key[0] == "__attr__" else z3.Bool)("state_" + str(i))
        for i, key in enumerate(atom_keys)
    }
    solver = z3.Solver()
    solver.set(timeout=case.get("solver_timeout_ms", 1000))
    for key, value in atoms.items():
        if key[0] == "__attr__":
            solver.add(
                value >= 0, value < len(universe["__attributes__"][key[1]][key[2]])
            )
    for fixed in case.get("fixed", []):
        solver.add(atoms[tuple(fixed["atom"])] == fixed["value"])
    for expression in case.get("invariants", []):
        solver.add(symbolic(expression, atoms, universe, request))
    while True:
        answer = solver.check()
        if answer != z3.sat:
            if answer == z3.unknown:
                yield dict(status="UNKNOWN", reason=solver.reason_unknown())
            return
        model = solver.model()
        relations = {name: [] for name in universe if name != "__attributes__"}
        attributes = {}
        for key, variable in atoms.items():
            value = model.eval(variable, model_completion=True)
            if key[0] == "__attr__":
                attributes.setdefault(key[1], {})[key[2]] = universe["__attributes__"][
                    key[1]
                ][key[2]][value.as_long()]
            elif z3.is_true(value):
                relations[key[0]].append(list(key[1:]))
        yield dict(status="SAT", relations=relations, attributes=attributes)
        solver.add(
            z3.Or(
                *(
                    variable != model.eval(variable, model_completion=True)
                    for variable in atoms.values()
                )
            )
        )


def independent(left, right, case):
    """Conservative semantic commutation including enabledness and read cones."""
    if (
        left["client"] == right["client"]
        or left["id"] in right.get("requires", [])
        or right["id"] in left.get("requires", [])
    ):
        return False
    if case.get("revision_observable") and (
        left["kind"] != "check" or right["kind"] != "check"
    ):
        return False
    if "execute" in (left["kind"], right["kind"]):
        return False
    if case["contract"] != "LIN" and (
        left["kind"] != "check" or right["kind"] != "check"
    ):
        return False

    def footprint(event):
        request = dict(
            principal=event["principal"],
            resource=event["resource"],
            action=event.get("action", "read"),
            context=event.get("context", {}),
        )
        reads = set().union(
            *cones(event.get("enabled", True), case["universe"], request)
        )
        writes = set()
        if event["kind"] == "check":
            reads |= set().union(
                *cones(case.get("policy", DEFAULT), case["universe"], request)
            )
        elif event["kind"] == "attribute":
            writes.add(
                (
                    "__attr__",
                    event.get("entity", event["principal"]),
                    event["attribute"],
                )
            )
        elif event["kind"] == "execute":
            return {("__global_execution__",)}, {("__global_execution__",)}
        else:
            writes.add((event["relation"], event["principal"], event["resource"]))
        return reads, writes

    a_read, a_write = footprint(left)
    b_read, b_write = footprint(right)
    return not (a_write & (b_read | b_write) or b_write & (a_read | a_write))
