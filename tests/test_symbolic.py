import copy
import unittest

from traceweaver import core, oracle, policy, smt


def inheritance_case():
    nodes = ["u", "staff", "o"]
    return dict(
        id="negative-inheritance",
        contract="LIN",
        mutant="stale",
        budget=12,
        universe={"member": nodes, "ban": nodes},
        policy={
            "and": [
                {"reach": ["member", "$principal", "staff"]},
                {"not": {"atom": ["ban", "$principal", "$resource"]}},
            ]
        },
        relations={"member": [], "ban": []},
        operations=[
            dict(
                id="w",
                client=0,
                sequence=0,
                kind="insert",
                relation="ban",
                principal="u",
                resource="o",
            ),
            dict(
                id="r",
                client=1,
                sequence=0,
                kind="check",
                principal="u",
                resource="o",
                requires=["w"],
            ),
        ],
    )


class SymbolicTests(unittest.TestCase):
    def test_vgd_constructs_both_policy_properties_with_independent_checking(self):
        from traceweaver.strategies import fixtures

        case = dict(
            id="property-generator",
            contract="LIN",
            mutant="correct",
            fixture_budget=12,
            universe={"allow": ["u", "o"], "deny": ["u", "o"]},
            allow=[],
            deny=[],
            operations=[
                dict(
                    id="r",
                    kind="check",
                    principal="u",
                    resource="o",
                    client=0,
                    sequence=0,
                )
            ],
        )
        generated = list(fixtures(case, "vgd_plus"))[1:]
        self.assertEqual({row["property_expected"] for row in generated}, {True, False})
        for row in generated:
            initial, history = core.simulate(row, row["operations"])
            self.assertEqual(history[0]["result"], row["property_expected"])
            self.assertEqual(oracle.check(initial, history, "LIN"), "CONFORMING")

    def test_bounded_enumerates_every_valid_state_without_duplicate_seed(self):
        universe = {"allow": ["u", "o"], "deny": ["u", "o"]}
        fixed = [
            dict(atom=[name, a, b], value=False)
            for name in universe
            for a in universe[name]
            for b in universe[name]
            if (a, b) != ("u", "o")
        ]
        case = dict(
            id="all-states",
            contract="LIN",
            mutant="correct",
            budget=20,
            universe=universe,
            fixed=fixed,
            allow=[],
            deny=[],
            operations=[
                dict(
                    id="r",
                    kind="check",
                    principal="u",
                    resource="o",
                    client=0,
                    sequence=0,
                )
            ],
        )
        states = list(
            policy.models(
                case, dict(principal="u", resource="o", action="read", context={})
            )
        )
        observed = {
            (
                ["u", "o"] in row["relations"]["allow"],
                ["u", "o"] in row["relations"]["deny"],
            )
            for row in states
        }
        self.assertEqual(
            observed, {(False, False), (False, True), (True, False), (True, True)}
        )
        result = core.run_case(case, "bounded")
        self.assertEqual(result["checked"], 4)
        self.assertTrue(result["search_status"]["orders_complete"])

    def test_registered_pending_completion_and_unknown_evidence(self):
        case = dict(
            id="pending",
            allow=[["u", "o"]],
            deny=[],
            contract="LIN",
            mutant="correct",
            operations=[],
        )
        initial = core.initial_state(case)
        history = [
            dict(
                id="w",
                kind="delete",
                relation="allow",
                principal="u",
                resource="o",
                client=0,
                sequence=0,
                start=0,
                end=None,
                pending=True,
            ),
            dict(
                id="r",
                kind="check",
                principal="u",
                resource="o",
                client=1,
                sequence=0,
                start=1,
                end=2,
                result=False,
            ),
        ]
        for checker in (core.check_history, oracle.check, smt.check):
            self.assertEqual(checker(initial, history, "LIN"), "INCONCLUSIVE")
            self.assertEqual(
                checker(dict(initial, _pending_rule="linearize"), history, "LIN"),
                "CONFORMING",
            )
            self.assertEqual(
                checker(dict(initial, _pending_rule="drop"), history, "LIN"),
                "VIOLATION",
            )
        history[1].update(error="transport", result=None)
        self.assertEqual(core.check_history(initial, history, "LIN"), "INCONCLUSIVE")

    def test_legal_snapshot_control_retains_false_report_denominator(self):
        case = dict(
            id="legal-old-snapshot",
            contract="SNAP",
            mutant="stale",
            budget=4,
            allow=[["u", "o"]],
            deny=[],
            operations=[
                dict(
                    id="w",
                    kind="delete",
                    relation="allow",
                    principal="u",
                    resource="o",
                    client=0,
                    sequence=0,
                ),
                dict(
                    id="r",
                    kind="check",
                    principal="u",
                    resource="o",
                    client=1,
                    sequence=0,
                    requires=["w"],
                ),
            ],
        )
        correct = core.run_case(case, "traceweaver")
        self.assertEqual(core.score(case, correct)["false_report"], 0)
        broken = core.run_case(case, "forced_lin")
        self.assertTrue(broken["reported"])
        self.assertFalse(broken["confirmed"])
        self.assertEqual(core.metric_counts(case, broken)["false_report"], [1, 1])

    def test_ngac_policy_classes_dynamic_associations_and_action_scope(self):
        from traceweaver.frontends import normalize

        model = dict(
            users=["u"],
            objects=["o"],
            user_attributes=["ua"],
            object_attributes=["oa"],
            policy_classes=["pc"],
            assignments=[["u", "ua"], ["o", "oa"], ["ua", "pc"], ["oa", "pc"]],
            associations=[
                dict(user_attribute="ua", object_attribute="oa", operations=["read"])
            ],
        )
        write = dict(
            id="w",
            kind="delete",
            relation="association:read",
            principal="ua",
            resource="oa",
            client=0,
            sequence=0,
        )
        read = dict(
            id="r",
            kind="check",
            principal="u",
            resource="o",
            action="read",
            client=1,
            sequence=0,
            requires=["w"],
        )
        case = normalize(
            dict(
                id="ngac",
                ngac=model,
                contract="LIN",
                mutant="stale",
                budget=8,
                operations=[write, read],
            )
        )
        initial, history = core.simulate(case, case["operations"])
        self.assertTrue(core.decision(initial, "u", "o", "read"))
        self.assertFalse(core.decision(initial, "u", "o", "write"))
        for checker in (core.check_history, oracle.check, smt.check):
            self.assertEqual(checker(initial, history, "LIN"), "VIOLATION")
        self.assertTrue(core.run_case(case, "traceweaver")["confirmed"])

    def test_attribute_update_and_execution_nonce_obligations(self):
        case = dict(
            id="attribute",
            contract="LIN",
            mutant="stale",
            budget=8,
            universe={"__attributes__": {"u": {"level": [0, 1, 2]}}},
            attributes={"u": {"level": 2}},
            policy={"attribute": ["$principal", "level", "ge", 1]},
            operations=[
                dict(
                    id="w",
                    kind="attribute",
                    principal="u",
                    resource="o",
                    entity="u",
                    attribute="level",
                    value=0,
                    client=0,
                    sequence=0,
                ),
                dict(
                    id="r",
                    kind="check",
                    principal="u",
                    resource="o",
                    client=1,
                    sequence=0,
                    requires=["w"],
                ),
            ],
        )
        seed = policy.separating(case, *case["operations"])
        self.assertEqual(seed["status"], "SAT")
        nonseparating = copy.deepcopy(case)
        nonseparating["attributes"]["u"]["level"] = 0
        self.assertTrue(core.run_case(nonseparating, "traceweaver")["confirmed"])
        initial, history = core.simulate(case, case["operations"])
        for checker in (core.check_history, oracle.check, smt.check):
            self.assertEqual(checker(initial, history, "LIN"), "VIOLATION")
        case["operations"][1].update(kind="execute", gate="revalidate", nonce="n")
        initial, history = core.simulate(case, case["operations"])
        for checker in (core.check_history, oracle.check, smt.check):
            self.assertEqual(checker(initial, history, "LIN"), "VIOLATION")
        case["mutant"] = "duplicate_nonce"
        calls = [
            dict(case["operations"][1], id=f"e{i}", sequence=i, requires=[])
            for i in range(2)
        ]
        initial, history = core.simulate(case, calls)
        for checker in (core.check_history, oracle.check, smt.check):
            self.assertEqual(checker(initial, history, "LIN"), "VIOLATION")

    def test_negative_inheritance_separation_and_three_checker_agreement(self):
        case = inheritance_case()
        write, request = case["operations"]
        seed = policy.separating(case, write, request)
        self.assertEqual(seed["status"], "SAT")
        self.assertTrue(seed["before"])
        self.assertFalse(seed["after"])
        fixture = dict(case, relations=seed["relations"])
        initial, history = core.simulate(fixture, fixture["operations"])
        self.assertEqual(core.check_history(initial, history, "LIN"), "VIOLATION")
        self.assertEqual(oracle.check(initial, history, "LIN"), "VIOLATION")
        self.assertEqual(smt.check(initial, history, "LIN"), "VIOLATION")
        self.assertEqual(smt.check(initial, history, "SNAP"), "CONFORMING")
        result = core.run_case(case, "traceweaver")
        self.assertTrue(result["confirmed"])
        self.assertEqual(
            (result["replay_successes"], result["replay_attempts"]), (10, 10)
        )

    def test_absent_inheritance_edges_are_dependencies(self):
        case = inheritance_case()
        positive, negative = policy.cones(
            case["policy"], case["universe"], case["operations"][1]
        )
        self.assertIn(("member", "u", "staff"), positive)
        self.assertIn(("ban", "u", "o"), negative)
        write = dict(case["operations"][0], relation="member", resource="staff")
        read = dict(case["operations"][1], requires=[])
        self.assertFalse(policy.independent(write, read, case))

    def test_smt_large_history_and_causality(self):
        case = inheritance_case()
        seed = policy.separating(case, *case["operations"])
        fixture = dict(case, relations=seed["relations"])
        reads = [
            dict(case["operations"][1], id=f"r{i}", client=i + 1) for i in range(13)
        ]
        initial, history = core.simulate(fixture, [case["operations"][0], *reads])
        self.assertEqual(core.check_history(initial, history, "LIN"), "VIOLATION")
        self.assertEqual(oracle.check(initial, history, "LIN"), "VIOLATION")
        fixture["mutant"] = "correct"
        initial, history = core.simulate(fixture, [case["operations"][0], *reads])
        self.assertEqual(smt.check(initial, history, "LIN"), "CONFORMING")

    def test_all_paper_generation_configurations_execute(self):
        case = inheritance_case()
        for method in core.METHODS:
            result = core.run_case(copy.deepcopy(case), method)
            self.assertLessEqual(result["checked"], case["budget"])
            self.assertIn("confirmed", result)
