import itertools
import os
from pathlib import Path
import shutil
import unittest

from traceweaver import core
from traceweaver.native import cedar_target, openfga_target
from traceweaver.strategies import representative


CEDAR = os.environ.get("CEDAR_EXECUTABLE") or shutil.which("cedar")
LOCAL_CEDAR = Path(__file__).resolve().parents[1] / ".tools/cedar/cedar.exe"
if CEDAR is None and LOCAL_CEDAR.exists():
    CEDAR = str(LOCAL_CEDAR)


class ReductionTests(unittest.TestCase):
    def test_semantic_reduction_preserves_small_observable_classes(self):
        case = dict(
            id="classes",
            allow=[["v", "p"]],
            deny=[],
            contract="LIN",
            mutant="correct",
            universe={name: ["u", "v", "o", "p"] for name in ("allow", "deny")},
            operations=[],
        )
        operations = [
            dict(
                id="wa",
                kind="insert",
                relation="allow",
                principal="u",
                resource="o",
                client=0,
                sequence=0,
            ),
            dict(
                id="wb",
                kind="insert",
                relation="deny",
                principal="v",
                resource="p",
                client=1,
                sequence=0,
            ),
            dict(
                id="ra", kind="check", principal="u", resource="o", client=2, sequence=0
            ),
            dict(
                id="rb", kind="check", principal="v", resource="p", client=3, sequence=0
            ),
        ]
        classes, observed = {}, set()
        for order in itertools.permutations(operations):
            _, history = core.simulate(case, order)
            signature = tuple(
                sorted((e["id"], e["result"]) for e in history if e["kind"] == "check")
            )
            key = representative(order, case, "traceweaver")
            self.assertEqual(classes.setdefault(key, signature), signature)
            observed.add(signature)
        self.assertEqual(set(classes.values()), observed)


class NativeTests(unittest.TestCase):
    @unittest.skipUnless(
        CEDAR, "Install Cedar or set CEDAR_EXECUTABLE for native checks"
    )
    def test_live_cedar_attribute_update(self):
        case = dict(
            id="native-attribute",
            contract="LIN",
            mutant="correct",
            attributes={"u": {"level": 2}},
            policy={"attribute": ["$principal", "level", "ge", 1]},
            universe={"__attributes__": {"u": {"level": [0, 1, 2]}}},
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
        initial, history = cedar_target(CEDAR, output="runs/native-test-cedar")(
            case, case["operations"]
        )
        self.assertFalse(history[1]["result"])
        self.assertEqual(core.check_history(initial, history, "LIN"), "CONFORMING")

    @unittest.skipUnless(
        os.environ.get("TRACEWEAVER_OPENFGA_URL"),
        "Set sandbox TRACEWEAVER_OPENFGA_URL for live HTTP checks",
    )
    def test_live_openfga_acknowledged_revocation(self):
        case = dict(
            id="native-http",
            contract="UNKNOWN",
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
        initial, history = openfga_target(os.environ["TRACEWEAVER_OPENFGA_URL"])(
            case, case["operations"]
        )
        self.assertFalse(history[1]["result"])
        self.assertEqual(
            core.check_history(initial, history, "UNKNOWN"), "INCONCLUSIVE"
        )
