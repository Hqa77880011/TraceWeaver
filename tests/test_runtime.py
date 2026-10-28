import sys
import unittest
from pathlib import Path

from traceweaver import core
from traceweaver.runtime import command_target, threaded_target


class RuntimeTests(unittest.TestCase):
    def case(self, mutant):
        return dict(
            id="causal-revoke",
            family="revoke",
            allow=[["u", "o"]],
            deny=[],
            mutant=mutant,
            contract="LIN",
            budget=4,
            operations=[
                dict(
                    id="w",
                    client=0,
                    sequence=0,
                    kind="delete",
                    relation="allow",
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

    def test_threads_and_external_command_preserve_the_causal_witness(self):
        command = [
            sys.executable,
            str(Path(__file__).resolve().parents[1] / "examples/reference_target.py"),
        ]
        for target in (threaded_target(), command_target(command)):
            result = core.run_case(self.case("stale"), "traceweaver", target)
            self.assertTrue(result["confirmed"])
            self.assertTrue(result["reproduced"])
            self.assertFalse(
                core.run_case(self.case("correct"), "traceweaver", target)["found"]
            )


if __name__ == "__main__":
    unittest.main()
