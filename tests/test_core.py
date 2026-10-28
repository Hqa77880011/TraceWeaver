import unittest

from traceweaver import core


def stale_history():
    initial = {"allow": {("u", "o")}, "deny": set()}
    history = [
        dict(
            id="w",
            client=0,
            sequence=0,
            kind="delete",
            relation="allow",
            principal="u",
            resource="o",
            start=0,
            end=1,
        ),
        dict(
            id="r",
            client=1,
            sequence=0,
            kind="check",
            principal="u",
            resource="o",
            start=2,
            end=3,
            result=True,
            revision=0,
        ),
    ]
    return initial, history


class TraceWeaverTests(unittest.TestCase):
    def test_stale_lin_is_invalid_but_named_old_snapshot_is_valid(self):
        initial, history = stale_history()
        self.assertEqual(core.check_history(initial, history, "LIN"), "VIOLATION")
        self.assertEqual(core.check_history(initial, history, "SNAP"), "CONFORMING")
        history[1]["min_revision"] = 1
        self.assertEqual(core.check_history(initial, history, "AT_LEAST"), "VIOLATION")

    def test_missing_snapshot_evidence_is_inconclusive(self):
        initial, history = stale_history()
        del history[1]["revision"]
        self.assertEqual(core.check_history(initial, history, "SNAP"), "INCONCLUSIVE")

    def test_overlapping_check_can_legally_precede_revoke(self):
        initial, history = stale_history()
        history[1].update(start=0, end=3)
        self.assertEqual(core.check_history(initial, history, "LIN"), "CONFORMING")

    def test_causal_edges_cannot_be_reordered_by_checker(self):
        initial, history = stale_history()
        history[1].update(start=0, end=3, requires=["w"])
        self.assertEqual(core.check_history(initial, history, "LIN"), "VIOLATION")


if __name__ == "__main__":
    unittest.main()
