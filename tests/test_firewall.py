import unittest
from unittest.mock import patch

from nextguard import firewall


class Result:
    def __init__(self, returncode=0, stdout=""):
        self.returncode, self.stdout = returncode, stdout


class FirewallTests(unittest.TestCase):
    @patch("nextguard.firewall.require_tools")
    @patch("nextguard.firewall.run")
    def test_population_precedes_swap_and_rules_are_drop(self, run, _):
        run.side_effect = lambda argv, **kw: Result(1 if "-C" in argv or "-nL" in argv else 0)
        firewall.apply(["192.0.2.1/32"])
        calls = run.call_args_list
        restore = next(c for c in calls if c.args[0] == ["ipset", "restore"])
        self.assertIn("add nextguard_tmp_v4 192.0.2.1/32", restore.kwargs["stdin"])
        swap_index = next(i for i,c in enumerate(calls) if c.args[0][:2] == ["ipset", "swap"])
        restore_index = calls.index(restore)
        self.assertLess(restore_index, swap_index)
        flattened = [c.args[0] for c in calls]
        self.assertTrue(any("DROP" in x for x in flattened))
        self.assertFalse(any("REJECT" in x for x in flattened))


if __name__ == "__main__":
    unittest.main()
