"""Tests for novpn_pf: the anchor ruleset, the enable token and live table updates."""
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import novpn_pf as pf  # noqa: E402

A = ["/sbin/pfctl", "-a", pf.ANCHOR]


class FakePfctl:
    """Stands in for subprocess.run on /sbin/pfctl."""

    def __init__(self):
        self.calls = []
        self.info = "Status: Enabled for 0 days 00:01:02           Debug: Urgent\n"
        self.rules = "block return out quick on ! en0 inet from any to <novpn>\n"
        self.enable_code = 0

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        args = cmd[1:]
        if args == ["-E"]:
            err = "No ALTQ support in kernel\nALTQ related functions disabled\npf enabled\nToken : 1844674407\n"
            return subprocess.CompletedProcess(cmd, self.enable_code, "", err if self.enable_code == 0 else "denied")
        if args == ["-s", "info"]:
            return subprocess.CompletedProcess(cmd, 0, self.info, "")
        if args[-2:] == ["-s", "rules"]:
            return subprocess.CompletedProcess(cmd, 0, self.rules, "")
        return subprocess.CompletedProcess(cmd, 0, "", "")


class RulesetTest(unittest.TestCase):
    def test_three_rules_around_the_uplink(self):
        self.assertEqual(pf.ruleset("en0", "/run/v4", "/run/v6"), (
            'table <novpn> persist file "/run/v4"\n'
            'table <novpn6> persist file "/run/v6"\n'
            "block return out quick on ! en0 inet from any to <novpn>\n"
            "block return out quick on en0 inet from ! (en0) to <novpn>\n"
            "block return out quick on ! en0 inet6 from any to <novpn6>\n"
        ))

    def test_rejects_odd_interface_names(self):
        for iface in ("en0; pass all", "", "EN0", "en"):
            with self.assertRaises(ValueError):
                pf.ruleset(iface, "/v4", "/v6")


class FirewallTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name) / "run"
        self.pfctl = FakePfctl()
        self.fw = pf.Firewall(self.dir, run=self.pfctl)

    def test_load_enables_pf_once_and_writes_tables_and_rules(self):
        self.fw.add_hosts(["93.184.216.34"])
        self.assertEqual(self.pfctl.calls, [])
        self.assertTrue(self.fw.load("en0", ["5.3.0.0/16"], ["2a00::/16"]))
        conf = self.dir / "pf.conf"
        self.assertEqual(self.pfctl.calls, [["/sbin/pfctl", "-E"], A + ["-f", str(conf)]])
        self.assertEqual(self.fw.token, "1844674407")
        self.assertEqual((self.dir / "pf-v4.txt").read_text(), "5.3.0.0/16\n93.184.216.34\n")
        self.assertEqual((self.dir / "pf-v6.txt").read_text(), "2a00::/16\n")
        self.assertEqual(conf.read_text(), pf.ruleset("en0", self.dir / "pf-v4.txt", self.dir / "pf-v6.txt"))
        self.assertTrue(self.fw.load("en0", ["5.3.0.0/16"], ["2a00::/16"]))
        self.assertEqual(len(self.pfctl.calls), 2)
        self.fw.load("en1", ["5.3.0.0/16"], ["2a00::/16"])
        self.assertEqual(self.pfctl.calls[-1], A + ["-f", str(conf)])
        self.assertEqual(self.pfctl.calls.count(["/sbin/pfctl", "-E"]), 1)

    def test_hosts_follow_into_the_live_table(self):
        self.fw.load("en0")
        self.fw.add_hosts(["93.184.216.34", "93.184.216.35"])
        self.fw.add_hosts(["93.184.216.34"])
        self.fw.remove_hosts(["93.184.216.35", "1.1.1.1"])
        self.assertEqual(self.pfctl.calls[2:], [
            A + ["-t", "novpn", "-T", "add", "93.184.216.34", "93.184.216.35"],
            A + ["-t", "novpn", "-T", "delete", "93.184.216.35"],
        ])
        self.assertEqual(self.fw.hosts, {"93.184.216.34"})

    def test_offline_flushes_the_anchor_and_keeps_the_token(self):
        self.fw.load("en0", ["5.3.0.0/16"])
        self.assertFalse(self.fw.load(None))
        self.assertEqual(self.pfctl.calls[-2:], [A + ["-F", "rules"], A + ["-F", "Tables"]])
        self.assertFalse(self.fw.active)
        self.assertEqual(self.fw.token, "1844674407")
        self.fw.add_hosts(["93.184.216.34"])
        self.assertEqual(len(self.pfctl.calls), 4)

    def test_check_repairs_a_disabled_pf_or_an_emptied_anchor(self):
        self.fw.load("en0", ["5.3.0.0/16"])
        self.assertFalse(self.fw.check())
        self.pfctl.rules = ""
        self.assertTrue(self.fw.check())
        self.assertEqual(self.pfctl.calls[-1][-2:], ["-f", str(self.dir / "pf.conf")])
        self.pfctl.rules = "block ...\n"
        self.pfctl.info = "Status: Disabled\n"
        self.assertTrue(self.fw.check())
        self.assertEqual(self.pfctl.calls.count(["/sbin/pfctl", "-E"]), 2)

    def test_check_does_nothing_while_offline(self):
        self.assertFalse(self.fw.check())
        self.assertEqual(self.pfctl.calls, [])

    def test_clear_flushes_and_hands_back_the_token(self):
        self.fw.load("en0", ["5.3.0.0/16"])
        self.fw.add_hosts(["93.184.216.34"])
        self.fw.clear()
        self.assertEqual(self.pfctl.calls[-3:], [
            A + ["-F", "rules"], A + ["-F", "Tables"], ["/sbin/pfctl", "-X", "1844674407"]])
        self.assertEqual((self.fw.token, self.fw.active, self.fw.hosts), (None, False, set()))
        self.assertEqual(list(self.dir.iterdir()), [])

    def test_adopt_releases_a_crashed_run(self):
        self.fw.adopt({"token": "77", "active": True})
        self.assertEqual(self.pfctl.calls, [A + ["-F", "rules"], A + ["-F", "Tables"], ["/sbin/pfctl", "-X", "77"]])
        self.fw.adopt({})
        self.assertEqual(self.pfctl.calls[-2:], [A + ["-F", "rules"], A + ["-F", "Tables"]])

    def test_failed_enable_loads_nothing(self):
        self.pfctl.enable_code = 1
        self.assertFalse(self.fw.load("en0", ["5.3.0.0/16"]))
        self.assertEqual(self.pfctl.calls, [["/sbin/pfctl", "-E"]])
        self.assertEqual(self.fw.snapshot(), {"active": False, "iface": "en0", "token": None})


if __name__ == "__main__":
    unittest.main()
