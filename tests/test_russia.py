"""Tests for novpn_russia: prefix lists, their weekly refresh and the routes made from them."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import novpn_russia as ru  # noqa: E402

GW = "192.168.0.1"


def v4_list(count=1200, extra=""):
    """count public /24 networks in 5.0.0.0/8 and beyond, ipverse style."""
    nets = [f"{5 + i // 65536}.{(i // 256) % 256}.{i % 256}.0/24" for i in range(0, count * 2, 2)]
    return "# Country: Russia (RU)\n#\n" + "\n".join(nets) + "\n" + extra


def v6_list(count=150):
    return "\n".join(f"2a00:{i * 2:x}::/32" for i in range(count)) + "\n"


class FakeKernel:
    """Route add/delete functions with the novpn_rtsock signatures."""

    def __init__(self, unroutable=()):
        self.routes = {}
        self.unroutable = set(unroutable)
        self.adds, self.deletes = [], []

    def add(self, networks, gateway, iface=None):
        self.adds.append(list(networks))
        routed = [net for net in networks if net not in self.unroutable]
        self.routes.update(dict.fromkeys(routed, (gateway, iface)))
        return routed, {net: "Network is unreachable" for net in networks if net in self.unroutable}

    def delete(self, networks):
        self.deletes.append(list(networks))
        for net in networks:
            self.routes.pop(net, None)
        return {}


class ParseTest(unittest.TestCase):
    def test_accepts_a_real_looking_list_and_collapses_it(self):
        nets = ru.parse_prefixes(v4_list(extra="5.0.1.0/24\n"), 4)
        self.assertIn("5.0.0.0/23", nets)
        self.assertEqual(len(ru.parse_prefixes(v6_list(), 6)), 150)

    def test_drops_private_shared_and_too_wide_networks(self):
        nets = ru.parse_prefixes(v4_list(extra="10.0.0.0/8\n0.0.0.0/1\n100.64.0.0/10\n4.0.0.0/7\n"), 4)
        self.assertEqual(len(nets), 1200)
        self.assertFalse({"10.0.0.0/8", "0.0.0.0/1", "100.64.0.0/10", "4.0.0.0/7"} & set(nets))

    def test_rejects_lists_that_look_wrong(self):
        for text in (v4_list(extra="junk\n"), v4_list(extra="5.0.0.1/24\n"), v4_list(extra="2a00::/32\n"),
                     v4_list(count=999), ""):
            with self.assertRaises(ValueError):
                ru.parse_prefixes(text, 4)

    def test_shipped_lists_are_valid(self):
        self.assertGreater(len(ru.parse_prefixes((ru.DATA_DIR / "ru-ipv4.txt").read_text(), 4)), 5000)
        self.assertGreater(len(ru.parse_prefixes((ru.DATA_DIR / "ru-ipv6.txt").read_text(), 6)), 1000)

    def test_index_answers_membership(self):
        index = ru.PrefixIndex(["5.3.0.0/16", "95.0.0.0/8"])
        self.assertEqual([ip in index for ip in ("5.3.200.1", "5.4.0.1", "95.255.255.255", "96.0.0.0", "x")],
                         [True, False, True, False, False])
        self.assertNotIn("1.1.1.1", ru.PrefixIndex())


class ModeTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.cache, self.data, self.record = root / "cache", root / "data", root / "run" / "russia-routes.json"
        self.data.mkdir()
        (self.data / "ru-ipv4.txt").write_text(v4_list())
        (self.data / "ru-ipv6.txt").write_text(v6_list())
        self.kernel = FakeKernel()
        self.downloads = []
        self.now = 10_000_000.0
        self.mode = self.make()

    def make(self):
        return ru.RussiaMode(self.record, cache_dir=self.cache, data_dir=self.data, add_routes=self.kernel.add,
                             delete_routes=self.kernel.delete, run=self.curl, clock=lambda: self.now)

    def curl(self, cmd):
        self.downloads.append(cmd)
        out = Path(cmd[cmd.index("-o") + 1])
        body = self.served.get(cmd[-1].rsplit("/", 1)[-1])
        if body is None:
            return subprocess.CompletedProcess(cmd, 22, "", "curl: (22) 404")
        out.write_text(body)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def test_apply_routes_every_network_and_records_them_first(self):
        installed = self.mode.apply(True, GW, "en0")
        self.assertEqual(len(installed), 1200)
        self.assertEqual(set(self.kernel.routes.values()), {(GW, "en0")})
        self.assertEqual(sorted(json.loads(self.record.read_text())), sorted(installed))
        self.assertIn("5.0.2.7", self.mode.index)
        self.assertNotIn("5.0.1.7", self.mode.index)
        self.assertEqual(len(self.mode.ipv6()), 150)
        self.assertEqual(self.mode.apply(True, GW, "en0"), installed)
        self.assertEqual(len(self.kernel.adds), 1)
        self.assertEqual(len(self.mode.sample(16)), 16)
        self.assertEqual(self.mode.sample(16)[0], installed[0])

    def test_same_router_on_another_interface_moves_every_route(self):
        self.mode.apply(True, GW, "en0")
        self.mode.apply(True, GW, "en7")
        self.assertEqual(set(self.kernel.routes.values()), {(GW, "en7")})
        self.assertEqual(len(self.kernel.deletes[0]), 1200)

    def test_new_gateway_moves_all_routes_and_off_removes_them(self):
        self.mode.apply(True, GW)
        self.mode.apply(True, "10.0.0.1")
        self.assertEqual(set(self.kernel.routes.values()), {("10.0.0.1", None)})
        self.assertEqual(len(self.kernel.deletes[0]), 1200)
        self.mode.apply(False, "10.0.0.1")
        self.assertEqual((self.kernel.routes, self.mode.installed, self.mode.gateway), ({}, [], None))
        self.assertFalse(self.record.exists())
        self.assertNotIn("5.0.2.7", self.mode.index)

    def test_offline_withdraws(self):
        self.mode.apply(True, GW)
        self.mode.apply(True, None)
        self.assertEqual(self.kernel.routes, {})
        self.mode.apply(True, GW)
        self.mode.withdraw()
        self.assertEqual(self.kernel.routes, {})

    def test_unroutable_networks_are_left_out_of_the_index(self):
        self.kernel.unroutable = {"5.0.0.0/24"}
        installed = self.mode.apply(True, GW)
        self.assertEqual(len(installed), 1199)
        self.assertNotIn("5.0.0.1", self.mode.index)

    def test_leftovers_of_a_crashed_run_are_deleted(self):
        self.mode.apply(True, GW)
        recorded = json.loads(self.record.read_text())
        fresh = self.make()
        fresh.adopt_leftovers()
        self.assertEqual(sorted(self.kernel.deletes[-1]), sorted(recorded))
        self.assertFalse(self.record.exists())
        fresh.adopt_leftovers()
        self.assertEqual(len(self.kernel.deletes), 1)

    def test_valid_cache_wins_over_the_shipped_copy(self):
        self.cache.mkdir()
        (self.cache / "ru-ipv4.txt").write_text(v4_list(count=1300))
        self.assertEqual(len(self.make().apply(True, GW)), 1300)
        (self.cache / "ru-ipv4.txt").write_text("garbage\n")
        self.kernel.routes.clear()
        self.assertEqual(len(self.make().apply(True, GW)), 1200)

    def test_refresh_keeps_the_old_list_when_a_download_is_bad(self):
        self.served = {"ipv4-aggregated.txt": v4_list(count=1300), "ipv6-aggregated.txt": "bad\n"}
        self.assertTrue(self.mode.refresh())
        self.assertEqual(len(ru.parse_prefixes((self.cache / "ru-ipv4.txt").read_text(), 4)), 1300)
        self.assertFalse((self.cache / "ru-ipv6.txt").exists())
        self.assertEqual(sorted(os.listdir(self.cache)), ["ru-ipv4.txt"])
        self.assertTrue(self.mode.take_update())
        self.assertFalse(self.mode.take_update())
        self.assertEqual(len(self.mode.apply(True, GW)), 1300)
        self.served = {}
        self.assertFalse(self.mode.refresh())
        self.assertFalse(self.mode.take_update())

    def test_refresh_runs_weekly_and_backs_off_after_failures(self):
        self.served = {}
        self.mode.maybe_refresh()
        self.mode.join_refresh()
        self.assertEqual(len(self.downloads), 2)
        self.mode.maybe_refresh()
        self.mode.join_refresh()
        self.assertEqual(len(self.downloads), 2)
        self.now += 3601
        self.served = {"ipv4-aggregated.txt": v4_list(), "ipv6-aggregated.txt": v6_list()}
        self.mode.maybe_refresh()
        self.mode.join_refresh()
        self.assertEqual(len(self.downloads), 4)
        os.utime(self.cache / "ru-ipv4.txt", (self.now, self.now))
        self.now += 2 * 86400
        self.mode.maybe_refresh()
        self.mode.join_refresh()
        self.assertEqual(len(self.downloads), 4)
        self.now += 6 * 86400
        self.mode.maybe_refresh()
        self.mode.join_refresh()
        self.assertEqual(len(self.downloads), 6)


if __name__ == "__main__":
    unittest.main()
