"""Tests for the daemon's fast path, its pf hook-up, russia mode and the matching CLI commands."""
import io
import ipaddress
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import novpn  # noqa: E402

GW = "192.168.0.1"
VPN_DNS = ("100.100.100.100", 53)


def answer(query, ips):
    _, _, qend = novpn.parse_question(query)
    records = b"".join(b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip) for ip in ips)
    return query[:2] + struct.pack("!HHHHH", 0x8180, 1, len(ips), 0, 0) + query[12:qend] + records


class RouteRun:
    def __init__(self):
        self.calls = []

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, "", "")

    def added(self):
        return [call[4] for call in self.calls if call[2] == "add"]


class FakeFirewall:
    def __init__(self):
        self.calls, self.hosts, self.active = [], set(), False

    def load(self, iface, networks4=(), networks6=()):
        self.calls.append(("load", iface, list(networks4), list(networks6)))
        self.active = iface is not None
        return self.active

    def add_hosts(self, ips):
        self.calls.append(("add", list(ips)))
        self.hosts.update(ips)

    def remove_hosts(self, ips):
        self.calls.append(("remove", list(ips)))
        self.hosts.difference_update(ips)

    def check(self):
        self.calls.append(("check",))
        return False

    def clear(self):
        self.calls.append(("clear",))

    def adopt(self, old):
        self.calls.append(("adopt", old))

    def snapshot(self):
        return {"active": self.active}

    def loads(self):
        return [call[1:] for call in self.calls if call[0] == "load"]


class FakeRussia:
    NETS = ["5.3.0.0/16", "95.0.0.0/8"]

    def __init__(self):
        self.calls, self.installed, self.updated = [], [], False

    def apply(self, enabled, gateway, iface=None):
        self.calls.append(("apply", enabled, gateway, iface))
        self.installed = list(self.NETS) if enabled and gateway else []
        return self.installed

    def covers(self, ip):
        return any(ipaddress.ip_address(ip) in ipaddress.ip_network(net) for net in self.installed)

    def ipv6(self):
        return ["2a00::/16"]

    def withdraw(self):
        self.calls.append(("withdraw",))
        self.installed = []

    def forget(self):
        self.calls.append(("forget",))
        self.installed = []

    def adopt_leftovers(self):
        self.calls.append(("adopt",))

    def maybe_refresh(self):
        self.calls.append(("refresh",))

    def take_update(self):
        updated, self.updated = self.updated, False
        return updated

    def snapshot(self):
        return {"networks": len(self.installed)}

    def applies(self):
        return [call[1:3] for call in self.calls if call[0] == "apply"]

    def sample(self, count):
        return self.installed[:count]


class DaemonTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.registry, self.resolver, self.state = root / "domains.txt", root / "resolver", root / "run" / "state.json"
        self.run, self.firewall, self.russia = RouteRun(), FakeFirewall(), FakeRussia()
        self.link = {"gateway": GW, "iface": "en0", "index": None, "dns": [(GW, 53)]}
        self.refreshes, self.flushes, self.now = 0, 0, 1000.0
        self.isp = {"site.example": ["151.101.1.1"], "www.site.example": ["151.101.65.1"],
                    "rusite.example": ["5.3.1.1"]}
        self.vpn = {"site.example": ["151.101.129.1"]}
        path = SimpleNamespace(current=None)

        def refresh():
            self.refreshes += 1
            path.current = dict(self.link) if self.link else None
            return path.current

        path.refresh = refresh
        self.daemon = novpn.Daemon(self.registry, resolver_dir=self.resolver, state_path=self.state,
                                   routes=novpn.RouteTable(run=self.run), path=path, flush_dns=self.count_flush,
                                   firewall=self.firewall, russia=self.russia, clock=lambda: self.now)
        self.daemon.forwarder._udp = self.upstream
        self.daemon.forwarder._system_dns = lambda: [VPN_DNS]

    def count_flush(self):
        self.flushes += 1

    def upstream(self, query, servers, iface_index=None, timeout=2.0):
        name = novpn.parse_question(query)[0]
        return answer(query, (self.vpn if servers == [VPN_DNS] else self.isp).get(name, []))

    def write_registry(self, text, mtime):
        self.registry.write_text(text)
        os.utime(self.registry, (mtime, mtime))

    def resolver_names(self):
        return sorted(path.name for path in self.resolver.iterdir())

    def state_json(self):
        return json.loads(self.state.read_text())

    def test_poll_applies_an_edit_without_the_network_check_and_primes_routes(self):
        self.daemon.tick()
        refreshes, flushes = self.refreshes, self.flushes
        self.write_registry("site.example\n", 1000)
        self.daemon.poll()
        self.assertEqual(self.resolver_names(), ["site.example"])
        self.assertEqual(self.refreshes, refreshes)
        self.assertEqual(self.flushes, flushes + 1)
        self.assertEqual(sorted(self.run.added()), ["151.101.1.1", "151.101.129.1", "151.101.65.1"])
        self.assertEqual(self.firewall.hosts, {"151.101.1.1", "151.101.129.1", "151.101.65.1"})
        self.assertEqual(self.state_json()["domains"], ["site.example"])
        self.daemon.poll()
        self.assertEqual(self.flushes, flushes + 1)

    def test_first_tick_loads_the_firewall_on_the_uplink(self):
        self.daemon.tick()
        self.assertEqual(self.firewall.loads(), [("en0", [], [])])
        self.assertEqual(self.russia.applies(), [(False, GW)])
        self.assertEqual(self.state_json()["firewall"], {"active": True})

    def test_russia_option_routes_networks_zones_and_skips_covered_hosts(self):
        self.write_registry("@russia\nrusite.example\n", 1000)
        self.daemon.tick()
        self.assertEqual(self.russia.applies()[-1], (True, GW))
        self.assertEqual(self.firewall.loads()[-1], ("en0", FakeRussia.NETS, ["2a00::/16"]))
        self.assertEqual(self.resolver_names(), ["ru", "rusite.example", "su", "xn--p1ai"])
        self.assertEqual(self.run.added(), [])
        self.assertEqual(self.state_json()["russia"], {"enabled": True, "networks": 2})
        self.write_registry("rusite.example\n", 2000)
        self.daemon.poll()
        self.assertEqual(self.russia.applies()[-1], (False, GW))
        self.assertEqual(self.firewall.loads()[-1], ("en0", [], []))
        self.assertEqual(self.resolver_names(), ["rusite.example"])
        self.assertEqual(self.run.added(), ["5.3.1.1"])

    def test_uplink_changes_move_routes_and_rules(self):
        self.write_registry("@russia\n", 1000)
        self.daemon.tick()
        self.daemon.routes.ensure("151.101.1.1", GW, "site.example")
        self.link = dict(self.link, gateway="10.0.0.1", iface="en1")
        self.daemon.tick()
        self.assertEqual(self.russia.applies()[-1], (True, "10.0.0.1"))
        self.assertEqual(self.firewall.loads()[-1], ("en1", FakeRussia.NETS, ["2a00::/16"]))
        self.assertIn(("remove", ["151.101.1.1"]), self.firewall.calls)
        self.link = None
        self.daemon.tick()
        self.assertEqual(self.russia.applies()[-1], (True, None))
        self.assertEqual(self.firewall.loads()[-1], (None, [], []))

    def test_refreshed_list_and_firewall_health_are_handled_on_ticks(self):
        self.write_registry("@russia\n", 1000)
        self.daemon.tick()
        applies = len(self.russia.applies())
        self.russia.updated = True
        self.daemon.tick()
        self.assertEqual(len(self.russia.applies()), applies + 1)
        self.assertIn(("refresh",), self.russia.calls)
        self.assertNotIn(("check",), self.firewall.calls)
        self.now += novpn.FIREWALL_CHECK_SECONDS + 1
        self.daemon.tick()
        self.assertIn(("check",), self.firewall.calls)

    def test_cleanup_and_leftovers_cover_firewall_and_russia(self):
        self.write_registry("@russia\n", 1000)
        self.daemon.tick()
        self.daemon.cleanup()
        self.assertIn(("clear",), self.firewall.calls)
        self.assertIn(("withdraw",), self.russia.calls)
        self.state.parent.mkdir(parents=True, exist_ok=True)
        self.state.write_text(json.dumps({"pid": 1, "routes": {}, "firewall": {"token": "5", "active": True}}))
        self.daemon.adopt_leftovers()
        self.assertIn(("adopt", {"token": "5", "active": True}), self.firewall.calls)
        self.assertIn(("adopt",), self.russia.calls)


class CliTest(unittest.TestCase):
    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = novpn.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.registry = Path(tmp.name) / "domains.txt"
        patcher = mock.patch.dict(os.environ, {"NOVPN_REGISTRY": str(self.registry)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_russia_on_and_off_edit_the_registry(self):
        with mock.patch.object(novpn, "daemon_state", return_value=None):
            self.cli("add", "ozon.ru")
            self.assertEqual(self.cli("russia", "on")[0], 0)
            self.assertIn("@russia", self.registry.read_text())
            code, out, err = self.cli("ls")
            self.assertEqual(out.split(), ["ozon.ru"])
            self.assertIn("russia mode on", err)
            self.assertEqual(self.cli("russia", "on")[0], 0)
            self.assertEqual(self.registry.read_text().count("@russia"), 1)
            self.cli("russia", "off")
            self.assertNotIn("@russia", self.registry.read_text())
            self.assertEqual(self.cli("rm", "ozon.ru")[0], 0)

    def test_options_are_not_domains(self):
        self.assertEqual(novpn.parse_registry("@russia\n@bogus\nozon.ru\n"), (["ozon.ru"], ["@bogus"]))
        self.assertEqual(novpn.parse_options("@russia # all of it\nozon.ru\n"), {"russia"})

    def test_add_waits_for_the_daemon_and_reports_the_time(self):
        states = [{"pid": 1, "domains": []}, {"pid": 1, "domains": []}, {"pid": 1, "domains": ["ozon.ru"]}]
        with mock.patch.object(novpn, "daemon_state", side_effect=states + states[-1:] * 10), \
                mock.patch.object(novpn.time, "sleep"):
            code, out, _ = self.cli("add", "ozon.ru")
        self.assertEqual(code, 0)
        self.assertRegex(out, r"applied in \d+\.\d s")

    def test_status_shows_russia_and_firewall(self):
        state = {"pid": 1, "domains": ["ru"], "gateway": GW, "iface": "en0", "dns": [GW], "routes": {},
                 "russia": {"enabled": True, "networks": 8662}, "firewall": {"active": True, "iface": "en0"}}
        with mock.patch.object(novpn, "daemon_state", return_value=state), \
                mock.patch.object(novpn, "tailscale_exit_node", return_value="my-exit-node"):
            code, out, _ = self.cli("status")
        self.assertEqual(code, 0)
        self.assertIn("russia     on, 8662 networks", out)
        self.assertIn("firewall   on", out)

    def test_cleanup_needs_root(self):
        with mock.patch.object(novpn.os, "geteuid", return_value=501):
            self.assertEqual(self.cli("cleanup")[0], 1)


if __name__ == "__main__":
    unittest.main()
