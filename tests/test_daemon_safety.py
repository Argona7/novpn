"""Tests for the review fixes: interface moves, lost kernel routes, unreadable registries, shutdown and rm."""
import io
import os
import socket
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import novpn  # noqa: E402
import novpn_rtsock as rt  # noqa: E402
from test_daemon_fast import FakeFirewall, FakeRussia, RouteRun  # noqa: E402

GW = "192.168.0.1"


class SafetyTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.registry, self.resolver, self.state = root / "domains.txt", root / "resolver", root / "run" / "state.json"
        self.run, self.firewall, self.russia = RouteRun(), FakeFirewall(), FakeRussia()
        self.link = {"gateway": GW, "iface": "en0", "index": 15, "dns": [(GW, 53)]}
        self.kernel = {}  # address -> interface index the fake kernel reports
        self.lookups = []
        path = SimpleNamespace(current=None)

        def refresh():
            path.current = dict(self.link) if self.link else None
            return path.current

        def lookup(addresses):
            self.lookups.append(list(addresses))
            return {address: self.kernel.get(address, 15) for address in addresses}

        path.refresh = refresh
        self.daemon = novpn.Daemon(self.registry, resolver_dir=self.resolver, state_path=self.state,
                                   routes=novpn.RouteTable(run=self.run), path=path, flush_dns=lambda: None,
                                   firewall=self.firewall, russia=self.russia, lookup=lookup)
        self.daemon.forwarder.prime = lambda domain, deadline=None: None

    def write_registry(self, data, mtime):
        self.registry.write_bytes(data)
        os.utime(self.registry, (mtime, mtime))

    def test_same_router_on_another_interface_moves_routes_and_rules(self):
        self.write_registry(b"@russia\n", 1000)
        self.daemon.tick()
        self.link = dict(self.link, iface="en7", index=7)
        self.daemon.tick()
        self.assertEqual(self.russia.calls[-1], ("apply", True, GW, "en7"))
        self.assertEqual(self.firewall.loads()[-1][0], "en7")

    def test_routes_the_kernel_lost_are_put_back(self):
        self.write_registry(b"@russia\n", 1000)
        self.daemon.tick()
        self.daemon.routes.ensure("151.101.1.1", GW, "site.example", "en0")
        self.daemon.tick()
        self.assertEqual(self.lookups[-1], ["151.101.1.1", "5.3.0.0", "95.0.0.0"])
        self.assertIn("151.101.1.1", self.daemon.routes.routes)
        self.kernel["95.0.0.0"] = 22
        self.daemon.tick()
        self.assertEqual(self.daemon.routes.routes, {})
        self.assertIn(("forget",), self.russia.calls)
        self.assertNotIn(("withdraw",), self.russia.calls)
        self.assertEqual(self.russia.calls[-1], ("apply", True, GW, "en0"))

    def test_an_address_another_route_keeps_does_not_loop(self):
        self.write_registry(b"@russia\n", 1000)
        self.daemon.tick()
        self.kernel["95.0.0.0"] = 22
        self.daemon.tick()
        resets = self.russia.calls.count(("forget",))
        with self.assertLogs("novpn", "WARNING"):
            self.daemon.tick()
        self.daemon.tick()
        self.daemon.tick()
        self.assertEqual(self.russia.calls.count(("forget",)), resets)
        self.assertNotIn("95.0.0.0", self.lookups[-1])
        self.kernel["5.3.0.0"] = 22
        self.daemon.tick()
        self.assertEqual(self.russia.calls.count(("forget",)), resets + 1)

    def test_host_route_on_the_old_interface_is_moved(self):
        self.daemon.routes.ensure("151.101.1.1", GW, "site.example", "en0")
        self.assertTrue(self.daemon.routes.ensure("151.101.1.1", GW, "site.example", "en7"))
        self.assertEqual(self.run.calls[-1][-2:], ["-ifp", "en7"])

    def test_unanswered_lookups_change_nothing(self):
        self.daemon.tick()
        self.daemon.routes.ensure("151.101.1.1", GW, "site.example", "en0")
        self.daemon._lookup = lambda addresses: dict.fromkeys(addresses)
        self.daemon.tick()
        self.assertIn("151.101.1.1", self.daemon.routes.routes)

    def test_no_kernel_checks_without_an_interface_index(self):
        self.link["index"] = None
        self.daemon.tick()
        self.daemon.tick()
        self.assertEqual(self.lookups, [])

    def test_unreadable_registry_keeps_the_last_good_one_and_the_loop_alive(self):
        self.write_registry(b"site.example\n", 1000)
        self.daemon.tick()
        self.write_registry(b"site.example\n# \xcf\xf0\xe8\xe2\xe5\xf2\n", 2000)
        self.link = dict(self.link, gateway="10.0.0.1")
        with self.assertLogs("novpn", "WARNING"):
            self.daemon.tick()
        self.daemon.poll()
        self.assertEqual(self.daemon.domains, ("site.example",))
        self.assertEqual(self.russia.calls[-1][2], "10.0.0.1")

    def test_registry_symlinks_are_not_followed(self):
        secret = self.registry.parent / "secret"
        secret.write_text("not-a-domain line from a root-only file\n")
        self.registry.symlink_to(secret)
        with self.assertLogs("novpn", "WARNING") as logs:
            self.daemon.tick()
        self.assertNotIn("root-only", "\n".join(logs.output))
        self.assertEqual(self.daemon.domains, ())

    def test_closed_route_table_adds_nothing(self):
        self.daemon.cleanup()
        self.assertFalse(self.daemon.routes.ensure("151.101.1.1", GW, "site.example"))
        self.assertEqual(self.run.added(), [])

    def test_priming_stops_at_its_deadline(self):
        primed = []
        self.daemon.forwarder.prime = lambda domain, deadline=None: primed.append(domain)
        self.write_registry(b"a.example\nb.example\n", 1000)
        with mock.patch.object(novpn, "PRIME_SECONDS", -1):
            self.daemon.tick()
        self.assertEqual(primed, [])
        self.assertTrue(self.state.exists())


class RouteTableFirewallTest(unittest.TestCase):
    def test_pinned_and_dropped_hosts_reach_the_firewall(self):
        firewall = FakeFirewall()
        routes = novpn.RouteTable(run=RouteRun())
        routes.firewall = firewall
        routes.ensure("151.101.1.1", GW, "a.example")
        routes.ensure("151.101.1.1", GW, "b.example")
        routes.ensure("151.101.1.2", GW, "a.example")
        routes.ensure("151.101.1.2", "10.0.0.1", "a.example")
        self.assertEqual(firewall.calls, [("add", ["151.101.1.1"]), ("add", ["151.101.1.2"])])
        routes.forget_domains({"b.example"})
        self.assertEqual(routes.flush(), 2)
        self.assertEqual(firewall.calls[-1], ("remove", ["151.101.1.1", "151.101.1.2"]))
        routes.remove(["9.9.9.9"])
        self.assertEqual(len(firewall.calls), 3)


class PrimeTest(unittest.TestCase):
    def test_each_query_is_short_and_the_deadline_is_kept(self):
        asked = []

        def upstream(query, servers, iface_index=None, timeout=2.0):
            asked.append((servers, timeout))
            raise OSError("timed out")

        uplink = {"gateway": GW, "iface": "en0", "index": 15, "dns": [(GW, 53), ("77.88.8.8", 53), ("1.1.1.1", 53)]}
        forwarder = novpn.Forwarder(novpn.RouteTable(run=RouteRun()), lambda: ("site.example",), lambda: uplink,
                                    udp=upstream)
        forwarder._system_dns = lambda: [("100.100.100.100", 53), ("100.100.100.101", 53)]
        forwarder.prime("site.example")
        self.assertEqual(asked, [([(GW, 53), ("77.88.8.8", 53)], 1.0), ([("100.100.100.100", 53)], 1.0)] * 2)
        asked.clear()
        forwarder.prime("site.example", deadline=0.0)
        self.assertEqual(asked, [])


class RunDaemonTest(unittest.TestCase):
    def test_refuses_to_start_next_to_a_live_daemon(self):
        with mock.patch.object(novpn.os, "geteuid", return_value=0), \
                mock.patch.object(novpn, "daemon_state", return_value={"pid": os.getpid() + 1}), \
                mock.patch.object(novpn, "start_dns_servers", side_effect=AssertionError("started")), \
                mock.patch.object(novpn.logging, "basicConfig"), \
                self.assertLogs("novpn", "ERROR"):
            self.assertEqual(novpn.run_daemon("/nonexistent/domains.txt"), 1)


class RmTest(unittest.TestCase):
    def test_rm_says_when_russia_mode_still_sends_a_site_direct(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"NOVPN_REGISTRY": str(Path(tmp) / "domains.txt")}), \
                mock.patch.object(novpn, "daemon_state", return_value=None):
            out = io.StringIO()
            with redirect_stdout(out), redirect_stderr(io.StringIO()):
                novpn.main(["add", "ozon.ru", "2ip.io"])
                novpn.main(["russia", "on"])
                self.assertEqual(novpn.main(["rm", "ozon.ru", "2ip.io"]), 0)
            self.assertIn("ozon.ru: still direct while russia mode is on", out.getvalue())
            self.assertNotIn("2ip.io: still direct", out.getvalue())

    def test_rm_checks_russian_networks_for_non_russian_zones(self):
        def resolve(host, *_):
            ip = {"vk.com": "87.240.132.72", "2ip.io": "188.40.167.81"}[host]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 443))]

        with mock.patch.object(novpn.socket, "getaddrinfo", side_effect=resolve):
            self.assertEqual(novpn.still_direct(["vk.com", "2ip.io", "sub.ozon.ru"]), ["vk.com", "sub.ozon.ru"])

    def test_cli_survives_an_undecodable_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = Path(tmp) / "domains.txt"
            registry.write_bytes(b"ozon.ru # \xcf\xf0\n")
            err = io.StringIO()
            with mock.patch.dict(os.environ, {"NOVPN_REGISTRY": str(registry)}), \
                    redirect_stdout(io.StringIO()), redirect_stderr(err):
                self.assertEqual(novpn.main(["ls"]), 1)
            self.assertIn("save it as UTF-8", err.getvalue())


class FakeRouteSocket:
    """Answers RTM_GET like the kernel, with other processes' messages mixed in."""

    def __init__(self, answers):
        self.answers = answers  # address -> interface index, 0 for ESRCH, None for silence
        self.queue = []

    def send(self, msg):
        address = socket.inet_ntoa(msg[rt.HEADER.size + 4:rt.HEADER.size + 8])
        fields = list(rt.HEADER.unpack_from(msg))
        answer = self.answers[address]
        if answer == 0:
            raise OSError(3, "No such process")
        noise = list(fields)
        noise[6] = os.getpid() + 1
        self.queue.append(rt.HEADER.pack(*noise))
        if answer is not None:
            fields[3], fields[6] = answer, os.getpid()  # the kernel stamps the sender's pid on the reply
            self.queue.append(rt.HEADER.pack(*fields) + msg[rt.HEADER.size:])
        else:
            self.queue.append(None)

    def recv(self, size):
        reply = self.queue.pop(0)
        if reply is None:
            raise socket.timeout("timed out")
        return reply


class RouteSocketTest(unittest.TestCase):
    def test_interface_is_pinned_with_a_link_sockaddr(self):
        msg = rt.route_message(rt.RTM_ADD, "5.3.0.0/16", GW, iface="lo0")
        addrs = rt.HEADER.unpack_from(msg)[5]
        self.assertEqual(addrs, rt.RTA_DST | rt.RTA_GATEWAY | rt.RTA_NETMASK | rt.RTA_IFP)
        self.assertEqual(len(msg), 92 + 3 * 16 + 20)
        size, family, index, _, nlen, _, _, name = rt.SOCKADDR_DL.unpack(msg[-20:])
        self.assertEqual((size, family, index, name[:nlen]), (20, socket.AF_LINK, socket.if_nametoindex("lo0"), b"lo0"))

    def test_lookup_reads_only_its_own_answers(self):
        sock = FakeRouteSocket({"5.3.0.0": 15, "8.8.8.8": 22, "9.9.9.9": 0, "1.1.1.1": None})
        found = rt.route_interfaces(["5.3.0.0", "8.8.8.8", "9.9.9.9", "1.1.1.1"], sock=sock)
        self.assertEqual(found, {"5.3.0.0": 15, "8.8.8.8": 22, "9.9.9.9": 0, "1.1.1.1": None})


if __name__ == "__main__":
    unittest.main()
