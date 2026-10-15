"""Tests for novpn. Run: python3 -m unittest discover -s tests (also under /usr/bin/python3)."""
import io
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
NETSTAT = """\
Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            link#22            UCSg                utun4
default            192.168.0.1        UGScIg                en0
203.0.113.9        link#22            UHWIig              utun4
100.64/10          link#22            UCS                 utun4
127                127.0.0.1          UCS                   lo0
192.168.0          link#15            UCS                   en0      !
"""
NWI = """\
Network information

IPv4 network interface information
   utun4 : flags      : 0x7 (IPv4,IPv6,DNS)
     en0 : flags      : 0x5 (IPv4,DNS)

Network interfaces: utun4 en0
"""


class FakeRun:
    """Stands in for subprocess.run: records commands and returns canned output."""

    def __init__(self, outputs=None, route_errors=None):
        self.calls = []
        self.outputs = outputs or {}
        self.route_errors = route_errors or {}

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        if cmd[0] == "/sbin/route" and cmd[2] in self.route_errors:
            out, err = self.route_errors[cmd[2]]
            return subprocess.CompletedProcess(cmd, 1, out, err)
        return subprocess.CompletedProcess(cmd, 0, self.outputs.get(cmd[0], ""), "")

    def route_calls(self, verb):
        return [call[4:] for call in self.calls if call[0] == "/sbin/route" and call[2] == verb]


def encode_name(name):
    return b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\0"


def make_answer(query, ips, cname=None):
    """Upstream-style reply: optional CNAME, then A records, all owner names compressed."""
    _, _, qend = novpn.parse_question(query)
    records, owner, count = b"", b"\xc0\x0c", 0
    if cname:
        target = encode_name(cname)
        records += owner + struct.pack("!HHIH", 5, 1, 60, len(target)) + target
        owner = struct.pack("!H", 0xC000 | (qend + 12))
        count += 1
    for ip in ips:
        records += owner + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
        count += 1
    return query[:2] + struct.pack("!HHHHH", 0x8180, 1, count, 0, 0) + query[12:qend] + records


class DomainTest(unittest.TestCase):
    def test_normalizes_urls_wildcards_and_idn(self):
        cases = {
            "Gosuslugi.RU": "gosuslugi.ru",
            "https://www.ozon.ru/product/1?x=2#y": "ozon.ru",
            "http://user:pw@Lk.Sber.ru:8443/": "lk.sber.ru",
            "*.example.ru": "example.ru",
            "example.ru.": "example.ru",
            "госуслуги.рф": "xn--c1aapkosapc.xn--p1ai",
            "рф": "xn--p1ai",
            "ru": "ru",
            "www.ru": "www.ru",
        }
        for raw, want in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(novpn.normalize_domain(raw), want)

    def test_rejects_paths_ips_and_reserved_names(self):
        for raw in ("", "  ", "..", "../etc/sudoers", "a..b", "-bad.ru", "bad-.ru", "bad_name.ru",
                    "*example.ru", "1.2.3.4", "x" * 64 + ".ru", "localhost", "printer.local",
                    "box.example-tailnet.ts.net", "4.3.2.1.in-addr.arpa"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                novpn.normalize_domain(raw)

    def test_match_prefers_the_most_specific_entry(self):
        domains = ["ru", "example.ru"]
        self.assertEqual(novpn.match_domain("a.b.example.ru.", domains), "example.ru")
        self.assertEqual(novpn.match_domain("EXAMPLE.RU", domains), "example.ru")
        self.assertEqual(novpn.match_domain("notexample.ru", domains), "ru")
        self.assertIsNone(novpn.match_domain("example.com", domains))


class RegistryTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.path = Path(tmp.name) / "cfg" / "domains.txt"

    def test_parse_skips_comments_duplicates_and_junk(self):
        text = "# header\n\nexample.ru  # bank\nwww.example.ru\n*.ozon.ru\nnot a domain\n"
        self.assertEqual(novpn.parse_registry(text), (["example.ru", "ozon.ru"], ["not a domain"]))

    def test_add_and_remove_keep_comments(self):
        result = novpn.registry_add(self.path, ["https://www.ozon.ru/x", "ozon.ru", "рф", "../x"])
        self.assertEqual(result, (["ozon.ru", "xn--p1ai"], ["ozon.ru"], ["../x"]))
        self.assertTrue(self.path.read_text().startswith("# novpn"))
        self.assertEqual(novpn.registry_add(self.path, ["OZON.ru"])[:2], ([], ["ozon.ru"]))
        self.assertEqual(novpn.registry_remove(self.path, ["www.ozon.ru", "nope.ru"]), (["ozon.ru"], ["nope.ru"]))
        self.assertEqual(novpn.read_registry(self.path), (["xn--p1ai"], []))
        self.assertTrue(self.path.read_text().startswith("# novpn"))


class ResolverDirTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name) / "resolver"
        self.dir.mkdir()
        (self.dir / "corp.example").write_text("nameserver 10.0.0.53\n")
        (self.dir / "taken.ru").write_text("nameserver 10.0.0.53\n")

    def test_sync_writes_and_removes_only_its_own_files(self):
        sync = novpn.sync_resolver_dir
        self.assertEqual(sync(self.dir, ["example.ru", "ru", "taken.ru"]), (["example.ru", "ru"], [], ["taken.ru"]))
        self.assertEqual((self.dir / "ru").read_text(), "# managed by novpn\nnameserver 127.0.0.1\nport 53535\n")
        self.assertEqual(sync(self.dir, ["example.ru", "ru"]), ([], [], []))
        self.assertEqual(sync(self.dir, ["ru"]), ([], ["example.ru"], []))
        sync(self.dir, [])
        self.assertEqual(sorted(p.name for p in self.dir.iterdir()), ["corp.example", "taken.ru"])
        self.assertEqual((self.dir / "taken.ru").read_text(), "nameserver 10.0.0.53\n")


class DnsCodecTest(unittest.TestCase):
    def test_query_roundtrip(self):
        query = novpn.build_query("WWW.Example.ru", novpn.QTYPE_A, qid=0xBEEF)
        self.assertEqual(novpn.parse_question(query), ("www.example.ru", novpn.QTYPE_A, len(query)))
        self.assertEqual(query[:2], b"\xbe\xef")

    def test_answer_ipv4s_follows_a_compressed_cname_chain(self):
        query = novpn.build_query("www.example.ru", novpn.QTYPE_A)
        answer = make_answer(query, ["93.184.216.34", "10.0.0.1"], cname="cdn.example.net")
        self.assertEqual(novpn.answer_ipv4s(answer), ["93.184.216.34", "10.0.0.1"])

    def test_compression_loops_and_truncation_are_rejected(self):
        loop = struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c\x00\x01\x00\x01"
        with self.assertRaises(ValueError):
            novpn.parse_question(loop)
        with self.assertRaises(novpn.DNS_ERRORS):
            novpn.parse_question(novpn.build_query("example.ru", novpn.QTYPE_A)[:15])

    def test_empty_and_servfail_replies_echo_the_question(self):
        query = novpn.build_query("example.ru", novpn.QTYPE_AAAA, qid=7)
        for reply, rcode in ((novpn.nodata_response(query), 0), (novpn.servfail_response(query), 2)):
            qid, flags, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", reply[:12])
            self.assertEqual((qid, qdcount, ancount, nscount, arcount), (7, 1, 0, 0, 0))
            self.assertTrue(flags & 0x8000)  # QR
            self.assertTrue(flags & 0x0100)  # RD copied
            self.assertEqual(flags & 0xF, rcode)
            self.assertEqual(reply[12:], query[12:])


class UplinkTest(unittest.TestCase):
    def test_picks_the_first_non_tunnel_default_in_service_order(self):
        self.assertEqual(novpn.physical_route(NETSTAT, NWI), (GW, "en0"))
        self.assertEqual(novpn.physical_route(NETSTAT, ""), (GW, "en0"))
        multi = NETSTAT + "default            10.0.0.1           UGScIg                en7\n"
        self.assertEqual(novpn.physical_route(multi, "Network interfaces: utun4 en7 en0\n"), ("10.0.0.1", "en7"))
        self.assertIsNone(novpn.physical_route("default            link#22            UCSg      utun4\n", NWI))

    def test_refresh_asks_for_router_dns_once_per_uplink(self):
        run = FakeRun(outputs={"/usr/sbin/netstat": NETSTAT, "/usr/sbin/scutil": NWI, "/usr/sbin/ipconfig": GW + "\n"})
        path = novpn.PhysicalPath(run=run)
        current = path.refresh()
        self.assertEqual((current["gateway"], current["iface"]), (GW, "en0"))
        self.assertEqual(current["dns"], [(GW, 53), ("77.88.8.8", 53), ("1.1.1.1", 53)])
        path.refresh()
        self.assertEqual(sum(call[0] == "/usr/sbin/ipconfig" for call in run.calls), 1)


class RouteTableTest(unittest.TestCase):
    def setUp(self):
        self.now = [1000.0]
        self.run = FakeRun()
        self.routes = novpn.RouteTable(run=self.run, clock=lambda: self.now[0])

    def test_adds_once_and_moves_to_a_new_gateway(self):
        self.assertTrue(self.routes.ensure("93.184.216.34", GW, "example.ru"))
        self.assertFalse(self.routes.ensure("93.184.216.34", GW, "example.ru"))
        self.assertTrue(self.routes.ensure("93.184.216.34", "10.0.0.1", "example.ru"))
        self.assertEqual(self.run.route_calls("add"), [["93.184.216.34", GW], ["93.184.216.34", "10.0.0.1"]])

    def test_existing_kernel_route_is_changed_instead(self):
        run = FakeRun(route_errors={"add": ("add host 1.2.3.4: gateway 192.168.0.1: File exists\n", "")})
        routes = novpn.RouteTable(run=run)
        self.assertTrue(routes.ensure("1.2.3.4", GW, "example.ru"))
        self.assertEqual(run.route_calls("change"), [["1.2.3.4", GW]])

    def test_failed_route_is_not_recorded(self):
        run = FakeRun(route_errors={"add": ("", "route: writing to routing socket: Operation not permitted\n")})
        routes = novpn.RouteTable(run=run)
        self.assertFalse(routes.ensure("1.2.3.4", GW, "example.ru"))
        self.assertEqual(routes.routes, {})

    def test_forget_expire_and_flush(self):
        self.routes.ensure("1.1.1.1", GW, "a.ru")
        self.routes.ensure("2.2.2.2", GW, "a.ru")
        self.routes.ensure("2.2.2.2", GW, "b.ru")
        self.assertEqual(self.routes.forget_domains({"a.ru"}), 1)  # 2.2.2.2 still serves b.ru
        self.assertEqual(self.run.route_calls("delete"), [["1.1.1.1"]])
        self.now[0] += novpn.ROUTE_TTL + 1
        self.routes.ensure("3.3.3.3", GW, "b.ru")
        self.assertEqual(self.routes.expire(novpn.ROUTE_TTL), 1)  # 2.2.2.2 unseen for too long
        self.assertEqual(list(self.routes.routes), ["3.3.3.3"])
        self.assertEqual(self.routes.flush(), 1)
        self.assertEqual(self.routes.routes, {})


class ForwarderTest(unittest.TestCase):
    """Real UDP/TCP listeners on 127.0.0.1 with a fake upstream; only the route command is faked."""

    def setUp(self):
        self.upstream_queries = []

        def upstream(query, tcp=False):
            self.upstream_queries.append(query)
            return make_answer(query, ["93.184.216.34", "10.1.2.3"], cname="edge.cdn.example.net")

        up = novpn.start_dns_servers(SimpleNamespace(handle=upstream), host="127.0.0.1", port=0)
        self.run = FakeRun()
        uplink = {"gateway": GW, "iface": "en0", "index": None, "dns": [("127.0.0.1", up[0].server_address[1])]}
        self.forwarder = novpn.Forwarder(novpn.RouteTable(run=self.run), lambda: ("example.ru",), lambda: uplink)
        servers = up + novpn.start_dns_servers(self.forwarder, host="127.0.0.1", port=0)
        self.port = servers[-1].server_address[1]
        for server in servers:
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)

    def ask(self, name, qtype, tcp=False):
        query = novpn.build_query(name, qtype)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
            sock.settimeout(5)
            if tcp:
                sock.connect(("127.0.0.1", self.port))
                sock.sendall(struct.pack("!H", len(query)) + query)
                return novpn._recv_exact(sock, struct.unpack("!H", novpn._recv_exact(sock, 2))[0])
            sock.sendto(query, ("127.0.0.1", self.port))
            return sock.recvfrom(65535)[0]

    def test_listed_name_pins_public_ips_before_answering(self):
        reply = self.ask("www.example.ru", novpn.QTYPE_A)
        self.assertEqual(novpn.answer_ipv4s(reply), ["93.184.216.34", "10.1.2.3"])
        self.assertEqual(self.run.route_calls("add"), [["93.184.216.34", GW, "-ifp", "en0"]])

    def test_listed_ipv6_and_https_records_come_back_empty(self):
        for qtype in (novpn.QTYPE_AAAA, novpn.QTYPE_HTTPS):
            flags, _, ancount = struct.unpack("!HHH", self.ask("example.ru", qtype)[2:8])
            self.assertEqual((flags & 0xF, ancount), (0, 0))
        self.assertEqual(self.upstream_queries, [])

    def test_unlisted_name_is_forwarded_without_routes(self):
        self.assertEqual(novpn.answer_ipv4s(self.ask("example.com", novpn.QTYPE_A)), ["93.184.216.34", "10.1.2.3"])
        self.assertEqual(self.run.calls, [])

    def test_tcp_queries_work_too(self):
        reply = self.ask("api.example.ru", novpn.QTYPE_A, tcp=True)
        self.assertEqual(novpn.answer_ipv4s(reply), ["93.184.216.34", "10.1.2.3"])
        self.assertEqual(self.run.route_calls("add"), [["93.184.216.34", GW, "-ifp", "en0"]])

    def test_dead_upstream_gives_servfail_and_garbage_is_dropped(self):
        def down(*_):
            raise OSError("unreachable")

        forwarder = novpn.Forwarder(novpn.RouteTable(run=self.run), lambda: ("example.ru",), lambda: None, udp=down)
        reply = forwarder.handle(novpn.build_query("example.ru", novpn.QTYPE_A))
        self.assertEqual(struct.unpack("!H", reply[2:4])[0] & 0xF, 2)
        self.assertIsNone(forwarder.handle(b"\x00\x01"))


class DaemonTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        self.registry = root / "domains.txt"
        self.resolver = root / "resolver"
        self.state = root / "run" / "state.json"
        self.run = FakeRun()
        self.dns_flushes = 0
        self.link = {"gateway": GW, "iface": "en0", "index": None, "dns": [(GW, 53)]}
        path = SimpleNamespace(current=None)

        def refresh():
            path.current = dict(self.link) if self.link else None
            return path.current

        path.refresh = refresh
        self.daemon = novpn.Daemon(self.registry, resolver_dir=self.resolver, state_path=self.state,
                                   routes=novpn.RouteTable(run=self.run), path=path, flush_dns=self.count_flush,
                                   firewall=novpn.novpn_pf.Firewall(root / "run", run=self.run))
        self.daemon.forwarder.prime = lambda domain, deadline=None: None  # no real DNS from unit tests

    def count_flush(self):
        self.dns_flushes += 1

    def write_registry(self, text, mtime):
        self.registry.write_text(text)
        os.utime(self.registry, (mtime, mtime))

    def test_registry_edits_reach_resolver_files_routes_and_state(self):
        self.write_registry("example.ru\nother.ru\n", 1000)
        self.daemon.tick()
        self.assertEqual(sorted(p.name for p in self.resolver.iterdir()), ["example.ru", "other.ru"])
        self.daemon.routes.ensure("93.184.216.34", GW, "example.ru")
        self.write_registry("other.ru\n", 2000)
        self.daemon.tick()
        self.assertEqual([p.name for p in self.resolver.iterdir()], ["other.ru"])
        self.assertEqual(self.run.route_calls("delete"), [["93.184.216.34"]])
        state = json.loads(self.state.read_text())
        self.assertEqual((state["domains"], state["gateway"], state["routes"]), (["other.ru"], GW, {}))
        self.assertEqual(self.dns_flushes, 2)

    def test_uplink_change_drops_routes_and_dns_cache(self):
        self.daemon.tick()
        self.daemon.routes.ensure("93.184.216.34", GW, "example.ru")
        flushes = self.dns_flushes
        self.daemon.tick()
        self.assertEqual(self.dns_flushes, flushes)
        self.link = dict(self.link, gateway="10.0.0.1")
        self.daemon.tick()
        self.assertEqual(self.daemon.routes.routes, {})
        self.assertEqual(self.dns_flushes, flushes + 1)

    def test_cleanup_and_leftovers_of_a_crashed_run(self):
        self.write_registry("example.ru\n", 1000)
        self.daemon.tick()
        self.daemon.routes.ensure("93.184.216.34", GW, "example.ru")
        self.daemon.tick()
        crashed = self.state.read_text()
        self.assertIn("93.184.216.34", json.loads(crashed)["routes"])
        self.daemon.cleanup()
        self.assertEqual(list(self.resolver.iterdir()), [])
        self.assertFalse(self.state.exists())
        self.state.write_text(crashed)
        self.run.calls.clear()
        self.daemon.adopt_leftovers()
        self.assertEqual(self.run.route_calls("delete"), [["93.184.216.34"]])


class CliTest(unittest.TestCase):
    def cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out), redirect_stderr(io.StringIO()):
            code = novpn.main(list(argv))
        return code, out.getvalue()

    def test_add_ls_rm(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"NOVPN_REGISTRY": str(Path(tmp) / "domains.txt")}), \
                mock.patch.object(novpn, "daemon_state", return_value=None):
            code, out = self.cli("add", "https://www.Sberbank.ru/ru/person", "кремль.рф")
            self.assertEqual(code, 0)
            self.assertIn("+ sberbank.ru", out)
            self.assertEqual(self.cli("ls")[1].split(), ["sberbank.ru", "xn--e1ajeds9e.xn--p1ai"])
            self.assertEqual(self.cli("add", "bad_name.ru")[0], 1)
            self.assertEqual(self.cli("rm", "sberbank.ru")[0], 0)
            self.assertEqual(self.cli("rm", "sberbank.ru")[0], 1)
            self.assertEqual(self.cli("ls")[1].split(), ["xn--e1ajeds9e.xn--p1ai"])

    def test_daemon_state_needs_a_live_pid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            self.assertIsNone(novpn.daemon_state(str(path)))
            path.write_text(json.dumps({"pid": os.getpid()}))
            self.assertEqual(novpn.daemon_state(str(path))["pid"], os.getpid())
            path.write_text(json.dumps({"pid": 0}))
            self.assertIsNone(novpn.daemon_state(str(path)))

    def test_route_of_parses_route_get(self):
        out = ("   route to: 34.117.59.81\ndestination: 34.117.59.81\n    gateway: 192.168.0.1\n"
               "  interface: en0\n      flags: <UP,GATEWAY,HOST,DONE,STATIC>\n")
        self.assertEqual(novpn.route_of("34.117.59.81", run=FakeRun(outputs={"/sbin/route": out})), ("en0", GW))


if __name__ == "__main__":
    unittest.main()
