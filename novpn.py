#!/usr/bin/env python3
"""novpn: chosen domains bypass any VPN exit node and leave through the local ISP.

Registry: ~/.config/novpn/domains.txt, one domain per line.  An entry covers its
subdomains, and a bare zone such as `ru` covers the whole zone.

The root daemon (`novpn daemon`, started by launchd) points
/etc/resolver/<domain> at a DNS forwarder on 127.0.0.1:53535.  The forwarder
resolves through the physical interface and, before it answers, adds a host
route via the physical gateway for every public IPv4 in the answer, so the
connection that follows never enters the tunnel.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import logging
import os
import re
import signal
import socket
import stat
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))  # `python3 -I` leaves the script's directory out
import novpn_pf  # noqa: E402
import novpn_rtsock  # noqa: E402
import novpn_russia  # noqa: E402

__version__ = "1.0.1"

DNS_HOST = "127.0.0.1"
DNS_PORT = 53535  # macOS intercepts port 53 before userspace listeners see it
RESOLVER_DIR = "/etc/resolver"
STATE_PATH = "/var/run/novpn/state.json"
LOG_PATH = "/var/log/novpn.log"
MARKER = "# managed by novpn"
FALLBACK_DNS = ("77.88.8.8", "1.1.1.1")
TUNNEL_IFACES = ("utun", "ipsec", "ppp", "tun", "tap", "gif", "stf")
RESERVED = ("local", "localhost", "arpa", "ts.net")
POLL_SECONDS = 2.0
FAST_POLL = 0.25  # registry edits are picked up this quickly; the network is checked every POLL_SECONDS
FIREWALL_CHECK_SECONDS = 30
PRIME_LIMIT = 50
PRIME_SECONDS = 5.0  # priming never holds the loop longer; later names get routed on their first lookup
ROUTE_SAMPLE = 16  # routes spot-checked in the kernel on every tick
REGISTRY_MAX_BYTES = 1 << 20
OPTIONS = (novpn_russia.OPTION,)
ROUTE_TTL = 12 * 3600
IP_BOUND_IF = 25  # Darwin <netinet/in.h>
QTYPE_A, QTYPE_AAAA, QTYPE_SVCB, QTYPE_HTTPS = 1, 28, 64, 65
NODATA_QTYPES = frozenset({QTYPE_AAAA, QTYPE_SVCB, QTYPE_HTTPS})  # IPv6 exists only inside the tunnel
DNS_ERRORS = (ValueError, IndexError, struct.error)
TAILSCALE_CLI = "/Applications/Tailscale.app/Contents/MacOS/Tailscale"
INSTALLER = Path(__file__).resolve().parent / "install.sh"
REGISTRY_TEMPLATE = (
    "# novpn: these domains and all their subdomains bypass the VPN exit node.\n"
    "# One per line, e.g. gosuslugi.ru, or a whole zone: ru\n"
)

log = logging.getLogger("novpn")
log.addHandler(logging.NullHandler())


# Domains and the registry

_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")


def extract_host(raw: str) -> str:
    """Host part of a domain or URL: lowercased, no scheme, path, port or trailing dot."""
    host = raw.strip().lower()
    if "://" in host:
        host = host.split("://", 1)[1]
    host = re.split(r"[/?#]", host, maxsplit=1)[0]
    host = host.rsplit("@", 1)[-1].split(":", 1)[0]
    return host.rstrip(".")


def to_ascii(host: str) -> str:
    """Punycode form of a (possibly Cyrillic) host name, every label checked."""
    if host.startswith("*."):
        host = host[2:]
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError(f"not a domain: {host!r}") from None
    labels = host.split(".")
    if len(host) > 253 or not all(_LABEL.fullmatch(label) for label in labels):
        raise ValueError(f"not a domain: {host!r}")
    if labels[-1].isdigit():
        raise ValueError(f"IP addresses are not supported: {host!r}")
    if any(host == name or host.endswith("." + name) for name in RESERVED):
        raise ValueError(f"reserved name: {host!r}")
    return host


def normalize_domain(raw: str) -> str:
    """Registry form of a domain or URL; a leading www. is dropped so the whole site is covered."""
    host = to_ascii(extract_host(raw))
    if host.startswith("www.") and host.count(".") >= 2:
        host = host[4:]
    return host


def match_domain(qname: str, domains) -> str | None:
    """Most specific registry entry that is qname or one of its parents."""
    name = qname.rstrip(".").lower()
    best = None
    for domain in domains:
        if (name == domain or name.endswith("." + domain)) and (best is None or len(domain) > len(best)):
            best = domain
    return best


def parse_registry(text: str) -> tuple[list[str], list[str]]:
    """Domains in file order without duplicates, plus entries that are not domains."""
    domains, invalid = [], []
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        if entry.startswith("@"):
            if entry[1:] not in OPTIONS:
                invalid.append(entry)
            continue
        try:
            domain = normalize_domain(entry)
        except ValueError:
            invalid.append(entry)
            continue
        if domain not in domains:
            domains.append(domain)
    return domains, invalid


def parse_options(text: str) -> set[str]:
    """Known `@option` lines of the registry, e.g. @russia."""
    entries = (line.split("#", 1)[0].strip() for line in text.splitlines())
    return {entry[1:] for entry in entries if entry.startswith("@") and entry[1:] in OPTIONS}


def read_user_file(path) -> str:
    """Text of a user-owned regular file, read by root without following links to other files."""
    path = Path(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as fh:
        info = os.fstat(fh.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"{path} is not a regular file")
        if info.st_uid != os.stat(path.parent).st_uid:
            raise ValueError(f"{path} does not belong to the owner of {path.parent}")
        if info.st_size > REGISTRY_MAX_BYTES:
            raise ValueError(f"{path} is larger than {REGISTRY_MAX_BYTES} bytes")
        return fh.read(REGISTRY_MAX_BYTES).decode("utf-8")


def read_registry(path) -> tuple[list[str], list[str]]:
    try:
        return parse_registry(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [], []


def atomic_write(path: Path, text: str, mode: int = 0o644) -> None:
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def ensure_registry(path: Path) -> None:
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(path, REGISTRY_TEMPLATE)


def registry_add(path: Path, raws) -> tuple[list[str], list[str], list[str]]:
    """Append domains; returns (added, already_listed, invalid)."""
    ensure_registry(path)
    text = path.read_text(encoding="utf-8")
    listed = parse_registry(text)[0]
    added, present, invalid = [], [], []
    for raw in raws:
        try:
            domain = normalize_domain(raw)
        except ValueError:
            invalid.append(raw)
            continue
        (present if domain in listed or domain in added else added).append(domain)
    if added:
        if text and not text.endswith("\n"):
            text += "\n"
        atomic_write(path, text + "".join(domain + "\n" for domain in added))
    return added, present, invalid


def registry_remove(path: Path, raws) -> tuple[list[str], list[str]]:
    """Delete domains given in any accepted spelling; returns (removed, not_listed)."""
    wanted = {}
    for raw in raws:
        try:
            wanted[normalize_domain(raw)] = raw
        except ValueError:
            wanted[raw] = raw
    try:
        lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
    except FileNotFoundError:
        lines = []
    kept, removed = [], []
    for line in lines:
        entry = line.split("#", 1)[0].strip()
        try:
            domain = normalize_domain(entry) if entry else None
        except ValueError:
            domain = None
        if domain in wanted:
            if domain not in removed:
                removed.append(domain)
            continue
        kept.append(line)
    if removed:
        atomic_write(path, "".join(kept))
    return removed, [raw for domain, raw in wanted.items() if domain not in removed]


def registry_set_option(path: Path, name: str, enabled: bool) -> bool:
    """Add or drop an `@name` line; True when the file changed."""
    ensure_registry(path)
    text = path.read_text(encoding="utf-8")
    if (name in parse_options(text)) == enabled:
        return False
    if enabled:
        text += ("" if not text or text.endswith("\n") else "\n") + f"@{name}\n"
    else:
        text = "".join(line for line in text.splitlines(keepends=True)
                       if line.split("#", 1)[0].strip() != f"@{name}")
    atomic_write(path, text)
    return True


# /etc/resolver

def resolver_body() -> str:
    return f"{MARKER}\nnameserver {DNS_HOST}\nport {DNS_PORT}\n"


def is_managed(path: Path) -> bool:
    """True for a resolver file this daemon wrote; symlinks never count."""
    if path.is_symlink() or not path.is_file():
        return False
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.readline().rstrip("\n") == MARKER
    except OSError:
        return False


def sync_resolver_dir(resolver_dir, domains) -> tuple[list[str], list[str], list[str]]:
    """One managed resolver file per domain; files without the marker are left alone.

    Returns (written, removed, foreign)."""
    root = Path(resolver_dir)
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    body = resolver_body()
    written, removed, foreign = [], [], []
    for domain in domains:
        path = root / to_ascii(domain)  # re-checked: the name becomes a path under /etc
        if path.exists() or path.is_symlink():
            if not is_managed(path):
                foreign.append(domain)
                continue
            if path.read_text(encoding="utf-8") == body:
                continue
        path.write_text(body, encoding="utf-8")
        path.chmod(0o644)
        written.append(domain)
    wanted = set(domains)
    for path in sorted(root.iterdir()):
        if path.name not in wanted and is_managed(path):
            path.unlink()
            removed.append(path.name)
    return written, removed, foreign


# DNS wire format

def read_name(msg: bytes, off: int) -> tuple[str, int]:
    """Decode a (possibly compressed) name; returns it with the offset just past it."""
    labels, end = [], None
    for _ in range(128):
        length = msg[off]
        if length & 0xC0 == 0xC0:
            if end is None:
                end = off + 2
            off = ((length & 0x3F) << 8) | msg[off + 1]
            continue
        if length & 0xC0:
            raise ValueError("unsupported label type")
        off += 1
        if length == 0:
            return ".".join(labels), (off if end is None else end)
        labels.append(msg[off:off + length].decode("ascii", "replace").lower())
        off += length
    raise ValueError("name too long or compression loop")


def parse_question(msg: bytes) -> tuple[str, int, int]:
    """(qname, qtype, offset past the first question)."""
    if len(msg) < 12 or struct.unpack("!H", msg[4:6])[0] < 1:
        raise ValueError("no question")
    name, off = read_name(msg, 12)
    qtype, _qclass = struct.unpack("!HH", msg[off:off + 4])
    return name, qtype, off + 4


def answer_ipv4s(msg: bytes) -> list[str]:
    """IPv4 addresses of the A records in the answer section (CNAME chains included)."""
    qdcount, ancount = struct.unpack("!HH", msg[4:8])
    off = 12
    for _ in range(qdcount):
        off = read_name(msg, off)[1] + 4
    ips = []
    for _ in range(ancount):
        off = read_name(msg, off)[1]
        rtype, rclass, _ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10
        if rtype == QTYPE_A and rclass == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(msg[off:off + 4]))
        off += rdlen
    return ips


def _reply(query: bytes, rcode: int) -> bytes:
    _, _, qend = parse_question(query)
    qid, flags = struct.unpack("!HH", query[:4])
    flags = 0x8000 | (flags & 0x7900) | 0x0080 | rcode  # QR; opcode and RD kept; RA
    return struct.pack("!HHHHHH", qid, flags, 1, 0, 0, 0) + query[12:qend]


def nodata_response(query: bytes) -> bytes:
    return _reply(query, 0)


def servfail_response(query: bytes) -> bytes:
    return _reply(query, 2)


def build_query(name: str, qtype: int, qid: int = 0x4E56) -> bytes:
    qname = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.rstrip(".").split("."))
    return struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + qname + b"\0" + struct.pack("!HH", qtype, 1)


# Upstream DNS through the physical interface

def _socket(kind: int, iface_index: int | None, timeout: float) -> socket.socket:
    sock = socket.socket(socket.AF_INET, kind)
    if iface_index:
        sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, iface_index)
    sock.settimeout(timeout)
    return sock


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    buf = b""
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def query_udp(packet: bytes, servers, iface_index: int | None = None, timeout: float = 2.0) -> bytes:
    """First answer with a matching ID, servers tried in order."""
    error = None
    for server in servers:
        sock = _socket(socket.SOCK_DGRAM, iface_index, timeout)
        try:
            sock.sendto(packet, server)
            while True:
                data, _ = sock.recvfrom(65535)
                if data[:2] == packet[:2]:
                    return data
        except OSError as exc:
            error = exc
        finally:
            sock.close()
    raise OSError(f"no upstream answered: {error}")


def query_tcp(packet: bytes, servers, iface_index: int | None = None, timeout: float = 3.0) -> bytes:
    error = None
    for server in servers:
        sock = _socket(socket.SOCK_STREAM, iface_index, timeout)
        try:
            sock.connect(server)
            sock.sendall(struct.pack("!H", len(packet)) + packet)
            return _recv_exact(sock, struct.unpack("!H", _recv_exact(sock, 2))[0])
        except OSError as exc:
            error = exc
        finally:
            sock.close()
    raise OSError(f"no upstream answered over TCP: {error}")


# Routes and the physical uplink

def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)


def _is_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(text)
    except ValueError:
        return False
    return True


def is_public_ipv4(ip: str) -> bool:
    try:
        return ipaddress.IPv4Address(ip).is_global
    except ValueError:
        return False


class RouteTable:
    """Host routes the daemon added, so it can move them or take them back."""

    def __init__(self, run=None, clock=time.time):
        self._run = run or _run
        self._clock = clock
        self._lock = threading.Lock()
        self.routes: dict[str, dict] = {}
        self.firewall = None  # told about every address that gains or loses its route
        self.closed = False

    def close(self) -> None:
        """No new routes from now on (DNS answers still in flight while the daemon stops)."""
        with self._lock:
            self.closed = True

    def ensure(self, ip: str, gateway: str, domain: str, iface: str | None = None) -> bool:
        """Route ip via gateway, pinned to iface when given; True when the kernel table changed."""
        with self._lock:
            if self.closed:
                return False
            entry = self.routes.get(ip)
            if entry is not None and (entry["gateway"], entry.get("iface")) == (gateway, iface):
                entry["domains"].add(domain)
                entry["seen"] = self._clock()
                return False
            pin = ["-ifp", iface] if iface else []
            result = self._run(["/sbin/route", "-n", "add", "-host", ip, gateway, *pin])
            if result.returncode != 0 and "File exists" in result.stdout + result.stderr:
                result = self._run(["/sbin/route", "-n", "change", "-host", ip, gateway, *pin])
            if result.returncode != 0:
                log.warning("route %s via %s failed: %s", ip, gateway, (result.stdout + result.stderr).strip())
                return False
            domains = entry["domains"] if entry is not None else set()
            domains.add(domain)
            self.routes[ip] = {"gateway": gateway, "iface": iface, "domains": domains, "seen": self._clock()}
            log.info("route %s via %s for %s", ip, gateway, domain)
            if entry is None and self.firewall is not None:
                self.firewall.add_hosts([ip])
            return True

    def remove(self, ips) -> None:
        with self._lock:
            self._drop(list(ips))

    def flush(self) -> int:
        with self._lock:
            ips = list(self.routes)
            self._drop(ips)
            return len(ips)

    def forget_domains(self, gone) -> int:
        """Delete routes that served only domains no longer listed."""
        with self._lock:
            stale = []
            for ip, entry in self.routes.items():
                entry["domains"].difference_update(gone)
                if not entry["domains"]:
                    stale.append(ip)
            self._drop(stale)
            return len(stale)

    def expire(self, max_age: float) -> int:
        with self._lock:
            cutoff = self._clock() - max_age
            stale = [ip for ip, entry in self.routes.items() if entry["seen"] < cutoff]
            self._drop(stale)
            return len(stale)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                ip: {"gateway": entry["gateway"], "domains": sorted(entry["domains"])}
                for ip, entry in sorted(self.routes.items())
            }

    def _drop(self, ips: list[str]) -> None:
        tracked = [ip for ip in ips if self._delete(ip)]
        if tracked and self.firewall is not None:
            self.firewall.remove_hosts(tracked)

    def _delete(self, ip: str) -> bool:
        self._run(["/sbin/route", "-n", "delete", "-host", ip])
        if self.routes.pop(ip, None) is None:
            return False
        log.info("route %s removed", ip)
        return True


def physical_route(netstat_out: str, nwi_out: str = "") -> tuple[str, str] | None:
    """(gateway, interface) of the highest-priority default route outside any tunnel."""
    defaults = {}
    for line in netstat_out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "default" and not parts[3].startswith(TUNNEL_IFACES) and _is_ipv4(parts[1]):
            defaults.setdefault(parts[3], parts[1])
    order = []
    for line in nwi_out.splitlines():
        if line.strip().startswith("Network interfaces:"):
            order = line.split(":", 1)[1].split()
    for iface in order + list(defaults):
        if iface in defaults:
            return defaults[iface], iface
    return None


class PhysicalPath:
    """Where traffic goes when it skips the tunnel: gateway, interface and that network's DNS."""

    def __init__(self, run=None):
        self._run = run or _run
        self.current: dict | None = None

    def refresh(self) -> dict | None:
        found = physical_route(
            self._run(["/usr/sbin/netstat", "-rn", "-f", "inet"]).stdout,
            self._run(["/usr/sbin/scutil", "--nwi"]).stdout,
        )
        if found is None:
            self.current = None
        elif self.current is None or (self.current["gateway"], self.current["iface"]) != found:
            gateway, iface = found
            dns = self._run(["/usr/sbin/ipconfig", "getoption", iface, "domain_name_server"]).stdout.strip()
            hosts = ([dns] if _is_ipv4(dns) else []) + [host for host in FALLBACK_DNS if host != dns]
            try:
                index = socket.if_nametoindex(iface)
            except OSError:
                index = None
            self.current = {"gateway": gateway, "iface": iface, "index": index, "dns": [(host, 53) for host in hosts]}
        return self.current


def system_dns_servers(run=None) -> list[tuple[str, int]]:
    """IPv4 servers of the default resolver (with a VPN up, the VPN's DNS)."""
    servers, block = [], 0
    for line in (run or _run)(["/usr/sbin/scutil", "--dns"]).stdout.splitlines():
        line = line.strip()
        if line.startswith("resolver #"):
            block += 1
        elif block == 1 and line.startswith("nameserver["):
            host = line.split(":", 1)[1].strip()
            if _is_ipv4(host) and not ipaddress.IPv4Address(host).is_loopback:
                servers.append((host, 53))
    return servers


# The DNS forwarder

class Forwarder:
    """Answers queries for registry domains and pins routes for the addresses it hands out."""

    def __init__(self, routes: RouteTable, domains, uplink, udp=None, tcp=None, covered=None):
        self.routes = routes
        self._domains = domains  # () -> registry domains
        self._uplink = uplink  # () -> PhysicalPath.current
        self._udp = udp or query_udp
        self._tcp = tcp or query_tcp
        self._covered = covered or (lambda ip: False)  # ip -> already routed by a network route
        self._system_dns = system_dns_servers

    def handle(self, query: bytes, tcp: bool = False) -> bytes | None:
        try:
            qname, qtype, _ = parse_question(query)
        except DNS_ERRORS:
            return None
        domain = match_domain(qname, self._domains())
        if domain and qtype in NODATA_QTYPES:
            return nodata_response(query)
        uplink = self._uplink()
        servers = uplink["dns"] if uplink else [(host, 53) for host in FALLBACK_DNS]
        try:
            answer = (self._tcp if tcp else self._udp)(query, servers, uplink["index"] if uplink else None)
        except OSError as exc:
            log.warning("no answer for %s: %s", qname, exc)
            return servfail_response(query)
        if domain and uplink:
            self._pin(answer, domain, uplink)
        return answer

    def prime(self, domain: str, deadline: float = float("inf")) -> None:
        """Route a newly listed site before anyone asks for it, giving up at deadline (monotonic).

        The VPN's DNS is asked as well: a browser may still hold the addresses it handed out,
        and those must leave directly too (pf resets the old tunnelled connections to them)."""
        uplink = self._uplink()
        if not uplink:
            return
        upstreams = ((uplink["dns"][:2], uplink["index"]), (self._system_dns()[:1], None))
        for name in (domain, "www." + domain):
            query = build_query(name, QTYPE_A)
            for servers, index in upstreams:
                if time.monotonic() > deadline:
                    return
                try:
                    self._pin(self._udp(query, servers, index, 1.0), domain, uplink)
                except OSError:
                    pass

    def _pin(self, answer: bytes, domain: str, uplink: dict) -> None:
        try:
            ips = answer_ipv4s(answer)
        except DNS_ERRORS:
            ips = []
        for ip in ips:
            if is_public_ipv4(ip) and not self._covered(ip):
                self.routes.ensure(ip, uplink["gateway"], domain, uplink["iface"])


class _UDPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        reply = self.server.forwarder.handle(data)
        if reply:
            sock.sendto(reply, self.client_address)


class _TCPHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(10)
        try:
            while True:
                size = struct.unpack("!H", _recv_exact(self.request, 2))[0]
                reply = self.server.forwarder.handle(_recv_exact(self.request, size), tcp=True)
                if not reply:
                    return
                self.request.sendall(struct.pack("!H", len(reply)) + reply)
        except OSError:
            return


class _UDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True


class _TCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def start_dns_servers(forwarder, host: str = DNS_HOST, port: int = DNS_PORT) -> list:
    """UDP and TCP listeners on one port, each served from a daemon thread."""
    servers = []
    for server_cls, handler in ((_UDPServer, _UDPHandler), (_TCPServer, _TCPHandler)):
        server = server_cls((host, port), handler)
        server.forwarder = forwarder
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, name=server_cls.__name__, daemon=True).start()
        servers.append(server)
    return servers


# The daemon

def flush_dns_cache() -> None:
    _run(["/usr/bin/dscacheutil", "-flushcache"])
    _run(["/usr/bin/killall", "-HUP", "mDNSResponder"])


def _describe(link) -> str:
    return f"{link[1]} via {link[0]}" if link else "none"


class Daemon:
    """Poll loop: registry -> /etc/resolver, uplink changes -> routes and pf rules, state for `novpn status`."""

    def __init__(self, registry, resolver_dir=RESOLVER_DIR, state_path=STATE_PATH,
                 routes: RouteTable | None = None, path: PhysicalPath | None = None, flush_dns=None,
                 firewall=None, russia=None, clock=time.monotonic, lookup=None):
        self.registry = Path(registry)
        self.resolver_dir = Path(resolver_dir)
        self.state_path = Path(state_path)
        self.routes = routes or RouteTable()
        self.path = path or PhysicalPath()
        self.flush_dns = flush_dns or flush_dns_cache
        self.firewall = firewall or novpn_pf.Firewall(self.state_path.parent)
        self.russia = russia or novpn_russia.RussiaMode(self.state_path.parent / "russia-routes.json")
        self.routes.firewall = self.firewall
        self.russia_on = False
        self.domains: tuple[str, ...] = ()
        self.forwarder = Forwarder(self.routes, lambda: self.domains, lambda: self.path.current,
                                   covered=lambda ip: self.russia_on and self.russia.covers(ip))
        self._clock = clock
        self._lookup = lookup or novpn_rtsock.route_interfaces
        self._mtime = object()  # forces the first load
        self._link: tuple[str, str] | None = None
        self._network_dirty = True
        self._recheck = False  # the last tick restored lost routes
        self._foreign: set[str] = set()  # addresses another route keeps even after a restore
        self._next_firewall_check = clock() + FIREWALL_CHECK_SECONDS
        self._state_text = ""

    def tick(self) -> None:
        """Full pass: registry, uplink, route expiry, list refresh and pf health."""
        changed, new = self._load_registry()
        current = self.path.refresh()
        link = (current["gateway"], current["iface"]) if current else None
        lost = link == self._link and self._routes_lost(current)
        if link != self._link:
            self._foreign.clear()
        if link != self._link or lost:
            dropped = self.routes.flush()
            if lost:
                self.russia.forget()  # re-added in place (add, or change where one survived), no gap
            self._recheck = lost
            log.info("uplink %s -> %s, %d routes dropped", _describe(self._link), _describe(link), dropped)
            self._link = link
            changed = self._network_dirty = True
            new = list(self.domains)
        if self.russia.take_update():
            self._network_dirty = True
        self.routes.expire(ROUTE_TTL)
        if self.russia_on:
            self.russia.maybe_refresh()
        now = self._clock()
        if self._network_dirty:
            self._apply_network()
        elif now >= self._next_firewall_check:
            self.firewall.check()
        if now >= self._next_firewall_check:
            self._next_firewall_check = now + FIREWALL_CHECK_SECONDS
        self._settle(changed, new)

    def poll(self) -> None:
        """Between ticks: registry edits only, so `novpn add` takes effect within FAST_POLL."""
        changed, new = self._load_registry()
        if changed or new:
            if self._network_dirty:
                self._apply_network()
            self._settle(changed, new)

    def _settle(self, changed: bool, new) -> None:
        if changed:
            self.flush_dns()
        self._publish()
        deadline = time.monotonic() + PRIME_SECONDS
        primed = False
        for domain in [domain for domain in new if "." in domain][:PRIME_LIMIT]:
            if time.monotonic() > deadline:
                break
            self.forwarder.prime(domain, deadline)
            primed = True
        if primed:
            self._publish()

    def _routes_lost(self, current) -> bool:
        """True when the kernel no longer sends some of our routes via the uplink (sleep, `route flush`)."""
        index = current.get("index") if current else None
        if not index:
            return False
        hosts = list(self.routes.snapshot())[:ROUTE_SAMPLE]
        networks = [str(ipaddress.IPv4Network(net).network_address) for net in self.russia.sample(ROUTE_SAMPLE)]
        found = self._lookup([ip for ip in hosts + networks if ip not in self._foreign])
        lost = [ip for ip, ifindex in found.items() if ifindex is not None and ifindex != index]
        if lost and self._recheck:
            self._foreign.update(lost)
            log.warning("%s still leave via another route right after a restore; leaving them to it", lost)
            lost = []
        self._recheck = False
        if lost:
            log.warning("%d of %d checked routes no longer leave via the uplink, e.g. %s; restoring",
                        len(lost), len(found), lost[0])
        return bool(lost)

    def _apply_network(self) -> None:
        """Russian network routes and pf rules for the current uplink (none while offline)."""
        self._network_dirty = False
        gateway, iface = self._link if self._link else (None, None)
        networks = self.russia.apply(self.russia_on, gateway, iface)
        self.firewall.load(iface, networks, self.russia.ipv6() if self.russia_on and iface else [])

    def _load_registry(self) -> tuple[bool, list[str]]:
        """(resolver files or russia mode changed, domains to route at once)."""
        try:
            mtime = self.registry.stat().st_mtime_ns
        except FileNotFoundError:
            mtime = None
        if mtime == self._mtime:
            return False, []
        try:
            text = read_user_file(self.registry)
        except FileNotFoundError:
            text = ""
        except (OSError, ValueError) as exc:
            log.warning("registry unreadable, keeping the last good one: %s", exc)
            self._mtime = mtime
            return False, []
        domains, invalid = parse_registry(text)
        for entry in invalid:
            log.warning("registry: ignoring %r, not a domain", entry)
        russia_on = novpn_russia.OPTION in parse_options(text)
        toggled = russia_on != self.russia_on
        if toggled:
            log.info("russia mode %s", "on" if russia_on else "off")
            self.russia_on = russia_on
            self._network_dirty = True
        if russia_on:
            domains += [zone for zone in novpn_russia.ZONES if zone not in domains]
        written, removed, foreign = sync_resolver_dir(self.resolver_dir, domains)
        for domain in foreign:
            log.warning("%s/%s exists and is not ours; leaving it alone", self.resolver_dir, domain)
        gone = set(self.domains) - set(domains)
        new = [domain for domain in domains if toggled or domain not in self.domains]
        self.domains = tuple(domains)
        self._mtime = mtime
        if gone:
            self.routes.forget_domains(gone)
        if written or removed:
            log.info("registry: %d domains; added %s; removed %s", len(domains), written or "-", removed or "-")
        return bool(written or removed or toggled), new

    def _publish(self) -> None:
        current = self.path.current
        state = {
            "pid": os.getpid(),
            "registry": str(self.registry),
            "domains": list(self.domains),
            "gateway": current["gateway"] if current else None,
            "iface": current["iface"] if current else None,
            "dns": [host for host, _ in current["dns"]] if current else [],
            "routes": self.routes.snapshot(),
            "russia": {"enabled": self.russia_on, **self.russia.snapshot()},
            "firewall": self.firewall.snapshot(),
        }
        text = json.dumps(state, indent=1, sort_keys=True) + "\n"
        if text != self._state_text:
            self.state_path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            atomic_write(self.state_path, text)
            self._state_text = text

    def adopt_leftovers(self) -> None:
        """Take back what a previous run could not clean up (crash, kill -9): pf rules, routes."""
        try:
            old = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            old = {}
        if not isinstance(old, dict):
            old = {}
        self.firewall.adopt(old.get("firewall") or {})
        self.routes.remove(old.get("routes") or {})
        self.russia.adopt_leftovers()

    def cleanup(self) -> None:
        self.routes.close()
        self.firewall.clear()
        sync_resolver_dir(self.resolver_dir, [])
        self.routes.flush()
        self.russia.withdraw()
        self.flush_dns()
        try:
            self.state_path.unlink()
        except FileNotFoundError:
            pass


def run_daemon(registry: str) -> int:
    if os.geteuid() != 0:
        print(f"novpn daemon must run as root; install it with: sudo {INSTALLER}", file=sys.stderr)
        return 1
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    other = daemon_state()
    if other is not None and other.get("pid") != os.getpid():
        log.error("another novpn daemon is running, pid %s", other.get("pid"))
        return 1
    daemon = Daemon(registry)
    servers = start_dns_servers(daemon.forwarder)  # fails while the port is taken, before anything is touched
    daemon.adopt_leftovers()
    stop = threading.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stop.set())
    log.info("listening on %s:%d, registry %s", DNS_HOST, DNS_PORT, registry)
    next_tick = 0.0
    try:
        while not stop.is_set():
            try:
                if time.monotonic() >= next_tick:
                    next_tick = time.monotonic() + POLL_SECONDS
                    daemon.tick()
                else:
                    daemon.poll()
            except Exception:
                log.exception("tick failed")
            stop.wait(FAST_POLL)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        daemon.cleanup()
        log.info("stopped; resolver files, routes and pf rules removed")
    return 0


# CLI

def default_registry() -> Path:
    return Path(os.environ.get("NOVPN_REGISTRY") or Path.home() / ".config" / "novpn" / "domains.txt")


def daemon_state(path: str = STATE_PATH) -> dict | None:
    """State published by the running daemon, or None when it is not running."""
    try:
        state = json.loads(Path(path).read_text(encoding="utf-8"))
        pid = int(state["pid"])
    except (OSError, ValueError, KeyError, TypeError):
        return None
    if pid <= 1:
        return None
    try:
        os.kill(pid, 0)
    except PermissionError:
        pass  # alive, owned by root
    except OSError:
        return None
    return state


def paint(text: str, code: str) -> str:
    """ANSI colour for a terminal; plain text when piped or NO_COLOR is set (CLICOLOR_FORCE forces it)."""
    if os.environ.get("NO_COLOR") or not (os.environ.get("CLICOLOR_FORCE") or sys.stdout.isatty()):
        return text
    return f"\033[{code}m{text}\033[0m"


GREEN, RED, YELLOW, DIM, BOLD = "32", "31", "33", "2", "1"


def wait_for_daemon(done, timeout: float) -> tuple[float, dict] | None:
    """(seconds, state) once done(state) holds; None when the daemon is not running or too slow."""
    if daemon_state() is None:
        print(f"daemon is not running; install it once: sudo {INSTALLER}", file=sys.stderr)
        return None
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        state = daemon_state()
        if state and done(state):
            return time.monotonic() - start, state
        time.sleep(0.1)
    print("the daemon has not applied this yet; see: novpn logs", file=sys.stderr)
    return None


def report_daemon(domains, active: bool, timeout: float = 5.0) -> None:
    """Wait until the daemon has applied a registry change and say how long it took."""
    result = wait_for_daemon(lambda state: all((domain in (state.get("domains") or [])) == active
                                               for domain in domains), timeout)
    if result is None:
        return
    took, state = result
    if not active:
        print(f"{paint(f'applied in {took:.1f} s', GREEN)}; these sites use the VPN again")
    elif (state.get("firewall") or {}).get("active"):
        print(f"{paint(f'applied in {took:.1f} s', GREEN)}; open tabs switch over by themselves"
              f" {paint('(reload one that still sees the VPN)', DIM)}")
    else:
        print(f"{paint(f'applied in {took:.1f} s', GREEN)}; reload open tabs of these sites")


def route_of(ip: str, run=None) -> tuple[str, str]:
    """(interface, gateway) the kernel picks for ip right now."""
    fields = {}
    for line in (run or _run)(["/sbin/route", "-n", "get", ip]).stdout.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return fields.get("interface", "?"), fields.get("gateway", "")


def tailscale_exit_node() -> str | None:
    try:
        status = json.loads(_run([TAILSCALE_CLI, "status", "--json"]).stdout)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None
    for peer in (status.get("Peer") or {}).values():
        if peer.get("ExitNode"):
            return peer.get("HostName") or peer.get("DNSName")
    return "none"


def cmd_add(args) -> int:
    added, present, invalid = registry_add(default_registry(), args.domains)
    for domain in added:
        print(f"{paint('+', GREEN)} {paint(domain, BOLD)}  {paint(f'(and *.{domain})', DIM)}")
    for domain in present:
        print(f"{paint('=', DIM)} {domain}  {paint('already listed', DIM)}")
    for raw in invalid:
        print(f"! {raw}: not a domain", file=sys.stderr)
    if added:
        report_daemon(added, active=True)
        print(cookie_hint(added))
    return 1 if invalid else 0


def cookie_hint(domains) -> str:
    """How to clear the cookies a site set while it saw the VPN: Ozon and others remember the verdict there."""
    if not domains:
        return ""
    lines = [paint("important: a site that already saw your VPN remembers it in cookies; clear them once", YELLOW)]
    lines += [f"  chrome://settings/content/all?searchSubpage={domain}" for domain in domains]
    lines.append(paint("  Safari: Settings > Privacy > Manage Website Data, search the site, Remove", DIM))
    return "\n".join(lines)


def cmd_rm(args) -> int:
    removed, missing = registry_remove(default_registry(), args.domains)
    for domain in removed:
        print(f"{paint('-', YELLOW)} {paint(domain, BOLD)}")
    for raw in missing:
        print(f"? {raw}: not listed", file=sys.stderr)
    covered = still_direct(removed) if russia_listed(default_registry()) else []
    if covered:
        print(f"{', '.join(covered)}: still direct while russia mode is on (novpn russia off)")
    rest = [domain for domain in removed if domain not in covered]
    if rest:
        report_daemon(rest, active=False)
    return 1 if missing else 0


RUSSIA_SCOPE = "every Russian network and .ru .рф .su"


def russia_listed(path: Path) -> bool:
    try:
        return novpn_russia.OPTION in parse_options(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return False


def cmd_ls(args) -> int:
    path = default_registry()
    ensure_registry(path)
    domains, invalid = read_registry(path)
    for domain in domains:
        print(domain)
    for raw in invalid:
        print(f"! {raw}: ignored, not a domain", file=sys.stderr)
    if russia_listed(path):
        print(f"russia mode on: {RUSSIA_SCOPE} bypass the VPN too", file=sys.stderr)
    elif not domains:
        print(f"(empty) add one with: novpn add <domain>   registry: {path}", file=sys.stderr)
    return 0


def still_direct(domains) -> list[str]:
    """Domains russia mode keeps off the VPN: a Russian zone, or addresses in Russian networks."""
    index, covered = None, []
    for domain in domains:
        if match_domain(domain, novpn_russia.ZONES):
            covered.append(domain)
            continue
        try:
            ips = {info[4][0] for info in socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)}
        except OSError:
            continue
        index = index or novpn_russia.PrefixIndex(novpn_russia.load_prefixes(4)[0])
        if any(ip in index for ip in ips):
            covered.append(domain)
    return covered


def cmd_russia(args) -> int:
    path = default_registry()
    if args.mode is None:
        print(f"russia mode {'on' if russia_listed(path) else 'off'}; switch with: novpn russia on|off")
        return 0
    enabled = args.mode == "on"
    registry_set_option(path, novpn_russia.OPTION, enabled)
    print(f"russia mode on: {RUSSIA_SCOPE} bypass the VPN" if enabled
          else "russia mode off: only listed domains bypass the VPN")
    result = wait_for_daemon(lambda state: (state.get("russia") or {}).get("enabled") == enabled
                             and bool((state.get("russia") or {}).get("networks")) == enabled, 15.0)
    if result is not None:
        took, state = result
        networks = state["russia"].get("networks", 0)
        print(f"{paint(f'applied in {took:.1f} s', GREEN)}; {networks} networks routed directly")
    return 0


def cmd_cleanup(args) -> int:
    if os.geteuid() != 0:
        print("novpn cleanup must run as root; install.sh --uninstall runs it", file=sys.stderr)
        return 1
    if daemon_state() is not None:
        print("the daemon is running; stop it first: sudo install.sh --uninstall", file=sys.stderr)
        return 1
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s", stream=sys.stderr)
    daemon = Daemon(default_registry())
    daemon.adopt_leftovers()
    daemon.cleanup()
    print("leftover resolver files, routes and pf rules removed")
    return 0


def cmd_check(args) -> int:
    path = default_registry()
    listed = read_registry(path)[0]
    russia = None
    if russia_listed(path):
        listed += [zone for zone in novpn_russia.ZONES if zone not in listed]
        russia = novpn_russia.PrefixIndex(novpn_russia.load_prefixes(4)[0])
    status = 0
    for raw in args.domains:
        try:
            host = to_ascii(extract_host(raw))
        except ValueError as exc:
            print(f"! {exc}", file=sys.stderr)
            status = 1
            continue
        entry = match_domain(host, listed)
        print(f"{paint(host, BOLD)}: {'listed as ' + entry if entry else paint('not listed', DIM)}")
        try:
            infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror as exc:
            print(f"  cannot resolve: {exc}")
            status = 1
            continue
        for ip in sorted({info[4][0] for info in infos}, key=ipaddress.IPv4Address):
            iface, gateway = route_of(ip)
            tunnel = iface.startswith(TUNNEL_IFACES)
            russian = russia is not None and ip in russia
            via = f" via {gateway}" if gateway else ""
            route = paint("VPN", RED) if tunnel else paint("direct", GREEN)
            print(f"  {ip:<15} {iface}{via}  {route}{paint('  (Russian network)', DIM) if russian else ''}")
            if (entry or russian) and tunnel:
                status = 1
    return status


def cmd_status(args) -> int:
    registry = default_registry()
    listed = read_registry(registry)[0]
    active = sum(is_managed(Path(RESOLVER_DIR) / domain) for domain in listed)
    label = lambda name: paint(f"{name:<10} ", DIM)  # noqa: E731
    print(f"{label('registry')}{registry}: {len(listed)} domains, {active} active in {RESOLVER_DIR}")
    state = daemon_state()
    if state is None:
        print(f"{label('daemon')}{paint('not running', RED)}; install it once: sudo {INSTALLER}")
        return 1
    print(f"{label('daemon')}{paint('running', GREEN)}, pid {state['pid']}")
    if state.get("gateway"):
        print(f"{label('uplink')}{state['iface']} via {state['gateway']}, dns {', '.join(state.get('dns', []))}")
    else:
        print(f"{label('uplink')}{paint('none', YELLOW)} (offline?)")
    print(f"{label('routes')}{len(state.get('routes', {}))} pinned host routes")
    russia = state.get("russia") or {}
    if russia.get("enabled"):
        print(f"{label('russia')}{paint('on', GREEN)}, {russia.get('networks', 0)} networks routed directly,"
              " .ru .рф .su resolved by your ISP")
    else:
        print(f"{label('russia')}{paint('off', YELLOW)}; all Russian networks direct: novpn russia on")
    firewall = state.get("firewall") or {}
    print(f"{label('firewall')}{paint('on', GREEN)}, routed addresses can never use the VPN" if firewall.get("active")
          else f"{label('firewall')}{paint('off', YELLOW)}; see: novpn logs")
    print(f"{label('exit node')}{tailscale_exit_node() or 'unknown'}")
    return 0


def cmd_logs(args) -> int:
    try:
        lines = Path(LOG_PATH).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        print(f"cannot read {LOG_PATH}: {exc}", file=sys.stderr)
        return 1
    print("\n".join(lines[-args.n:]))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="novpn",
        description="Domains (with all subdomains) that bypass the VPN exit node and use your real IP.",
        epilog="examples: novpn add gosuslugi.ru https://www.ozon.ru/  |  novpn russia on  |  novpn check gosuslugi.ru",
    )
    parser.add_argument("--version", action="version", version=f"novpn {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name, func, help_text in (
        ("add", cmd_add, "add domains or URLs"),
        ("rm", cmd_rm, "remove domains"),
        ("check", cmd_check, "show which interface a domain's addresses leave through"),
    ):
        cmd = sub.add_parser(name, help=help_text)
        cmd.add_argument("domains", nargs="+", metavar="domain")
        cmd.set_defaults(func=func)
    sub.add_parser("ls", help="list the registry").set_defaults(func=cmd_ls)
    sub.add_parser("status", help="daemon, uplink, routes, russia mode, firewall, exit node").set_defaults(
        func=cmd_status)
    cmd = sub.add_parser("russia", help=f"{RUSSIA_SCOPE} bypass the VPN: on, off, or show")
    cmd.add_argument("mode", nargs="?", choices=("on", "off"))
    cmd.set_defaults(func=cmd_russia)
    sub.add_parser("cleanup", help="remove leftovers of a stopped daemon (root)").set_defaults(func=cmd_cleanup)
    cmd = sub.add_parser("logs", help="tail the daemon log")
    cmd.add_argument("-n", type=int, default=40, help="number of lines (default 40)")
    cmd.set_defaults(func=cmd_logs)
    cmd = sub.add_parser("daemon", help="run the root daemon (launchd starts it)")
    cmd.add_argument("--registry", required=True)
    cmd.set_defaults(func=lambda args: run_daemon(args.registry))
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except UnicodeDecodeError as exc:
        print(f"cannot read {default_registry()}: {exc}; save it as UTF-8 or remove the bad line", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
