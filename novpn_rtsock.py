"""Bulk IPv4 network routes through the macOS routing socket.

Launching /sbin/route once per prefix costs a few milliseconds, so thousands of prefixes would
leave the table half-built for half a minute; writing the kernel messages directly takes a
fraction of a second.  Layout from <net/route.h> with RTM_VERSION 5: a 92-byte rt_msghdr
followed by 16-byte sockaddr_in records in RTA_* bit order, then a 20-byte sockaddr_dl that pins
the interface (route(8)'s -ifp), so a route never lands on another NIC on the same subnet.
"""
from __future__ import annotations

import errno
import ipaddress
import os
import socket
import struct

RTM_VERSION = 5
RTM_ADD, RTM_DELETE, RTM_CHANGE, RTM_GET = 1, 2, 3, 4
RTF_UP, RTF_GATEWAY, RTF_HOST, RTF_STATIC = 0x1, 0x2, 0x4, 0x800
RTA_DST, RTA_GATEWAY, RTA_NETMASK, RTA_IFP = 0x1, 0x2, 0x4, 0x10
HEADER = struct.Struct("=HBBH2xiiiiiiI56x")  # rt_msghdr; the trailing rt_metrics stay zero
SOCKADDR_IN = struct.Struct("=BBH4s8x")
SOCKADDR_DL = struct.Struct("=BBHBBBB12s")


def _sockaddr(address: str) -> bytes:
    return SOCKADDR_IN.pack(SOCKADDR_IN.size, socket.AF_INET, 0, socket.inet_aton(address))


def _sockaddr_dl(iface: str) -> bytes:
    name = iface.encode("ascii")
    return SOCKADDR_DL.pack(SOCKADDR_DL.size, socket.AF_LINK, socket.if_nametoindex(iface), 0, len(name), 0, 0, name)


def route_message(rtm_type: int, network: str, gateway: str | None, seq: int = 0, iface: str | None = None) -> bytes:
    """rt_msghdr plus destination, gateway (when given), netmask and interface (when given)."""
    net = ipaddress.IPv4Network(network)
    addrs, flags = RTA_DST | RTA_NETMASK, RTF_UP | RTF_STATIC
    body = _sockaddr(str(net.network_address))
    if gateway:
        addrs |= RTA_GATEWAY
        flags |= RTF_GATEWAY
        body += _sockaddr(gateway)
    body += _sockaddr(str(net.netmask))
    if iface:
        addrs |= RTA_IFP
        body += _sockaddr_dl(iface)
    header = HEADER.pack(HEADER.size + len(body), RTM_VERSION, rtm_type, 0, flags, addrs, 0, seq, 0, 0, 0)
    return header + body


def open_socket() -> socket.socket:
    sock = socket.socket(socket.AF_ROUTE, socket.SOCK_RAW, socket.AF_UNSPEC)
    try:
        sock.shutdown(socket.SHUT_RD)  # nothing is read back, so the kernel need not queue for us
    except OSError:
        pass
    return sock


def _send(sock, rtm_type: int, network: str, gateway: str | None, seq: int, iface: str | None = None) -> int:
    """0 on success, otherwise the errno the kernel refused the message with."""
    try:
        sock.send(route_message(rtm_type, network, gateway, seq, iface))
    except OSError as exc:
        return exc.errno or errno.EIO
    return 0


def add_routes(networks, gateway: str, iface: str | None = None, sock=None) -> tuple[list[str], dict[str, str]]:
    """Route each network via gateway on iface, taking over a route that already exists.

    Returns (routed, {network: error})."""
    networks = list(networks)
    if not networks:
        return [], {}
    own = sock is None
    sock = sock or open_socket()
    routed, failed = [], {}
    try:
        for seq, network in enumerate(networks, 1):
            code = _send(sock, RTM_ADD, network, gateway, seq, iface)
            if code == errno.EEXIST:
                code = _send(sock, RTM_CHANGE, network, gateway, seq, iface)
            if code:
                failed[network] = os.strerror(code)
            else:
                routed.append(network)
    finally:
        if own:
            sock.close()
    return routed, failed


def delete_routes(networks, sock=None) -> dict[str, str]:
    """Delete network routes; one that is already gone counts as deleted.  Returns {network: error}."""
    networks = list(networks)
    if not networks:
        return {}
    own = sock is None
    sock = sock or open_socket()
    failed = {}
    try:
        for seq, network in enumerate(networks, 1):
            code = _send(sock, RTM_DELETE, network, None, seq)
            if code and code != errno.ESRCH:
                failed[network] = os.strerror(code)
    finally:
        if own:
            sock.close()
    return failed


def route_interfaces(addresses, sock=None, timeout: float = 1.0) -> dict[str, int | None]:
    """Interface index the kernel picks for each IPv4 address right now (route(8) get).

    0 means no route at all; None means the kernel did not answer in time."""
    addresses = list(addresses)
    if not addresses:
        return {}
    own = sock is None
    if own:
        sock = socket.socket(socket.AF_ROUTE, socket.SOCK_RAW, socket.AF_UNSPEC)
        sock.settimeout(timeout)
    pid, found = os.getpid(), {}
    try:
        for seq, address in enumerate(addresses, 1):
            found[address] = None
            body = _sockaddr(address)
            msg = HEADER.pack(HEADER.size + len(body), RTM_VERSION, RTM_GET, 0, RTF_UP | RTF_HOST, RTA_DST,
                              0, seq, 0, 0, 0) + body
            try:
                sock.send(msg)
                while True:
                    reply = sock.recv(2048)
                    if len(reply) < HEADER.size:
                        continue
                    _, _, rtm_type, index, _, _, rtm_pid, rtm_seq, rtm_errno, _, _ = HEADER.unpack_from(reply)
                    if rtm_type == RTM_GET and rtm_pid == pid and rtm_seq == seq:
                        found[address] = 0 if rtm_errno else index
                        break
            except OSError as exc:
                if exc.errno == errno.ESRCH:
                    found[address] = 0
    finally:
        if own:
            sock.close()
    return found
