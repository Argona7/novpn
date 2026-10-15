"""Tests for novpn_rtsock: routing socket messages and bulk route changes."""
import errno
import os
import socket
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import novpn_rtsock as rt  # noqa: E402

GW = "192.168.0.1"


class FakeSocket:
    """Accepts route messages; errors are keyed by (message type, destination)."""

    def __init__(self, errors=None):
        self.sent = []
        self.errors = errors or {}
        self.closed = False

    def send(self, msg):
        self.sent.append(msg)
        dst = socket.inet_ntoa(msg[rt.HEADER.size + 4:rt.HEADER.size + 8])
        code = self.errors.get((msg[3], dst))
        if code:
            raise OSError(code, os.strerror(code))
        return len(msg)

    def close(self):
        self.closed = True

    def types(self):
        return [msg[3] for msg in self.sent]


def sockaddrs(msg):
    body = msg[rt.HEADER.size:]
    return [rt.SOCKADDR_IN.unpack(body[i:i + 16]) for i in range(0, len(body), 16)]


class MessageTest(unittest.TestCase):
    def test_sizes_match_net_route_h(self):
        self.assertEqual((rt.HEADER.size, rt.SOCKADDR_IN.size), (92, 16))

    def test_add_message_carries_destination_gateway_and_netmask(self):
        msg = rt.route_message(rt.RTM_ADD, "5.3.0.0/16", GW, seq=7)
        length, version, rtm_type, index, flags, addrs, pid, seq, err, use, inits = rt.HEADER.unpack(msg[:92])
        self.assertEqual((length, version, rtm_type, index), (len(msg), 5, rt.RTM_ADD, 0))
        self.assertEqual(len(msg), 92 + 3 * 16)
        self.assertEqual(flags, rt.RTF_UP | rt.RTF_GATEWAY | rt.RTF_STATIC)
        self.assertEqual(addrs, rt.RTA_DST | rt.RTA_GATEWAY | rt.RTA_NETMASK)
        self.assertEqual((pid, seq, err, use, inits), (0, 7, 0, 0, 0))
        self.assertEqual(msg[92 - 56:92], bytes(56))
        self.assertEqual(sockaddrs(msg), [
            (16, socket.AF_INET, 0, socket.inet_aton("5.3.0.0")),
            (16, socket.AF_INET, 0, socket.inet_aton(GW)),
            (16, socket.AF_INET, 0, socket.inet_aton("255.255.0.0")),
        ])

    def test_delete_message_has_no_gateway(self):
        msg = rt.route_message(rt.RTM_DELETE, "95.0.0.0/8", None)
        _, _, rtm_type, _, flags, addrs, *_ = rt.HEADER.unpack(msg[:92])
        self.assertEqual((rtm_type, flags & rt.RTF_GATEWAY, addrs), (rt.RTM_DELETE, 0, rt.RTA_DST | rt.RTA_NETMASK))
        self.assertEqual([addr[3] for addr in sockaddrs(msg)],
                         [socket.inet_aton("95.0.0.0"), socket.inet_aton("255.0.0.0")])

    def test_rejects_networks_with_host_bits(self):
        with self.assertRaises(ValueError):
            rt.route_message(rt.RTM_ADD, "5.3.0.1/16", GW)


class BulkTest(unittest.TestCase):
    def test_add_takes_over_existing_routes_and_reports_failures(self):
        sock = FakeSocket({(rt.RTM_ADD, "5.3.0.0"): errno.EEXIST, (rt.RTM_ADD, "5.4.0.0"): errno.ENETUNREACH})
        routed, failed = rt.add_routes(["5.3.0.0/16", "5.4.0.0/16", "5.5.0.0/16"], GW, sock=sock)
        self.assertEqual(routed, ["5.3.0.0/16", "5.5.0.0/16"])
        self.assertEqual(list(failed), ["5.4.0.0/16"])
        self.assertEqual(sock.types(), [rt.RTM_ADD, rt.RTM_CHANGE, rt.RTM_ADD, rt.RTM_ADD])
        self.assertFalse(sock.closed)

    def test_delete_counts_missing_routes_as_gone(self):
        sock = FakeSocket({(rt.RTM_DELETE, "5.3.0.0"): errno.ESRCH, (rt.RTM_DELETE, "5.4.0.0"): errno.EPERM})
        failed = rt.delete_routes(["5.3.0.0/16", "5.4.0.0/16", "5.5.0.0/16"], sock=sock)
        self.assertEqual(list(failed), ["5.4.0.0/16"])
        self.assertEqual(sock.types(), [rt.RTM_DELETE] * 3)

    def test_socket_opened_here_is_closed(self):
        sock = FakeSocket()
        with mock.patch.object(rt, "open_socket", return_value=sock):
            self.assertEqual(rt.add_routes(["5.3.0.0/16"], GW), (["5.3.0.0/16"], {}))
            self.assertTrue(sock.closed)
            sock.closed = False
            self.assertEqual(rt.delete_routes(["5.3.0.0/16"]), {})
            self.assertTrue(sock.closed)

    def test_nothing_to_do_opens_nothing(self):
        with mock.patch.object(rt, "open_socket", side_effect=AssertionError("opened")):
            self.assertEqual(rt.add_routes([], GW), ([], {}))
            self.assertEqual(rt.delete_routes([]), {})


if __name__ == "__main__":
    unittest.main()
