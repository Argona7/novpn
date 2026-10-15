"""pf anchor that keeps bypassed addresses off every tunnel.

The stock /etc/pf.conf evaluates `anchor "com.apple/*"`, so rules loaded into com.apple/novpn
take effect without touching the system ruleset.  pf is switched on with a reference token
(`pfctl -E`) and that token is handed back on cleanup, so pf returns to the state it was in.

`block return` answers a refused TCP packet with a reset and a UDP one with ICMP unreachable,
so a browser holding a connection through the tunnel sees it fail at once and reconnects,
now over the direct route, instead of waiting minutes for a timeout.
"""
from __future__ import annotations

import logging
import re
import subprocess
import threading
from pathlib import Path

ANCHOR = "com.apple/novpn"
PFCTL = "/sbin/pfctl"
TABLE4, TABLE6 = "novpn", "novpn6"
_IFACE = re.compile(r"[a-z]+[0-9]+")
_TOKEN = re.compile(r"Token\s*:\s*(\d+)")

log = logging.getLogger("novpn")


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=False)


def ruleset(iface: str, v4_file, v6_file) -> str:
    """Listed IPv4 never leaves through a tunnel; packets still carrying a tunnel source address
    after their route moved to the uplink are refused; listed IPv6 is refused off the uplink,
    so browsers fall back to IPv4 at once."""
    if not _IFACE.fullmatch(iface or ""):
        raise ValueError(f"not an interface name: {iface!r}")
    return (
        f'table <{TABLE4}> persist file "{v4_file}"\n'
        f'table <{TABLE6}> persist file "{v6_file}"\n'
        f"block return out quick on ! {iface} inet from any to <{TABLE4}>\n"
        f"block return out quick on {iface} inet from ! ({iface}) to <{TABLE4}>\n"
        f"block return out quick on ! {iface} inet6 from any to <{TABLE6}>\n"
    )


class Firewall:
    """The anchor's rules and tables; host addresses are kept in step with pinned routes."""

    def __init__(self, run_dir, run=None):
        self.dir = Path(run_dir)
        self._run = run or _run
        self._lock = threading.Lock()
        self.token: str | None = None
        self.active = False
        self.hosts: set[str] = set()
        self._wanted: tuple | None = None
        self._loaded: tuple | None = None

    def load(self, iface: str | None, networks4=(), networks6=()) -> bool:
        """Rules for this uplink and these networks; no uplink means no rules.  True when active."""
        with self._lock:
            self._wanted = (iface, tuple(networks4), tuple(networks6))
            return self._load()

    def add_hosts(self, ips) -> None:
        with self._lock:
            new = [ip for ip in dict.fromkeys(ips) if ip not in self.hosts]
            self.hosts.update(new)
            if new and self.active:
                self._table("add", new)

    def remove_hosts(self, ips) -> None:
        with self._lock:
            gone = [ip for ip in dict.fromkeys(ips) if ip in self.hosts]
            self.hosts.difference_update(gone)
            if gone and self.active:
                self._table("delete", gone)

    def check(self) -> bool:
        """Load the rules again when pf was switched off, the anchor was emptied or an earlier load
        failed; True when that brought them back."""
        with self._lock:
            if self._wanted is None or self._wanted[0] is None:
                return False
            if not self.active:
                return self._load()
            enabled = "Status: Enabled" in self._run([PFCTL, "-s", "info"]).stdout
            if enabled and self._run([PFCTL, "-a", ANCHOR, "-s", "rules"]).stdout.strip():
                return False
            log.warning("pf %s; loading the novpn rules again", "anchor was emptied" if enabled else "was switched off")
            if not enabled:
                self._release()
            self._loaded = None
            self._load()
            return True

    def clear(self) -> None:
        with self._lock:
            self._flush()
            self._release()
            self.active, self._loaded, self._wanted = False, None, None
            self.hosts.clear()
            for name in ("pf.conf", "pf-v4.txt", "pf-v6.txt"):
                (self.dir / name).unlink(missing_ok=True)

    def adopt(self, old: dict) -> None:
        """Take back what a crashed run left: its rules and its pf enable reference."""
        with self._lock:
            self._flush()
            token = str(old.get("token") or "")
            if token.isdigit():
                self._run([PFCTL, "-X", token])

    def snapshot(self) -> dict:
        with self._lock:
            return {"active": self.active, "iface": self._wanted[0] if self._wanted else None, "token": self.token}

    def _load(self) -> bool:
        iface, networks4, networks6 = self._wanted
        if iface is None:
            if self.active:
                self._flush()
            self.active, self._loaded = False, None
            return False
        if self.active and self._loaded == self._wanted:
            return True
        if self.token is None and not self._enable():
            self.active = False
            return False
        self.dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        v4, v6, conf = self.dir / "pf-v4.txt", self.dir / "pf-v6.txt", self.dir / "pf.conf"
        v4.write_text("".join(f"{net}\n" for net in [*networks4, *sorted(self.hosts)]), encoding="utf-8")
        v6.write_text("".join(f"{net}\n" for net in networks6), encoding="utf-8")
        conf.write_text(ruleset(iface, v4, v6), encoding="utf-8")
        result = self._run([PFCTL, "-a", ANCHOR, "-f", str(conf)])
        if result.returncode != 0:
            log.warning("pf rules not loaded: %s", result.stderr.strip())
            self.active, self._loaded = False, None
            return False
        if not self.active:
            log.info("pf rules active on %s: %d networks, %d hosts, %d IPv6 networks",
                     iface, len(networks4), len(self.hosts), len(networks6))
        self.active, self._loaded = True, self._wanted
        return True

    def _enable(self) -> bool:
        result = self._run([PFCTL, "-E"])
        match = _TOKEN.search(result.stdout + result.stderr)
        if result.returncode != 0 or not match:
            log.warning("pf could not be enabled: %s", (result.stdout + result.stderr).strip())
            return False
        self.token = match.group(1)
        return True

    def _release(self) -> None:
        if self.token:
            self._run([PFCTL, "-X", self.token])
        self.token = None

    def _flush(self) -> None:
        self._run([PFCTL, "-a", ANCHOR, "-F", "rules"])
        self._run([PFCTL, "-a", ANCHOR, "-F", "Tables"])

    def _table(self, verb: str, ips: list[str]) -> None:
        result = self._run([PFCTL, "-a", ANCHOR, "-t", TABLE4, "-T", verb, *ips])
        if result.returncode != 0:
            log.warning("pf table %s %s failed: %s", verb, ips, result.stderr.strip())
