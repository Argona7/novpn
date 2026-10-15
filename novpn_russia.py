"""Russia mode: every Russian network bypasses the tunnel, not only listed sites.

The prefix lists are ipverse/rir-ip (RIR delegations, aggregated).  A copy ships in data/; the
daemon refreshes it weekly into CACHE_DIR and keeps the old list when a download looks wrong.
Routes go in through the routing socket and are recorded on disk first, so a crashed run can
take them back.
"""
from __future__ import annotations

import bisect
import ipaddress
import json
import logging
import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path

import novpn_rtsock

OPTION = "russia"
ZONES = ("ru", "xn--p1ai", "su")  # .ru .рф .su
CACHE_DIR = Path("/var/db/novpn")
DATA_DIR = Path(__file__).resolve().parent / "data"
BASE_URL = "https://raw.githubusercontent.com/ipverse/rir-ip/master/country/ru/"
CURL = "/usr/bin/curl"
REFRESH_SECONDS = 7 * 86400
RETRY_SECONDS = 3600
MIN_PREFIXES = {4: 1000, 6: 100}
MIN_PREFIXLEN = {4: 8, 6: 16}

log = logging.getLogger("novpn")


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=90, check=False)


def list_name(version: int) -> str:
    return f"ru-ipv{version}.txt"


def parse_prefixes(text: str, version: int) -> list[str]:
    """Collapsed public networks of one IP version.

    Junk, host bits or the wrong version reject the whole list (a broken download); private,
    shared or implausibly wide networks are just left out."""
    networks = []
    for line in text.splitlines():
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        net = ipaddress.ip_network(entry)
        if net.version != version:
            raise ValueError(f"IPv{net.version} network in the IPv{version} list: {entry}")
        if net.is_global and net.prefixlen >= MIN_PREFIXLEN[version]:
            networks.append(net)
    if len(networks) < MIN_PREFIXES[version]:
        raise ValueError(f"only {len(networks)} IPv{version} networks")
    return [str(net) for net in ipaddress.collapse_addresses(networks)]


def load_prefixes(version: int, cache_dir=CACHE_DIR, data_dir=DATA_DIR) -> tuple[list[str], Path | None]:
    """The refreshed list when it is valid, else the copy shipped with novpn."""
    for path in (Path(cache_dir) / list_name(version), Path(data_dir) / list_name(version)):
        try:
            return parse_prefixes(path.read_text(encoding="utf-8"), version), path
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            log.warning("%s: %s", path, exc)
    return [], None


class PrefixIndex:
    """Membership test of an IPv4 address against non-overlapping networks."""

    def __init__(self, networks=()):
        spans = sorted((int(net.network_address), int(net.broadcast_address))
                       for net in map(ipaddress.IPv4Network, networks))
        self._starts = [start for start, _ in spans]
        self._ends = [end for _, end in spans]

    def __contains__(self, ip) -> bool:
        try:
            value = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return False
        i = bisect.bisect_right(self._starts, value) - 1
        return i >= 0 and value <= self._ends[i]

    def __len__(self) -> int:
        return len(self._starts)


class RussiaMode:
    """Routes for every Russian IPv4 network via the physical gateway and interface, or none."""

    def __init__(self, record_path, cache_dir=CACHE_DIR, data_dir=DATA_DIR,
                 add_routes=None, delete_routes=None, run=None, clock=time.time):
        self.record = Path(record_path)
        self.cache_dir, self.data_dir = Path(cache_dir), Path(data_dir)
        self._add = add_routes or novpn_rtsock.add_routes
        self._delete = delete_routes or novpn_rtsock.delete_routes
        self._run = run or _run
        self._clock = clock
        self._lock = threading.Lock()
        self.networks4: list[str] | None = None
        self.networks6: list[str] | None = None
        self.sources: dict[int, Path | None] = {}
        self.installed: list[str] = []
        self.gateway: str | None = None
        self.iface: str | None = None
        self.index = PrefixIndex()
        self._updated = False
        self._next_attempt = 0.0
        self._thread: threading.Thread | None = None

    def load(self) -> None:
        self.networks4, self.sources[4] = load_prefixes(4, self.cache_dir, self.data_dir)
        self.networks6, self.sources[6] = load_prefixes(6, self.cache_dir, self.data_dir)

    def ipv6(self) -> list[str]:
        if self.networks6 is None:
            self.load()
        return self.networks6

    def covers(self, ip: str) -> bool:
        return ip in self.index

    def apply(self, enabled: bool, gateway: str | None, iface: str | None = None) -> list[str]:
        """Bring the kernel to: every listed network via gateway on iface, or no routes at all.

        A new gateway or a new interface (Wi-Fi to Ethernet on the same router) moves every route."""
        wanted = []
        if enabled and gateway:
            if self.networks4 is None:
                self.load()
            wanted = self.networks4
        if (gateway, iface) == (self.gateway, self.iface):
            want, have = set(wanted), set(self.installed)
            stale = [net for net in self.installed if net not in want]
            fresh = [net for net in wanted if net not in have]
        else:
            stale, fresh = list(self.installed), list(wanted)
        if not stale and not fresh:
            return self.installed
        self._write_record(set(self.installed) | set(fresh))
        gone = set(stale)
        kept = [net for net in self.installed if net not in gone]
        failed = self._delete(stale) if stale else {}
        if failed:
            log.warning("russia: %d routes not removed, e.g. %s", len(failed), next(iter(failed.items())))
        routed, failed = self._add(fresh, gateway, iface) if fresh else ([], {})
        if failed:
            log.warning("russia: %d of %d networks not routed, e.g. %s", len(failed), len(fresh),
                        next(iter(failed.items())))
        self.installed = kept + routed
        self.gateway, self.iface = (gateway, iface) if self.installed else (None, None)
        self.index = PrefixIndex(self.installed)
        self._write_record(self.installed)
        if self.installed:
            log.info("russia: %d networks via %s on %s", len(self.installed), gateway, iface)
        else:
            log.info("russia: network routes removed")
        return self.installed

    def withdraw(self) -> None:
        self.apply(False, None)

    def forget(self) -> None:
        """Treat every route as missing, so the next apply adds them all again (changing survivors)."""
        self.installed, self.gateway, self.iface = [], None, None

    def sample(self, count: int) -> list[str]:
        """Up to count installed networks spread over the list, for spot checks of the kernel table."""
        step = max(1, len(self.installed) // count) if count else 0
        return self.installed[::step][:count] if step else []

    def adopt_leftovers(self) -> None:
        """Delete the routes a crashed run recorded."""
        try:
            networks = json.loads(self.record.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(networks, list):
            self._delete([net for net in networks if isinstance(net, str)])
        self._write_record([])

    def snapshot(self) -> dict:
        source = self.sources.get(4)
        return {"networks": len(self.installed), "list": str(source) if source else None}

    def maybe_refresh(self) -> None:
        """Download fresh lists in the background once the cached one is a week old."""
        with self._lock:
            now = self._clock()
            if now < self._next_attempt or (self._thread and self._thread.is_alive()):
                return
            try:
                age = now - (self.cache_dir / list_name(4)).stat().st_mtime
            except OSError:
                age = float("inf")
            if age < REFRESH_SECONDS:
                return
            self._next_attempt = now + RETRY_SECONDS
            self._thread = threading.Thread(target=self.refresh, name="russia-refresh", daemon=True)
            self._thread.start()

    def join_refresh(self, timeout: float | None = None) -> None:
        if self._thread:
            self._thread.join(timeout)

    def refresh(self) -> bool:
        """Download both lists; each replaces the cached one only when it parses.  True if any did."""
        self.cache_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        updated = False
        for version in (4, 6):
            target = self.cache_dir / list_name(version)
            fd, tmp = tempfile.mkstemp(dir=str(self.cache_dir), prefix=f".{target.name}.")
            os.close(fd)
            try:
                result = self._run([CURL, "-fsS", "--max-time", "60", "-o", tmp,
                                    f"{BASE_URL}ipv{version}-aggregated.txt"])
                if result.returncode != 0:
                    raise ValueError(result.stderr.strip() or f"curl exit {result.returncode}")
                count = len(parse_prefixes(Path(tmp).read_text(encoding="utf-8"), version))
                os.chmod(tmp, 0o644)
                os.replace(tmp, target)
                updated = True
                log.info("russia: IPv%d list refreshed, %d networks", version, count)
            except (OSError, ValueError) as exc:
                log.warning("russia: IPv%d list not refreshed: %s", version, exc)
            finally:
                if os.path.exists(tmp):
                    os.unlink(tmp)
        if updated:
            with self._lock:
                self._updated = True
        return updated

    def take_update(self) -> bool:
        """True once after a refresh, with the new lists loaded."""
        with self._lock:
            updated, self._updated = self._updated, False
        if updated:
            self.load()
        return updated

    def _write_record(self, networks) -> None:
        if not networks:
            self.record.unlink(missing_ok=True)
            return
        self.record.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(self.record.parent), prefix=f".{self.record.name}.")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(sorted(networks), fh)
        os.chmod(tmp, 0o644)
        os.replace(tmp, self.record)
