# Security

novpn runs a small daemon as **root**, so here is what it touches.

| What | Where | Why |
|---|---|---|
| Resolver files | `/etc/resolver/<domain>` — only files that start with `# managed by novpn` | send DNS for listed domains to the local forwarder |
| Host and network routes | kernel routing table, via `/sbin/route` and a `PF_ROUTE` socket | send listed addresses out through your real network interface |
| pf rules | its own anchor `com.apple/novpn`; `/etc/pf.conf` is never edited | the kill switch |
| State | `/var/run/novpn/`, `/var/db/novpn/` (Russian network list cache) | crash recovery and status |
| Log | `/var/log/novpn.log` | `novpn logs` |
| pf on/off | `pfctl -E` with its own reference token, handed back on stop | pf must be enabled for the kill switch |
| DNS cache | flushed (`dscacheutil -flushcache`, HUP to mDNSResponder) when the list changes | so the browser asks again |
| Installer | `/Library/LaunchDaemons/com.argona.novpn.plist`, `/usr/local/lib/novpn`, `~/.local/bin/novpn` link | start at boot |

Design rules the code follows:

- The daemon runs from a root-owned copy in `/usr/local/lib/novpn`, never from your user-writable checkout.
- Your site list (`~/.config/novpn/domains.txt`) is read with `O_NOFOLLOW`, must be a regular file owned by the owner of its folder, at most 1 MB, and every entry is validated as a domain before it becomes a file name in `/etc/resolver`.
- The Russian network list is downloaded over HTTPS with `/usr/bin/curl` and accepted only if every line parses as a network of the right IP version and at least 1,000 IPv4 (100 IPv6) public networks remain; a bad download keeps the previous list.
- Nothing is sent anywhere except DNS queries for listed sites (to your network's resolver, or Yandex DNS 77.88.8.8 and Cloudflare 1.1.1.1 when it does not answer, plus the VPN's resolver when a site is added and at each start or network change) and, while Russia mode is on, the list download from `raw.githubusercontent.com` (right away, then weekly).
- `sudo ./install.sh --uninstall` removes the daemon, its routes, its pf anchor, its resolver files, its state, its log, the list cache and the command link; your site list is kept.

## Reporting a vulnerability

Please open a [private security advisory](../../security/advisories/new) instead of a public issue.
