<p align="center"><b>English</b> · <a href="README.ru.md">Русский</a></p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/banner-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/banner-light.svg">
    <img alt="novpn: keep the VPN on, chosen sites go straight through your ISP" src="assets/banner-light.svg" width="100%">
  </picture>
</p>

<p align="center">
  <b>Keep the VPN on. Let Ozon, your bank and Gosuslugi see your normal internet.</b><br>
  A small macOS daemon that sends the sites you choose past your VPN and out through your own provider.
</p>

<p align="center">
  <img alt="macOS" src="https://img.shields.io/badge/macOS-tested%20on%2026-111?style=flat-square&logo=apple&logoColor=white">
  <img alt="Python 3.9+ standard library" src="https://img.shields.io/badge/python-3.9%2B%20stdlib-3776AB?style=flat-square&logo=python&logoColor=white">
  <img alt="zero dependencies" src="https://img.shields.io/badge/dependencies-0-2ea44f?style=flat-square">
  <a href="https://github.com/Argona7/novpn/actions/workflows/tests.yml"><img alt="tests" src="https://img.shields.io/github/actions/workflow/status/Argona7/novpn/tests.yml?branch=main&style=flat-square&label=tests"></a>
  <a href="LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-blue?style=flat-square"></a>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#usage">Usage</a> ·
  <a href="#russia-mode">Russia mode</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#security-and-privacy">Security</a> ·
  <a href="#faq">FAQ</a>
</p>

<p align="center">
  <img alt="novpn demo: a site sees the VPN, novpn add, the same site sees your ISP" src="assets/demo.gif" width="860">
  <br>
  <sub>A real recording with the VPN on. Addresses are swapped for documentation ones (<a href="assets/demo.tape">tape source</a>).</sub>
</p>

## Why

Since April 2026 most large Russian services (Ozon, Wildberries, Yandex, VK, Sber, T-Bank, Gosuslugi) restrict visitors whose address looks like a VPN ([Meduza](https://meduza.io/feature/2026/04/15/krupneyshie-rossiyskie-servisy-perestayut-rabotat-pri-vklyuchennom-vpn-kak-i-trebovalo-mintsifry)). Ozon shows *«Что-то с интернетом»*, Wildberries asks you to turn the VPN off, the Gosuslugi app refuses to open.

Turning the VPN off for one purchase breaks everything else you use it for, and macOS VPN apps cannot help: Tailscale has [no split tunnelling on macOS](https://github.com/tailscale/tailscale/issues/13677), and Xray-based clients route per rule set, need a reconnect after every change and leave open tabs on the old route.

**novpn** works under the VPN you already have. You name the sites; their traffic leaves through your normal connection, everything else stays in the tunnel.

## Highlights

- **One command per site.** `novpn add ozon.ru` covers every subdomain. URLs and Cyrillic domains work too.
- **Russia mode.** `novpn russia on` sends all 8,600+ Russian IPv4 networks and the `.ru`, `.рф`, `.su` zones past the VPN.
- **Instant.** A change is applied in about 0.3 s. A connection the browser already had open through the VPN is reset and comes back direct within a second, so open tabs switch over by themselves.
- **No leaks.** A pf kill switch refuses every address novpn routed directly on any interface other than your physical connection, so it cannot slip back into the VPN. In Russia mode, IPv6 to Russian networks that would enter the tunnel is refused too, and browsers fall back to IPv4 at once.
- **Survives real life.** Wi-Fi changes, sleep, `route flush` and crashes are handled; routes are spot-checked every 2 seconds. `--uninstall` removes everything it added except your site list.
- **Zero dependencies.** About 1,900 lines of Python standard library that ships with macOS, covered by 92 tests.

## Quick start

```bash
git clone https://github.com/Argona7/novpn.git && cd novpn
sudo ./install.sh          # once: installs the background daemon
novpn add ozon.ru          # this site now skips the VPN
novpn check ozon.ru        # proof: "en0 ... direct"
```

> [!IMPORTANT]
> **Clear the site's cookies once after `novpn add`.** Ozon and other sites remember that they saw a VPN and keep showing the block even when the traffic is already direct. In Chrome open `chrome://settings/content/all?searchSubpage=ozon.ru` and delete the site's data; in Safari use Settings > Privacy > Manage Website Data. `novpn add` prints these links for every site you add.

## Install

> [!IMPORTANT]
> `install.sh` installs a launchd daemon that runs as root, because only root can change routes, `/etc/resolver` and pf. [Security and privacy](#security-and-privacy) lists what it touches; [SECURITY.md](SECURITY.md) has the details.

**Requirements**

- macOS with `/usr/bin/python3` (it comes with the Command Line Tools: `xcode-select --install`). Tested on macOS 26.
- A VPN that runs as a system tunnel (see [Works with](#works-with)).

**Install or update**

```bash
git clone https://github.com/Argona7/novpn.git && cd novpn
sudo ./install.sh
```

The daemon runs from a root-owned copy in `/usr/local/lib/novpn`; the `novpn` command is a link from this folder into `~/.local/bin`, so keep the folder (add `~/.local/bin` to `PATH` if your shell cannot find the command). To update: `git pull && sudo ./install.sh`.

**Uninstall**

```bash
sudo ./install.sh --uninstall
```

This removes the daemon, its routes, its pf rules, its `/etc/resolver` files, its state, its log, the downloaded network list and the `novpn` command link. Your site list in `~/.config/novpn/domains.txt` is kept.

## Usage

| Command | What it does |
|---|---|
| `novpn add <site>…` | Send sites past the VPN. A site covers all its subdomains; `https://www.ozon.ru/…` and `кремль.рф` are accepted. |
| `novpn rm <site>…` | Put sites back into the VPN. |
| `novpn ls` | Show the list. |
| `novpn russia on` / `off` | All Russian networks and `.ru` `.рф` `.su` past the VPN, or back. |
| `novpn check <site>…` | Show where each of the site's IPv4 addresses leaves right now: `direct` or `VPN`. |
| `novpn status` | Daemon, uplink, routes, Russia mode, kill switch, current Tailscale exit node. |
| `novpn logs` | The daemon's log. |

The list is a plain text file, `~/.config/novpn/domains.txt`, one site per line; edit it by hand if you like, the daemon picks up changes within a quarter of a second.

```console
$ novpn add gosuslugi.ru https://www.wildberries.ru/
+ gosuslugi.ru  (and *.gosuslugi.ru)
+ wildberries.ru  (and *.wildberries.ru)
applied in 0.3 s; open tabs switch over by themselves (reload one that still sees the VPN)

$ novpn check ozon.ru            # with Russia mode on
ozon.ru: listed as ozon.ru
  185.73.193.68   en0 via 192.168.0.1  direct  (Russian network)
  185.73.194.82   en0 via 192.168.0.1  direct  (Russian network)
```

## Russia mode

```bash
novpn russia on     # all Russian networks and .ru .рф .su skip the VPN
novpn russia off    # only the sites on your list do
```

Russia mode adds about 8,600 IPv4 networks (and about 2,200 IPv6 ones for the kill switch) registered to Russia by the regional internet registries, plus the `.ru`, `.рф` and `.su` zones. It covers what a per-site list misses: a Russian service on a `.com` domain (vk.com), its image CDN on another domain (ozone.ru for Ozon) or an API on an IP address.

The list comes from [ipverse/rir-ip](https://github.com/ipverse/rir-ip). A copy ships with novpn; while Russia mode is on, the daemon downloads a fresh one right away and then once a week; a download that does not parse is thrown away and the old list stays. All 8,600 routes go in through the kernel routing socket in about 0.4 s.

The trade-off: with Russia mode on, your provider sees all of your traffic to Russian services, exactly as it would without a VPN.

## How it works

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/how-it-works-dark.svg">
    <source media="(prefers-color-scheme: light)" srcset="assets/how-it-works-light.svg">
    <img alt="DNS for a listed site goes to novpn, which pins a direct route before answering; the connection then leaves through your ISP; a pf rule resets anything that still tries the tunnel" src="assets/how-it-works-light.svg" width="100%">
  </picture>
</p>

1. **DNS.** For every listed site novpn writes `/etc/resolver/<site>`, so macOS asks novpn's own DNS server on `127.0.0.1:53535` about it. novpn asks your network's DNS over the physical interface, not through the tunnel (Yandex DNS and Cloudflare are the fallback if it does not answer).
2. **Route before answer.** Before it hands the address back, novpn adds a host route for it via your router. By the time the browser connects, the route is already there, so the connection leaves through your provider and the site sees your real address.
3. **Kill switch.** pf rules in novpn's own anchor (`com.apple/novpn`) reset any packet to a routed address that tries to leave through anything but your physical connection, the tunnel included. That is what moves already-open tabs: their old connection fails at once and the browser reconnects directly, instead of hanging for minutes.
4. **Russia mode** routes the Russian networks the same way, with the interface pinned, and adds the `.ru`, `.рф`, `.su` zones to step 1.
5. **Housekeeping.** The daemon follows Wi-Fi and Ethernet changes, spot-checks its routes every 2 seconds and restores them after sleep or `route flush`, and on stop, uninstall or the next start after a crash takes back everything it added.

## Works with

novpn does not care which VPN protocol you use (WireGuard, VLESS, Reality, VMess, Trojan, Shadowsocks, Hysteria…): it decides before traffic reaches the tunnel. What matters is how the client attaches to macOS.

| VPN client | Status |
|---|---|
| Tailscale with an exit node | **Tested** |
| Happ and other Xray / sing-box clients in VPN (TUN) mode | Should work, not tested yet |
| WireGuard, OpenVPN, IKEv2 and other system VPNs (`utun`) | Should work, not tested yet |
| Any client in **system proxy** mode | No: the browser hands traffic to the proxy, which routes cannot change |
| Clients that force *all* traffic into the tunnel at the system level ("include all networks") | No |

Tested something? Please open an issue with the client name and the output of `novpn status` (remove your user name and exit node name).

## novpn vs alternatives

| | novpn | Rules inside a VPN client (Happ, Clash, sing-box) | AmneziaVPN split tunnelling (macOS) | WireGuard AllowedIPs / route scripts |
|---|---|---|---|---|
| Works under any VPN | yes (tested with Tailscale) | only inside that client | only Amnezia | one setup per VPN |
| Per site, with subdomains | yes, resolved live | yes, CDNs on other domains by hand | resolved once, then stale | IP only |
| All of Russia in one command | yes | via `geoip:ru` rule sets | via imported IP lists | build the list yourself |
| Open tabs switch at once | yes | reconnect or restart the app | not documented | no |
| A listed site can never leak into the tunnel | yes, for every address novpn resolved (pf) | a missed rule falls back to the VPN | hostname rules can fail silently ([#3240](https://github.com/amnezia-vpn/amnezia-client/issues/3240)) | no |
| Setup | `install.sh` + `novpn add` | profiles, JSON or YAML, reconnect after edits | IP list files | scripts to maintain |

If you want a menu-bar app aimed at corporate VPNs, look at [VPN Bypass](https://github.com/GeiserX/VPN-Bypass).

## Security and privacy

- **What runs as root:** one Python daemon from a root-owned copy in `/usr/local/lib/novpn`. It writes only resolver files it marks as its own, host and network routes, pf rules in its own anchor and its state under `/var/run/novpn` and `/var/db/novpn`. It turns pf on with its own reference token (`pfctl -E`) and hands it back on stop, and flushes the DNS cache when the list changes. `/etc/pf.conf` is never edited.
- **What `install.sh` adds:** `/Library/LaunchDaemons/com.argona.novpn.plist`, `/usr/local/lib/novpn`, `/var/log/novpn.log`, the `~/.local/bin/novpn` link and your list `~/.config/novpn/domains.txt`.
- **What leaves your Mac:** DNS questions for listed sites, over your physical connection to your network's resolver, or to Yandex DNS (77.88.8.8) and Cloudflare (1.1.1.1) when it does not answer. The VPN's resolver is also asked about a site and its `www.` name when it is added, and again at each start or network change, to learn which addresses the browser may already hold. While Russia mode is on, the Russian network list is downloaded from `raw.githubusercontent.com` (right away, then weekly). No telemetry, no accounts, no servers of ours.
- **Your list** is opened with `O_NOFOLLOW`, must be a regular file owned by the owner of its folder, at most 1 MB, and every entry is checked to be a domain before it becomes a file name in `/etc/resolver`.

Full details and how to report a vulnerability: [SECURITY.md](SECURITY.md).

## FAQ

<details>
<summary><b>Will Ozon, Wildberries and my bank work?</b></summary>

In the browser these sites decide by the address they see, and with novpn they see your provider's. Ozon in Chrome is tested; if another site still complains, see the next question. Phone apps are a different story: an app can also look for a VPN on the device itself, and novpn runs on a Mac.
</details>

<details>
<summary><b>A site still says I use a VPN.</b></summary>

1. Run `novpn check <site>`. Every line should say `direct`.
2. The page may load parts from other domains. Open DevTools → Network, find the domains it talks to and add them, or turn on Russia mode if they are Russian.
3. Clear the site's cookies (see [Quick start](#quick-start)). If a private window works and the normal one does not, this is exactly the case: the site remembered your VPN from before.
</details>

<details>
<summary><b>Does it hide that I use a VPN?</b></summary>

No. It changes which address the listed sites see. It does not hide the VPN from the system, and it does not unblock anything: it is the opposite of a VPN.
</details>

<details>
<summary><b>What about my browser's "secure DNS"?</b></summary>

Russia mode works on IP addresses, so it does not depend on DNS. For listed sites outside Russian networks novpn relies on the system resolver; a browser set to its own DNS-over-HTTPS provider may skip it, so turn that setting off or to "use your current provider".
</details>

<details>
<summary><b>Does it slow anything down?</b></summary>

Only DNS lookups of listed sites (and of `.ru` `.рф` `.su` in Russia mode) go through novpn. Each costs one query to your provider, plus a few milliseconds to pin a route the first time an address appears. Everything else is untouched. The daemon is idle between a quarter-second file check and a 2-second network check.
</details>

<details>
<summary><b>How do I see what it is doing?</b></summary>

`novpn status` for the overview, `novpn check <site>` for one site, `novpn logs` for the log.
</details>

## Limitations

- macOS only, and it needs your password once to install.
- It does not help with VPN clients in proxy mode or ones that force all traffic into the tunnel (see [Works with](#works-with)).
- A site that serves parts of a page from foreign domains needs those domains listed too.
- Phone apps that check the device for a VPN are out of scope.

## Contributing

Bug reports and pull requests are welcome. `make test` runs the suite under the same Python the daemon uses; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © 2026 Argona ([@Argona0x](https://x.com/Argona0x))
