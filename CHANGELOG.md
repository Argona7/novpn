# Changelog

## 1.0.0 — 2026-10-15

- Per-site registry: `novpn add ozon.ru` covers every subdomain, URLs and Cyrillic domains are accepted.
- Russia mode: `novpn russia on` sends all ~8,600 Russian IPv4 networks and the `.ru`, `.рф`, `.su` zones past the VPN.
- Changes apply in about 0.3 s; open connections to a newly listed site are reset and reconnect directly within a second.
- pf kill switch: every address novpn routes directly is refused on any interface but the physical one; in Russia mode IPv6 to Russian networks falls back to IPv4.
- Routes are pinned to the physical interface, re-checked every 2 s and restored after sleep or `route flush`.
- Weekly refresh of the Russian network list with validation; full cleanup on uninstall and after crashes.
