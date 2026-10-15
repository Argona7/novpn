"""Builds the README art: python3 assets/make_art.py assets  (social-preview.png is a 1280x640 Chrome screenshot of the social SVG)."""
import sys
from pathlib import Path

OUT = Path(sys.argv[1])
SANS = "-apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Helvetica, Arial, sans-serif"
MONO = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"

THEMES = {
    "dark": dict(bg1="#0b0f17", bg2="#111827", line="#1f2937", grid="#ffffff", grid_o="0.035", text="#f0f6fc",
                 muted="#8b949e", faint="#30363d", green="#3fb950", green2="#7ee787", glow="#2ea043",
                 vpn="#6e7681", vpn2="#484f58", card="#0f1622", card_line="#263041", red="#f85149", chip="#11281a"),
    "light": dict(bg1="#ffffff", bg2="#f6f8fa", line="#d0d7de", grid="#0b0f17", grid_o="0.04", text="#1f2328",
                  muted="#57606a", faint="#d8dee4", green="#1a7f37", green2="#2da44e", glow="#2da44e",
                  vpn="#8c959f", vpn2="#afb8c1", card="#ffffff", card_line="#d0d7de", red="#cf222e", chip="#dafbe1"),
}


def mark(x, y, s, t):
    """Logo mark: one line in, splitting: dashed path into a tunnel, solid path straight out."""
    k = s / 64
    return f'''<g transform="translate({x} {y}) scale({k})">
  <circle cx="10" cy="32" r="7" fill="{t['text']}"/>
  <path d="M17 32 C 30 32, 32 14, 46 14 L 56 14" fill="none" stroke="{t['vpn']}" stroke-width="5"
        stroke-linecap="round" stroke-dasharray="2 8"/>
  <path d="M17 32 C 30 32, 32 50, 46 50 L 54 50" fill="none" stroke="{t['green']}" stroke-width="6" stroke-linecap="round"/>
  <path d="M51 43 L 60 50 L 51 57" fill="none" stroke="{t['green']}" stroke-width="6" stroke-linecap="round"
        stroke-linejoin="round"/>
</g>'''


def banner(name, t, animated=True):
    w, h = 1280, 420
    up = "M 790 215 C 860 215, 870 128, 950 128 L 1150 128"
    down = "M 790 215 C 860 215, 870 302, 950 302 L 1150 302"
    pills = ""
    lane = "M 990 268 L 1052 268"
    for i, site in enumerate(("ozon.ru", "gosuslugi.ru", "vk.com", "sberbank.ru")):
        width = 22 + 10.6 * len(site)
        pills += f'''
  <g opacity="0">
    <rect x="{-width / 2}" y="-15" width="{width}" height="30" rx="15" fill="{t['chip']}" stroke="{t['green']}" stroke-width="1.5"/>
    <text x="0" y="5.5" text-anchor="middle" font-family="{MONO}" font-size="15" fill="{t['green']}">{site}</text>
    <animateMotion dur="8s" begin="{i * 2}s" repeatCount="indefinite" path="{lane}" keyPoints="0;1;1" keyTimes="0;0.25;1"
                   calcMode="linear"/>
    <animate attributeName="opacity" dur="8s" begin="{i * 2}s" repeatCount="indefinite"
             values="0;1;1;0;0" keyTimes="0;0.04;0.2;0.25;1"/>
  </g>'''
    dots = ""
    for i in range(3):
        dots += f'''
  <circle r="5" fill="{t['green2']}" opacity="0">
    <animateMotion dur="2.4s" begin="{i * 0.8}s" repeatCount="indefinite" path="{down}"/>
    <animate attributeName="opacity" dur="2.4s" begin="{i * 0.8}s" repeatCount="indefinite" values="0;1;1;0" keyTimes="0;0.1;0.85;1"/>
  </circle>'''
    for i in range(4):
        dots += f'''
  <circle r="4" fill="{t['vpn']}" opacity="0">
    <animateMotion dur="4s" begin="{i}s" repeatCount="indefinite" path="{up}"/>
    <animate attributeName="opacity" dur="4s" begin="{i}s" repeatCount="indefinite" values="0;0.9;0.9;0" keyTimes="0;0.1;0.85;1"/>
  </circle>'''
    if not animated:
        pills = (f'<g transform="translate(1030 268)"><rect x="-48" y="-15" width="96" height="30" rx="15" fill="{t['chip']}" '
                 f'stroke="{t['green']}" stroke-width="1.5"/><text x="0" y="5.5" text-anchor="middle" font-family="{MONO}" '
                 f'font-size="15" fill="{t['green']}">ozon.ru</text></g>')
        dots = ""
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img"
     aria-label="novpn: keep the VPN on, chosen sites go straight through your ISP">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="{t['bg1']}"/><stop offset="1" stop-color="{t['bg2']}"/>
    </linearGradient>
    <pattern id="grid" width="32" height="32" patternUnits="userSpaceOnUse">
      <path d="M 32 0 L 0 0 0 32" fill="none" stroke="{t['grid']}" stroke-opacity="{t['grid_o']}" stroke-width="1"/>
    </pattern>
    <radialGradient id="glow" cx="0.5" cy="0.5" r="0.5">
      <stop offset="0" stop-color="{t['glow']}" stop-opacity="0.28"/><stop offset="1" stop-color="{t['glow']}" stop-opacity="0"/>
    </radialGradient>
    <clipPath id="card"><rect x="1" y="1" width="{w - 2}" height="{h - 2}" rx="24"/></clipPath>
  </defs>
  <g clip-path="url(#card)">
    <rect width="{w}" height="{h}" fill="url(#bg)"/>
    <rect width="{w}" height="{h}" fill="url(#grid)"/>
    <ellipse cx="1100" cy="302" rx="260" ry="140" fill="url(#glow)"/>
  </g>
  <rect x="1" y="1" width="{w - 2}" height="{h - 2}" rx="24" fill="none" stroke="{t['line']}" stroke-width="2"/>

  {mark(72, 92, 92, t)}
  <text x="176" y="170" font-family="{SANS}" font-size="112" font-weight="800" letter-spacing="-4" fill="{t['text']}">novpn</text>
  <text x="76" y="262" font-family="{SANS}" font-size="30" font-weight="650" fill="{t['text']}">Keep the VPN on.</text>
  <text x="76" y="304" font-family="{SANS}" font-size="30" fill="{t['muted']}">Chosen sites go straight through your ISP.</text>
  <text x="76" y="352" font-family="{MONO}" font-size="19" fill="{t['muted']}"><tspan fill="{t['green']}">$</tspan> novpn add ozon.ru</text>

  <!-- the split -->
  <path d="{up}" fill="none" stroke="{t['vpn2']}" stroke-width="3" stroke-dasharray="3 9" stroke-linecap="round"/>
  <path d="{down}" fill="none" stroke="{t['green']}" stroke-width="4" stroke-linecap="round"/>
  {dots}
  <rect x="955" y="104" width="150" height="48" rx="24" fill="{t['bg2']}" stroke="{t['vpn2']}" stroke-width="2"/>
  <text x="1030" y="134" text-anchor="middle" font-family="{SANS}" font-size="17" font-weight="600" fill="{t['vpn']}">VPN tunnel</text>
  {pills}

  <circle cx="770" cy="215" r="34" fill="{t['card']}" stroke="{t['card_line']}" stroke-width="2"/>
  <g transform="translate(770 215)" fill="none" stroke="{t['text']}" stroke-width="2.5" stroke-linejoin="round">
    <rect x="-15" y="-11" width="30" height="20" rx="2.5"/><path d="M -20 13 L 20 13" stroke-linecap="round"/>
  </g>
  <text x="770" y="275" text-anchor="middle" font-family="{SANS}" font-size="16" fill="{t['muted']}">your Mac</text>

  <circle cx="1176" cy="128" r="26" fill="{t['card']}" stroke="{t['vpn2']}" stroke-width="2"/>
  <g transform="translate(1176 128)" fill="none" stroke="{t['vpn']}" stroke-width="2">
    <circle r="11"/><ellipse rx="5" ry="11"/><path d="M -11 0 L 11 0"/>
  </g>
  <text x="1176" y="180" text-anchor="middle" font-family="{SANS}" font-size="16" fill="{t['muted']}">exit node</text>

  <circle cx="1176" cy="302" r="30" fill="{t['card']}" stroke="{t['green']}" stroke-width="2.5"/>
  <g transform="translate(1176 302)" fill="none" stroke="{t['green']}" stroke-width="2.5" stroke-linejoin="round" stroke-linecap="round">
    <path d="M -12 2 L 0 -10 L 12 2"/><path d="M -8 -1 L -8 11 L 8 11 L 8 -1"/>
  </g>
  <text x="1176" y="358" text-anchor="middle" font-family="{SANS}" font-size="16" font-weight="600" fill="{t['green']}">your ISP</text>
</svg>
'''


def how(name, t):
    w, h = 1280, 600

    def box(x, y, bw, bh, title, sub, stroke, title_fill=None, mono_sub=False):
        sub_font = MONO if mono_sub else SANS
        lines = sub.split("\n")
        subs = "".join(f'<text x="{x + 20}" y="{y + 62 + 22 * i}" font-family="{sub_font}" font-size="{15 if mono_sub else 16}" '
                       f'fill="{t["muted"]}">{line}</text>' for i, line in enumerate(lines))
        return (f'<rect x="{x}" y="{y}" width="{bw}" height="{bh}" rx="14" fill="{t["card"]}" stroke="{stroke}" stroke-width="2"/>'
                f'<text x="{x + 20}" y="{y + 36}" font-family="{SANS}" font-size="19" font-weight="700" '
                f'fill="{title_fill or t["text"]}">{title}</text>{subs}')

    def num(x, y, n, color):
        return (f'<circle cx="{x}" cy="{y}" r="15" fill="{color}"/>'
                f'<text x="{x}" y="{y + 5.5}" text-anchor="middle" font-family="{SANS}" font-size="15" font-weight="800" '
                f'fill="{t["bg1"]}">{n}</text>')

    def arrow(x1, y1, x2, y2, color, dashed=False):
        dash = ' stroke-dasharray="4 8"' if dashed else ""
        return (f'<path d="M {x1} {y1} L {x2} {y2}" stroke="{color}" stroke-width="2.5" fill="none"{dash} '
                f'marker-end="url(#arrow-{"g" if color == t["green"] else "m"})"/>')

    g, m = t["green"], t["vpn"]
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" role="img"
     aria-label="How novpn works: DNS for listed sites goes to novpn, which pins a direct route before answering; a pf rule resets anything that still tries the tunnel">
  <defs>
    <marker id="arrow-g" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="{g}"/></marker>
    <marker id="arrow-m" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="{m}"/></marker>
  </defs>
  <rect x="1" y="1" width="{w - 2}" height="{h - 2}" rx="24" fill="{t['bg1']}" stroke="{t['line']}" stroke-width="2"/>

  <text x="48" y="64" font-family="{SANS}" font-size="15" font-weight="700" letter-spacing="2" fill="{t['muted']}">WHEN THE BROWSER LOOKS UP A LISTED SITE</text>
  {box(48, 88, 250, 120, "Browser", "asks for\nozon.ru", t['card_line'])}
  {arrow(300, 148, 352, 148, g)}
  {box(356, 88, 300, 120, "/etc/resolver/ozon.ru", "sends the question to\nnovpn on 127.0.0.1:53535", t['card_line'])}
  {arrow(658, 148, 710, 148, g)}
  {box(714, 88, 250, 120, "Your ISP's DNS", "asked over Wi-Fi,\nnot through the tunnel", t['card_line'])}
  {arrow(966, 148, 1018, 148, g)}
  {box(1022, 88, 210, 120, "Route first", "then the answer\ngoes back", g, g)}
  {num(1210, 88, 1, g)}

  <text x="48" y="268" font-family="{SANS}" font-size="15" font-weight="700" letter-spacing="2" fill="{t['muted']}">WHEN IT CONNECTS</text>
  {box(48, 292, 250, 236, "Routing table", "185.73.193.68\n  via 192.168.0.1 (en0)\n\n8,600+ Russian\nnetworks, same way", t['card_line'], mono_sub=True)}
  {arrow(300, 350, 1018, 350, g)}
  <text x="660" y="336" text-anchor="middle" font-family="{SANS}" font-size="17" font-weight="600" fill="{g}">listed sites: straight out through your provider</text>
  {box(1022, 292, 210, 110, "Your ISP", "the site sees your\nreal address", g, g)}
  {num(1210, 292, 2, g)}
  {arrow(300, 466, 1018, 466, m, dashed=True)}
  <text x="660" y="452" text-anchor="middle" font-family="{SANS}" font-size="17" fill="{m}">everything else: unchanged, through the VPN</text>
  {box(1022, 418, 210, 110, "VPN exit", "YouTube, Telegram,\nthe rest of the web", t['vpn2'])}

  <rect x="356" y="496" width="646" height="64" rx="14" fill="none" stroke="{t['red']}" stroke-width="2" stroke-dasharray="6 6"/>
  <text x="380" y="524" font-family="{SANS}" font-size="17" font-weight="700" fill="{t['red']}">pf kill switch</text>
  <text x="380" y="547" font-family="{SANS}" font-size="15" fill="{t['muted']}">a listed address on a tunnel interface is reset at once, so open tabs reconnect directly</text>
  {num(1002, 496, 3, t['red'])}
</svg>
'''


def social(t):
    """1280x640 link preview: the banner content full-bleed on a solid background."""
    import re
    w, h = 1280, 640
    body = banner("dark", t, animated=False)
    inner = body.split(">", 1)[1].rsplit("</svg>", 1)[0]
    defs = re.search(r"<defs>.*?</defs>", inner, re.S).group(0)
    inner = re.sub(r"<defs>.*?</defs>", "", inner, flags=re.S)
    inner = re.sub(r'<g clip-path="url\(#card\)">.*?</g>', "", inner, flags=re.S)
    inner = re.sub(r'<rect x="1" y="1"[^>]*/>', "", inner)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}">
  {defs}
  <rect width="{w}" height="{h}" fill="url(#bg)"/>
  <rect width="{w}" height="{h}" fill="url(#grid)"/>
  <ellipse cx="1100" cy="412" rx="300" ry="180" fill="url(#glow)"/>
  <g transform="translate(0 100)">{inner}</g>
  <text x="76" y="574" font-family="{SANS}" font-size="24" fill="{t['muted']}">macOS · per-site split tunnel · Russia mode · kill switch · zero dependencies</text>
</svg>
'''


OUT.mkdir(parents=True, exist_ok=True)
for theme, t in THEMES.items():
    (OUT / f"banner-{theme}.svg").write_text(banner(theme, t))
    (OUT / f"how-it-works-{theme}.svg").write_text(how(theme, t))
(OUT / "social-preview.svg").write_text(social(THEMES["dark"]))
print("written to", OUT)
