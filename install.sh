#!/bin/bash
# Installs the novpn root daemon as a LaunchDaemon, or removes it with --uninstall.
# Usage: sudo ./install.sh [--uninstall]
set -euo pipefail

LABEL="com.argona.novpn"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="/usr/local/lib/novpn"
CACHE="/var/db/novpn"
PLIST="/Library/LaunchDaemons/$LABEL.plist"
LOG="/var/log/novpn.log"
PYTHON="/usr/bin/python3"
MODULES=(novpn.py novpn_pf.py novpn_rtsock.py novpn_russia.py)

if [[ $EUID -ne 0 ]]; then
  echo "run it with sudo: sudo $0 $*" >&2
  exit 1
fi
OWNER="${SUDO_USER:-}"
if [[ -z "$OWNER" || "$OWNER" == "root" ]]; then
  echo "run it with sudo from your own account, not from a root shell" >&2
  exit 1
fi
OWNER_HOME="$(dscl . -read "/Users/$OWNER" NFSHomeDirectory | awk '{print $2}')"
REGISTRY="$OWNER_HOME/.config/novpn/domains.txt"
LINK="$OWNER_HOME/.local/bin/novpn"

as_owner() { sudo -u "$OWNER" env HOME="$OWNER_HOME" NOVPN_REGISTRY="$REGISTRY" "$@"; }

stop_daemon() {
  # SIGTERM: the daemon removes its /etc/resolver files and host routes on the way out.
  launchctl bootout "system/$LABEL" 2>/dev/null || true
  for _ in {1..50}; do
    launchctl print "system/$LABEL" >/dev/null 2>&1 || return 0
    sleep 0.2
  done
  echo "warning: $LABEL is still loaded" >&2
}

if [[ "${1:-}" == "--uninstall" ]]; then
  stop_daemon
  # Leftovers of a daemon that died without cleaning up: resolver files, routes, pf rules.
  if [[ -f "$LIB/novpn.py" ]]; then "$PYTHON" -I "$LIB/novpn.py" cleanup || true; fi
  rm -f "$PLIST" "$LOG"
  rm -rf "$LIB" "$CACHE" /var/run/novpn
  if [[ -L "$LINK" ]]; then rm -f "$LINK"; fi
  echo "novpn removed; registry kept at $REGISTRY"
  exit 0
fi

if ! "$PYTHON" -c 'import sys; sys.exit(sys.version_info < (3, 9))'; then
  echo "$PYTHON must be Python 3.9+ (xcode-select --install)" >&2
  exit 1
fi

# The daemon runs as root, so it runs from a root-owned copy, never from the user-writable checkout.
install -d -o root -g wheel -m 755 "$LIB" "$LIB/data"
for module in "${MODULES[@]}"; do
  install -o root -g wheel -m 644 "$SRC/$module" "$LIB/$module"
done
chmod 755 "$LIB/novpn.py"
install -o root -g wheel -m 644 "$SRC/data/ru-ipv4.txt" "$SRC/data/ru-ipv6.txt" "$LIB/data/"
rm -rf "$LIB/__pycache__"

as_owner chmod +x "$SRC/novpn.py"
as_owner mkdir -p "$(dirname "$LINK")"
as_owner ln -sfn "$SRC/novpn.py" "$LINK"
as_owner "$PYTHON" "$SRC/novpn.py" ls >/dev/null 2>&1  # creates the registry, owned by you

touch "$LOG"
chown root:wheel "$LOG"
chmod 644 "$LOG"

cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PYTHON</string>
    <string>-I</string>
    <string>$LIB/novpn.py</string>
    <string>daemon</string>
    <string>--registry</string>
    <string>$REGISTRY</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>$LOG</string>
  <key>StandardErrorPath</key>
  <string>$LOG</string>
</dict>
</plist>
EOF
chown root:wheel "$PLIST"
chmod 644 "$PLIST"
plutil -lint "$PLIST" >/dev/null

stop_daemon
launchctl bootstrap system "$PLIST"

for _ in {1..25}; do
  as_owner "$PYTHON" "$SRC/novpn.py" status >/dev/null 2>&1 && break
  sleep 0.2
done
as_owner "$PYTHON" "$SRC/novpn.py" status || true
echo
echo "next: novpn add ozon.ru   |   novpn russia on   |   novpn --help"
echo "(novpn: command not found? add ~/.local/bin to PATH:  echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.zshrc)"
