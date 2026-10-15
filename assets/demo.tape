# Real recording of novpn with a VPN switched on.  Re-record: make demo
# Your real and exit-node addresses are replaced on the fly with documentation addresses
# (198.51.100.23 = your ISP, 203.0.113.77 = VPN exit), so nothing personal ends up in the GIF.
Output assets/demo.gif

Set Shell "bash"
Set FontFamily "Menlo"
Set FontSize 21
Set Width 1360
Set Height 620
Set Padding 30
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set BorderRadius 12
Set TypingSpeed 42ms
Set Framerate 30

Hide
Type `export PS1='\[\e[38;5;183m\]$\[\e[0m\] ' PATH="$HOME/.local/bin:$PATH" CLICOLOR_FORCE=1` Enter
Type `REAL=$(command curl -s -m 10 https://ipv4-internet.yandex.net/api/v0/ip | tr -d '"'); EXIT=$(command curl -s -m 10 https://ifconfig.co)` Enter
Type `NODE=$(NO_COLOR=1 command novpn status | awk '/^exit node/{print $NF}')` Enter
Type `mask() { sed -e "s/${REAL:-@@}/198.51.100.23/g" -e "s/${EXIT:-@@}/203.0.113.77/g" -e "s#$HOME#~#g" -e "s/${NODE:-@@}/my-exit-node/g"; }` Enter
Type `novpn() { command novpn "$@" 2>&1 | mask; }; curl() { command curl "$@" | mask; echo; }` Enter
Type "clear" Enter
Sleep 300ms
Show

Type "curl -s ipinfo.io/ip" Sleep 300ms Enter
Sleep 2s
Type "novpn add ipinfo.io" Sleep 300ms Enter
Sleep 2.5s
Type "curl -s ipinfo.io/ip" Sleep 300ms Enter
Sleep 3s
Type "clear" Enter
Type "novpn check ozon.ru" Sleep 300ms Enter
Sleep 3s
Type "novpn status" Sleep 300ms Enter
Sleep 5s
Type "novpn rm ipinfo.io" Sleep 300ms Enter
Sleep 3s
