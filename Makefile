.PHONY: test lint install uninstall demo

test:        ## run the unit tests with the same Python the daemon uses
	/usr/bin/python3 -m unittest discover -s tests

lint:        ## ruff + shellcheck
	ruff check .
	shellcheck install.sh

install:     ## install or update the daemon (asks for your password)
	sudo ./install.sh

uninstall:   ## remove the daemon, its routes and pf rules; keeps your site list
	sudo ./install.sh --uninstall

demo:        ## re-record assets/demo.gif (needs charmbracelet/vhs and a VPN that is on)
	vhs assets/demo.tape
