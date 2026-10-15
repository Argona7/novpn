# Contributing

Issues and pull requests are welcome.

```bash
make test   # unit tests under /usr/bin/python3, the interpreter the daemon uses
make lint   # ruff and shellcheck
```

- Standard library only: the daemon must run on a stock Mac with the Command Line Tools.
- Every behaviour change comes with a test in `tests/`; external effects (`route`, `pfctl`, DNS, the routing socket) are faked there.
- Keep new modules under 300 lines.
- For a bug, attach `novpn status` and `novpn logs -n 80` (remove anything private).
