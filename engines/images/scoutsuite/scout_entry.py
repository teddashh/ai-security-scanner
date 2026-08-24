#!/opt/scoutsuite/bin/python
"""Fixed ScoutSuite console entry for the managed JSON-only profile."""

from ScoutSuite.__main__ import run_from_cli


if __name__ == "__main__":
    raise SystemExit(run_from_cli() or 0)
