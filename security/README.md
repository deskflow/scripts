# Deskflow Security Scripts

Per-CVE proof-of-concept scripts under `poc/`. Each script targets one specific
vulnerability and reports whether a running Deskflow instance is affected.

## Layout

```
poc/
  cve_<year>_<id>_<area>_<class>.py   # one PoC per CVE
  utils.py                            # shared helpers
```

PoCs follow the convention `cve_YYYY_NNNNN_<area>_<class>.py`.

## Prerequisites

- Python 3.9+
- A running Deskflow instance to target

## Running a PoC

```bash
python poc/<script>.py --host <target_ip> [--port <port>]
```

All PoCs default to `localhost:24800` and support `--help`.

## Adding a new PoC

1. Drop a file in `poc/` named `cve_YYYY_NNNNN_<area>_<class>.py`.
2. Reuse helpers from `poc/utils.py` where it makes sense.
3. Exit non-zero (or print a clear `[FAIL]`/`VULNERABLE` line).
