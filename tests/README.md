# tests/

```bash
python -m pytest -q tests/
```

`make_fixtures.py` generates every fixture at test time into a temporary
directory: replay recordings for each profile in a compromised and a benign
variant, a TSF-shaped tarball with hostile members (a `../` path and a symlink
to `/`), a FortiOS hash baseline, and PHP samples for the YARA rules.

They are generated rather than committed because some depend on exact bytes -
leaked non-printable bytes inside an ns.log line, tar members with traversal
paths - that editors and git attributes do not preserve reliably.

All data is synthetic. Addresses are from the documentation ranges, hosts and
users are placeholders, and the "malicious" content is the minimum needed to
exercise a detection: no working exploit or implant code.

To look at a fixture by hand:

```bash
python tests/make_fixtures.py /tmp/fx
python -m edgetriage collect --profile netscaler --case-id DEMO --output /tmp/cases \
    --replay /tmp/fx/netscaler-compromised
python -m edgetriage analyze /tmp/cases/DEMO && less /tmp/cases/DEMO/report.md
```
