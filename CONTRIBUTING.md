# Contributing

Contributions are welcome: profiles for new platforms, corrections from real
devices, detection packs for new CVEs, and Sigma or YARA rules.

## Before you open a PR

```bash
python artifacts/scripts/validate.py
python -m pytest -q tests/
```

Both must pass. CI runs them plus a Sigma conversion and a YARA compile.

## Corrections from a real device

The most valuable contribution. If a profile command, prompt regex or pager
pattern is wrong on a real device, say which model and release you ran it on,
fix the profile, raise the step's `confidence` if you verified it, and record
what changed in `docs/VERIFICATION.md`. Do not include device output that
identifies your organization.

## Profiles

- Every impact-free step must pass the profile's `allow` list and miss its
  `deny` list. The loader refuses the profile otherwise.
- Anything that writes to the device is `impact: vendor-bundle`. Anything that
  can crash, reload, reboot or image it is `impact: break-glass`.
- `session_setup` may only contain session-scoped commands (`set cli ...`,
  `terminal pager|length|width ...`).
- Put each step in the right tier. When unsure, ask whether the evidence
  survives a reboot.
- `confidence: low` requires `unverified: true`.

## Detection packs

- File name `EDGE-PACK-NNNN-<slug>.yml`, next free id, never reuse an id.
- At least one public reference per pack.
- Each detection declares the evidence it reads (`sources`, `scope`) so it can
  report `not-evaluated` honestly.
- Add a malicious and a benign case to `tests/make_fixtures.py` and a test that
  proves both outcomes.
- Prefer `log_regex` / `path_exists` / `yara`. Use a coded check
  (`edgetriage/checks/`) only when the logic cannot be declared.

## Rules (Sigma / YARA)

- Reference a CVE, advisory or published research.
- Document false positives.
- Lowercase snake_case file names.
- Sigma only for log detections; no vendor query dialects.

## What will not be merged

Working exploits or implants, steps that change device state without declaring
it, guessed paths or commands marked as anything above `low`, and content
derived from non-public incident data.
