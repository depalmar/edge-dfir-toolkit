# artifacts/ - Platform catalog and detection packs

## catalog/ - `EDGE-NNNN`

One entry per platform: what the OS is, whether customers get a shell, how
memory can be acquired, the collection paths that exist and their impact, what
is lost on reboot or upgrade, and the anti-forensics seen in public reporting.
It answers: **what can I reach on this box, and what will I lose if I wait.**

## packs/ - `EDGE-PACK-NNNN`

One pack per vulnerability family. Each detection declares:

- `type` - `log_regex`, `path_exists`, `yara` or `check` (coded, in `edgetriage/checks/`)
- `tier` - `possible` (often an attempt), `likely`, `confirmed`
- `evidence_class` - used to decide whether two hits corroborate each other
- the evidence it needs (`sources`, `scope`), so it can report `not-evaluated`

## Rules

- Ids are permanent. New entries take the next free id.
- Confidence reflects provenance: `high` vendor-documented or device-verified,
  `medium` multiple independent sources, `low` single-source and `unverified: true`.
- Omit rather than guess.

## Validation

```bash
python artifacts/scripts/validate.py        # schema + cross-references + regex + YARA
python artifacts/scripts/mappings.py --check
```
