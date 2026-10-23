# 06-sonicwall-sma/ - SonicWall SMA 100

Platform: `EDGE-0006` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0008`, `EDGE-PACK-0022` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `sma_cve_2024_38475_css_suffix_read.yml` | Sigma | the `%3f.1.1.1.1a-1.css` file-read suffix from watchTowr's CVE-2024-38475 reproduction |

## Notes

OVERSTEP hid itself from on-box tools and deleted its own log lines. Its pack only evaluates against an ingested offline disk image or image-triage output, by design.
