# 05-cisco-asa-ftd/ - Cisco ASA / FTD

Platform: `EDGE-0005` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0006` (see `artifacts/packs/`).

## Notes

No log signature here is reliable: LINE DANCER disabled syslog. Detection is state-based - the vendor's memory-region check (`asa_lina_exec_regions`), the disk0 listing, and a core dump scanned with CISA's RayDetect. Order matters: the memory check runs before anything that could reload the device.
