# 11-sonicwall-sma1000/ - SonicWall SMA 1000

Platform: `EDGE-0011` (see `artifacts/catalog/`).  
Detection packs: `EDGE-PACK-0036`, `EDGE-PACK-0037` (see `artifacts/packs/`).

## Rules

| File | Format | Detects |
|---|---|---|
| `sma1000_cve_2026_15409_wsproxy_loopback.yml` | Sigma | a `/wsproxy` WebSocket tunnel to the appliance itself answered 101 (SonicWall's IoC, Volexity's request shape) |
| `sma1000_uta0533_api_route_access.yml` | Sigma | requests to `/__api__/login` or `/__api__/logout` answered 200 (SonicWall's IoC) |
| `sma1000_cve_2026_15410_hotfix_traversal.yml` | Sigma | a hotfix removal given a path outside the rollback directory in `ctrl-service.log` |
| `sma1000_orangetail_volexity.yar` | YARA | ORANGETAIL and the user-agent-gated Suo5 agent (Volexity, file and memory) |
| `sma1000_knuckleball_volexity.yar` | YARA | KNUCKLEBALL, the Python injector (Volexity, file and memory) |
| `sma1000_rootrun_volexity.yar` | YARA | ROOTRUN, the setuid root helper (Volexity, file and memory) |
| `sma1000_uta0533_user_agent_volexity.yar` | YARA | the bogus user agent UTA0533's implants gate on (Volexity, any blob) |

## Notes

The four YARA files are Volexity's rules, copied byte for byte from its
threat-intel repository (`2026/2026-07-17 SonicWall/rules.yar`) under its BSD
2-Clause licence, which each file reproduces. Every one has `scan_context`
"file,memory" and reads only its strings, so the memory checks run them over
every SMA 1000 memory image. That matters here: KNUCKLEBALL deletes the two JARs
after injecting them into the workplace JVM, so on a running appliance ORANGETAIL
and Suo5 are found in memory or not at all.
