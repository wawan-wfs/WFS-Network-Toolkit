# WeNet Toolkit — native graph, DHCPv6 history and IPAM backup candidate

## Accepted baseline evidence (2026-11-25)
- Manual CI run [45667059429](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45667059429), job 139391958085, exact commit a11ea99f2a0d96dadd22b3df2d1abe4eb0afd0f4. All 11 gates PASS. Rust 1.100.0; 83 passed, 0 failed, 2 ignored. Python branding 4, SQLite 9, gate runner 5, IPAM 7 tests passed. Release build 45.14s. CLI and native smoke passed including metadata fixture/editor/undo, graph and bandwidth viewer; NSIS and artifact upload passed. Physical installation/UAC/hardware not tested.
- Evidence artifact [15047952246](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45667059429/artifacts/15047952246), 7,990 bytes; SHA256 f9b2871b1159aa258c7b4ffed585733afbe61b6d55a23afb9c1587f52b4f63bf. Package [15047762535](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45667059429/artifacts/15047762535), 5,534,505 bytes; SHA256 ff8d1446df68ee21d172643e0e2f4226c350fb385de679c3c31ee2e6f82ea802. Both downloaded, ZIP CRC and hashes matched.
- Installer SHA256 95704ed1548504135a21165ec1d5890ded83bf5056645e2458dc814d469cc51b; GUI eb6293a9dc177de6e7a18f360931a7f6e6a82620b9e8a82b73b779c619c6925f; CLI c28c90205ee1247e1f888b244efd20b2bc6f1c82aebff24f7175f80c062160e6. All three matched package manifest. Evidence belongs only to accepted baseline, not new source.

## New candidate implementation (pending Rust/Windows CI)
- Shared graph model: bounded 1,000 evidence edges, typed nodes, explicit router authority, conservative interface/VRF scope isolation, grouped bridge/VLAN labels, no cross-router identity merging or physical-cabling inference. Native GDI viewer, zoom 40–200%, pan keyboard WASD/right drag, selection through node incidents, clipping and provenance. Graph remains a snapshot and layout is deterministic column-based, not automatic physical topology.
- Dashboard row opens exact selected RX/TX series directly; chart adds P95 per selected window and gaps. Resource row exposes measured CPU and RAM derived only from valid counters and source coverage/time. No summing different interfaces. Chart remains a separate native owned viewer, not embedded in the dashboard.
- DHCPv6 server REST GET based on official RouterOS documentation https://help.mikrotik.com/docs/spaces/ROS/pages/24805500/DHCP ; explicit unique server/interface mapping, complete table and <=60-second aligned time, listed VRF only (not proof of resolved VRF). No client identifiers or DUID. Optional tables remain last after existing traffic tables. New SQLite database dhcp6-history-v1.sqlite3 in legacy data directory, immutable timestamp keys, idempotent identical saves, conflicting snapshot rejected, max 512 rows/256 KiB per capture, 120 samples/router, 32 routers, 64 MiB aggregate payload, no silent eviction. UI records confirmed manually and reads latest 20 exact-router snapshots with coverage and detail up to 100 rows. Not a reconstructed continuous assignment interval.
- IPAM metadata export is aggregate JSON only when redact is checked; contains no scope/CIDR/notes; unchecked explicitly confirmed backup produces consistent SQLite copy via staged no-overwrite publication and integrity check. Restore UI and observed-to-operator scope identity integration are still pending.
- Offline syslog import (1 MiB UTF-8, 10,000 lines, header priority only, no message/host/date retention); grouped facility/severity and accepted/rejected counters, explicit unauthenticated source. No UDP/TCP listener, no remote polling or security claims. SNMPv3 authPriv and authenticated live syslog transport intentionally deferred until protocol/security test infrastructure available.
- Light-mode accent refinement and native viewer; old feature controls, installation identity, data/Flow schema and dependencies unchanged. New fixtures for graph, history, backup/export, syslog and Windows smoke. Additional independent SQL gate; 12 gates now required, none weakened.
- Local Rust/rustfmt unavailable. Candidate not compiled, linted or run on Windows in this turn. Formatting/compilation/GUI acceptance must be confirmed on exact new SHA. No screenshot artifact from baseline; no new installer claim.

## Actual candidate offline SQL evidence
Command: python test_dhcp6_history_schema.py (same 4 Git blob bytes as candidate).
Python 3.13.5 / SQLite 3.46.1: 7 passed, 0 failed, 0.205s.
- schema: 703ba99bb9378e245ceccbbded26af5544561995
- insert: 51de4aa46afc8601e96b224ef51deb68d4965cd9
- page: 65175b7ba18231e3fc1a5af05348722e139767e3
- test: 9dfcaf30edb100ac713dea4c13727b8fdb0943a0
Tests: identity, router cap, isolation/conflict, total-byte cap, bounded page, payload/stamp rollback, per-router cap. Does not verify Rust or runtime. All four candidate input blobs matched GitHub.

## Still incomplete
Embedded chart and full UI redesign, explicit scope-aware IPAM joins and restore, complete DHCPv6 history navigation and independent backup, more precise graph layout and accessibility, SNMPv3 authPriv, authenticated live syslog, flow sampling/sequence/provenance enhancements, 3x 1M-record benchmarks, VM/hardware acceptance and screenshots. Do not bump version or claim full feature parity until verified.
