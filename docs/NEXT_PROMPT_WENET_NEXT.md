# Checkpoint — format recovery from run 45552687279

Read [CI_FORMAT_RECOVERY_45552687279.md](CI_FORMAT_RECOVERY_45552687279.md). Baseline 5db18a13 passed 76 Rust tests, Clippy, and release build, but failed two rustfmt gates. All 13 reported formatting hunks have been applied. Run manual workflow on **newest main**, not old SHA; check all 10 gates, CLI, smoke GUI, NSIS and checksums. If failed, fix exact log errors; if passed, implement the complete P1 batch below. Do not repeat format corrections already applied, downgrade gates, or claim new installer until accepted. Keep Actions manual-only and existing application version, data compatibility and branding. 

---

# WeNet Toolkit — large development batch, gate first

Use latest main on https://github.com/wawan-wfs/WFS-Network-Toolkit. Read WENET_P1_GATE_STATUS.md, TEST_REPORT.md, CHANGELOG.md, WENET_BRANDING.md, and NEXT_PROMPT_WENET_GATE_RECOVERY.md. Do not roll back to 5da35be8. Keep WeNet Toolkit by WFS Project, native Rust Win32 and existing storage/registry/installer upgrade identity.

## P0 (mandatory before feature expansion)
- Run manual workflow on the exact latest SHA and inspect logs for every independent build gate, CLI, GUI smoke, and NSIS. Existing success ae36e729 is not current HEAD. Fix real compiler/Clippy/format/test failures, including new subnet and dashboard tests. Never change CI to auto or create dummy PRs. If connector lacks dispatch, use user-initiated Run workflow. Verify full gate and package SHA before claiming release.
- Verify dashboard loading/empty/error/partial/unknown, filtered navigation and source freshness; add smoke on temporary DB only. Verify subnet evidence at 60/61 s, unknown/overlapping VRF, incomplete DHCP server, inactive vs active bindings, IPv4 /0 /31 /32 and IPv6 /0 /64 /128, overlapping scope, bounded result. Review all changes in overview.rs/network_map.rs; no assumptions of free IP or physical cabling.
- Restore toolchain if available; run Rust formatting, Clippy, tests, locked release, native smoke. Preserve existing SQL/alert regression; test final flush, quota/full, shutdown and archive migration. Benchmark 10 exporters × 2,000 IP × 1M records (3 repetitions), record drops, P50/P95/P99, DB/WAL, RAM and stop time, without live production traffic.
- UAC interactivity, upgrade/uninstall, DPI, accessibility and Realtek/MikroTik hardware remain separate VM/lab gates.

## P1 (substantial feature batch after gate)
1. Native graph: typed router/interface/VRF/bridge/VLAN/FDB/neighbor/route nodes and explicit evidence edges, zoom/pan/keyboard, source timestamp, filters, bounded layout, no unproved cabling. Drilldown scoped source to detail/history/export.
2. IPAM: distinct observed/assigned/reserved/unknown; IPv4/v6 CIDR and overlapping VRFs, DHCPv6 address bindings and PD only if RouterOS exposes data; separate ND and SLAAC; offline aliases/notes/tags scoped with undo, migrations, redacted export and historical evidence. Never allocate automatically.
3. Bandwidth dashboard: real time series RX/TX per router/interface, gaps/reset and actual zero distinct, P95, freshness, selectable time/scope, archive samples. No double-counting across interfaces.
4. Multi-router monitoring: HTTPS read-only, TLS, coverage per table, timeout/cancel/backoff, source health; SNMPv3 authPriv and syslog only once scope, authorization and privacy tests pass. No router config writes.
5. Flow: sequence/generation/replay/reorder, sampling, start/end, NAT provenance, source clocks, kernel drops only measured, retained scopes, safe exports. No claim of Internet access from lack of data.
6. Native premium UI/UX: accessible navy/teal light mode, small credit WFS Project, keyboard/DPI, clear evidence and popup for important/error. Preserve IPv4/DNS/MAC backup/restore and single-window Admin handoff.

## Delivery
Push fast-forward only. Preserve manual Actions. Full source pinned commit ZIP, test report with actual commands/logs/results and exact SHA, CHANGELOG, capability matrix, installer/portable and SHA256SUMS only when gate passed, next prompt. Do not bump version without meaningful verified release or fabricate results.
