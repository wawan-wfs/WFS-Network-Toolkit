# Latest checkpoint — CI formatting recovery

Read CI_FORMAT_RECOVERY_45663046203.md. Run 45663046203 on ad3077ce passed 8/11 gates (83 Rust tests, 7 IPAM SQL tests, Clippy, release build); failed three format gates. All 45 rustfmt hunks from the artifact have been applied. Run Windows workflow_dispatch on current main; check all 11 gates and CLI, native smoke (especially graph/chart/IPAM editor and undo), NSIS, checksums. Fix only actual remaining errors, without bypassing checks. Do not claim installer/screenshot before evidence. After acceptance, continue the complete P1 development below, including shared-node graph, integrated dashboard, IPAM scope mapping and backup, DHCPv6 history, monitoring, secure SNMPv3/Syslog, performance and UI/UX. Preserve compatibility, branding, single-window Admin and manual-only Actions. No artificial version bump.

---

# Latest acceptance checkpoint

P1 source includes native evidence relation viewer, chart, DHCPv6 inventory and IPAM metadata ledger. Offline SQL 7/7 passed (docs/evidence/IPAM_SQL_20261125.md). New native smoke opens/paints/navigates/closes the viewers and exercises metadata fixture/editor/undo. Not yet run. Prior baseline c570b86a accepted, new candidate requires manual CI; do not present old package as latest candidate. Review formatting diffs, actual Rust/Windows errors and all 11 gates. Continue remaining P1 after successful acceptance; preserve manual triggers.

---

# Additional acceptance — IPAM metadata

Run the new 11th gate ipam_metadata together with all existing gates and native smoke/packaging. Add Windows fixture smoke for metadata load/create/edit/undo, stale selection, capacity, wrong DB identity, file lock, corrupt/malformed records, read-only recovery, and independent backup/restore; use temporary directory. Validate scoped keys with Unicode, prefix boundaries, no mutation of main archive or router, no credentials. Verify chart click/keyboard and viewer close/reopen under resize/DPI. Finish full graph node identity and pan, dashboard embedding, DHCPv6 mapping/history, expanded monitoring and benchmark only after actual gate acceptance.

---

# Checkpoint — visual intelligence candidate after baseline CI success

Read VISUAL_INTELLIGENCE.md and TEST_REPORT.md. Baseline c570b86a passed run 45632871037; exact new HEAD requires new manual CI. Fix all formatting/compile/Clippy/test/GUI/packaging errors without bypasses. Include visual_window.rs rustfmt. Add native smoke for actual graph viewer and chart via fixture (open/paint/key/click/close, no modal hang), DHCPv6 coverage unavailable/empty/partial, filtered row mapping, immutable snapshot, DPI and accessibility. Test input bounds, resize, zoom, time gap, huge u64 counters, unknown status, noncanonical prefix, duplicate router/server scopes. Check polling time budget and that optional DHCPv6 table failure is not misdiagnosed as all router unavailable. No DUID collection. Validate no history/schema or installer compatibility regression. Only after gates pass, implement remaining P1: real shared-node graph with typed scoped identities and no inferred physical links, pan/zoom, IPAM persistent offline labels/tags/notes/reservation metadata and transactional undo, DHCPv6 server/VRF/interface mapping, PD history, separate ND/SLAAC evidence, integrated dashboard chart/filters and source status, multi-router monitoring, safe flow sequence/generation/sampling, UI/UX premium and full benchmark/VM/hardware. Preserve branding, existing features and manual-only Actions. Do not bump version before verified acceptance.

---

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
