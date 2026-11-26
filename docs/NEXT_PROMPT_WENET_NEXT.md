## Integrated P1 increment 8 — indexed native graph virtualization and streaming offline analysis

Connected-component bands now carry exact node/link indexes; binary search selects visible bands in O(log components) before individual clip checks and hit tests. Added bounded offscreen GDI double-buffer fallback and F key focus on selected evidence. Added regression against brute force for 1,000 disconnected components. Syslog octet-counted parser now reads incremental fragments with an 8 KiB frame buffer, total byte/frame limits and truncation failure; .bin import integrated into native offline Syslog view. New native Replay Flow offline mode imports bounded JSONL and displays aggregate decoder diagnostics, no socket, no archive writes. Rust/Windows build and new tests NOT RUN: local toolchain absent and GitHub/crates DNS unavailable. Actual TLS listener and SNMPv3 authPriv still outstanding; no auth claim based on framing. Full redesign and acceptance pending.

---

## Integrated P1 increment 7 — durable Flow metadata and bounded selector options correlation

The optional Flow.provenance JSON field is stored in the existing atomic SQLite writer transaction with the original row; no new schema version, unchanged dedup fingerprint, legacy rows missing the field still deserialize. Removed separate collector provenance map to avoid snapshot races and double retention. Both live and archived native details read the same provenance. Unredacted JSON exports include reported provenance, redacted JSON excludes NAT identities and provenance object; CSV columns unchanged with sampling label only. IPFIX Options Template/Data Set parser supports single standard selectorId scope and same-datagram exact selector linkage, rejects ambiguous conflicting values and never infers a multiplier or carries options data across datagrams. Source tests for reopen, dedup, old JSON, redaction and options correlation added. No Rust compilation/CI; actual build and full regression remain pending. IANA registry https://www.iana.org/assignments/ipfix . SNMPv3 authPriv and authenticated TLS transport remain pending; no fake security implementation.

---

## Integrated P1 increment 6 — scoped IPAM metadata pivot and selectable embedded chart range

Native Subnet view creates an explicit draft of operator IPAM metadata from canonical authority, unique interface and time-aligned explicitly reported VRF only; opaque SHA-256 scope key is length-delimited and stable. No automatic save, no guessed local interface identity, no migration of legacy operator labels, no network mutation. Unknown scope cannot generate a linked draft. Dashboard adds keyboard-accessible existing native button for 30/60/120 sample range with actual selected-range P95 RX/TX, excluding missing measurements. Regression fixtures added for scope isolation and percentile boundaries. No new CI, no compilation, no acceptance claim. Remaining full-module redesign, real authenticated TLS and SNMPv3 transports, durable flow provenance and options-based sampling, hardware/runtime verification, benchmarks.

---

## Integrated P1 increment 5 — live Flow provenance, deterministic offline replay and framed Syslog

Source changes: bounded session-only IPFIX standard data-record sampling (legacy 34/35 and 305/306) and post-NAT fields (225–228, 281/282); original Flow record and SQLite schema unchanged. No sampling multiplier, no inferred NAT mapping, no option-template support, no vendor-field interpretation. Metadata remains associated with exact exporter/version/domain/datagram/ordinal and visible in native Flow detail; bounded collector counters. Offline JSONL datagram replay uses the same Decoder without opening a socket or writing archives. Strict bounds and receive ordering; CLI emits aggregate diagnostics only. New RFC 5425 octet-counting parser and offline CLI summary reject malformed/truncated framing; transport is NOT authenticated. No TLS listener or SNMPv3 client implemented. Field registry: https://www.iana.org/assignments/ipfix . Added Rust fixture tests for metadata, replay, framing. Rust toolchain unavailable locally; no new Rust tests, CI or installer run. Remaining: vetted SNMPv3 authPriv and mTLS listener, durable flow provenance, option-template sampling, dashboard range, typed IPAM, UI redesign, performance and full acceptance.

---

## Integrated P1 increment 4 — durable polling health + accepted P0 baseline

Verified main baseline 66c981152c0a226f8ded138f5fe5ffa745d32e81, Auto CI run 45758336730 attempt 1: 12/12 gates PASS; 89 Rust tests passed, 0 failed, 2 ignored; CLI and native GUI smoke PASS; NSIS build and package upload PASS. Artifact 15088827742 SHA-256 18b29b5691d2190d16dfc6b3719bee14c494b5ab57bd7fa2fa3234b9bb7fa17b and evidence 15088548742 SHA-256 751d365611d1bddc64583c1a59bdc0c8e360dcc13a80099a421f9035041cc58c verified locally with ZIP CRC. All five manifest entries matched including installer 895ca298265204cbb4651af79911fb3cbb0a966718ba36a92c59555d04692d4d and source ZIP b5d893395913ad5f2dd32d0fead4e0a3a70f63c5edb454b253b30768015dbc04. No screenshot or physical installation evidence. These binaries are BASELINE ONLY, not this P1 branch.

New source: independent SQLite journal poll-health-v1.sqlite3 for successful, partial and failed authorized HTTPS polling; bounded retention (512 per authority, 4096 total), categorized outcomes only, elapsed monotonic duration, separate archive-write status, no raw errors or secrets, no automated restart of polling. Native Histori kesehatan and CLI read-only page, added regression. Candidate Rust and Win32 build NOT RUN; no toolchain available in local environment. Existing main Auto CI untouched. Complete outstanding security integrations, typed IPAM, flow sampling/NAT, dashboard range and UI modernization before consolidated acceptance. No claim of SNMPv3 or TLS syslog implementation.

---

## Integrated P1 increment 3 — native history and recovery workflow

DHCPv6 history now has exclusive cursor paging via Lanjut, redacted aggregate export and explicitly confirmed full backup, plus restore to a new filename. IPAM native recovery uses the same no-overwrite verification, and save confirmation includes exact-scope overlapping prefix counts from loaded operator metadata. Export summary uses one read statement and validates all rows in that snapshot before publication. Active files and sidecars are excluded as restore destinations; no automatic activation. All changes source-only, uncompiled. Existing IPAM and DHCPv6 regression suites extend to these operations; no new CI has been started.

---

## Integrated P1 increment 2 — source only

Main-window GDI owner-drawn RX/TX chart strip uses selected dashboard row and native list selection notifications; compact client retains modal drilldown. Shared scale, missing-data discontinuities, observed zero, maximum label and fixed 60-sample window. Added layout regression. Flow diagnostic counters displayed in dashboard, and regression covers wrap/repeat/reorder/isolation/v9 restart. DHCPv6 standalone backup validates all captures, bounds and identity; recovery verifies fingerprint and publishes a new destination, with CLI and regression coverage. None of the new Rust/Win32 code has been compiled or run here. No claims of CI or installer acceptance.

Remaining: selectable time range and full chart keyboard/DPI smoke, native DHCPv6 paging and export/recovery controls, typed observed/operator IPAM mapping, full multi-router/SNMPv3/TLS security integration, sampling/NAT and replay, complete UI redesign, benchmark runs and release gates. Keep all on candidate branch until integrated development is ready for acceptance.

---

# P1 integrated development candidate — staged before CI

Base: 66c981152c0a226f8ded138f5fe5ffa745d32e81. Operator changed order on 2026-11-26: develop on a candidate branch first, consolidate and test after feature implementation. Main Auto CI remains unchanged. This is an unaccepted source candidate, not a release.

Implemented source: deterministic connected-component graph bands and offscreen edge culling; native text RX/TX preview in dashboard details (not full embedded GDI canvas); exclusive cursor DHCPv6 history with redacted aggregate export and CLI access; exact operator-scope IPAM overlap checks and independent no-overwrite recovery with revision validation; flow sequence/restart diagnostics (not loss counters or sampling correction); benchmark harness with three executions of actual million-row test and P50/P95/P99 query latency.

Added Rust regression cases for graph components, preview missing/zero, DHCPv6 cursor/redaction, IPAM overlap and recovery. Toolchain unavailable locally; these tests, rustfmt, Clippy, Windows build, runtime and benchmarks are NOT RUN. No installer/screenshot or hardware acceptance claimed.

Remaining P1: full embedded GDI chart and range/selection, typed observed/operator scope mapping and UI for overlap/recovery, DHCPv6 validated backup and native paging UI, full flow sampling/NAT provenance and replay tests, bounded multi-router health, trusted SNMPv3 authPriv and authenticated TLS Syslog implementation with pinned dependencies and security tests, all-module accessibility/DPI redesign, measured three million-row repetitions including memory/drops/stop. Do not implement custom crypto or misrepresent text preview as full chart. Complete remaining scope on candidate branch; then run all existing gates once for consolidated candidate, verify logs, artifacts and hashes before promotion. Keep no deployment/force push.

---

# Latest checkpoint — authorized automatic CI contract recovery (run 45757516983)

Exact tested parent: `e29aff717dacfb3080f449227ff1fa3306f08bd4`, run [45757516983](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45757516983), attempt 1, push. 11/12 gates PASS; branding FAIL only. All three rustfmt gates, Clippy, release build, SQLite, IPAM metadata and DHCPv6 history PASS; 89 Rust tests passed, 0 failed, 2 ignored. CLI, native smoke and installer skipped by fail-closed gating. Downloaded evidence artifact [15087638968](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45757516983/artifacts/15087638968), SHA-256 `f07c50bc5f36fdcf029b7c99908bb6a2c5c9e5098500224a0cf539f9af63089f`, matched metadata. The log identifies `test_ui_workflow_and_credit`, line 60, obsolete manual-only assertion. Other three branding tests passed. Recovery updates the CI contract rather than suppressing the gate. New exact commit remains NOT TESTED until its own run completes.

## Current instructions (supersede historic manual-only instructions below)

- Automatic CI on main pushes and manual dispatch are authorized, serialized per ref, read-only contents permission, no deployment or force-push. Do not dispatch another run while the automatic run is active.
- Inspect the new exact SHA's run, all 12 gates, CLI, native smoke, NSIS, package provenance, source ZIP and checksum. Fix only actual remaining failures; do not claim acceptance until all are verified.
- After P0 acceptance, execute the full integrated P1 roadmap below. Preserve all features, native Rust Win32, WFS Project branding, database compatibility and single-window Admin. No speculative hardware claims or insecure SNMPv3/TLS implementation. Require actual regression and benchmark evidence, screenshots only if captured.
- Historical checkpoints below describe former policy and former evidence, not current release instructions.

---

# Latest checkpoint — CI format recovery (run 45672963967)

Run [45672963967](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45672963967), attempt 1, exact parent 19d4686e8b04f32aec21d6434f3a5ec294777515: 9/12 gates PASS; three format gates FAIL; 89 Rust tests passed, 0 failed, 2 ignored; Clippy and release build PASS. CLI/native smoke/NSIS skipped. All 43 rustfmt hunks across nine files applied from verified artifact 15049804007. New exact SHA NOT TESTED. See [CI recovery evidence](CI_FORMAT_RECOVERY_45672963967.md).

Do not repeat these 43 corrections or rerun the old SHA. Manually dispatch Windows workflow on the current repaired main; require all 12 gates, CLI, native smoke (graph pan/zoom, chart selection, DHCPv6 history, IPAM export/backup, Syslog), installer packaging and checksum verification. Repair actual remaining failures without weakening gates. After successful P0, implement the entire P1 batch below in integrated native code, including embedded dashboard chart, connected-component graph, scope-aware IPAM, history/recovery, vetted SNMPv3 authPriv and authenticated TLS Syslog with negative security tests, Flow Intelligence, three measured million-record benchmark runs and premium redesign of all modules. Preserve all features, database compatibility, single-window Admin, WFS Project branding, Rust native without WebView and manual-only workflow. Deliver exact source and accepted artifacts with evidence, no version bump or fabricated results.

---

# Latest checkpoint — Extreme Large Development Batch, graph/history candidate

Accepted baseline a11ea99f passed run 45667059429 (all 11 gates, 83 Rust tests, native GUI smoke and NSIS packaging; hashes verified). Read WENET_GRAPH_HISTORY_BATCH.md, TEST_REPORT.md, CAPABILITY_MATRIX.md and previous sections. New candidate is not compiled or accepted. Exact SQL history contract passed 7/7 locally, all four blob hashes match. Preserve all previous behavior and manual-only workflow. Do not repeat earlier completed audits as a substitute for implementation.

## P0 — candidate acceptance, no bypass
1. Manual workflow_dispatch on exact current main. Review all **12** gates including dhcp6_history. Apply actual rustfmt hunks, compiler/Clippy/test failures and native smoke fixes, not version bumps or gate bypass. Verify CLI, graph zoom/pan/pointer/selection, exact dashboard filtered chart row, P95 and gaps, DHCPv6 scope/history, IPAM backup/export, Syslog summary, NSIS, SHA256 and ZIP contents. Capture real screenshots if supported by runner; mark unavailable otherwise. Do not claim actual device testing from fixture.
2. Add regression for mixed routers and overlapping VRF names, duplicate/ambiguous server/interface, 60 vs 61 seconds and incomplete/failed source, caps and source-clock conflict, graph 1,000 links / 2,000 nodes and empty, hit/drag/resize/high DPI, old archive open/backup/restore and IPAM optimistic conflicts. Smoke on temp DB; verify no writes to routers and no credentials/DUID. Secure file paths and no-overwrite semantics.
3. Run full locked tests, formatting, Clippy, release build; physical hardware/VM and million-record benchmark separately (three repetitions, measured P50/P95/P99, DB/WAL, RAM, drops, stop). Confirm install/uninstall and upgrade, admin single-window handoff, DPI, screen reader/keyboard, collector retention and recovery. No automatic CI on push.

## P1 — next extreme integrated batch after P0
- Graph: more robust native canvas, connected-component layout and virtualization, explicit snapshot freshness and typed router/interface/VRF/bridge/VLAN/neighbor/route identity without claiming cabling; node/edge selection and safe export with provenance; preserve legacy table. Integrate selection across dashboard, graph and IPAM.
- Dashboard: embed native RX/TX chart directly into main dashboard without WebView, range/scope selector, selectable timeline/archived exact interface, source health/resource trends, no double counting or invented metrics; preserve missing vs true zero.
- Advanced IPAM: typed operator vs observed scope mapping, assignment vs reservation vs unknown, prefix overlap by authority/interface/VRF, offline note editor with revision-safe rollback, secure independent backup restoration and validation, redacted export, never allocate automatically.
- DHCPv6: durable independent history query/pagination/export/backup, clear actual address versus PD versus ND/SLAAC, ambiguity/disabled/partial handling, no DUID or live config writes. Explicit server/VRF labels are not proof of route or client reachability.
- Multi-router monitoring: bounded polling, secure credential scope, TLS errors and coverage, health and archive; implement SNMPv3 only with tested trusted authPriv dependency, engine replay/time/auth/privacy verification, no v1/v2 downgrade; authenticated TLS syslog with authorization/limits/retention/secret redaction only after security tests, preserve offline import. Do not implement custom insecure crypto or enable unauthenticated live collectors by default.
- Flow: generation/replay/sequence/reorder, sampling, clocks, NAT provenance, archive retention and bounded resource consumption; actual performance tests. No invented kernel-drop counters or WAN access claims.
- Premium native light UI/UX: modernize every module independently, accessibility and keyboard/DPI, stable layout, clear source status and popups for important errors. Keep Rust native Win32, no WebView, WeNet Toolkit by WFS Project, legacy installer paths and data compatibility, admin handoff.
- Deliver pinned full-source ZIP, exact commits, verified installer/portable only for accepted SHA, actual logs/screenshots, evidence matrix, changelog and next complex prompt. Fast-forward only; no automated triggers or speculative results.

---

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
