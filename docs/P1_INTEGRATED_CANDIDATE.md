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
