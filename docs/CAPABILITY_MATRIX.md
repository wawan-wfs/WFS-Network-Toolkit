## Integrated P1 increment 9 — actual secure transport companion source, acceptance blocked

Added independent native Rust secure-transport crate using async-snmp 0.18.1 USM (SHA-256/AES-128 authPriv only, strict source and response shape, bounded exact read-only sysUpTime GET) and rustls 0.23.46 (mandatory WebPKI client CA validation plus exact certificate SHA-256 authorization, TLS 1.2/1.3 only, one-shot listener with absolute deadlines, root project's incremental Syslog framing parser, no raw payload persistence). Direct dependency versions pinned, parent lock unchanged; companion transitive Cargo.lock NOT generated due missing Rust/network. Source and unit tests NOT compiled or run; no security certification, installer integration or continuous service. Mandatory next: resolve and audit lock on trusted host, test real agent and negative SNMP cases, TLS valid/invalid/unknown CA/unpinned/expired/plaintext/truncated/slow cases, then integrate into native UI/monitoring and package only after all pass. No remote CI or deployment started.

---

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

| Capability | Tested parent e29aff717 | Recovery candidate |
|---|---|---|
| Formatting (all three), Clippy, Rust tests, release build | PASS | NOT TESTED |
| SQLite / IPAM metadata / DHCPv6 history | PASS | NOT TESTED |
| Branding / CI policy | FAIL: obsolete manual-only contract | Corrected, NOT TESTED |
| CLI / native GUI smoke / NSIS / package integrity | SKIPPED | NOT TESTED |
| P1 expansion / hardware / actual screenshots | NOT TESTED | Pending P0 |

---

# Latest CI status — graph/history format recovery

Run [45672963967](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45672963967), attempt 1, exact parent 19d4686e8b04f32aec21d6434f3a5ec294777515: 9/12 gates PASS; three format gates FAIL; 89 Rust tests passed, 0 failed, 2 ignored; Clippy and release build PASS. CLI/native smoke/NSIS skipped. All 43 rustfmt hunks across nine files applied from verified artifact 15049804007. New exact SHA NOT TESTED. See [CI recovery evidence](CI_FORMAT_RECOVERY_45672963967.md).

| Capability | Evidence at tested parent | Repaired HEAD |
|---|---|---|
| Rust regression, Clippy, release build | PASS | NOT TESTED |
| DHCPv6 history and IPAM SQL | PASS | NOT TESTED |
| Format (all three gates) | FAIL | Corrections applied, NOT TESTED |
| Native graph pan/zoom, chart navigation, IPAM backup/export, DHCPv6 and Syslog smoke | SKIPPED | NOT TESTED |
| CLI / NSIS / package hashes / screenshot | SKIPPED | NOT TESTED |
| Embedded dashboard, connected-component layout, advanced IPAM recovery, SNMPv3 authPriv, authenticated TLS Syslog, Flow Intelligence, 3x million-record benchmark, premium redesign | P1 pending | P1 pending |

---

# Latest evidence status — graph/history batch

| Capability | Baseline a11ea99f | New candidate |
|---|---|---|
| Windows build / native fixture / installer | PASS (run 45667059429) | NOT TESTED |
| Graph shared nodes + pan/zoom | Prior relation viewer PASS | Source + Rust/smoke fixtures, NOT TESTED |
| RX/TX selected range P95 + dashboard direct chart | Prior viewer PASS | Source, NOT TESTED |
| IPAM metadata / undo | Baseline PASS | Backup/export source, NOT TESTED |
| DHCPv6 / PD | Prior binding parser tests PASS | Explicit mapping/history SQL 7/7; Rust/UI NOT TESTED |
| Syslog offline | Not implemented | Header-only source, NOT TESTED |
| SNMPv3 authPriv / authenticated live syslog | Not tested | Deferred |
| Hardware, UAC, DPI, upgrade/uninstall, benchmark | NOT TESTED | NOT TESTED |

See WENET_GRAPH_HISTORY_BATCH.md for exact evidence. Do not conflate source with tested binary.

---

# Capability Matrix — WeNet Toolkit (kandidat 1.3.0-rc.1)

| Area | Status | Batas bukti |
| --- | --- | --- |
| IPFIX/NetFlow v9 IPv4/IPv6 | Lulus tes parser dan penerimaan UDP loopback | Hingga 16 profil per listener. Isolasi domain, restart, dan replay diuji. Options/sampling belum dikoreksi. Belum diuji langsung dengan MikroTik. |
| Akses internet berdasarkan flow | Lulus tes observasi satu arah, pasangan balik, dan pemisahan domain | IP WAN dan jaringan LAN ditentukan lewat profil scope/ifIndex. Bukan akses universal atau evaluasi kebijakan. |
| Histori dan diff | Lulus tes reopen, retensi, dan snapshot parsial | Flow persisten di SQLite dengan filter dan ekspor. GUI menggabungkan snapshot JSON dan impor SQLite yang memenuhi batas histori. CLI menyediakan backup konsisten dengan verifikasi. |
| Detail IP → Koneksi → Ekspor | Lulus fixture host dengan IP tumpang tindih, VRF tidak diketahui, beda sesi exporter, IPv6, port dan ekspor tersamarkan | Ringkasan maksimal 2.000 baris dan 128 scope. Tidak mengklaim keputusan firewall atau menggabungkan bukti HTTPS lokal ke scope router. |
| Bridge/VLAN/filter/NAT | Lulus tes parser dan pembatasan field | Hanya inventaris konfigurasi REST HTTPS IPv4 untuk filter/NAT. Tidak menyimulasikan kebijakan. |
| Windows x64 | Lulus pada rilis historis; kandidat sekarang BLOCKED | Lihat Actions untuk smoke test Windows CI. Windows 10/11 fisik dan router produksi bukan bagian dari uji otomatis. |
| Realtek dan RouterOS live | Belum diuji fisik | Memerlukan Windows, NIC dan perangkat peer terotorisasi untuk MAC, serta router lab untuk REST/Flow. |
| Penyimpanan arsip | Retensi, kuota, diagnosis, backup, impor, pulihkan salinan, pratinjau hapus | GUI native. Tidak memulihkan dengan menimpa DB aktif. Tidak menghapus arsip JSON ketika menghapus snapshot SQLite. |
| Topologi RouterOS dan IPAM observasi | Lulus fixture offline | Tabel relasi, tidak ada graf fisik. Tidak mengalokasikan IP. |
| Polling RouterOS | Scheduler diuji dengan waktu sintetis | HTTPS GET, per target, satu pekerjaan aktif. Berhenti di antartahap I/O. Perangkat RouterOS fisik belum diuji. |
| Tren interface dan histori lease | Fixture SQLite menguji migrasi, retensi, reopen dan backup | DHCPv4 dan counter interface. Rentang detik UTC. Tidak memprediksi riwayat sebelum observasi atau masa lease. |
| Alert collector | PARTIAL — 9 tes kontrak SQL lulus; Rust belum diuji | Scoped ledger dan ack persisten, global writer errors; sequence gap/generasi exporter belum tersedia. |
| Fitur lanjutan | Belum ada | Alias/catatan IPAM, histori waktu lokal, DHCPv6 binding, sequence gap/generasi exporter, SNMPv3/syslog, agen opt-in dan agregat persisten. |

Baseline 0.6.0 ZIP SHA-256 `46d44bf76d64285e3a24abf09b2362e991b1d9cf517728e2f55d9a8b1afb9869`.
