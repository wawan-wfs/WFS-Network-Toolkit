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
