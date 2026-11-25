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
