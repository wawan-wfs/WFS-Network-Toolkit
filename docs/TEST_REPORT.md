# WeNet Toolkit — gate acceptance and P1 candidate

Manual run 45431125979 on ae36e7293cf846ee639f2210775e71b1c8f7d850: all 10 build gates, CLI, native GUI smoke and NSIS packaging passed. Rust 70 passed, 0 failed, 2 ignored; Python 18 passed. Release build 74 s. Native smoke log ends PASS. Package artifact 14939820358 and evidence 14938594329. Both artifact ZIP SHA-256 digests match GitHub metadata; all three executable SHA-256 checks match SHA256SUMS.txt. This acceptance applies to ae36e729 only, not new P1 code.

New source batch: dashboard with source coverage, local and router inventory, per-interface bandwidth samples and P95, collector/exporter health, archive measurement, and navigation to existing modules. New IPv4/IPv6 subnet inventory counts distinct observed addresses per explicit interface, caps 512 prefixes per source, does not infer free addresses or aggregate overlapping prefixes. Includes unit and GUI fixture checks. New source has not yet been compiled or executed; no new installer claimed. Physical UAC, installation upgrade, Realtek/MikroTik, benchmark and full graph canvas/DHCPv6 binding remain pending. Actions manual only.

[Successful CI](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45431125979) · [Package](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45431125979/artifacts/14939820358)

---

# WeNet Toolkit — native GUI gate recovery

Run manual [45429043158](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45429043158), commit e561f864e01e53a9c47fdb537cb8d51fab854dc5, job 138568955282. All ten build gates passed, including three format checks, Clippy, unit tests and release build (72.828 s); read-only CLI passed. Native GUI smoke exited 1 after approximately one second, not a timeout. Packaging skipped. The log did not contain the internal assertion error, so the exact failing assertion is not known.

Source inspection found a definite asynchronous test defect: selecting alert mode starts a SQLite worker but the old smoke test immediately asserted the completed panel and subsequently invoked other actions. The revised smoke waits for completion, tests a temporary archive with one alert, acknowledges it, checks persisted ACK, and verifies the open filter. The panel clears stale data while loading. GUI smoke now logs stage and internal failure to gate-evidence/native-ui-smoke.log; workflow prints it and still fails on a nonzero exit or missing log. No production archive is used by the alert test. This correction is uncompiled/unverified until the next manual run; do not assume the original exit 1 was solely caused by this defect. Installer remains unavailable. Keep all gates.

[Original evidence](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45429043158/artifacts/14937951808)

---

# WeNet Toolkit — pemeriksaan CI manual 45426915628

Baseline: d511189e7ef8e0ed169caa8c9e989a8d10d260f4. Run 45426915628 (workflow_dispatch), job 138561312745, artifact 14936888586. SHA256 ZIP: ec7c81a038b5a0bcc94b63b1b0f7e39c2beae60274ff9be347e49a5006b5664a. Semua 11 file artefak dibaca; hash cocok.

Windows Server 2025, Rust 1.100.0. PASS 7/10 gate: branding 4/4, SQLite 9/9, runner 5/5, rust version, Clippy, Rust unit tests 70 passed/0 failed/2 ignored, release build (81.641 s). FAIL: cargo fmt, rustfmt toolkit, rustfmt intelligence. CLI smoke, GUI smoke, NSIS dan upload paket dilewati. Tidak ada kesalahan compiler/Clippy/unit test pada run ini.

Perubahan: koreksi format pada tujuh source berdasarkan diff aktual dari tiga log format. Tidak ada perubahan fitur, versi, schema, workflow trigger, atau lockfile. Semua koreksi dicocokkan dengan source baseline; penerapan format tidak sama dengan menjalankan ulang rustfmt. Gate belum diverifikasi pada commit hasil koreksi. Run manual baru wajib. P1 menunggu seluruh gate lulus, termasuk GUI smoke dan installer. Tidak ada installer baru.

[Run asli](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45426915628) · [Artefak asli](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45426915628/artifacts/14936888586)

---

# WeNet Toolkit — latest gate recovery report

Baseline 107135e2674a857df91b5ad71aac7ad272401d47.

| Gate | Actual result |
|---|---|
| Python gate runner | PASS 5/5, 3.144 s (synthetic subprocess tests) |
| SQLite regression | PASS 9/9, 0.094 s; exact SQL and test script blob hashes verified |
| Branding asset bytes | PASS 7 ICO size headers, 3 matching asset Git hashes |
| Source safety adjustments | PARTIAL, not compiled |
| Rust/Clippy/format/Windows smoke/installer | BLOCKED (no toolchain; no current manual CI) |
| Network P1 features / lab / benchmark | NOT STARTED in this batch; P0 pending |

See [GATE_RECOVERY.md](GATE_RECOVERY.md). Historical reports below are not evidence of this commit.

---

# WeNet Toolkit — status batch rebranding

Baseline: 5da35be8cf0ba9869b6b6f0e33d4483a211f8998. Versi Cargo tetap 1.3.0-rc.1.

- PASS: ikon sumber dirender dan tujuh ukuran ICO (16,24,32,48,64,128,256) dibuka dengan Pillow; byte ikon dan logo PNG dicocokkan ke hash Git blob. Ini validasi berkas, bukan LoadIconW di Windows.
- PASS: pemeriksaan statis staged tree untuk nama produk, EXE, build resource, smoke test, shortcut, paket, workflow manual, kompatibilitas registry/data dan hash SQL/engine. Bukan kompilasi.
- PARTIAL: source UI native, palette, resource, installer, docs. Tes kontrak SQLite sebelumnya 9/9 pada baseline, source SQL tidak berubah; hasil historis bukan rerun di batch ini.
- BLOCKED: cargo/rustc/rustfmt tidak tersedia, jaringan container gagal DNS dan workflow manual belum dijalankan pada baseline terbaru. Run sukses yang ditemukan adalah commit 4bb5aca8, bukan kandidat.
- BLOCKED: Rust compilation/Clippy/unit test, smoke Win32, UAC, installer, upgrade/uninstall, benchmark UDP, lab fisik. Tidak tersedia paket executable baru.
- P1 fitur besar masih menunggu gate P0. Tidak ada perubahan pada konfigurasi jaringan produksi.

Lihat WENET_BRANDING.md dan NEXT_PROMPT_WENET.md.

---

# Batch v1.4 — laporan gate aktual

Baseline 22e97abcaee82f59feb46306c237b24d9b22d29c. Versi aplikasi tetap kandidat 1.3.0-rc.1.

| Gate | Status |
|---|---|
| Kontrak SQL yang dipakai oleh Rust | PASS — 9/9 tes Python/SQLite, 0 gagal, 0.099 detik pada container Linux, Python 3.13.5, SQLite 3.46.1. |
| Source Rust/GUI | PARTIAL — perubahan telah diintegrasikan tetapi belum dikompilasi. |
| Kompilasi, Clippy, Rust test, format, smoke GUI, NSIS | BLOCKED — toolchain tidak tersedia dan dispatch manual tidak tersedia melalui konektor. |
| Paket Windows, benchmark UDP, UAC, DPI, perangkat fisik | BLOCKED — tidak ada hasil baru. |
| Fitur P1 | NOT STARTED — menunggu gate P0, sesuai urutan permintaan. |

Rincian dan langkah manual: [V14_GATE_STATUS.md](V14_GATE_STATUS.md). Hasil di bawah merupakan riwayat, bukan verifikasi commit batch ini.

---

# WFS Network Toolkit 1.3.0-rc.1 — kandidat pemulihan

Baseline d468d19861a82e77d0786e8d3caaaf809931da1b. Source v1.3 lama tidak ditemukan; hasil ini rekonstruksi parsial.

| Gate | Hasil |
|---|---|
| PASS — kontrak SQLite offline | python scripts/test_alert_schema.py: 3 tes lulus (migrasi 1→4 dan 2→4, application_id, scope/sesi, ack idempotent, replay, backup, reopen, retensi, rollback). Python SQLite, bukan crate Rust. |
| PARTIAL — source | Monitor alert per scope dan ledger, handoff admin, pengaman queue, GUI native terhubung pada source; belum verifikasi executable. |
| BLOCKED — Rust/Windows | cargo/rustc/rustfmt tidak tersedia di lingkungan; GitHub Actions tetap manual dan tidak dijalankan. Tidak ada installer baru. |
| BLOCKED — schema 3 asli | Definisi arsip lama belum tersedia, sengaja ditolak. |
| BLOCKED — benchmark, VM/hardware | Benchmark satu juta record belum diulang. UAC interaktif, DPI, RouterOS, Realtek belum diuji. |

Rangkaian Rust test baru belum dijalankan. Tidak ada perubahan konfigurasi jaringan produksi. Source lama dan data pengguna tidak ditimpa.

---

# WFS Network Toolkit 1.2.1 — laporan uji

## Status verifikasi 1.2.1

- Perbaikan sumber ditargetkan pada repo `wawan-wfs/WFS-Network-Toolkit` yang ditemukan berisi source v1.2.0. Histori v1.3 dari repo `wawanwfs` **belum dipulihkan** di repo pengganti.
- Penambahan tes `archive_drop_categories_are_separate_and_sum_to_total` membuktikan penjumlahan penghitung untuk tiga alasan di level unit. Bukan bukti kehilangan paket kernel atau benchmark UDP di perangkat fisik.
- Mode Admin sekarang menjalankan child dengan parameter PID induk dan baru membuka GUI setelah induk berhenti. **Belum ada pengujian UAC interaktif** sampai mesin Windows tersedia. UAC batal harus meninggalkan jendela lama terbuka.
- Perubahan tidak menyentuh konfigurasi router, adaptor, firewall, atau profil jaringan untuk QA.

## Riwayat laporan 1.2.0

Baseline pengembangan v1.2 adalah `82a25d36e761d619b9f861785071b53cda493cd1`.

| Gate | Bukti |
| --- | --- |
| PASS — unit host | Fixture scheduler, pembatalan, backoff, klasifikasi kegagalan, migrasi schema 1 → 2, retensi, scope router, reload tren dan lease dari backup. |
| Windows CI | Format, Clippy, tes, smoke GUI fixture termasuk kontrol polling, serta paket installer/portable dan checksum. Status final ada di [Actions](https://github.com/wawanwfs/WFS-Network-Toolkit/actions/workflows/windows.yml). |
| PARTIAL — cakupan v1.2 | Histori filter UTC. Catatan/alias lokal, alert per exporter, DHCPv6, provenance flow dan graf topologi belum termasuk. |
| BLOCKED — perangkat dan VM | Belum ada verifikasi RouterOS live, Realtek fisik, upgrade/uninstall VM, atau multi-DPI. |

## Benchmark IPFIX loopback

Tes opsional: `cargo test --locked --offline --release --lib benchmark_udp_million_loopback -- --ignored --nocapture`.

Pengukuran baseline v1.1 pada Linux x64 pada lingkungan Intel Xeon Platinum 8573C dengan kuota arsip 1 GiB. Sepuluh soket UDP loopback dan observation domain terpisah mewakili 10 exporter sintetis; 2.000 IP perangkat, 80 record per datagram dan jeda 3 ms antardatagram. Bukan tes trafik eksternal atau hardware RouterOS.

| Metrik | Hasil |
| --- | --- |
| Terkirim, didekode, tersimpan | 1.000.000 masing-masing |
| Drop arsip / tidak terhitung | 0 / 0 |
| Waktu kirim / laju | 39,20 detik / sekitar 25.510 record per detik |
| Waktu stop collector | 211 ms |
| P95 inspeksi IP, 100 kueri setelah stop | 3,873 ms |
| DB / WAL | 904.785.920 byte setelah stop / 6.423.112 byte sebelum stop |

Tidak mengukur lag per record, RAM puncak, Windows UDP, ataupun beban tanpa jeda. Ini bukan jaminan throughput produksi.

---

## Arsip laporan 1.0.0

Baseline `aed2678a292e10772eda0d8737a6ccf00ec657d4`, 44 tes host lulus sebelum perubahan.

| Gate | Bukti |
| --- | --- |
| PASS — tes host | 50 tes, termasuk batas retensi, idle tanpa trafik, kuota kecil dan drop, backup WAL, salinan pemulihan, perubahan sumber, perlindungan tujuan dan pembatalan hapus jika record berubah. |
| Windows CI | Menjalankan format, Clippy, tes, GUI native dengan fixture, paket portable/NSIS, serta checksum. Lihat [Actions](https://github.com/wawanwfs/WFS-Network-Toolkit/actions/workflows/windows.yml). |
| PARTIAL — observabilitas | Topologi/IPAM, data start/end flow, tren counter, scheduler network dan alert belum diimplementasikan di versi ini. |
| PARTIAL — kondisi operasi | Pengujian kuota SQLite menggunakan fixture, bukan disk fisik penuh. Benchmark penyimpanan langsung lulus, tetapi belum mengukur lag, drop UDP atau waktu stop collector. Belum ada uji semua DPI, volume read-only fisik atau instal/upgrade/uninstall fisik. |
| BLOCKED — perangkat fisik | Tidak ada RouterOS live atau Realtek fisik di lingkungan pengembangan. Tidak ada pengujian pada jaringan produksi. |


## Benchmark penyimpanan sintetis

Dua pengulangan tes `cargo test --locked --offline --release --lib benchmark_archive_million -- --ignored --nocapture` pada Linux x64, Intel Xeon Platinum 8573C. Dataset berisi 1.000.000 record, 10 scope exporter, dan 2.000 IP perangkat. Batch 2.000 record masuk langsung ke SQLite dengan kuota 1 GiB, tanpa UDP.

| Metrik | Hasil |
| --- | --- |
| Tersimpan | 1.000.000 dari 1.000.000 pada kedua pengulangan |
| Waktu tulis | 34,54–36,46 detik |
| Throughput | 27.428–28.954 record/detik |
| P95 inspeksi IP | 5,84–8,97 ms pada 100 query, masing-masing 500 record |
| Ukuran sebelum tutup | DB 812.388.352 byte, WAL 21.971.992 byte |
| RAM puncak proses tes | 9.244 KiB pada satu pengulangan, di luar cache OS |

Angka bukan target kinerja Windows atau ingest UDP. Benchmark tidak mengukur lag antar perangkat, drop di jaringan, atau waktu stop collector. Dataset tidak muat pada kuota default 256 MiB.

---

## Arsip laporan 0.9.0

Baseline `895f28e4e6e1808d08896e843b96acee7f7fe4ff`, 40 tes host lulus sebelum perubahan.

| Gate | Bukti |
| --- | --- |
| PASS — tes host | 44 tes mencakup pivot dan ekspor dengan IP yang sama di beberapa scope, korelasi tuple/interface, waktu usang, beda sesi exporter, IPv6 dan batas ringkasan, backup WAL, deduplikasi histori dan kunci SQLite. |
| PASS — format/lint host | `cargo fmt --check`, format modul Win32, `cargo clippy --locked --all-targets -- -D warnings`. |
| PASS — cross-build Windows GNU x64 | Clippy target Windows, kompilasi tes tanpa menjalankannya, dan build release. |
| Windows CI | Workflow menjalankan format, Clippy, tes, build, CLI read-only, smoke GUI dengan fixture Detail IP/non-mutasi, dan paket NSIS/portable beserta checksum. Hasil per commit tercatat di [Actions](https://github.com/wawanwfs/WFS-Network-Toolkit/actions/workflows/windows.yml). |
| PARTIAL — operasional | Belum ada pilihan UI kuota/retensi dan recovery otomatis, uji sejuta record, uji disk penuh, topologi graf/IPAM, alert, atau verifikasi semua DPI. |
| BLOCKED — perangkat fisik | Belum ada uji RouterOS live, Realtek fisik, dan installer upgrade/uninstall pada mesin Windows 10/11 pengguna. |

---

## Arsip laporan 0.8.0

| Pemeriksaan | Cakupan |
| --- | --- |
| Suite host | 40 tes host lulus. Arsip persisten, identitas database, impor/ekspor, retensi dasar, query site/VRF, dan regresi yang sudah ada. |
| UDP loopback | Dua domain yang menggunakan alamat IP LAN sama, domain tak terdaftar ditolak, buka ulang database, dedup lintas restart dan satu ekspor tersamarkan. |
| Cross-build Windows GNU x64 | Format, Clippy host/Windows, kompilasi tes Windows tanpa menjalankannya, dan build release lulus dengan Rust 1.100. |
| Windows CI | Workflow menjalankan fmt, Clippy, test, CLI read-only dan smoke GUI, lalu membangun paket Windows. Hasil masing-masing run tercatat di [Actions](https://github.com/wawanwfs/WFS-Network-Toolkit/actions/workflows/windows.yml). |
| Di luar uji otomatis | RouterOS fisik, semua DPI, instal/upgrade/uninstall fisik, kehilangan daya, uji sejuta record, dan verifikasi frame Ethernet Realtek. |

Untuk menjalankan rangkaian yang sama, lihat [README](../README.md) dan workflow Windows. Uji perangkat fisik mengikuti [Hardware Acceptance](HARDWARE_ACCEPTANCE.md).

---

## Arsip laporan 0.7.0

| Pemeriksaan | Hasil |
| --- | --- |
| Baseline 0.6.0 | ZIP cocok dengan SHA-256 rilis dan lulus CRC. |
| Unit test host 0.7.0 | 35 lulus, termasuk IPFIX/NetFlow v9, UDP loopback, isolasi domain dan template, histori snapshot, retensi, diff parsial, serta parsing firewall/VLAN. |
| Format, lint, Windows cross-build | Lulus untuk target host dan Windows GNU x64. Binary unit test Windows berhasil dikompilasi, bukan dijalankan. |
| Build portable dan installer | Lulus. ZIP diuji dengan CRC, dan SHA-256 setiap EXE dibandingkan dengan daftar checksum dalam paket. |
| Windows GUI, HTTPS end-to-end, RouterOS live, dan Realtek | Belum diuji pada perangkat nyata. Tidak ada jaringan produksi yang diubah. |

Command yang dijalankan dari root source, dengan toolchain x64 Windows GNU dan MinGW tersedia:

```text
cargo fmt --check
rustfmt --edition 2024 --check src/bin/native/toolkit_window.rs src/bin/native/intelligence_window.rs
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo clippy --locked --offline --target x86_64-pc-windows-gnu --all-targets -- -D warnings
cargo test --locked --offline --target x86_64-pc-windows-gnu --no-run
cargo build --locked --offline --release --target x86_64-pc-windows-gnu
makensis -DBIN_DIR=<absolute-path-to-windows-release> installer/WFS-Network-Toolkit.nsi
```

Gunakan `--smoke-ui` dari Windows untuk memeriksa tampilan tanpa mengubah jaringan atau membuka probe internet. Rencana uji router ada di [Capability Matrix](CAPABILITY_MATRIX.md) dan uji fisik di [Hardware Acceptance](HARDWARE_ACCEPTANCE.md).
