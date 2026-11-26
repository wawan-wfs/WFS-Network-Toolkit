# P1 integrated development candidate — staged before CI

Base: 66c981152c0a226f8ded138f5fe5ffa745d32e81. Operator changed order on 2026-11-26: develop on a candidate branch first, consolidate and test after feature implementation. Main Auto CI remains unchanged. This is an unaccepted source candidate, not a release.

Implemented source: deterministic connected-component graph bands and offscreen edge culling; native text RX/TX preview in dashboard details (not full embedded GDI canvas); exclusive cursor DHCPv6 history with redacted aggregate export and CLI access; exact operator-scope IPAM overlap checks and independent no-overwrite recovery with revision validation; flow sequence/restart diagnostics (not loss counters or sampling correction); benchmark harness with three executions of actual million-row test and P50/P95/P99 query latency.

Added Rust regression cases for graph components, preview missing/zero, DHCPv6 cursor/redaction, IPAM overlap and recovery. Toolchain unavailable locally; these tests, rustfmt, Clippy, Windows build, runtime and benchmarks are NOT RUN. No installer/screenshot or hardware acceptance claimed.

Remaining P1: full embedded GDI chart and range/selection, typed observed/operator scope mapping and UI for overlap/recovery, DHCPv6 validated backup and native paging UI, full flow sampling/NAT provenance and replay tests, bounded multi-router health, trusted SNMPv3 authPriv and authenticated TLS Syslog implementation with pinned dependencies and security tests, all-module accessibility/DPI redesign, measured three million-row repetitions including memory/drops/stop. Do not implement custom crypto or misrepresent text preview as full chart. Complete remaining scope on candidate branch; then run all existing gates once for consolidated candidate, verify logs, artifacts and hashes before promotion. Keep no deployment/force push.

---

# Latest change — CI contract recovery

- Align branding regression with authorized main-push and workflow_dispatch CI, exact concurrency and read-only permissions; preserve existing binary, icon, UI credit and upgrade checks.
- Verify provenance/source/checksum and checkout credential policy in static contract.
- Record verified 11/12 gate evidence; no application version bump, no deployment and no claim of accepted installer.

---

# CI format recovery — acceptance pending (2026-11-25)

Run [45672963967](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45672963967), attempt 1, exact parent 19d4686e8b04f32aec21d6434f3a5ec294777515: 9/12 gates PASS; three format gates FAIL; 89 Rust tests passed, 0 failed, 2 ignored; Clippy and release build PASS. CLI/native smoke/NSIS skipped. All 43 rustfmt hunks across nine files applied from verified artifact 15049804007. New exact SHA NOT TESTED. See [CI recovery evidence](CI_FORMAT_RECOVERY_45672963967.md).

No version, feature, schema, dependency or workflow change.

---

# Graph and history development candidate — Windows acceptance pending

- Baseline a11ea99f: 11/11 CI gates, 83 Rust tests, native smoke and installer packaging passed; verified hashes.
- Add shared-node topology with conservative scope identity, native pan and zoom, direct dashboard chart drilldown and selected-window P95, source-stamped resource metrics.
- Add DHCPv6 server/interface mapping and separate immutable history SQLite with no DUID; add 7 passing offline SQL tests and independent CI gate.
- Add IPAM aggregate redacted export and no-overwrite SQLite backup, bounded offline Syslog header summary, new native fixture smoke and light-mode refinements.
- New source not compiled or run on Windows yet. No version bump, schema change to legacy archive, dependency changes or auto workflow.

---

# CI format recovery — acceptance pending

- Applied 45 rustfmt diff hunks from run 45663046203 across five Rust files.
- Previous candidate passed 83 Rust tests, Clippy, release build and IPAM SQL; three format gates failed; native smoke and installer skipped.
- No version bump or intended behavior change. New exact SHA requires manual CI.

---

- Offline IPAM SQL contract: 7/7 passed on five exact matching inputs; Windows fixture smoke for visual viewers and metadata added, pending execution.

- Added separate IPAM operator metadata ledger with immutable revisions, optimistic conflicts and undo; native editor controls and SQL contract tests.

# Visual intelligence candidate — new source, gate pending

- Accepted baseline CI 45632871037 (10 gates, 76 Rust tests, native smoke, packaging, checksums).
- Native GDI evidence graph and per-interface bandwidth chart with bounded navigation and zoom.
- RouterOS read-only DHCPv6 binding inventory, address vs PD and source coverage. No DUID storage or network writes.
- New unit fixtures and viewer formatting check. New candidate not yet compiled; no new executable claim.

---

# CI format recovery — candidate, verification pending

- Applied 13 exact formatting corrections from run 45552687279 (three Rust files).
- Baseline Rust tests: 76 passed, 0 failed, 2 ignored; release build and Clippy passed. Formatting blocked CLI/GUI/installer.
- No version bump or feature change; new manual CI required.

---

# P1 corrective candidate — gate pending

- Align subnet evidence timestamps and VRF mapping; exclude inactive DHCP leases from observed count.
- Distinguish archive loading, absent and read failures; label future timestamps ambiguous.
- Strengthen read-only CLI exit gate; add Rust regression fixtures (not yet executed).
- Re-run identical SQLite contract: 9 passed; no release version bump.

---

# P1 dashboard and scoped IPv4/IPv6 subnet candidate

- Baseline ae36e729 passed all Windows gates and produced a portable/installer.
- Added native network dashboard and module navigation, source freshness/coverage, RX/TX/P95 per interface, flow exporter and archive summary.
- Added bounded scoped IPv4/IPv6 prefix and distinct observation counts; no inferred free addresses. Tests added for mixed-family prefix boundaries, scope separation, cap, coverage and GUI; new Rust and GUI gate pending. Existing versions/schema/backup identifiers retained.

---

# Native GUI smoke recovery

- All ten build gates and CLI passed on e561f864; native GUI smoke exited 1 without internal diagnostics.
- Wait for async alert load in temporary SQLite fixture, verify persistent acknowledgement and state filter. Clear stale alert display.
- Capture native smoke progress and internal errors as CI evidence without disabling or bypassing smoke. Manual-only Actions retained.
- Candidate unchanged; new source requires manual build/smoke verification.

---

# Koreksi gate berdasarkan CI Windows manual

- Terapkan diff rustfmt dari run 45426915628 pada 7 source files; tidak ada perubahan perilaku yang disengaja.
- Baseline Windows: Clippy, 70 tes Rust dan release build lulus, 3 format gagal. Ulangi manual untuk memastikan koreksi, smoke GUI dan paket.
- Versi kandidat tetap 1.3.0-rc.1, Actions manual-only; P1 belum diimplementasikan.

---

# WeNet Toolkit — gate recovery candidate

- Added independent fail-closed gate runner, JSON and per-command logs uploaded even on CI failure; retains existing native smoke and packaging gate. Manual trigger only.
- Five local runner tests and nine SQL regression tests passed (14/14); 11 test/SQL/runner file hashes match. Asset hashes preserved.
- Revalidate collector direct configuration at start; explicit stop exposes final writer/alert/receiver errors and pending/dropped counters. Rust implementation not compiled yet.
- Version and legacy identifiers unchanged. P1 features remain pending until Rust/Windows gate passes.

---

# WeNet Toolkit — changelog

## Rebranding kandidat (versi Cargo tetap 1.3.0-rc.1)

- Nama produk WeNet Toolkit, credit by WFS Project. Ikon W jaringan navy/mint tujuh ukuran ICO, SVG, PNG; palet Win32 light navy/teal, indikator navigasi, tagline.
- EXE GUI, resource, shortcut, daftar aplikasi, dokumentasi, laporan diagnostik dan nama paket diselaraskan. CLI, folder arsip, mutex, crate dan identitas installer tetap.
- Pembersihan shortcut lama saat upgrade; EXE lama dicoba hapus setelah file baru terpasang. Tidak ada perubahan schema atau konfigurasi jaringan.
- Tes statis konsistensi branding ditambahkan ke workflow manual. Build Rust, UI Windows, installer upgrade dan benchmark belum lulus.

---

# Catatan rilis WFS Network Toolkit

## Batch v1.4 — stabilisasi kandidat (belum build)

- Query alert berbagi berkas SQL dengan suite offline; filter state exact, perlindungan identitas/replay/ACK, retensi, cap, lock dan backup.
- Pending writer mencakup transaksi aktif. Collector memisahkan stop receiver dan stop monitor agar final sample mengikuti drain writer. Observasi pendek saat penutupan normal tetap dicoba simpan.
- Mode alert otomatis membaca arsip saat dipilih. Handoff Administrator memakai konstanta pesan dan guard jika sudah elevated.
- Workflow hanya workflow_dispatch. Sembilan tes Python SQLite lulus; gate Rust/Windows belum dijalankan. Versi Cargo tidak dinaikkan.

## 1.3.0-rc.1 — kandidat pemulihan (belum build)

- Rekonstruksi ledger alert per profil/site/VRF/IP/domain, penyimpanan schema 4 dan pengakuan persisten; schema 3 lama belum didukung.
- Monitor terpisah, debounce, retensi dan pembatasan histori, status pemulihan berbasis observasi, pembacaan backup dan filter.
- Antrean writer dibatasi 256 batch (belum benchmark). Handoff Admin menutup lewat loop pesan; metadata EXE diselaraskan.
- Tes kontrak SQL offline dan kasus unit Rust ditambahkan. Gate Rust/Windows belum dijalankan. CI tetap manual.

## 1.2.1

- Mode Admin: child menunggu PID jendela lama selesai setelah UAC berhasil, sehingga tidak membuka dua GUI bersamaan; UAC ditolak mempertahankan sesi biasa.
- Pengaman perpindahan Mode Admin saat collector UDP atau polling RouterOS aktif, agar tidak memotong sesi/kesempatan flush.
- Diagnostik penyebab kehilangan record: antrean writer penuh, channel writer terputus, dan kesalahan tulis SQLite dibedakan, dengan regresi perhitungan agregat.
- Workflow GitHub tetap **manual** (tanpa push-trigger) pada repo pengganti.

## 1.2.0

- Polling RouterOS HTTPS GET opt-in per target, batas konkurensi dan interval, penghentian, jeda ulang, serta status hasil.
- Histori SQLite schema 2 untuk tren interface dan pengamatan lease DHCPv4, dengan arsip per router, filter UTC, retensi, backup, dan pembukaan salinan baca-saja.
- Detail tren memisahkan waktu pembacaan tabel dan waktu selesai pengambilan. Reset counter, ganti identitas, dan data yang tidak dapat dibandingkan tidak ditampilkan sebagai nol.

## 1.1.0

- Topologi RouterOS read-only dan IPAM observasi IPv4/IPv6, dengan sumber, waktu, serta pemisahan bukti dan indikasi.
- Histori lease sesi, tren interface RX/TX, dan alert lokal collector dengan debounce, cooldown, serta ack.
- Fixture RouterOS, smoke GUI dan benchmark UDP loopback.

## 1.0.0

- Panel Penyimpanan arsip dengan ukuran DB/WAL, pengaturan retensi flow dan snapshot, serta kuota DB utama.
- Backup konsisten, pemulihan sebagai salinan baca-saja dan impor snapshot JSON dari GUI.
- Pratinjau hapus per jenis dan rentang UTC. Transaksi dibatalkan jika record berubah sebelum konfirmasi.

## 0.9.0

- Detail IP, observasi WAN per scope, lima mitra teratas, dan pivot histori koneksi dengan scope yang tetap terkunci hingga ekspor.
- Filter port, profil, serta scope tanpa label VRF. Bukti Windows terpisah dari metadata exporter.
- Gabung histori JSON/SQLite, backup SQLite konsisten, verifikasi backup, dan perawatan flow saat collector idle.

## 0.8.0

- Multi-exporter schema 2 hingga 16 profil serta kompatibilitas profil schema 1.
- Arsip SQLite WAL, batas penyimpanan, retensi flow 30 hari, dedup rekaman, pencarian dan ekspor CSV/JSON.
- Impor histori JSON lokal idempoten via CLI.
- Paket portable dan pemasang Windows x64 dengan SHA-256.

## 0.7.0

- Collector IPFIX/NetFlow v9 UDP dengan konfigurasi eksplisit, periksa exporter/domain, statistik decoder, dan pasangan trafik WAN berbasis ifIndex.
- Tampilan Flow, mitra trafik, status collector, histori ringkas, serta perbandingan perubahan per sumber.
- MikroTik read-only menambah bridge port/PVID, interface VLAN, firewall filter IPv4, dan NAT IPv4.
- CLI histori dan konfigurasi contoh dengan alamat dokumentasi.

## 0.6.0

- Halaman Analisis Jaringan untuk inventaris IPv4/IPv6, cache tetangga, soket Windows, layanan lokal, dan penilaian akses internet per IP berbasis bukti.
- Snapshot MikroTik read-only melalui REST HTTPS dengan tampilan sistem, DHCP, ARP/ND, rute default, interface, dan tuple conntrack/NAT IPv4. Penanda sumber parsial dan tidak tersedia.
- Probe HTTPS manual dari PC operator, filter data, impor bukti JSON, ekspor CSV dengan samaran opsional, dan perkiraan bit/s dari dua pembacaan interface.
- Fungsi lama, Light Mode, footer, pop-up dan jalur recovery tetap dipertahankan.

## 0.5.2

- Error, peringatan, detail driver, dan konfirmasi hasil penting tampil di dialog Windows, bukan di bilah bawah.
- Status rutin seperti memuat adaptor dan ping selesai tetap di bilah bawah. Peringatan pratinjau disatukan dalam satu dialog, sementara tabel perubahan tetap dapat ditinjau sebelum menerapkan.
- Hasil operasi Administrator hanya ditampilkan sekali, baik saat aplikasi sudah berjalan sebagai admin maupun saat memerlukan UAC.

## 0.5.1

- Perubahan MAC memeriksa status link, antarmuka, dan driver secara terpisah. Ethernet yang tidak tersambung dapat meneruskan perubahan MAC jika driver berjalan dan tidak bermasalah.
- Verifikasi MAC membaca alamat aktif persis, memeriksa kembali driver setelah restart, dan hanya menunggu link bila link semula aktif. Jika tidak cocok, Toolkit tidak mengganti MAC dengan nilai alternatif.
- Halaman MAC Address menampilkan status link dan menyediakan pintasan ke Koneksi Jaringan Windows. Detail driver membedakan perangkat yang tidak dimulai dan perangkat yang melaporkan kode masalah.
- Memperbaiki penerusan perubahan pilihan restore ke kontrol terkait dan menggambar ulang footer serta kontrol setelah perubahan ukuran jendela.

## 0.5.0

- Header aplikasi menampilkan nama produk. Atribusi © WFS Project berada di footer kiri bersama versi, dengan ukuran teks lebih kecil. WFS Project tetap tercatat di metadata EXE dan installer.
- Restore kini memiliki pilihan IPv4 dan DNS, DNS saja, atau MAC saja. Opsi menyertakan MAC dalam restore gabungan tetap tidak aktif secara default. Jika bagian yang diminta tidak ada, aplikasi tidak menggantinya dengan operasi lain.
- Restore dan pemulihan DNS saja memakai operasi DNS khusus. IP, subnet, gateway, mode DHCP, dan MAC tidak ditulis oleh operasi DNS saja.
- Pratinjau dan tahap penerapan menolak IPv4 statis baru atau MAC baru yang sudah dipakai adaptor aktif lain pada PC yang sama. Fitur ini tidak memindai perangkat lain di LAN.
- Profil backup kosong, nama sumber yang tidak valid, dan field JSON duplikat ditolak. Perintah `check-backup` memeriksa backup tanpa mengubah adaptor.
- Snapshot pemulihan divalidasi sebelum pemulihan. Snapshot dari versi sebelumnya tetap bisa dibaca.
