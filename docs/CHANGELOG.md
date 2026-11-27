## P1 increments 15–16 — extended concurrent collector, transactional secure monitoring, CRL and IPAM revision explorer

Commit 7e83e53c90441d83041f13f04938073daebce3d6 adds bounded 30-minute TLS collection (4 concurrent, max 1024 admissions), separate typed TLS rejection events without authenticated identity, and additive secure observation schema v2. SNMP successful observations and attempts share a transaction; failed attempts contain no observation. Existing v1 observations preserved, prior separate attempt file read-only and combined in history. SQL-only local evidence: v1→v2 preserves rows, forced second-insert failure rolls back observation, 3000 inserted attempts retain 2048 (max observed 205 per target), 6 invalid rows rejected, reopen/integrity PASS. Evidence ZIP SHA-256 a50fd8a9ea91b503a8abc9a257c9af20053afa968b5a90feedc861b32b38ec47. No Rust runtime test. Second increment adds opt-in client CRL path using rustls strict unknown/expired revocation rejection when configured; explicit stop/update/re-authorize rotation, no auto-reload, CRL absent is not checked. Native read-only IPAM revision explorer, exact scope/prefix keyset pagination of 25, latest/older/back and CLI; no network mutation. Full premium redesign, actual TLS/CRL tests, Windows builds, dependency lock, long-lived sender streaming, secure installer ACL and benchmarks remain blocked or pending. No CI triggered or main changed.

---

## Integrated P1 increments 13–14 — bounded supervised secure sessions, durable attempt history and fresh selector correlation

Commit 1ed24cef13766f9860e8882cad1cbd82591c89f1 added a native opt-in multi-connection TLS listener for up to 5 minutes/128 admissions, per-connection mutual TLS verification and streaming JSONL summaries, cancellation, bounded IPC, per-report commits and SNMP read-only polling (10 GETs, 30-second delay, stop on first failure), separate bounded attempt DB. Helper file held open without write/delete sharing during verification/execution; protected installation ACL, parent-path replacement and abrupt termination remain security acceptance items. No persistent credentials, no automatic restart or service. TLS rejection count is not durable, and one long-lived sender is still limited by the existing per-connection deadline. Attempt and observation databases are separate transactions, not atomic together. SQL-only local test using schema and exact insert/prune statements: 3,000 inserts, 2,048 retained, max 256 per target, six invalid rows rejected, reopen and integrity_check PASS; ZIP SHA-256 1b86031dd7f81273c00df2be5a448a075181571df7784ccf75854888b857bb50. No Rust execution. Added conservative session-scoped IPFIX selector cache (60-second TTL, 1024 cap, forward sequence/export time only, invalidation on template or option refresh and reorder; provenance timestamp/cache flag, no counter multiplier); native history reload, context-specific table headers, Escape/close cancellation and secure-attempts CLI. Source tests added but NOT RUN. Full multi-module redesign, stronger durable TLS lifecycle, dependency lock resolution, Windows build/security acceptance and benchmarks still outstanding. Main unchanged; no new CI or deployment.

---

## Integrated P1 increment 12 — immutable confirmed transport config, revision-aware IPAM workflow and native UI refinement

TLS desktop bridge now pipes the exact confirmed config (new helper command syslog-tls-pipe), not a mutable config file path; stdin writer runs separately under process timeout. Certificate/key ACL and helper directory race acceptance still required. SNMP credential length validated before IPC, temporary buffers preallocated. IPAM subnet pivot now loads existing scope/CIDR metadata and captures current revision before populating editor; save checks expected revision rather than blindly treating existing key as new. Added read-only secure-history CLI and context-specific controls; refined shared light palette/buttons. SQL-only local test against secure_monitor_schema.sql and exact retention statements: 3000 inserts -> 2048 retained, max 256 per scope, five invalid records rejected, integrity_check ok. Rust, Win32 and security executable tests remain NOT RUN. No claim of full redesign or continuous collector. No CI/deployment started.

---

## Integrated P1 increment 11 — fail-closed native Secure Transport integration

Added native mode 33 with explicit SNMP authPriv GET and one-session mutual TLS actions, session-only Windows credential prompts, typed result validation and independent bounded SQLite summary history. A build must explicitly embed WENET_SECURE_HELPER_SHA256 and install the matching helper in a protected application directory; ordinary builds remain disabled. Bridge launches no shell, passes credentials through stdin, checks result identity/time and uses process deadlines. TLS report includes bind and observation timestamp. This is source integration only: root and companion uncompiled; helper packaging, ACL/TOCTOU security acceptance, dependency resolution and real agent tests pending. Continuous collector, full redesign and benchmark remain outstanding. No CI/deployment triggered.

---

## Integrated P1 increment 10 — executable security acceptance harnesses

Added TLS loopback fixture harness generating ephemeral trusted and foreign CA, server and client certs via OpenSSL. Runs seven actual cases against companion executable (authorized, absent cert, foreign CA, same CA unpinned, plaintext, truncated and invalid length). Added explicit authorized SNMPv3 lab harness: valid authPriv, wrong auth, wrong privacy and wrong user, no credentials persisted in report. Harness code committed; NOT RUN because companion executable cannot be compiled in current environment. Dependency lock, adversarial replay/source/downgrade, expiry and slow-peer cases, continuous collector and full UI/runtime acceptance remain blockers.

---

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
