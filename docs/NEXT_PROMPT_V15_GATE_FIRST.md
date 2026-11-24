# WFS Network Toolkit — Batch lanjutan gate-first

Mulai dari HEAD main repo https://github.com/wawan-wfs/WFS-Network-Toolkit. Baca V14_GATE_STATUS.md, TEST_REPORT.md, ALERT_LEDGER.md, NEXT_PROMPT_V14.md, master prompt, dan matriks. Kandidat masih 1.3.0-rc.1. Jangan naikkan versi ke 1.4 sebelum kompilasi/regresi terbukti. Jangan force push atau otomatis menjalankan CI setiap push.

## P0: selesaikan build dan regresi (wajib sebelum fitur besar)
- Jalankan workflow manual Windows, simpan SHA dan run ID. Baca semua log. Pulihkan toolchain Rust sesuai lockfile/MSRV; jalankan Python SQL contract, cargo fmt --check, rustfmt native, cargo clippy --locked --all-targets -- -D warnings, cargo test --locked, release build, --smoke-ui, paket NSIS dan checksum. Perbaiki kesalahan nyata; jangan hapus test atau turunkan gate. Jangan buat PR untuk memicu CI.
- Audit seluruh diff dari 22e97abc: shared SQL, identity, filter exact, ACK, replay, cap, retention, migration 1/2→4, schema 3 reject, backup WAL, quota, lock, readonly; uji Rust integration dan smoke UI dua VRF dengan fixture. Tambah test final flush, drain, pending counters, gagal SQLite, listener socket error, race close dan clock mundur. Verifikasi shutdown bounded dan tampilkan kegagalan final flush.
- Uji Mode Admin interaktif pada VM Windows (UAC setuju/batal, satu GUI, PID reuse, user biasa/admin, timeout, task aktif, kolektor/polling aktif). Pertahankan pemulihan IP/DNS/MAC dan guard. Uji install/upgrade/uninstall, DPI 100/125/150/200, keyboard, narrow window. RouterOS dan Realtek fisik hanya lab berizin.
- Benchmark 10 exporter × 2.000 perangkat × 1 juta record (3 run); UDP received/decoded/committed/drop per penyebab, P50/P95/P99 receive→commit, kernel bila tersedia, DB/WAL/RAM, stop latency. Jangan mengarang angka dan jangan menambah antrean tanpa batas.

## P1 setelah gate lulus: batch fitur besar, bukan patch versi
- Network intelligence: dashboard native dengan kartu cakupan lokal, router, flow, alert dan arsip; tren RX/TX dengan counter reset/gap/p95; drilldown IP → bukti akses → koneksi → histori → ekspor. Bedakan bukti HTTPS lokal, trafik dua arah, NAT ambigu, FastTrack/offload, unknown.
- Topologi graf native Win32, bukan WebView: node router/bridge/VLAN/VRF/interface/neighbor/FDB dengan sumber, timestamp, edge eksplisit/inferensi, filter site/VRF/VLAN/interface; jangan klaim sambungan fisik hanya dari subnet. Batas graf besar dan keyboard.
- IPAM: lease/ARP/ND/DHCPv6/PD, alias/catatan/tag offline scoped, overlap IPv4/IPv6, utilization assigned/observed/reserved/unknown, konflik berbukti dan undo. Tidak menyatakan alamat tak terlihat bebas. Pertahankan read-only RouterOS.
- MikroTik multi-router polling opt-in: scope TLS terverifikasi, timeout/backoff/cancel, statistik per tabel, FDB/VRF/queue/VPN/IPv6 bila tersedia. SNMPv3 authPriv dan syslog perangkat terdaftar setelah autentikasi/retensi tervalidasi. Tidak mengubah router/firewall otomatis.
- Flow: start/end, metode UTC dan sampling valid, sequence gap/reorder/rollover/restart, generasi exporter, provenance perubahan profil, filter tersimpan, cancel/export atomik. Retensi, kuota, backup/restore aman, database schema yang terverifikasi.
- UI/UX light mode premium Indonesia, navigasi rapi, dashboard dari data asli, popup error/penting, WFS Project kecil, tanpa WebView. Semua fitur lama tetap ada.

## Output wajib
Full source ZIP, laporan PASS/PARTIAL/BLOCKED/FAIL dengan log/angka nyata, commit, matriks, changelog, upgrade, installer dan portable Windows dengan checksum hanya bila lulus, next prompt. Push fast-forward sekali setelah verifikasi dan jangan mengaktifkan trigger otomatis.
