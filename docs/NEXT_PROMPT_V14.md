# WFS Network Toolkit — Next Prompt v1.4 (setelah kandidat pemulihan)

Mulai dari HEAD main terbaru repo https://github.com/wawan-wfs/WFS-Network-Toolkit. Baca ALERT_LEDGER.md, TEST_REPORT.md, CAPABILITY_MATRIX.md, README.md, NEXT_PROMPT_V13_RESTORED.md dan NEXT_MASTER_PROMPT.md. Catat SHA. Kandidat 1.3.0-rc.1 bukan rilis terverifikasi. Source asli 1.3.0 lama belum ditemukan; audit schema 3 lama bila tersedia. Jangan pernah menimpa atau memigrasi schema 3 tanpa kontrak kompatibilitas.

## P0 — Build, keselamatan dan regresi

- Siapkan Rust stable (sesuai MSRV dan lockfile), jalankan Python scripts/test_alert_schema.py, cargo fmt --all, rustfmt untuk modul native, cargo clippy --locked --all-targets -- -D warnings, cargo test --locked, cargo build --locked --release. Perbaiki semua error, bukan menurunkan gate. Uji Windows x64 dan smoke GUI. CI harus tetap manual, tanpa push-trigger.
- Audit handoff Mode Admin: UAC terima/batal, child wait, PID reuse, failure close, tidak ada dua GUI, timeout, collector/polling aktif, pekerjaan background dan backup. Uji VM fisik berizin; jangan samakan compile dengan interaksi UAC.
- Tambahkan Rust integration test SQLite schema 1/2→4, rollback, future/unknown/schema 3 reject, reader schema lama, backup WAL konsisten, lock/full, retention, cap, reopening, ack identity dan idempotency. Tambahkan smoke UI alert data fixture dua VRF dan backup baca-saja. Pantau lag, tidak freeze UI.
- Perkuat ledger: sequence gap dan rollover IPFIX/v9 dengan confidence, generasi sesi exporter dari bukti, event recovery/dedup/cooldown berbasis monotonik, penghitung dropped global vs scope, proses mati, flush akhir, dan indikator persistensi parsial. Jangan menganggap jeda trafik berarti down.
- Ukur benchmark end-to-end 10 exporter, 2.000 IP, 1 juta record, 3 pengulangan; P50/P95/P99 receive→commit, queue, kernel drop bila tersedia, RAM, DB/WAL, shutdown. Bedakan data aktual vs sintetis. Jangan menaikkan antrean tanpa batas.

## P1 — Analisis jaringan lebih lengkap

- IPAM histori assignment, alias/catatan/tag offline per scope, DHCPv6/PD/NDP, subnet utilization dengan unknown, konflik IP berdasarkan bukti, edit undo dan ekspor tersamarkan.
- Topologi native graf dengan tipe edge bridge/VLAN/FDB/neighbor/rute, waktu, coverage, filter site/VRF/interface/VLAN; jangan menyimpulkan kabel fisik dari subnet bersama.
- Flow provenance: waktu flow start/end, metode UTC, sampling valid, NAT bila field memang ada, sequence/restart/reorder, filter tersimpan, cancel query/export atomik. Jangan mengira byte unik lintas sensor. Local/UTC dan DST secara eksplisit.
- MikroTik read-only HTTPS TLS terverifikasi, routing/VRF, queue, VPN, DHCPv6 jika tabel tersedia, monitoring multi-router opt-in. SNMPv3/syslog hanya untuk perangkat berizin dan setelah batas scope, autentikasi serta retensi lulus.
- UI native Rust Win32 tanpa WebView, light mode premium Indonesia, navigasi rapi, footer kecil WFS Project, popup error/penting. Dashboard dan chart asli dari data, state loading/partial/empty, keyboard, DPI 100/125/150/200. Pertahankan seluruh backup/restore IP DNS MAC dan rollback.
- Rilis portable/installer x64 checksum hanya jika build lulus, VM install/upgrade/uninstall, RouterOS lab, Realtek peer frame dan rollback. Jangan menguji konfigurasi jaringan produksi.

## Output
Catat PASS/PARTIAL/BLOCKED/FAIL, hasil perintah dan log, angka benchmark, batas bukti, full source, paket jika lulus, changelog/matriks/upgrade, next prompt. Push fast-forward sekali per batch, tanpa force dan tanpa mengaktifkan Actions setiap push.
