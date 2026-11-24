# WeNet Toolkit by WFS Project — master prompt lanjutan

Gunakan HEAD main terbaru dari https://github.com/wawan-wfs/WFS-Network-Toolkit. Audit terlebih dahulu WENET_BRANDING.md, TEST_REPORT.md, V14_GATE_STATUS.md, NEXT_PROMPT_V15_GATE_FIRST.md, NEXT_PROMPT_V14.md, NEXT_MASTER_PROMPT.md dan source. Jangan mengubah nama repo, folder data legacy, format backup, schema database, mutex mutasi, registry uninstall atau CLI tanpa migrasi teruji. Jangan menaikkan versi sebelum gate lulus.

## P0 — Verifikasi wajib
- Baca run Windows manual yang benar-benar cocok dengan HEAD. Bila belum ada, jalankan workflow_dispatch hanya bila alat mendukung/diizinkan; jangan aktifkan push/pull_request trigger. Jalankan scripts/test_branding.py dan scripts/test_alert_schema.py, cargo fmt --check, rustfmt modul Win32, cargo clippy --locked --all-targets -- -D warnings, cargo test --locked, cargo build --locked --release, smoke WeNet-Toolkit.exe --smoke-ui, installer NSIS dan SHA256SUMS. Selesaikan setiap error nyata.
- Uji installer fresh, upgrade dari paket WFS lama, uninstall, rollback portable, penggunaan arsip dan backup lama, shortcut tidak ganda, metadata, ikon ukuran kecil/taskbar, UAC satu jendela, UAC batal, helper, DPI dan keyboard. Jangan menyatakan hardware teruji dari CI.
- Uji collector shutdown setelah drain, error flush, per-exporter alerts, exact filter, ACK, WAL, read-only, quota, migrasi 1/2→4 dan penolakan schema 3. Benchmark 10 exporter × 2.000 IP × 1 juta record, 3 run, catat decode/commit/drop/P95/DB/WAL/RAM/stop. Kernel drop unavailable jika tidak terukur.

## P1 — Large Development Batch setelah gate hijau
- Dashboard WeNet native dengan status cakupan, jumlah perangkat teramati, router, flow, alert, arsip, bandwidth RX/TX dan freshness. Tidak mengarang status online atau data dummy tanpa label.
- Topologi native interaktif Win32: router, bridge, VLAN, VRF, interface, FDB, neighbor, route, sumber dan timestamp; pencarian, pan/zoom, batas graf, keyboard. Jangan menyimpulkan kabel fisik dari subnet bersama.
- Advanced IPAM: scope/site/VRF, catatan/alias/tag offline, DHCPv4/v6/PD/NDP, subnet overlap, histori lease, konflik berdasar bukti, utilization dan unknown, undo serta ekspor tersamarkan.
- Network intelligence: alur IP → bukti internet → koneksi historis → ekspor; NAT, FastTrack/offload, sampling, provenance, sequence gap/restart, waktu UTC/lokal dan filter konsisten. Jangan menyamakan dua arah dengan akses internet universal.
- Monitoring MikroTik multi-router HTTPS TLS read-only dengan polling opt-in, per-table coverage, backoff dan cancel. SNMPv3/syslog hanya perangkat terotorisasi dengan autentikasi/retensi lulus.
- UI premium light mode navy/teal sesuai identitas WeNet, hierarki visual, navigasi rapi, empty/loading/partial/error states, keyboard dan DPI; credit kecil by WFS Project. Native Rust tanpa WebView/Tauri/Electron. Pertahankan IP/subnet/gateway/DNS/MAC, backup/restore, no-op dan rollback, popup penting, satu jendela admin.
- Uji perangkat lab RouterOS dan Realtek dengan peer frame dan rollback. Tidak mengubah jaringan produksi. 
- Output: full source ZIP, laporan aktual PASS/PARTIAL/BLOCKED/FAIL, matriks, changelog, installer+portable hanya bila build lulus, checksum, next prompt. Push fast-forward ke main; Actions tetap manual. Jangan mengarang hasil.
