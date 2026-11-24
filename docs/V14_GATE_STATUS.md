# Batch v1.4 — Gate regresi sebelum pengembangan fitur

Baseline: 22e97abcaee82f59feb46306c237b24d9b22d29c.
Versi Cargo tetap 1.3.0-rc.1: ini kandidat source, bukan rilis 1.4.

## Hasil aktual

- PASS: Python 3.13.5 / SQLite 3.46.1, 9 tes offline, 0 gagal. Perintah: `python scripts/test_alert_schema.py`. Query upsert, ACK, page, prune, cap digunakan bersama dengan Rust melalui include_str. Tes: migrasi 1→4/2→4, rollback, filter status, replay dan identitas, clock regression, retensi/cap, WAL backup/reopen/read-only/write lock, kuota SQLite penuh simulasi.
- PARTIAL: perubahan source Rust dan Win32 untuk final-sample alert, flush setelah writer selesai, pending in-flight, filter dan status, handoff admin. Belum dikompilasi, belum menguji interaksi native.
- BLOCKED: cargo/rustc/rustfmt tidak ditemukan; akses jaringan container ke GitHub gagal DNS. Konektor GitHub hanya mendukung baca workflow dan rerun job yang sudah ada, bukan workflow_dispatch. Jangan membuat PR untuk memicu CI otomatis.
- BLOCKED: clippy, test Rust, smoke Win32, build/NSIS, benchmark UDP, perangkat fisik. Tidak ada paket executable baru.
- BLOCKED: fitur P1 (graf topologi, dashboard native, IPAM lanjut, SNMPv3/syslog) menunggu gate P0 sesuai urutan permintaan; belum diterapkan dalam batch ini.

## Langkah penerimaan

1. Buka Actions → Windows build and unit tests → Run workflow → main. Workflow kini hanya workflow_dispatch. Jangan gunakan push atau pull_request trigger.
2. Jalankan format, Clippy -D warnings, tes terkunci, build release, smoke native dan packaging tanpa menurunkan gate. Jika gagal, simpan log lengkap, perbaiki dan ulangi manual. Python tes SQL bukan pengganti pengujian Rust.
3. Uji UAC, DPI, upgrade/uninstall dan perangkat fisik secara terpisah. Gunakan fixture, localhost atau lab berizin.
4. Setelah semua gate hijau, lanjutkan backlog P1 dari NEXT_PROMPT_V14.md. Jangan mengklaim rilis atau persen kesetaraan yang belum terbukti.

## Penggunaan alert

Filter: `state=open site/A`, `state=ack vrf-b`, `state=recovered`, `state=all`, atau teks biasa. Kata tepat Diakui/Belum diakui/Pulih juga didukung. Status exact disaring sebelum LIMIT; ACK hanya sesuai identitas lengkap. Penutupan normal mencoba flush setelah writer selesai; crash/DB penuh tetap dapat menghilangkan histori. Schema 4 tidak berubah.
