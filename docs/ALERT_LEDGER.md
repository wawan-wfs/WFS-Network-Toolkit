# Alert exporter persisten — kandidat pemulihan 1.3.0-rc.1

Source asli rilis 1.3.0 lama tidak tersedia di repo pengganti. Implementasi ini adalah rekonstruksi, bukan salinan atau klaim paritas penuh.

- Buka Analisis Jaringan → Alert collector → Cari. Filter merupakan substring site, VRF, profil, IP/domain, sinyal atau status. Halaman menampilkan maksimal 1.000 record terbaru dari ledger, dan Akui menyimpan waktu pertama secara idempoten. Salinan backup hanya-baca.
- Scope exporter merupakan tuple JSON [site, VRF, profil, IP, observation domain] dari profil terdaftar. Sesi collector dipisahkan oleh identitas PID/waktu mulai; ini bukan generasi reboot exporter. Malformed yang tidak dapat diatribusikan tetap hanya pada statistik global. Writer error bersifat global, tidak dituduhkan ke satu exporter.
- Monitor terpisah mengamati counter setiap kira-kira 1 detik. Debounce 5 detik, jeda 300 detik. Sinyal template hilang, parser menolak, duplikat, belum ada datagram diterima, jeda observasi, antrean penuh, writer tertutup, dan SQLite gagal. Pulih teramati memerlukan bukti aktivitas yang relevan; bukan bukti router online, template tertentu pulih, atau jaringan normal total.
- Retensi memakai retensi snapshot dan batas 4.096 record terbaru. Kegagalan penyimpanan dapat membuat histori parsial; status error ditampilkan saat membaca alert. Monitor belum menjamin semua kejadian selama shutdown/crash atau saat DB penuh tersimpan. Tidak ada pemindaian atau tindakan jaringan otomatis.
- **Schema 4 baru** dibedakan dari schema 3 rilis lama yang belum dapat diverifikasi. Schema 1/2 dapat dibaca dan dimigrasi secara transaksional ketika writer dibuka. Schema 3 ditolak sampai ada migrator yang diaudit. Simpan backup sebelum upgrade. Jangan menggunakan file schema 4 pada versi sebelumnya.
- Gate Rust/Windows, benchmark UDP dan UAC belum lulus pada batch ini. Jalankan Python SQL contract, Rust tests, Clippy, build, smoke, serta uji VM dari panduan NEXT_PROMPT. Jangan menggunakan kandidat ini untuk jaringan produksi sebelum gate selesai.

## Batch gate v1.4

Gunakan `state=open`, `state=ack`, `state=recovered`, atau `state=all` diikuti teks scope. Kata status tepat Bahasa Indonesia juga tersedia. Query bersama diuji offline; Rust dan GUI belum diuji. Replay setelah pulih tidak mengubah histori, dan benturan identitas membatalkan batch. Penghentian normal mencoba final sample setelah writer drain. Kegagalan DB atau crash belum menjamin flush. Tidak ada migrasi schema baru.
