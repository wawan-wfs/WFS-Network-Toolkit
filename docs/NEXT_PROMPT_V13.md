# WFS Network Toolkit — Next Prompt v1.3

Lanjutkan repo `wawanwfs/WFS-Network-Toolkit` dari HEAD `main` terbaru. Baca README, changelog, matriks kemampuan, laporan uji, panduan polling, skema SQL dan prompt v1.2. Cocokkan HEAD dengan Actions dan paket sebelum mengubah kode. Jangan force push, jangan menghapus fungsi yang bekerja, dan teruskan per batch sampai gate selesai atau blocker konkret didokumentasikan. Fokus pada alat operasi jaringan Windows yang read-only untuk RouterOS dan perangkat yang dikelola pengguna. Pengujian default menggunakan fixture, localhost dan VM. Jangan menerapkan konfigurasi jaringan pada proses pengujian. Pertahankan perilaku backup/restore Windows yang sudah ada dan popup hanya untuk error atau tindakan penting.

## P0 — Alert per exporter dan pemulihan

- Tetapkan identitas exporter dari site, VRF, profil, IP sumber, observation domain dan generasi sesi. Kasus exporter sama dengan domain berbeda, IP berubah, profil dihapus dan restart collector harus diuji.
- Bedakan jeda observasi, sequence gap, penolakan parser, template hilang, writer penuh, reset exporter, duplikat, dan sumber yang belum pernah mengirim. Jangan menyimpulkan router putus dari ketiadaan flow. Tampilkan data lengkap, parsial, stale dan belum ada.
- Terapkan state machine buka → diakui → pulih, debounce, cooldown, deduplikasi, limiter per exporter dan global, masa retensi, transaksi ack yang idempoten dan persistensi lintas restart. Siapkan filter status, site/domain, pencarian, jumlah belum diakui, dan riwayat baca-saja dari backup. Uji dua exporter tumpang tindih serta reboot proses. Jangan jadikan alert pemicu perubahan jaringan.

## P0 — Histori RouterOS, lease dan IPAM

- Tampilkan waktu lokal dan UTC di GUI serta ekspor. Uji perubahan jam PC dan zona, ambiguitas DST, pergantian zona dan data terlambat. Pisahkan waktu lokal pengambilan, waktu perangkat jika terbukti tersedia, waktu ingest dan waktu commit.
- Tambah alias, catatan, tag dan lokasi offline. Kunci scope oleh router, site/VRF, subnet dan interface jika diketahui. Pisahkan label pengguna dari observasi. Uji IP sama pada dua VRF, history sebelum/sesudah identitas berubah, dan undo pengeditan lokal.
- Uji polling lama, Stop saat hampir commit, cancel sebelum persiapan kerja dan UI saat panel arsip terbuka. Tampilkan kegagalan yang bisa ditindaklanjuti tanpa menyimpan credential atau isi respons mentah. Tambah ringkasan perubahan identitas dan coverage per tabel.
- Tambah statistik sampel router di panel **Penyimpanan arsip**, batas penghapusan dengan preview yang terikat pada data, retensi dan kuota, backup/recovery, migrasi atomik, pembukaan schema lama baca-saja, serta pengujian database penuh dan program crash.
- Tambah DHCPv6 hanya saat tabel perangkat menyediakan data. Pisahkan NDP, SLAAC, DHCPv6 address binding, prefix delegation dan data tidak diketahui. Jangan mengasumsikan alamat yang tidak terlihat bisa dialokasikan.

## P1 — Topologi dan inventaris per scope

- Buat graf opsional dengan label setiap relasi dan bukti. Pisahkan FDB teramati, bridge/VLAN logical membership, L3 next hop, serta adjacency yang hanya diketahui dari satu sisi. Jangan menggambar koneksi fisik yang belum dibuktikan.
- Dukung filter site, VRF, VLAN, bridge, subnet, interface, router dan rentang pengamatan. Tampilkan konfigurasi dan observasi sebagai kelas terpisah. Uji FDB yang pindah port, VLAN tumpang tindih, trunk/access, interface list dinamis, scope ambigu, dan tampilan dengan 1.000 node.
- Tambah subnet utilization yang membedakan reserved/assigned/observed/not observed dan unknown, konflik dengan tingkat keyakinan, serta snapshot diff dan ekspor tersamarkan. Semua baseline harus dapat ditelusuri ke sumber dan waktu.

## P1 — Flow yang dapat diverifikasi

- Tambah waktu flow start/end, metode interpretasi UTC, sampling dan asal field bila tersedia. Simpan waktu terima/commit secara terpisah dan pertahankan nilai raw tanpa mengira NAT, bytes unik atau tingkat sampling. Uji IPFIX/v9, template expiry, reorder, exporter restart, sequence rollover, IPv6, metadata parsial dan replay.
- Tambahkan preset filter, pembatalan kueri/ekspor, navigasi halaman yang stabil, dan scope yang tidak meluas saat membuka Detail IP. Dukung ekspor CSV/JSON tersamarkan secara default dan transaksi output atomik.
- Pertimbangkan integrasi defensif SNMPv3 read-only, syslog metadata, dan agen endpoint opt-in setelah kontrak identitas dan bukti disetujui. Implementasikan hanya bila bisa diuji dan dimatikan tanpa mengganggu mode offline.

## P1 — Penerimaan dan rilis

- Uji unit, integrasi SQLite, parser resilience, cross-build lint, Actions Windows, native GUI dan build NSIS. Upgrade v1.1 → v1.2 → v1.3 di VM termasuk uninstall dan backup sebelum rollback. Uji 100/125/150/200% DPI, keyboard dan screen reader, restart, akses user biasa dan admin. Pisahkan fakta Windows runner, VM, dan fisik.
- Jalankan ulang benchmark satu juta record untuk insert SQLite langsung dan UDP loopback 10 exporter × 2.000 IP. Ukur throughput, latensi receive→commit P50/P95/P99, antrean, drop kernel vs penolakan aplikasi, CPU, RAM puncak, file DB/WAL, dan durasi shutdown. Simpan konfigurasi serta perintah reproduksi. Jangan memakai trafik publik.
- RouterOS TLS, fitur Flow dan MAC Realtek hanya diuji di perangkat lab yang diizinkan. Jika perangkat tidak tersedia, tulis BLOCKED dan jangan menyatakan lulus.
- Kirim direktori portable dan installer, SHA-256, changelog, matriks kemampuan yang sesuai bukti, panduan upgrade, serta next prompt baru yang langsung melanjutkan pekerjaan. Push fast-forward ke `main` sesuai izin, konfirmasi SHA pergeseran, pantau Actions hingga hasil terminal dan tautkan paket untuk commit yang sama.
