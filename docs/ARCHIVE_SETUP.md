# Arsip flow dan beberapa exporter

## Dari router ke histori per IP

1. Salin [profil schema 2](examples/flow-collector-v2.example.json). Ganti alamat contoh, port, domain, site, VRF, CIDR LAN dan `wan_ifindex` dengan nilai jaringan yang Anda kelola. Nilai `wan_ifindex` adalah indeks interface yang dilaporkan exporter. Pastikan nilainya dengan data router. Untuk satu exporter, profil schema 1 tetap diterima.
2. Di **Analisis Jaringan → Flow UDP…**, pilih profil dan tinjau cakupan. Listener baru mulai setelah operator menyetujui. Toolkit tidak membuat aturan firewall dan tidak mengubah RouterOS. UDP tidak autentik. Gunakan jalur manajemen yang dibatasi, bukan listener publik.
3. Tunggu template dan flow. **Kesehatan sumber** menampilkan paket yang diterima/ditolak serta statistik arsip pada sesi yang sedang berjalan. Tidak semua router, bridge, atau VLAN terlihat dari satu sensor.
4. Pilih **Arsip flow SQLite**, masukkan filter, lalu klik **Cari**. Klik baris dan **Detail** untuk IP/port, interface, site/VRF, sumber dan timestamp. **Lanjut** beralih ke maksimal 200 baris berikutnya. Setelah restart, arsip tetap dapat dibuka tanpa menjalankan collector.
5. Gunakan **Ekspor arsip…**, pilih CSV atau JSON, dan simpan ke nama file baru. **Samarkan** aktif secara default. File berisi maksimal 10.000 baris dari filter yang sama. Jika lebih banyak, persempit rentang waktu. Anonimisasi menyamarkan IP dan identitas scope/exporter di dalam laporan, tapi menyisakan waktu, port dan pola hubungan.

Contoh filter tanpa akses jaringan baru:

```text
ip=10.20.0.21 site="Gudang Barat" vrf=operasional protocol=6
exporter=192.0.2.2:54421 domain=2 if=7
since=1794700800 until=1794787200
```

Kondisi digabung dengan AND. `ip` mencocokkan pengirim atau tujuan, `if` mencocokkan ingress atau egress, dan `exporter` menggunakan **IP dan port UDP sumber**. Waktu menggunakan detik Unix UTC saat record diterima collector, bukan waktu mulai flow. Gunakan tanda kutip untuk nama yang berisi spasi dan kurung siku untuk alamat socket IPv6.

## Penyimpanan, migrasi, dan batas observasi

- Database lokal berada di `%LOCALAPPDATA%\WFS Network Toolkit\flow-v1.sqlite3`. Jalankan Toolkit dengan akun Windows yang sama untuk membaca arsipnya.
- Default retensi flow 30 hari dan snapshot SQLite 7 hari, dengan kuota DB utama 256 MiB. Pengaturan bisa diubah di [Penyimpanan arsip](PENYIMPANAN_ARSIP.md). Perawatan berjalan saat collector aktif. WAL dapat menambah pemakaian disk dan penghapusan tidak langsung mengecilkan file.
- **Stop** menutup listener dan menuntaskan penulisan yang mengantre saat penghentian normal. DB yang terkunci, disk penuh, UDP loss, cache template dan backpressure dapat membuat arsip parsial. Arsip menyimpan metadata flow dan hash datagram, bukan payload paket atau password router.
- Berhentilah mengumpulkan flow dan tutup aplikasi sebelum menyalin database secara manual. Jika file SQLite terkait `-wal` atau `-shm` masih ada, simpan satu set bersama database; jangan menimpa file aktif. GUI dapat memverifikasi backup mandiri dan memulihkan ke salinan baca-saja.
- `wfs-netctl.exe archive-info` melihat jumlah flow dan snapshot. `wfs-netctl.exe archive-import-history --confirm` menyalin snapshot JSON yang masih masuk batas histori lama, tanpa menghapus sumber. Jalankan `wfs-netctl.exe archive-list-snapshots` untuk melihat ringkasan impor terakhir. Mulai 0.9, Histori dan Perubahan jaringan menggabungkan snapshot SQLite dengan file JSON terbaru. Untuk backup konsisten lewat CLI dan cara pulih manual, lihat [panduan Detail IP](DETAIL_IP.md).
- Sampling belum didekode dan counter yang ditampilkan adalah nilai yang dilaporkan exporter. Tidak terlihat bukan diblokir. Bukti WAN dua arah pada collector live juga tidak sama dengan hasil tes HTTPS dari klien.
