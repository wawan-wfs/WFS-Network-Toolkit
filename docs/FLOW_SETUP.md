# Collector Flow dan histori di WFS Network Toolkit 0.7.0

## Menerima Flow

1. Salin [profil contoh](examples/flow-collector.example.json) ke file baru. Alamat dalam contoh dikhususkan untuk dokumentasi. Ganti dengan alamat PC, exporter dan subnet yang Anda kelola. `bind` harus alamat spesifik milik PC, bukan `0.0.0.0` atau `::`. Masukkan sumber paket UDP yang benar pada `exporter`, ID domain pada `observation_domain`, dan indeks interface sisi WAN pada `wan_ifindex`. Pada NetFlow v9, isi domain dari Source ID exporter.
2. Buka **Analisis Jaringan**, klik **Flow UDP…**, pilih profil dan tinjau alamat sebelum menyetujui listener. Listener tidak mulai otomatis. Batasi izin inbound firewall Windows ke alamat exporter pada jaringan manajemen. UDP berbasis allowlist bukan autentikasi kriptografis. Jangan publikasikan port ke internet.
3. Dari router yang diotorisasi, atur target Traffic Flow melalui prosedur admin Anda sendiri ke alamat dan port PC. Pilih IPFIX atau NetFlow v9 yang cocok. Aktifkan field source/destination address, source/destination port, protocol, ingressInterface dan egressInterface untuk analisis WAN. Tambahkan byte/packet delta jika tersedia. Cocokkan WAN ifIndex dan domain dengan data exporter atau capture lab, bukan dengan menebak nama interface. Toolkit tidak menulis konfigurasi router maupun firewall Windows.
4. Buka **Status collector**, **Flow IPFIX / NetFlow**, **Mitra trafik**, atau **Akses Internet** dari daftar tampilan. Klik **Cari** untuk membaca data terbaru. Paket tanpa template yang cocok dihitung terpisah dan tidak ditebak. Klik **Stop** untuk menghentikan listener. Flow hanya disimpan di buffer sesi hingga 10.000 record.
5. **Trafik WAN dua arah teramati** membutuhkan arah balik dengan pasangan IP, port, protokol, exporter, dan domain yang sama, serta waktu export yang berdekatan. Ini bukti observasi, bukan bukti HTTPS sukses, policy allow, atau seluruh jaringan dapat diakses. NAT yang mengubah tuple sehingga tidak dapat dipasangkan tidak dipaksakan. **Hanya upaya WAN teramati** berarti flow keluar teramati, bukan berarti firewall menolak.

Parser menangani template IPFIX/NetFlow v9, IPv4 dan IPv6, integer panjang reduksi serta field variabel IPFIX, buffer terbatas, dan expiry template UDP. Options/sampling tidak dipakai untuk koreksi volume. Data IPFIX v10 tidak membawa uptime exporter pada header. Saat exporter restart tanpa template baru, restart tidak dapat dipastikan dari header saja. Untuk reconfig/restart exporter, hentikan dan mulai kembali collector. Snapshot IPFIX tidak melihat jalur yang tidak diekspor, termasuk hardware-offloaded Traffic Flow pada RouterOS. Referensi: [MikroTik Traffic Flow](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/traffic-flow/), [RFC 7011](https://www.rfc-editor.org/info/rfc7011/), [RFC 3954](https://datatracker.ietf.org/doc/html/rfc3954).

## Histori dan perbandingan

- Setelah membaca Windows atau RouterOS, klik **Simpan** untuk menyimpan snapshot ringkas. Ulangi setelah perubahan, lalu buka **Histori → Perubahan jaringan** dari daftar tampilan. Perbandingan menggunakan dua timestamp terbaru yang berbeda per sumber.
- Histori disimpan untuk akun Windows yang menjalankan aplikasi di `%LOCALAPPDATA%\WFS Network Toolkit\observations-v1`. Maksimum 64 snapshot / 32 MiB / tujuh hari. Retensi berkas ditegakkan ketika menyimpan. Snapshot lama juga tidak dimuat dalam tampilan. Data tidak disamarkan dan memuat metadata jaringan. Tidak ada password, URL pribadi, atau isi paket.
- Aturan IPv4/NAT dalam snapshot hanyalah field yang diizinkan untuk dibaca. Pindah posisi rule dicatat bila identitas ID sama, sedangkan counter trafik tidak dihitung sebagai perubahan konfigurasi. Tidak ada simulasi firewall. Perbedaan data parsial tidak dapat berarti perangkat hilang. Jangan menjadikan selisih snapshot sebagai log perubahan yang pasti dan lengkap.
- CLI `wfs-netctl.exe history-list` menampilkan daftar ringkas arsip. Jika memang ingin menghapusnya, jalankan `wfs-netctl.exe history-clear --confirm`. Perintah menghapus berkas snapshot yang dikenali dalam folder di atas saja. Arsip tidak otomatis dihapus oleh uninstaller.

## Multi-exporter dan histori 0.8.0

Langkah schema 1 di atas tetap kompatibel. Untuk skema 2, penyimpanan lintas restart dan filter, lihat [panduan arsip](ARCHIVE_SETUP.md).
