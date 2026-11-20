# Detail IP dan histori koneksi

## Dari inventaris ke laporan

1. Buka **Analisis Jaringan → Perangkat & alamat** atau **Akses Internet**.
2. Pilih baris, lalu tekan **Detail IP**. Anda juga bisa memilih **Detail IP** dari daftar tampilan dan mencari satu IPv4 atau IPv6 secara langsung.
3. Pilih scope arsip yang cocok dengan site, VRF, profil, endpoint exporter, dan domain. Gunakan **Detail** untuk melihat waktu bukti, rentang observasi, dan lima mitra teratas berdasarkan jumlah record dalam hasil yang diperiksa.
4. Tekan **Koneksi**. Semua halaman histori tetap terikat pada IP dan scope tersebut. Ubah port, protokol, interface atau rentang waktu lalu tekan **Cari** untuk mempersempit hasil. Tekan **Kembali** untuk pindah scope atau kembali ke inventaris.
5. Pilih **Ekspor arsip…** setelah pencarian selesai. Ekspor memakai filter pencarian terakhir yang berhasil diterapkan, termasuk scope yang terkunci. Penyamaran aktif secara default.

Contoh filter yang bisa ditempel:

```text
ip=192.0.2.21 site="Gudang Barat" vrf=operasional port=443 protocol=6
ip=2001:db8:1::21 vrf-unknown=true since=1794700800 until=1794787200
ip=192.0.2.21 profile=edge-hq domain=1 if=7
```

Kolom `port` mencocokkan port pengirim atau tujuan. Ambang `since` dan `until` inklusif, dalam detik Unix UTC saat collector menerima record. `vrf-unknown=true` berarti record tidak diberi label VRF oleh profil, bukan VRF default. Scope yang muncul dari pencarian IP tidak otomatis terhubung ke baris inventaris Windows atau MikroTik yang dipilih.

## Baca bukti dengan benar

| Status | Yang benar-benar diketahui |
| --- | --- |
| Dua arah WAN teramati | Metadata TCP/UDP berpasangan dengan tuple terbalik, arah interface terbalik, versi dan scope sama, serta selisih waktu ekspor dan penerimaan paling banyak 300 detik. Ini bukan bukti aplikasi berhasil atau tujuan tertentu dapat diakses saat ini. |
| Arah keluar WAN teramati | Ada record yang diklasifikasikan mengarah keluar, tetapi pasangan balik yang sesuai tidak terlihat pada hasil terfilter. |
| Observasi WAN historis | Bukti WAN terpilih diterima lebih dari 15 menit lalu. |
| Bukti WAN belum cukup | Hasil tidak membuktikan akses atau penolakan. Flow timeout, NAT, sampling, offload, tidak seimbangnya jalur, jam exporter, atau filter bisa membatasi observasi. |
| Teruji dari PC ini | Hanya muncul sebagai bukti Windows terpisah untuk IP sumber dan interface yang dapat diatribusikan. Berlaku untuk target HTTPS yang diuji operator, tanpa menguji target atau klien baru otomatis. |

Detail IP memeriksa maksimal 2.000 record terbaru yang cocok, hingga 128 scope. Hasil parsial ditandai. Histogram atau top peers tidak dipakai untuk memperkirakan bandwidth jaringan. Paginasi histori dan ekspor memiliki batas sendiri, sehingga bisa mencakup lebih banyak record dari ringkasan.

## Backup SQLite dan upgrade dari 0.8

Tutup aplikasi lama sebelum mengganti EXE portable atau menjalankan installer baru. Jalur arsip tetap `%LOCALAPPDATA%\WFS Network Toolkit\flow-v1.sqlite3` dan dibuka menggunakan format yang sama. Jalankan backup ke nama file baru:

```powershell
.\wfs-netctl.exe archive-backup .\sebelum-upgrade.sqlite3 --confirm
.\wfs-netctl.exe archive-verify .\sebelum-upgrade.sqlite3
```

SQLite menyalin snapshot konsisten termasuk commit yang masih berada di WAL. File berisi metadata yang tidak disamarkan. Simpan secara privat. Perintah menolak nama yang sudah ada dan dapat berhenti bila sumber terus berubah atau terkunci. Untuk pemulihan manual, tutup seluruh proses yang memakai arsip, verifikasi backup, lalu pindahkan DB lama beserta file `-wal` dan `-shm` ke folder terpisah sebelum menyalin backup ke lokasi awal. Jangan campur sidecar dari arsip berbeda. Gunakan [Penyimpanan arsip](PENYIMPANAN_ARSIP.md) bila ingin memulihkan dan melihatnya sebagai salinan baca-saja.

Jalankan `wfs-netctl.exe archive-health` untuk melihat jumlah metadata, rentang waktu terima, ukuran DB dan WAL saat dibaca, serta batas retensi dan kuota writer.

**Histori** dan **Perubahan jaringan** dapat membaca snapshot JSON lokal dan snapshot yang disalin melalui `archive-import-history --confirm`. View menampilkan gabungan hingga 64 snapshot atau 32 MiB dan mendeduplikasi isi identik. Retensi snapshot SQLite mengikuti pengaturan penyimpanan, sedangkan file lama tetap 7 hari. `history-clear` tetap hanya menghapus file JSON lama bila dikonfirmasi. Impor SQLite tidak dibersihkan oleh perintah tersebut.
