# Penyimpanan arsip

Buka **Analisis Jaringan → Penyimpanan arsip**. Pilih **Muat** untuk menyegarkan metrik. Panel menampilkan jumlah flow, snapshot dan scope, pemakaian file SQLite/WAL, serta waktu pengukuran. Pilih baris lalu tekan **Detail** untuk rentang waktu dan rincian. Jika collector berjalan, hitungan antre, drop, dan pemangkasan berlaku sejak sesi collector mulai. Ukuran file dan antrean dapat berubah setelah pengukuran.

## Retensi dan kuota

Di kotak masukan, ketik tiga angka dalam urutan **hari flow, hari snapshot SQLite, kuota DB utama MiB**, lalu tekan **Atur**. Default `30 7 256`. Retensi masing-masing 1–365 hari dan kuota 16–1.024 MiB. SQLite menolak kuota baru yang lebih kecil dari DB saat ini. Ukuran file tidak otomatis mengecil setelah penghapusan. File WAL dapat menambah pemakaian disk di luar kuota.

Saat collector aktif, perawatan dimulai walau belum ada trafik dan berulang kira-kira setiap lima menit, maksimal 10.000 record kedaluwarsa per jenis per siklus. Jika penyimpanan penuh, batch baru dapat ditolak dan dihitung sebagai drop. Arsip tidak menghapus data di luar retensi untuk membuat ruang. Snapshot JSON lama masih memakai batas tersendiri. Tidak ada tabel agregat persisten pada versi ini.

## Backup dan pemulihan

- **Backup SQLite…** membuat salinan konsisten termasuk commit dari WAL. Salinan baru diperiksa sebelum muncul di nama tujuan. Berkas berisi metadata jaringan tanpa penyamaran, jadi simpan secara privat.
- **Pulihkan salinan…** memeriksa backup mandiri, menunjukkan jumlah record, lalu meminta nama file baru dan konfirmasi. Isi sumber diperiksa ulang sebelum salinan dipublikasikan. Gunakan volume lokal yang mendukung hard link, misalnya NTFS. Jika ada file tujuan atau sidecar yang bentrok, aplikasi menolak publikasi. Jangan pilih path arsip utama.
- Setelah dipulihkan, aplikasi membuka salinan sebagai arsip baca-saja untuk Detail IP, histori, Perubahan jaringan, tren interface, histori lease dan ekspor flow. Untuk berpindah kembali, pilih **Penyimpanan arsip → Reset**. Collector selalu menggunakan arsip utama. Pemulihan tidak menimpa arsip utama atau mencampur WAL.
- **Impor JSON** menyalin snapshot dari folder histori lama akun ini. File JSON sumber tetap utuh. Impor berulang tidak menggandakan snapshot identik.

## Hapus rentang dengan pratinjau

Hentikan collector aplikasi ini, lalu isi salah satu bentuk berikut:

```text
flow 1794700800 1794787199
snapshot 1794700800 1794787199
```

Kedua batas inklusif dan menggunakan detik Unix UTC. Flow memakai waktu terima collector, snapshot memakai waktu observasi. Pilih **Tinjau hapus…**, baca jumlahnya, dan konfirmasi bila benar. Operasi maksimal 10.000 record dan batal seluruhnya jika himpunan record berubah setelah pratinjau, termasuk jika jumlahnya tetap sama. Penghapusan snapshot SQLite tidak menghapus salinan JSON lama atau sampel RouterOS. Sampel RouterOS mengikuti retensi hari snapshot dan batas jumlah sampel.

## Upgrade

Buat backup SQLite sebelum upgrade, lalu tutup versi lama. Arsip schema 1 tetap dapat dibaca oleh v1.2. Pembukaan pertama untuk tulis memigrasikannya ke schema 2. Setelah migrasi, aplikasi v1.1 tidak dapat membuka arsip baru. Untuk kembali ke v1.1, gunakan salinan pra-upgrade tanpa menimpa arsip schema 2. Upgrade tidak mengubah profil collector, registry jaringan, atau pengaturan router.
