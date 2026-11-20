# Polling RouterOS dan histori

Fitur berada di **Analisis Jaringan**. Siapkan REST HTTPS RouterOS v7 pada perangkat yang Anda kelola. Gunakan hostname/IP yang cocok dengan sertifikat, CA yang dipercaya Windows, dan akun khusus baca. Sertifikat yang gagal diverifikasi ditolak. Aplikasi tidak mengaktifkan REST, mengubah firewall, atau memodifikasi opsi RouterOS.

## Menjadwalkan pembacaan

1. Pilih **Polling RouterOS**, isi host, dan masukkan interval 60–3.600 detik di kolom filter. Jika kosong, interval 120 detik.
2. Klik **Mulai polling**, baca konfirmasi, lalu masukkan kredensial. Polling hanya aktif pada sesi aplikasi ini. Kata sandi tidak masuk SQLite atau ke log.
3. Lihat status per target. Buka **Kesehatan sumber** untuk rincian tabel snapshot terbaru bila tersedia. Klik **Hentikan target** dengan host yang sama untuk membatalkan jadwal. Saat panggilan WinHTTP masih berlangsung, panel menunggu batas I/O. Permintaan berikutnya dicegah, dan hasil terlambat tidak diterapkan ke tampilan. Sampel yang telah selesai disimpan tidak dihapus saat Stop.

Maksimal delapan target dengan satu pekerjaan polling pada satu waktu dan jeda minimum 15 detik sesudah pekerjaan sebelumnya selesai. Interval dihitung dari penyelesaian pekerjaan, bukan jadwal wall clock. Coba ulang kegagalan sementara dengan backoff dan batas maksimum satu jam. Galat autentikasi, TLS, atau HTTP 403/404 tanpa tabel berhasil menjeda target sampai diatur ulang. Jika beberapa tabel berhasil, cakupan ditandai parsial. Error sambungan dan pembacaan latar tampil pada status target, tanpa popup berulang.

## Membuka dan menyimpan sampel

1. Pilih **Tren interface** atau **Histori lease sesi** dan isi host dalam bentuk yang sama seperti saat melakukan pembacaan.
2. Setelah baca manual, klik **Sampel** untuk menyimpan observasi terakhir. Polling yang diaktifkan menyimpan sampel secara otomatis apabila arsip dapat ditulis. Jika penyimpanan gagal, detail polling menampilkan peringatan.
3. Klik **Arsip UTC**. Kosongkan kolom filter untuk memakai rentang retensi aktif, atau isi dua detik Unix UTC inklusif dengan satu spasi di antara keduanya. Contoh `1794700800 1794787199`. **Reset** kembali ke data sesi.
4. Untuk melihat sampel dari backup, buka salinannya melalui **Penyimpanan arsip → Pulihkan salinan…**, lalu buka **Arsip UTC** pada mode tren atau lease. Salinan tetap baca-saja. Polling yang masih berjalan tetap menulis ke arsip utama.

Arsip memakai waktu selesai pengambilan untuk seleksi rentang. Detail menampilkan waktu tabel dibaca dan selesai pengambilan, keduanya berdasarkan jam PC pengamat. Waktu tersebut bukan timestamp intrinsik perangkat. Tren menghitung estimasi bit/s dari dua counter yang dapat dibandingkan. Snapshot pertama, counter turun, reset uptime, dan identitas yang berubah tidak otomatis berarti nol. Lease hanya menunjukkan bukti binding DHCPv4 yang terlihat, bukan kapan lease dimulai, berakhir, atau kapan perangkat online.

Retensi mengikuti **hari snapshot SQLite**. Batas tambahan 120 sampel terbaru per router, 32 router, 512 interface, 2.000 binding dan 1 MiB per sampel. Arsip tidak menyimpan payload REST, credential atau hostname klien, tetapi mengandung metadata jaringan yang dapat mengidentifikasi perangkat. Backup harus disimpan secara privat.

Lihat [cara upgrade dan rollback arsip](PENYIMPANAN_ARSIP.md).
