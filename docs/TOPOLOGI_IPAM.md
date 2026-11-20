# Topologi, IPAM dan tren sesi

Buka **Analisis Jaringan**, pilih tampilan yang dibutuhkan, masukkan alamat RouterOS, lalu tekan **Baca MikroTik**. Gunakan akun baca dan HTTPS dengan sertifikat yang dipercaya Windows. Aplikasi meminta tabel menggunakan GET, tidak mengubah perangkat, dan membatasi ukuran respons serta waktu. Jika suatu tabel tidak tersedia atau belum sempat dibaca, buka **Kesehatan sumber**.

| Tampilan | Yang ditampilkan |
| --- | --- |
| **Topologi RouterOS** | Relasi bridge/port/PVID, interface VLAN, anggota VLAN aktual dan konfigurasi, entri MAC FDB, tetangga discovery, VRF, tabel routing, dan rute default. Ini tabel bukti, bukan peta fisik atau hasil scan. |
| **IPAM observasi** | Alamat dan subnet IPv4/IPv6, DHCP server, rentang pool atau prefix delegasi, lease, cache ARP/ND, serta alamat dan tetangga Windows. Filter menurut IP atau scope lalu tekan **Cari**. |
| **Histori lease sesi** | Lease yang terlihat dan MAC lease yang berubah pada server dan IP yang sama. Catatan bertanda UTC, maksimal 512 event dan 2.000 binding per router. Lease tidak terlihat tidak dianggap kedaluwarsa. |
| **Tren interface** | Sampel bit/detik dari pembacaan manual, P95 dan puncak RX/TX. **Detail** menampilkan 20 sampel terbaru. Maksimal 120 sampel per interface dan 512 interface per router. |
| **Alert collector** | Template hilang, drop arsip, dan 300 detik tanpa kenaikan jumlah datagram yang diterima. Tekan **Cari** untuk memuat ulang daftar dan **Akui** untuk menandai baris. Maksimal 64 alert per sesi collector. Tidak ada popup atau aksi jaringan. |

- **Detail** menunjukkan nama sumber dan waktu pengamatan. Pembacaan tabel dilakukan berurutan. Label *lengkap* berlaku untuk respons tersebut, bukan seluruh jaringan.
- **VRF tercantum** berarti interface disebut eksplisit pada entri VRF. Aplikasi tidak mengembangkan daftar all, daftar interface, atau pengecualian. Cakupan ambigu ditandai **tidak diketahui**. Nama routing table pada rute bukan bukti keanggotaan VRF suatu interface.
- **Konflik terindikasi** memerlukan dua MAC berbeda untuk IP yang sama pada satu interface dari lease aktif atau cache reachable dengan cakupan tabel lengkap dan selisih paling lama 60 detik. Cache stale, pool, dan subnet tumpang tindih bukan bukti konflik. IPv6 link-local tanpa interface tetap ambigu. IP yang tidak terlihat belum tentu tersedia.
- Tren tidak mengisi gap dengan nol. Counter turun, restart, perubahan tipe/status interface, sampel ganda, atau jeda lebih dari 15 menit bisa menghasilkan gap. P95 dihitung per arah dari sampel valid tanpa pembobotan durasi.
- Alert menggabungkan sinyal selama lima detik dengan jeda minimal 60 detik antar-alert per jenis. Collector sepi belum tentu putus. Tidak ada polling RouterOS otomatis. Tren dan histori lease belum disimpan lintas sesi.

Fixture offline bersifat sintetis, bukan bukti kompatibilitas perangkat nyata. Installer dan versi portable tidak memindahkan arsip SQLite atau konfigurasi dari versi sebelumnya.

Rujukan RouterOS [REST API](https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API), [Bridging and Switching](https://manual.mikrotik.com/docs/bridging-and-switching/), [IP Pools](https://help.mikrotik.com/docs/spaces/ROS/pages/129531938/IP+Pools).
