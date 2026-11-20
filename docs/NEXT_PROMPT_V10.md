# WFS Network Toolkit — Next Prompt v1.0

Lanjutkan dari `main` terbaru. Audit [arsitektur](ARCHITECTURE.md), [Detail IP](DETAIL_IP.md), [laporan uji](TEST_REPORT.md), [cakupan fitur](CAPABILITY_MATRIX.md), [arsip](ARCHIVE_SETUP.md), [prompt v0.9](NEXT_PROMPT_V09.md), adapter Windows, dan pipeline rilis. Catat SHA awal dan ulangi tes baseline. Pertahankan desktop Rust/Win32 tanpa WebView, bahasa Indonesia, mode terang, publisher dan footer WFS Project, serta alur IPv4/DNS/MAC. Kerjakan per batch teruji. Push fast-forward langsung ke main bila izin masih berlaku. Jangan jalankan diagnostik di jaringan produksi tanpa permintaan operator.

## Batch A — daya tahan penyimpanan

- Tambah menu penyimpanan untuk ukuran DB/WAL, rentang data, jumlah sumber, kuota aktif, retensi raw flow/snapshot/agregat, antrean, dan hitungan drop. Label hasil parsial dan waktu pengukuran.
- Jadikan retensi dan kuota konfigurabel. Uji batas minimum/maksimum, disk penuh dengan DB fixture kecil, direktori read-only, kunci lintas proses dan perawatan tanpa traffic. Jangan menghapus diam-diam karena penulisan gagal. Tidak boleh ada busy retry tanpa batas.
- Tambah impor/pulih/backup arsip lewat UI dengan verifikasi identitas, pratinjau, komit atau rollback atomik, dan uji rollback bila berkas tujuan berubah. Pulih tidak boleh menimpa DB aktif, mencampur WAL, atau menghapus arsip lama. Tambah dry-run hapus berdasarkan rentang, hitungan, dan konfirmasi.
- Tambahkan pilihan rentang lokal/UTC, filter tersimpan, batal pencarian, tes ekspor terfilter lintas revisi, serta statistik kualitas record. Jangan mengasumsikan bahwa mark arah WAN valid setelah profil berubah tanpa provenance.
- Pisahkan waktu aliran, ekspor, dan masuk collector. Jangan menebak sampling, NAT atau volume unik. Tambah uji flow start/end IPFIX/v9, opsi sampling, out-of-order, restart exporter, template lama, IPv6, dan gap akibat offload.

## Batch B — observabilitas jaringan yang bisa diverifikasi

- Susun daftar site, router, interface, VRF, bridge, VLAN dan port menggunakan data RouterOS read-only. Tambah tampilan topologi dengan sumber tiap relasi dan cap waktu. Bedakan relasi eksplisit, inferensi, dan belum diketahui. Jangan menyimpulkan sambungan hanya dari dua subnet yang tumpang tindih.
- Tambah histori inventory/IPAM berbasis sumber assignment dan interval. Dukungan dasar mencakup lease, ARP/ND, subnet, pool, alias, catatan operator, pencarian, dan konflik IP terindikasi per scope. Jangan menganggap IP yang tak teramati tersedia. Catat ketidakpastian untuk IPv6 link-local yang tidak berinterface.
- Tambahkan tabel route/VRF, bridge FDB, IPv6, queue dan VPN jika API RouterOS mendukung. HTTPS dan verifikasi TLS Windows tetap wajib. Buat pengujian fixture respons parsial dan kegagalan otorisasi. Jangan mengubah konfigurasi router atau Windows Firewall.
- Simpan histori counter per interface dengan satuan jelas, interval, reset/wrap, titik hilang, p95 dan puncak. Jangan menjumlahkan catatan flow beberapa exporter sebagai bandwidth total. Tambah event lokal untuk hilang template, backlog/drop, sumber stale, link flap, dan perpindahan WAN. Cegah popup berulang dengan debounce/ack.
- Tunda SNMPv3/syslog dan pengiriman luar sampai scope, autentikasi, serta retensi lulus pengujian lokal. Jangan menyalakan service atau port eksternal otomatis.

## Batch C — rilis dan bukti

- Perluas smoke GUI ke inventaris → Detail IP → Koneksi → Ekspor → Kembali memakai fixture dua VRF dan IPv6. Tambahkan uji keyboard dan Windows DPI 100/125/150/200, jendela sempit, status kosong, partial, busy, serta popup kegagalan.
- Uji package x64 portable dan instal/upgrade/uninstall dalam VM Windows. Pastikan rollback konfigurasi tidak berubah. Buat hasil CI yang bisa dirujuk dan checksum. Uji perangkat fisik terpisah untuk RouterOS TLS/flow, Realtek dengan kabel lepas dan pemeriksaan frame dari peer berizin. Jangan mengklaim lulus tanpa bukti.
- Jalankan beban sintetis 10 exporter, 2.000 perangkat dan 1 juta record. Catat spesifikasi, dataset, volume, lag, throughput, drop, p95 filter, RAM/disk/WAL, dan waktu stop. Jika gate tidak tercapai, laporkan angka sebenarnya dan hambatannya.
- Di akhir, dokumentasikan PASS/PARTIAL/BLOCKED/FAIL dengan perintah, hasil aktual, commit, tautan CI/artefak, panduan upgrade, daftar risiko yang relevan, dan next prompt bertarget. Jangan mengisi menu hanya dengan placeholder.
