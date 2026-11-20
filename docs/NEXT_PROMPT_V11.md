# WFS Network Toolkit — Next Prompt v1.1

Lanjutkan dari HEAD `main` terbaru. Baca [Penyimpanan arsip](PENYIMPANAN_ARSIP.md), [Detail IP](DETAIL_IP.md), [laporan uji](TEST_REPORT.md), [matriks fitur](CAPABILITY_MATRIX.md), dan [prompt v1.0](NEXT_PROMPT_V10.md). Pertahankan aplikasi native Win32 tanpa WebView, mode terang, bahasa Indonesia, branding WFS Project, dan fitur pengaturan jaringan yang sudah ada. Ulangi baseline, kerjakan per batch teruji, push fast-forward sesuai izin, dan tunggu hasil CI.

## Batch pertama — topologi dan IPAM berbasis bukti

- Gunakan fixture RouterOS read-only untuk route/VRF, bridge FDB, VLAN/PVID, neighbor, DHCP lease dan ND. Setiap node/relasi memiliki scope, sumber, waktu, label eksplisit atau inferensi, dan keterangan jika sumber tidak mendukung. Jangan menyamakan subnet yang tumpang tindih dengan relasi fisik.
- Tambah inventaris scoped IPv4/IPv6, subnet/pool, alias/catatan, lease history bertanggal, dan indikator konflik yang menyebut bukti. Bedakan cache, lease dan alamat lokal. IPv6 link-local tanpa interface tetap ambigu. Jangan menyatakan alamat kosong tersedia.
- Tambah timeline counter interface dengan reset/wrap, data hilang, p95 dan puncak. Monitoring lokal untuk template hilang, scope stale dan drop dengan debounce dan status ack. Jadwal read-only opt-in, timeout dan batas antrean eksplisit. Tidak mengubah firewall, router, atau adaptor.

## Lanjutkan gate arsip yang belum tuntas

- Tambah input waktu lokal/UTC terstruktur, filter tersimpan, pembatalan query/ekspor, ukuran antrean stabil, peningkatan performa query, dan retensi agregat hanya setelah agregat persisten benar-benar tersedia. Catat provenance arah saat konfigurasi exporter berubah.
- Simpan waktu start/end flow bila tersedia dari versi/template yang didukung. Uji reorder, restart exporter, template expiry, sampling valid dan invalid, jumbo counter, serta IPv6. Jangan mengasumsikan NAT, sampling, atau volume unik dari sensor yang tumpang tindih.
- Uji pemulihan dan backup di Windows 10/11, izin direktori, sidecar bentrok, dan disk penuh nyata pada volume uji kecil. Jangan menimpa arsip yang aktif. Uji install/upgrade/uninstall di VM, dan tampilan DPI 100/125/150/200 persen. Tambah fixture ekspor Win32 dengan dua VRF dan IPv6. Uji adaptor fisik Realtek dan RouterOS secara terpisah pada perangkat berizin.
- Pertahankan benchmark SQLite langsung yang sudah lulus untuk 1 juta record. Tambah benchmark end-to-end UDP 10 exporter dan 2.000 perangkat. Laporkan jumlah yang diterima, tersimpan, atau drop, p95, throughput, disk/WAL, RAM, dan waktu stop. Jangan menandai pengujian fisik lulus jika hanya menggunakan simulator.

Laporkan PASS, PARTIAL, BLOCKED dan FAIL dengan perintah, angka, cakupan sebenarnya, link commit/CI dan paket Windows. Perbarui README, changelog, instruksi upgrade, matriks, dan next prompt.
