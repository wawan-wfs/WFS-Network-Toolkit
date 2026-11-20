# WFS Network Toolkit — Next Prompt v1.2

Mulai dari HEAD main terbaru. Baca [Topologi dan IPAM](TOPOLOGI_IPAM.md), [laporan uji](TEST_REPORT.md), [penyimpanan arsip](PENYIMPANAN_ARSIP.md) dan [prompt sebelumnya](NEXT_PROMPT_V11.md). Pertahankan mode terang native, TLS yang terverifikasi, penyamaran ekspor, serta operasi IP/DNS/MAC yang sudah ada. Gunakan fixture atau perangkat lab berizin. Jangan mengubah konfigurasi RouterOS, firewall, atau adaptor untuk pengujian. Push fast-forward sesuai izin dan pantau hingga CI selesai.

## Batch A — jadwal dan histori

- Tambah polling RouterOS read-only yang diaktifkan manual per router dengan interval minimum, anggaran global, pembatalan, timeout, backoff dan batas konkurensi. Hindari credential dalam log atau SQLite. Bedakan kegagalan autentikasi, TLS, timeout, HTTP 403/404, data parsial dan perubahan konfigurasi.
- Simpan tren interface dan lease bertanggal dengan retensi, migrasi, backup, dan pemulihan yang diuji. Simpan waktu sumber dan terima, tandai gap dan perubahan identitas router, jangan menebak masa lease. Tambah alias/catatan lokal scoped, serta filter waktu lokal/UTC.
- Alert per exporter, peristiwa pulih, persistensi ack dan batas deduplikasi. Jangan menilai exporter putus hanya karena tidak ada flow, dan jangan memicu aksi jaringan.

## Batch B — cakupan topologi, IPAM dan flow

- Visualisasikan relasi bridge, FDB, VLAN, L3 dan tetangga per scope tanpa merangkai link fisik yang belum terbukti. Tangani prioritas VRF dan interface list berdasarkan data lengkap.
- Tambah statistik subnet, DHCPv6 binding bila didukung, inventaris berkala, dan pengelolaan label offline. Jangan menyatakan IP tidak terlihat tersedia.
- Simpan metode dan timestamp start/end flow, sampling serta provenance perangkat. Tambah uji reorder, restart, template expiry, counter dan IPv6. Jangan mengasumsikan volume unik atau NAT. Tambah filter tersimpan, pembatalan query dan ekspor, dan verifikasi isolasi lintas VRF.

## Batch C — rilis

- Ulangi benchmark SQLite langsung dan loopback 10 exporter × 2.000 IP. Tambah lag berdasarkan waktu receive/commit, drop kernel vs penolakan writer, P95, RAM/disk/WAL, dan shutdown Windows/Linux. Laporkan hasil parsial sebagai parsial.
- Tambah uji installer upgrade/uninstall di VM, GUI pada beberapa DPI, dan verifikasi RouterOS TLS dan Realtek fisik hanya di lab berizin.
- Laporkan PASS/PARTIAL/BLOCKED/FAIL, commit, hasil CI Windows, paket dan checksum, instruksi upgrade, dan next prompt.
