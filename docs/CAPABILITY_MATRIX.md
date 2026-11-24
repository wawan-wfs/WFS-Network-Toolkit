# Capability Matrix — 1.3.0-rc.1 (kandidat source)

| Area | Status | Batas bukti |
| --- | --- | --- |
| IPFIX/NetFlow v9 IPv4/IPv6 | Lulus tes parser dan penerimaan UDP loopback | Hingga 16 profil per listener. Isolasi domain, restart, dan replay diuji. Options/sampling belum dikoreksi. Belum diuji langsung dengan MikroTik. |
| Akses internet berdasarkan flow | Lulus tes observasi satu arah, pasangan balik, dan pemisahan domain | IP WAN dan jaringan LAN ditentukan lewat profil scope/ifIndex. Bukan akses universal atau evaluasi kebijakan. |
| Histori dan diff | Lulus tes reopen, retensi, dan snapshot parsial | Flow persisten di SQLite dengan filter dan ekspor. GUI menggabungkan snapshot JSON dan impor SQLite yang memenuhi batas histori. CLI menyediakan backup konsisten dengan verifikasi. |
| Detail IP → Koneksi → Ekspor | Lulus fixture host dengan IP tumpang tindih, VRF tidak diketahui, beda sesi exporter, IPv6, port dan ekspor tersamarkan | Ringkasan maksimal 2.000 baris dan 128 scope. Tidak mengklaim keputusan firewall atau menggabungkan bukti HTTPS lokal ke scope router. |
| Bridge/VLAN/filter/NAT | Lulus tes parser dan pembatasan field | Hanya inventaris konfigurasi REST HTTPS IPv4 untuk filter/NAT. Tidak menyimulasikan kebijakan. |
| Windows x64 | Lulus cross-build portable dan installer | Lihat Actions untuk smoke test Windows CI. Windows 10/11 fisik dan router produksi bukan bagian dari uji otomatis. |
| Realtek dan RouterOS live | Belum diuji fisik | Memerlukan Windows, NIC dan perangkat peer terotorisasi untuk MAC, serta router lab untuk REST/Flow. |
| Penyimpanan arsip | Retensi, kuota, diagnosis, backup, impor, pulihkan salinan, pratinjau hapus | GUI native. Tidak memulihkan dengan menimpa DB aktif. Tidak menghapus arsip JSON ketika menghapus snapshot SQLite. |
| Topologi RouterOS dan IPAM observasi | Lulus fixture offline | Tabel relasi, tidak ada graf fisik. Tidak mengalokasikan IP. |
| Polling RouterOS | Scheduler diuji dengan waktu sintetis | HTTPS GET, per target, satu pekerjaan aktif. Berhenti di antartahap I/O. Perangkat RouterOS fisik belum diuji. |
| Tren interface dan histori lease | Fixture SQLite menguji migrasi, retensi, reopen dan backup | DHCPv4 dan counter interface. Rentang detik UTC. Tidak memprediksi riwayat sebelum observasi atau masa lease. |
| Alert collector | PARTIAL — kontrak SQL lulus; Rust belum diuji | Scoped ledger dan ack persisten, global writer errors; sequence gap/generasi exporter belum tersedia. |
| Fitur lanjutan | Belum ada | Alias/catatan IPAM, histori waktu lokal, DHCPv6 binding, alert per exporter, SNMPv3/syslog, agen opt-in dan agregat persisten. |

Baseline 0.6.0 ZIP SHA-256 `46d44bf76d64285e3a24abf09b2362e991b1d9cf517728e2f55d9a8b1afb9869`.
