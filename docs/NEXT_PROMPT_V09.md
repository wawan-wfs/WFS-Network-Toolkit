# WFS Network Toolkit — Next Prompt v0.9, operasi multi-site

Lanjutkan implementasi pada `main` terbaru dari https://github.com/wawanwfs/WFS-Network-Toolkit. Baca [master prompt](NEXT_MASTER_PROMPT.md), [panduan arsip](ARCHIVE_SETUP.md), laporan uji, matriks kemampuan, installer, dan workflow. Catat SHA awal, uji baseline, dan buat batch yang dapat dioperasikan, bukan sekadar mockup. Jika perlu beberapa batch, prioritaskan urutan P0 → P1 → P2, dokumentasikan bukti tiap batch.

## Batas produk yang tidak berubah

- Aplikasi desktop Windows 10/11 x64 dalam Rust/Win32, tanpa WebView, tanpa server frontend. Light Mode modern, tampilan Indonesia, ringkas tanpa label teknologi di UI. Ikon harus ada pada EXE, jendela, Start Menu dan pemasang. WFS Project sebagai publisher dan footer kecil © WFS Project.
- Status rutin hanya di bilah status. Error, kehilangan data, konfirmasi mutasi, dan hasil penting muncul dalam pop-up berjudul jelas, sekali per tindakan, dengan rincian yang dapat disalin. Jangan otomatis membuka pop-up berulang dari polling latar belakang.
- Menu yang sudah tersedia dan transaksi IPv4/DNS/MAC tidak boleh rusak. Jangan menulis router, melewati hak akses, atau mengubah jaringan produksi untuk pengujian. Integrasi diberi scope operator, read-only sebagai default, dan tidak meluncurkan scan atau perubahan otomatis.
- Sebut **terverifikasi**, **teramati**, **diinferensikan**, **lama**, **belum diketahui**, atau **parsial** secara konsisten. Tunjukkan sumber, waktu, IP family, site, VRF, interface dan kekurangan cakupan. Jangan menyamakan lalu lintas teramati dengan izin internet universal.

## P0 — selesaikan penyimpanan dan kerjakan alur inti

1. Tambahkan pilihan retensi dan kuota untuk raw flow, agregat dan snapshot. Tampilkan jumlah/mutu data, rentang waktu, perincian main DB/WAL, antrean dan penolakan. Pilih kebijakan database penuh yang bisa diuji, termasuk telemetri drop dan tombol pemulihan. Maintenance berjalan terjadwal, berhenti ketika operator menutup aplikasi, dan tidak freeze UI. Uji writer/reader bersamaan, disk penuh, file terkunci/read-only, Windows restart dan migrasi gagal. Tambah backup/restore SQLite konsisten, dry-run hapus dan konfirmasi. Hubungkan snapshot SQLite ke Histori/Perubahan jaringan, bukan hanya daftar CLI. Pertahankan file lama dan fixture offline.
2. Buat view **Perangkat → Detail IP → Akses → Koneksi**. Rekam provenance dan interval penugasan alamat, dukung identitas scoped IPv4/IPv6 dengan subnet tumpang tindih. Pivot ke histori pasangan sumber/tujuan, port, protokol, interface, domain, NAT asal/balasan yang memang terlihat, byte/paket terlapor dan waktu. Fitur favorit filter, kembali ke halaman sebelumnya, pencarian yang dapat dibatalkan, pilihan rentang lokal/UTC, filter port/interface, dan ekspor konsisten. Tambahkan top peers dan layanan *teramati* vs alias dugaan, tanpa menebak aplikasi dari port saja.
3. Benahi kualitas flow. Tambahkan start/end dan bentuk waktu masing-masing protokol, sampling tervalidasi, kind counter, status restart/reorder dan umur template. Dukung NetFlow v9 + IPFIX IPv4/IPv6 dengan pengujian per profile/domain/session; tolak versi/record rusak yang tidak dapat ditafsirkan. Jangan mengalikan byte tanpa sampling sah. NAT dan mirror membuat agregat per exporter tidak aditif secara default.
4. Buat panel **Akses Internet** per IP/site/VRF/time range dengan lapisan bukti terpisah. Uji HTTPS dari IP sumber yang benar aktif hanya bila diminta operator. Flow dua arah hanya untuk pasangan tuple/alur interface/window yang valid. DNS-only, rute default, paket satu arah dan timeout tidak dianggap berhasil atau diblokir. Tampilkan usia bukti, captive portal, mismatch alamat sumber, NAT ambigu, jalur asimetris, FastTrack dan hardware offload. Pertimbangkan agent opt-in terautentikasi setelah jaringan lokal lulus, bukan sebagai syarat fitur dasar.

## P1 — topologi, MikroTik, inventaris, dan perubahan

| Modul | Kerjakan dan buktikan |
| --- | --- |
| Perangkat dan IPAM | DHCP lease, neighbor, MAC/hostname, alias aset, subnet/pool/gateway/reservasi, pemecahan konflik ambigu, histori perpindahan port/alamat, overlap VRF, CSV preview/dedup. Alamat tidak terlihat bukan berarti bebas. |
| Topologi native | Hubungan dari LLDP/MNDP, FDB, bridge, VLAN/PVID, route dan neighbor yang dikelola. Edge memiliki tipe dilaporkan/inferensi/manual, sumber dan waktu. Tampilkan site, router, switch, AP, VLAN dan VPN tanpa mengisi edge yang tidak diketahui. |
| MikroTik | HTTPS RouterOS read-only per router dengan bounded GET, timeout, TLS Windows, tidak ada redirect lintas host atau fallback HTTP. Tambah routing table/VRF, DHCP, FDB, lease IPv6, queue, PPPoE/VPN dan interface lists sepanjang sumber menyediakan. Credential Manager opt-in, uji 401/403/redaksi dan versi/kemampuan router. |
| Firewall/NAT | Inventaris chain/rule/order, perubahan konfigurasi terpisah dari counter, tuple NAT hanya bila sumber memberi pasangan. Ambiguitas routing, mangle, waktu dinamis, offload dan data parsial harus terlihat. Tidak ada auto-block. |
| Bandwidth | Tren RX/TX, rate, utilisasi, p95, peak, counter reset/wrap, missing point, lag, sumber sampling dan perubahan WAN. Ukur flow vs counter sebagai seri berbeda. |
| Diagnostik terarah | Viewer route/neighbor, DNS A/AAAA/PTR berizin, TLS/HTTPS, reachability TCP ke satu target eksplisit, ping gateway/counter jaringan lokal, tes bersumber dari adaptor dipilih bila dapat dibuktikan. Tidak ada pengujian terhadap target yang tidak dipilih operator. |

## P2 — kesiapan operasional

- Event engine lintas restart untuk stale source, hilang template, queue drop, link flap, WAN failover, antrean bandwidth, konflik IP terindikasi dan diff kebijakan. Terapkan debounce, cooldown, dedup, ack/silence dan drill-down bukti. Scheduler bounded dan cancellable, default mati untuk semua sumber baru. Tambah kesehatan per collector dan opsi notifikasi lokal dahulu.
- Tambah SNMPv3 authPriv dan syslog dari perangkat terdaftar hanya setelah topologi dan histori bekerja. Manajemen secret via Credential Manager, schema ketat, parsers bounded. Jangan membuka firewall atau layanan router otomatis. Integrasi eksternal tidak mengirim data sebelum operator memilih tujuan dan scope.
- UX Light Mode yang bersih dengan satu tindakan utama setiap layar, tabel native dengan navigasi keyboard, filter terstruktur, empty/error/loading states, layout sempit dan DPI 100/125/150/200%. Buat screenshot Windows nyata untuk Ringkasan, Detail IP, Koneksi, Akses, MikroTik, dan satu pop-up kegagalan. Foto mockup tidak dianggap screenshot.
- Uji 10 exporter, 2.000 perangkat dan 1 juta record sintetis. Catat RAM, disk/WAL, throughput, lag, p95 waktu filter, drop count, dan stop time. Ulangi negatif untuk penolakan IP/domain, fixture cache isolation, filter injection, crash recovery, dan redaksi ekspor.
- Gate Windows: fmt, Clippy, tests, build x64, smoke UI termasuk filter arsip dan popup, artefak portable + NSIS dengan checksum, instal/upgrade/uninstall, dan tanpa WebView2. Pisahkan Windows CI, Windows fisik dan RouterOS fisik. Verifikasi MAC persis pada Ethernet fisik berizin dengan MAC yang terlihat dari peer, rollback, kasus kabel lepas, dan driver yang menolak override. Jangan klaim dukungan semua driver atau signing yang belum dilakukan.

## Output wajib

Usahakan menyelesaikan alur **pilih perangkat → lihat cakupan → bukti internet → koneksi historis → laporan** dalam batch pertama. Tambah fitur P1/P2 berdasarkan data nyata, bukan placeholder. Buat laporan PASS/PARTIAL/BLOCKED/FAIL dengan perintah, hasil, log CI, checksum, risiko, dan sisa pekerjaan. Perbarui README, arsitektur, matriks kemampuan, changelog, petunjuk upgrade dan NEXT_PROMPT bertarget. Push fast-forward langsung ke `main` sesuai otorisasi bila proteksi mengizinkan. Jangan force-push atau mentransfer credential. Jika main terkunci, laporkan status jalur alternatif.
