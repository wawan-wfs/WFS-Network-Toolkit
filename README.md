# WeNet Toolkit — by WFS Project

![WeNet Toolkit](assets/logo.png)

**Network intelligence & management** · Windows 10/11 x64 · Native Rust/Win32

Sebelumnya bernama WFS Network Toolkit. Kandidat source masih `1.3.0-rc.1`. Rebranding tidak mengubah format arsip, identitas installer, data pengguna, mutex mutasi, CLI `wfs-netctl.exe`, atau aturan keamanan. Nama EXE GUI baru: `WeNet-Toolkit.exe`. Baca [panduan rebranding dan upgrade](docs/WENET_BRANDING.md).

## Buka aplikasi

Belum tersedia executable dari kandidat ini. Jalankan gate build Windows di bawah, atau gunakan [Actions Windows manual](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/workflows/windows.yml) dengan **Run workflow** setelah siap. Pilih commit kandidat dan unduh artifact hanya setelah run lulus. Jangan memakai paket versi lama untuk menyatakan kandidat baru lulus.

## Batch v1.4 — gate stabilisasi (source 1.3.0-rc.1)

Sembilan tes kontrak SQL offline lulus. Query SQL digunakan bersama oleh source Rust dan suite Python. Filter alert mendukung `state=open/ack/recovered/all` ditambah teks scope, identitas ACK lebih ketat, dan replay tidak mengubah record yang sudah pulih. Final sample setelah writer berhenti ditambahkan pada source; belum diverifikasi dengan Rust/Windows. Workflow hanya manual. Baca [status gate](docs/V14_GATE_STATUS.md). Fitur besar P1 menunggu kompilasi/regresi.

## Kandidat 1.3.0-rc.1 — Alert persisten

Ledger alert per profil exporter, site/VRF, IP dan domain; ACK tersimpan di SQLite lintas sesi. Arsip global tidak menuduh satu exporter. Monitor terpisah, retensi, backup, filter, dan indikator kegagalan. **Schema 4 baru**: backup sebelum upgrade; schema 3 asli belum didukung. Baca [panduan ledger](docs/ALERT_LEDGER.md) dan [laporan uji](docs/TEST_REPORT.md). Kandidat source belum lulus gate Rust/Windows; paket baru belum tersedia. Jangan gunakan link paket lama sebagai build kandidat.

## Perbaikan 1.2.1 — Mode Admin dan diagnosis arsip

- **Mode Admin tidak membuka dua jendela sekaligus.** Setelah UAC diizinkan, aplikasi biasa meminta tutup dan aplikasi dengan hak Administrator menunggu proses lama berakhir sebelum menampilkan jendela. Jika UAC dibatalkan, jendela biasa tetap terbuka. Hentikan collector dan polling terlebih dahulu agar data tidak terputus; aplikasi akan mengingatkan jika masih aktif.
- **Penyebab drop arsip terpisah.** Panel Penyimpanan arsip menampilkan antrean penuh, writer tertutup dan kegagalan SQLite. Total drop tetap tersedia untuk kompatibilitas. Statistik selama sesi, bukan bukti tidak ada drop pada socket/kernel.
- **Batas verifikasi:** Smoke test Windows dapat memvalidasi startup tetapi persetujuan/penolakan UAC secara interaktif harus diuji pada Windows fisik atau VM. Pengaturan MAC Realtek tetap memerlukan uji frame Ethernet dari peer.

## Fitur 1.2.0

- **Polling RouterOS** dapat diaktifkan dan dihentikan per target. Proses hanya membaca melalui REST HTTPS, dengan interval minimum 60 detik, satu pekerjaan polling sekaligus, dan jeda ulang otomatis saat gagal.
- **Tren interface** dan **Histori lease** dapat membuka sampel SQLite lintas restart atau dari salinan backup baca-saja. Dokumen panduan menjelaskan cara memilih target, rentang UTC, retensi, dan perbedaan data sesi dengan data arsip. [Panduan polling dan histori](docs/POLLING_ROUTEROS.md)

## Baru di 1.1.0

- **Topologi RouterOS** dan **IPAM observasi** menampilkan sumber, cakupan, waktu, relasi, dan indikasi konflik tanpa menggabungkan subnet yang tumpang tindih.
- **Histori lease sesi** dan **Tren interface** berasal dari snapshot manual. Tren menampilkan gap, P95 dan puncak RX/TX.
- **Alert collector** menampilkan template hilang, drop arsip dan jeda trafik, dengan pengakuan manual tanpa popup atau perubahan jaringan. [Panduan Topologi dan IPAM](docs/TOPOLOGI_IPAM.md)

## Baru di 1.0.0

- **Penyimpanan arsip** menampilkan ukuran SQLite/WAL, cakupan, waktu, antrean dan drop dengan pembaruan manual.
- Retensi flow dan snapshot SQLite serta batas DB dapat diatur. Kuota penuh menolak batch baru, tidak menghapus data di luar retensi.
- Backup dan pemulihan salinan baca-saja tersedia dari GUI. Hapus rentang memerlukan pratinjau dan membatalkan jika daftar record berubah. [Panduan penyimpanan dan upgrade](docs/PENYIMPANAN_ARSIP.md)

## Baru di 0.9.0

- **Detail IP** menampilkan ringkasan koneksi dan bukti WAN per scope, lalu membuka histori yang tetap terkunci pada IP, site, VRF, profil, exporter, dan domain yang dipilih. Gunakan filter port, rentang waktu UTC dan ekspor tersamarkan.
- **Histori** dan **Perubahan jaringan** dapat membaca snapshot impor SQLite serta snapshot JSON lama, tanpa menggandakan isi identik.
- **Backup SQLite** menyalin database secara konsisten melalui CLI. Arsip flow lama tidak perlu dimigrasikan.

Baca [panduan Detail IP dan upgrade](docs/DETAIL_IP.md).

## Baru di 0.8.0

- **Arsip flow SQLite** menyimpan metadata IPFIX/NetFlow v9 lintas restart. Cari pasangan IP, scope, domain, protokol, interface, atau rentang waktu. Buka detail, lanjutkan halaman, atau ekspor hasil filter ke CSV/JSON dengan penyamaran aktif secara default.
- **Flow UDP…** menerima hingga 16 profil berdasarkan pasangan IP sumber exporter dan observation domain. Setiap profil punya cakupan site/VRF, LAN, dan interface WAN sendiri. Profil lama tetap kompatibel.
- **Kesehatan sumber** memunculkan hitungan yang masuk arsip, duplikat, pemangkasan, dan drop sesi. `wfs-netctl.exe archive-import-history --confirm` menyalin histori JSON yang memenuhi batas lama ke SQLite tanpa mengubah file sumber.

Ikuti [panduan arsip](docs/ARCHIVE_SETUP.md), [penyetelan Flow](docs/FLOW_SETUP.md), dan [contoh profil multi-exporter](docs/examples/flow-collector-v2.example.json).

## Analisis Jaringan

1. Buka **Analisis Jaringan** dan gunakan **Data Windows**. Lihat alamat lokal IPv4/IPv6, cache tetangga, koneksi TCP serta port lokal TCP/UDP. Nama proses tampil jika izin Windows mencukupi.
2. Pilih **Uji HTTPS PC ini** dan setujui tujuan yang ditampilkan. Hasil positif berlaku hanya untuk IP sumber dan endpoint uji yang tercatat, bukan untuk klien lain. Kegagalan uji bukan bukti firewall memblokir.
3. Untuk MikroTik, masukkan hostname/IP yang cocok dengan sertifikat HTTPS, klik **Baca MikroTik**, lalu masukkan akun khusus baca. REST HTTPS RouterOS v7 harus sudah tersedia, dengan CA yang dipercaya Windows. Password tidak disimpan. Lihat **Kesehatan sumber** jika tabel tidak tersedia.
4. Ubah tampilan ke **Koneksi MikroTik**, **Interface MikroTik**, **Rute default MikroTik**, atau **Sistem MikroTik**. Pilih baris dan klik **Detail** untuk sumber, waktu, tuple balasan/NAT, dan batas cakupan yang berlaku. Baca router dua kali untuk estimasi bit/s bila counter serta uptime dapat dibandingkan.
5. Dari **Akses Internet**, impor bukti dari sensor yang Anda kelola bila diperlukan. Lihat [format contoh data sintetis](docs/examples/traffic-evidence.example.json). Status impor tidak dinyatakan sebagai tes langsung. Gunakan **Ekspor Akses CSV** untuk semua baris yang cocok dengan filter. Opsi samarkan aktif secara default.

Data Windows dan RouterOS adalah snapshot. Snapshot manual Windows dan RouterOS tetap ditulis ke JSON, sementara Histori juga membaca snapshot yang sudah diimpor ke SQLite. Flow UDP disimpan terpisah ke database lokal setelah collector dimulai secara eksplisit. Tidak ada pemindaian host, konfigurasi router otomatis, atau penetapan kebijakan akses firewall. Snapshot conntrack tidak menentukan bahwa IP klien punya internet. Lihat [batas versi dan status uji](docs/CAPABILITY_MATRIX.md).

## Pindahkan pengaturan ke PC baru

1. Di PC lama, pilih adaptor. Buka **Backup dan Restore** lalu klik **Simpan file JSON**. Centang **Sertakan MAC aktif** hanya bila perlu.
2. Salin file JSON ke PC baru. Putuskan PC lama dari jaringan jika alamatnya akan dipakai kembali.
3. Pilih adaptor tujuan, lalu pilih **IPv4 dan DNS**, **DNS saja**, atau **MAC saja**. Pada pilihan pertama, MAC tidak ikut kecuali Anda mencentang **Sertakan MAC dari backup**. Klik **Buka file backup** dan bandingkan kolom **Sebelum** dan **Target**. Gunakan **Lihat nilai lengkap** bila teksnya terpotong.
4. Klik **Terapkan** dan setujui permintaan Administrator jika muncul. Jika ingin membatalkan perubahan terakhir, buka **Tinjau pemulihan** untuk melihat pengaturan yang akan dikembalikan.

**IPv4 dan DNS** mengatur IP statis, DHCP, subnet, gateway, dan DNS tanpa mengubah MAC. **MAC Address** mengubah atau mengembalikan MAC bawaan pada adaptor Ethernet yang mendukungnya. **Diagnostik** menyediakan ping gateway, kalkulator subnet, dan ekspor laporan yang menyamarkan identitas jaringan secara default.

**DNS saja** mempertahankan mode IPv4, alamat, subnet, gateway, dan MAC. Pemulihan transaksi DNS saja juga tidak menulis ulang IP. Toolkit menolak IPv4 statis baru atau MAC baru yang sudah terdeteksi pada adaptor aktif lain di PC yang sama. Ini bukan pemindaian LAN dan tidak menggantikan langkah memutus PC lama.

Untuk memeriksa isi backup tanpa menerapkannya, jalankan `wfs-netctl.exe check-backup "backup.json"`. CLI melaporkan format dan apakah bagian IPv4/DNS serta MAC tersedia tanpa menampilkan nilainya.

Pengubahan MAC tergantung pada adaptor dan driver. Jangan menganggap tampilan MAC di Windows sebagai bukti alamat yang dikirim melalui Ethernet. Untuk menguji adaptor Anda, ikuti [panduan pengujian](docs/HARDWARE_ACCEPTANCE.md). Aplikasi tidak mengubah pengaturan MikroTik, IPv6, VLAN, atau 802.1X.

## Jika MAC tidak bisa diubah

1. Buka **MAC Address**, pilih Ethernet fisik, lalu gunakan **Tinjau MAC**. Untuk memulihkan dari JSON tanpa mengubah IP, pilih **MAC saja** di Backup dan Restore.
2. **Link tidak tersambung** tidak otomatis berarti perangkat dinonaktifkan. Jika driver masih berjalan dan perangkat tidak bermasalah, set MAC bisa diteruskan tanpa kabel. Sambungkan kabel setelahnya untuk menguji pengiriman frame. Jangan menghubungkan dua perangkat dengan MAC yang sama ke LAN yang sama.
3. Jika tertulis **kode 22**, aktifkan adaptor yang dipilih di **Device Manager**, lalu klik **Muat ulang**. Jika antarmuka dinonaktifkan dari Koneksi Jaringan, buka **Koneksi Jaringan** dari halaman MAC Address, aktifkan Ethernet yang dipilih, lalu klik **Muat ulang**. Toolkit tidak mengaktifkan perangkat sendiri.
4. Jika muncul pesan **MAC tidak terverifikasi**, periksa nilai target dan MAC yang dibaca Windows pada pesan tersebut. Gunakan **Ringkasan → Detail driver** untuk melihat Hardware ID, versi driver, status antarmuka, link, dan perangkat. Jika driver menolak MAC persis, Toolkit tidak menggantinya dengan MAC lain.

Nama WFS Project tercantum pada properti berkas dan daftar aplikasi terpasang. Paket ini belum ditandatangani secara digital. Untuk memeriksa berkas, bandingkan SHA-256 dengan `SHA256SUMS.txt`.

Error, peringatan sebelum perubahan jaringan, serta hasil penting (termasuk hasil set MAC, pemulihan, dan backup) tampil di pop-up. Bilah bawah hanya menampilkan status rutin. Dialog hasil operasi Administrator ditampilkan satu kali, sekalipun Windows meminta UAC.

## Build dan uji Windows

Gunakan Visual Studio Build Tools dan toolchain Windows x64 dari root source.

```powershell
rustup target add x86_64-pc-windows-msvc
cargo fmt --check
rustfmt --edition 2024 --check src/bin/native/toolkit_window.rs src/bin/native/intelligence_window.rs
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked --release --target x86_64-pc-windows-msvc
$app = Start-Process .\target\x86_64-pc-windows-msvc\release\WeNet-Toolkit.exe -ArgumentList '--smoke-ui' -Wait -PassThru
$app.ExitCode
New-Item -ItemType Directory -Force dist
makensis .\installer\WeNet-Toolkit.nsi
```

Smoke test memeriksa kontrol, navigasi halaman, footer, pilihan restore, kalkulator, pratinjau, dan inventaris tanpa mengubah jaringan. Kode keluar `0` berarti pemeriksaan lulus. Untuk cross-build, gunakan MinGW-w64 dengan target `x86_64-pc-windows-gnu` dan arahkan argumen `BIN_DIR` NSIS ke direktori build release.

## Pengembangan berikutnya

Lanjutkan dengan [Next Prompt WeNet Toolkit — gate recovery](docs/NEXT_PROMPT_WENET_GATE_RECOVERY.md).
