# Catatan rilis WFS Network Toolkit

## Batch v1.4 — stabilisasi kandidat (belum build)

- Query alert berbagi berkas SQL dengan suite offline; filter state exact, perlindungan identitas/replay/ACK, retensi, cap, lock dan backup.
- Pending writer mencakup transaksi aktif. Collector memisahkan stop receiver dan stop monitor agar final sample mengikuti drain writer. Observasi pendek saat penutupan normal tetap dicoba simpan.
- Mode alert otomatis membaca arsip saat dipilih. Handoff Administrator memakai konstanta pesan dan guard jika sudah elevated.
- Workflow hanya workflow_dispatch. Sembilan tes Python SQLite lulus; gate Rust/Windows belum dijalankan. Versi Cargo tidak dinaikkan.

## 1.3.0-rc.1 — kandidat pemulihan (belum build)

- Rekonstruksi ledger alert per profil/site/VRF/IP/domain, penyimpanan schema 4 dan pengakuan persisten; schema 3 lama belum didukung.
- Monitor terpisah, debounce, retensi dan pembatasan histori, status pemulihan berbasis observasi, pembacaan backup dan filter.
- Antrean writer dibatasi 256 batch (belum benchmark). Handoff Admin menutup lewat loop pesan; metadata EXE diselaraskan.
- Tes kontrak SQL offline dan kasus unit Rust ditambahkan. Gate Rust/Windows belum dijalankan. CI tetap manual.

## 1.2.1

- Mode Admin: child menunggu PID jendela lama selesai setelah UAC berhasil, sehingga tidak membuka dua GUI bersamaan; UAC ditolak mempertahankan sesi biasa.
- Pengaman perpindahan Mode Admin saat collector UDP atau polling RouterOS aktif, agar tidak memotong sesi/kesempatan flush.
- Diagnostik penyebab kehilangan record: antrean writer penuh, channel writer terputus, dan kesalahan tulis SQLite dibedakan, dengan regresi perhitungan agregat.
- Workflow GitHub tetap **manual** (tanpa push-trigger) pada repo pengganti.

## 1.2.0

- Polling RouterOS HTTPS GET opt-in per target, batas konkurensi dan interval, penghentian, jeda ulang, serta status hasil.
- Histori SQLite schema 2 untuk tren interface dan pengamatan lease DHCPv4, dengan arsip per router, filter UTC, retensi, backup, dan pembukaan salinan baca-saja.
- Detail tren memisahkan waktu pembacaan tabel dan waktu selesai pengambilan. Reset counter, ganti identitas, dan data yang tidak dapat dibandingkan tidak ditampilkan sebagai nol.

## 1.1.0

- Topologi RouterOS read-only dan IPAM observasi IPv4/IPv6, dengan sumber, waktu, serta pemisahan bukti dan indikasi.
- Histori lease sesi, tren interface RX/TX, dan alert lokal collector dengan debounce, cooldown, serta ack.
- Fixture RouterOS, smoke GUI dan benchmark UDP loopback.

## 1.0.0

- Panel Penyimpanan arsip dengan ukuran DB/WAL, pengaturan retensi flow dan snapshot, serta kuota DB utama.
- Backup konsisten, pemulihan sebagai salinan baca-saja dan impor snapshot JSON dari GUI.
- Pratinjau hapus per jenis dan rentang UTC. Transaksi dibatalkan jika record berubah sebelum konfirmasi.

## 0.9.0

- Detail IP, observasi WAN per scope, lima mitra teratas, dan pivot histori koneksi dengan scope yang tetap terkunci hingga ekspor.
- Filter port, profil, serta scope tanpa label VRF. Bukti Windows terpisah dari metadata exporter.
- Gabung histori JSON/SQLite, backup SQLite konsisten, verifikasi backup, dan perawatan flow saat collector idle.

## 0.8.0

- Multi-exporter schema 2 hingga 16 profil serta kompatibilitas profil schema 1.
- Arsip SQLite WAL, batas penyimpanan, retensi flow 30 hari, dedup rekaman, pencarian dan ekspor CSV/JSON.
- Impor histori JSON lokal idempoten via CLI.
- Paket portable dan pemasang Windows x64 dengan SHA-256.

## 0.7.0

- Collector IPFIX/NetFlow v9 UDP dengan konfigurasi eksplisit, periksa exporter/domain, statistik decoder, dan pasangan trafik WAN berbasis ifIndex.
- Tampilan Flow, mitra trafik, status collector, histori ringkas, serta perbandingan perubahan per sumber.
- MikroTik read-only menambah bridge port/PVID, interface VLAN, firewall filter IPv4, dan NAT IPv4.
- CLI histori dan konfigurasi contoh dengan alamat dokumentasi.

## 0.6.0

- Halaman Analisis Jaringan untuk inventaris IPv4/IPv6, cache tetangga, soket Windows, layanan lokal, dan penilaian akses internet per IP berbasis bukti.
- Snapshot MikroTik read-only melalui REST HTTPS dengan tampilan sistem, DHCP, ARP/ND, rute default, interface, dan tuple conntrack/NAT IPv4. Penanda sumber parsial dan tidak tersedia.
- Probe HTTPS manual dari PC operator, filter data, impor bukti JSON, ekspor CSV dengan samaran opsional, dan perkiraan bit/s dari dua pembacaan interface.
- Fungsi lama, Light Mode, footer, pop-up dan jalur recovery tetap dipertahankan.

## 0.5.2

- Error, peringatan, detail driver, dan konfirmasi hasil penting tampil di dialog Windows, bukan di bilah bawah.
- Status rutin seperti memuat adaptor dan ping selesai tetap di bilah bawah. Peringatan pratinjau disatukan dalam satu dialog, sementara tabel perubahan tetap dapat ditinjau sebelum menerapkan.
- Hasil operasi Administrator hanya ditampilkan sekali, baik saat aplikasi sudah berjalan sebagai admin maupun saat memerlukan UAC.

## 0.5.1

- Perubahan MAC memeriksa status link, antarmuka, dan driver secara terpisah. Ethernet yang tidak tersambung dapat meneruskan perubahan MAC jika driver berjalan dan tidak bermasalah.
- Verifikasi MAC membaca alamat aktif persis, memeriksa kembali driver setelah restart, dan hanya menunggu link bila link semula aktif. Jika tidak cocok, Toolkit tidak mengganti MAC dengan nilai alternatif.
- Halaman MAC Address menampilkan status link dan menyediakan pintasan ke Koneksi Jaringan Windows. Detail driver membedakan perangkat yang tidak dimulai dan perangkat yang melaporkan kode masalah.
- Memperbaiki penerusan perubahan pilihan restore ke kontrol terkait dan menggambar ulang footer serta kontrol setelah perubahan ukuran jendela.

## 0.5.0

- Header aplikasi menampilkan nama produk. Atribusi © WFS Project berada di footer kiri bersama versi, dengan ukuran teks lebih kecil. WFS Project tetap tercatat di metadata EXE dan installer.
- Restore kini memiliki pilihan IPv4 dan DNS, DNS saja, atau MAC saja. Opsi menyertakan MAC dalam restore gabungan tetap tidak aktif secara default. Jika bagian yang diminta tidak ada, aplikasi tidak menggantinya dengan operasi lain.
- Restore dan pemulihan DNS saja memakai operasi DNS khusus. IP, subnet, gateway, mode DHCP, dan MAC tidak ditulis oleh operasi DNS saja.
- Pratinjau dan tahap penerapan menolak IPv4 statis baru atau MAC baru yang sudah dipakai adaptor aktif lain pada PC yang sama. Fitur ini tidak memindai perangkat lain di LAN.
- Profil backup kosong, nama sumber yang tidak valid, dan field JSON duplikat ditolak. Perintah `check-backup` memeriksa backup tanpa mengubah adaptor.
- Snapshot pemulihan divalidasi sebelum pemulihan. Snapshot dari versi sebelumnya tetap bisa dibaca.
