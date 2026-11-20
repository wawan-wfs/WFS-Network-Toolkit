# WFS Network Toolkit — Uji Windows dan Ethernet fisik

**Tujuan rilis:** buktikan MAC aktif berubah di Windows **dan** perangkat kedua melihat MAC baru sebagai Ethernet source. Pengujian tidak mengubah router atau jaringan produksi. Gunakan adaptor uji, Windows x64 dengan akses konsol lokal, perangkat peer yang dikelola, dan segmen Ethernet yang sama, idealnya switch uji terisolasi.

## 1. Catat kondisi awal

1. Di PC tujuan buka `winver` dan catat build Windows. Ekstrak paket dan jalankan `wfs-netctl.exe list` dari terminal pada folder tersebut, atau buka aplikasi dan pilih Ethernet fisik.
2. Catat GUID, nama, MAC aktif, MAC bawaan, Hardware ID lengkap, serta driver. Tombol **Detail driver** atau `wfs-netctl.exe inspect "{GUID}"` dapat membantu.
3. Catat IP uji dan IP perangkat peer pada subnet yang sama. Konfirmasi komunikasi lokal. Simpan backup JSON dengan **Sertakan MAC aktif** untuk catatan.
4. Di perangkat peer mulai capture pada antarmuka Ethernet. Gunakan Wireshark. Untuk ICMP, filter `icmp && ip.src == IP_PC_TUJUAN`; untuk ARP, filter `arp.src.proto_ipv4 == IP_PC_TUJUAN`. Lihat kolom atau field **Ethernet II → Source**. Picu trafik baru dengan ping peer dari PC tujuan. Jika ICMP tidak tersedia, periksa frame ARP baru dengan sender IPv4 PC tujuan. Jangan menggunakan catatan ARP lama sebagai bukti.

## 2. Jalankan dua uji yang berbeda

### A. Set MAC lokal (MAC-01)

- Pilih MAC locally administered unicast yang unik di lab. Format contoh `02-17-20-10-00-01`, jangan gunakan contoh jika sudah dipakai.
- Pilih GUID yang dicatat di halaman **MAC Address**, masukkan MAC target, klik **Tinjau MAC**, lalu konfirmasi dan setujui UAC bila diminta. Alternatif CLI elevated dari PowerShell:

```powershell
.\wfs-netctl.exe set-mac '{GUID}' '02-17-20-10-00-01' --confirm
.\wfs-netctl.exe inspect '{GUID}'
```

- Setelah link kembali, kirim trafik baru ke peer. Simpan tiga nilai, yaitu MAC yang diminta, MAC hasil baca ulang Windows, dan Ethernet source dari capture. Ketiganya harus identik untuk lulus.
- Ulangi observasi setelah reboot bila ingin mengklaim override persisten. Klik **Tinjau pemulihan** pada Backup & Restore untuk mengembalikan kondisi tepat sebelum perubahan. Uji juga **Reset ke bawaan** jika nilai permanen tersedia. Lakukan capture ulang untuk MAC yang dikembalikan.

### B. Migrasi persis (MAC-02)

- Gunakan alamat dari adaptor sumber yang Anda kelola. Lepas adaptor sumber dari jaringan lebih dulu. Catat alamat asli persis seperti yang tampil di Windows.
- Lakukan langkah A menggunakan **MAC persis** dari sumber. Uji terpisah dari MAC lokal. Jika driver menerima MAC lokal tetapi menolak MAC persis, catat migrasi sebagai **FAIL** untuk hardware/driver tersebut. Jangan mengubah bit MAC dan menganggapnya lulus.
- Verifikasi perubahan dan pemulihan di kedua perangkat. Jika driver atau izin menolak perubahan, simpan pesan aplikasi dan kondisi MAC/IP setelah gagal. Jangan mengubah ACL.

## 3. Regresi IPv4 dan alur pemulihan

- **MAC-03 / tanpa kabel:** saat Ethernet aktif di Windows, lepas kabel dari adaptor uji. Klik **Muat ulang** dan catat status link, antarmuka, dan driver. Jalankan **MAC Address → Tinjau MAC** dengan alamat lokal unik. Windows harus membaca MAC persis meskipun tidak ada link. Sambungkan kembali ke segmen uji dan verifikasi alamat frame di peer. Pulihkan konfigurasi awal.
- **MAC-04 / perangkat dinonaktifkan:** nonaktifkan adaptor uji lewat Device Manager. Adaptor boleh hilang dari inventaris IP Helper. Jika masih tampil dan dipilih, pengubahan MAC harus ditolak tanpa menulis override. Aktifkan kembali adaptor yang sama dan klik **Muat ulang**. Jangan menjalankan uji ini melalui adaptor yang dipakai untuk akses jarak jauh.

- Tanpa admin, uji **Simpan file JSON**. Periksa JSON dan pastikan backup tanpa centang tidak berisi nilai MAC.
- Dari aplikasi admin, uji **Restore IPv4/DNS saja** pada konfigurasi uji, cek IP, mask, gateway, DNS 1 dan 2, serta MAC tetap. Uji DHCP dengan DNS manual dan DNS otomatis, lalu **Tinjau pemulihan**. Status DHCP aktif berbeda dengan berhasil mendapatkan lease.
- Uji pilihan **DNS saja** dari profil yang memiliki IP dan gateway berbeda. Verifikasi bahwa hanya DNS berubah, termasuk saat mengembalikan DNS otomatis. Untuk uji rollback khusus DNS, ubah IP uji secara manual setelah restore DNS, lalu pulihkan snapshot dan pastikan IP manual tersebut tidak ditimpa.
- Uji **MAC saja** dari profil yang juga memuat IPv4. Periksa bahwa konfigurasi IPv4 dan DNS tidak berubah. Pada PC uji dengan dua adaptor aktif di segmen lab terisolasi, coba target IP atau MAC milik adaptor lain. Pratinjau harus menolak tanpa perubahan.
- Uji MAC target yang sama persis dengan yang sedang aktif dari jendela tanpa admin. Harus no-op tanpa UAC, akses override driver, atau restart. Uji pembatalan UAC.
- Untuk Windows smoke test, jalankan installer/portable, jalankan `wfs-netctl.exe list`, uji jalur buka jendela admin, serta uninstall. Installer/uninstaller tidak boleh mengubah jaringan.

## 4. Rekam hasil

Simpan bukti dengan pasangan **build Windows + hardware ID + versi driver**. Untuk setiap ID uji catat waktu, metode, hasil `PASS` / `FAIL` / `BLOCKED`, MAC sebelum/target/sesudah/pulih, dan nomor frame pada capture peer. Untuk hasil di luar lab, samarkan identitas jaringan yang tidak relevan.

**Kriteria penerimaan pengguna:** uji B lulus pada adaptor tujuan atau kombinasi hardware ID, driver, dan build Windows yang ekuivalen. CI, VM, UI, atau nilai yang tersimpan di registry tidak menggantikan bukti ini.
