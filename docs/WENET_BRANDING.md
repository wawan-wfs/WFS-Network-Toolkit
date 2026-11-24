# WeNet Toolkit — by WFS Project

Nama produk dipilih agar singkat dan dapat menaungi pengelolaan jaringan, monitoring, dan analisis. Tidak ada klaim pemeriksaan merek dagang. Repo tetap wawan-wfs/WFS-Network-Toolkit agar riwayat dan URL pengguna tidak putus.

## Identitas visual
- Nama tampilan WeNet Toolkit; tagline Network intelligence; kredit kecil by WFS Project.
- Logo W dengan node/topologi: navy #102C46, mint #47D6C6, pearl #E9F8FA. Aksen tombol teal gelap #00676B, rail #F1F6F9, latar putih. File SVG, PNG 256, ICO 16–256. Sumber UI Win32, bukan mockup atau WebView.
- File EXE GUI WeNet-Toolkit.exe; CLI wfs-netctl.exe (tetap); installer WeNet-Toolkit-<version>-x64-Setup.exe; artifact wenet-toolkit-windows-x64. Credit/publisher WFS Project.

## Upgrade aman
1. Backup SQLite menggunakan fitur backup dan salin profil/riwayat. Tutup collector, polling, aplikasi dan helper lama sebelum upgrade. Jangan jalankan dua versi sekaligus.
2. Versi baru tetap memakai folder data %LOCALAPPDATA%\WFS Network Toolkit dan folder instalasi default lama agar upgrade dapat menemukan data dan registry yang sama. Tidak ada rename atau pemindahan data otomatis. Identitas Windows class, application_id SQLite, schema 4, mutex Global, format backup dan crate internal tetap.
3. Installer memakai uninstall key WFSNetworkToolkit dan registry Software\WFS\NetworkToolkit\Installer. Shortcut baru WFS Project → WeNet Toolkit. Shortcut legacy dihapus setelah salin file baru; EXE legacy dicoba hapus, jika terkunci pengguna diberi pesan. Uninstall tidak menghapus profil, arsip, konfigurasi adaptor atau jurnal pemulihan. Upgrade/uninstall nyata belum diuji.
4. Untuk portable, simpan EXE lama terpisah sebagai rollback, tutup dahulu sebelum menjalankan WeNet. Schema 3 lama tetap ditolak, jangan menimpa arsip schema 4 dengan versi yang lebih tua.

## Acceptance
Nama dan ikon pada taskbar, title, properti EXE, shortcut, Apps & Features, dialog UAC, installer, uninstall, smoke UI serta layout DPI 100/125/150/200 perlu diuji di Windows. Gate Rust tetap wajib. Tidak ada paket Windows kandidat sampai build lulus.
