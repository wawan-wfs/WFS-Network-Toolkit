# WFS Network Toolkit — Lanjutan setelah hotfix v1.2.1

Gunakan repo resmi pengganti `https://github.com/wawan-wfs/WFS-Network-Toolkit`, bukan repo lama `wawanwfs` yang tidak dapat diakses. HEAD harus diverifikasi sebelum pengembangan. Jangan force-push, jangan aktifkan workflow `push`/`pull_request` yang memicu Actions otomatis; gunakan `workflow_dispatch` untuk verifikasi yang memang diperlukan.

## Prioritas tertinggi

1. **Pulihkan kesetaraan fungsional v1.3** dari source asli bila arsip terverifikasi tersedia. Repo pengganti baru dipastikan memuat v1.2.0 sebelum hotfix 1.2.1. Jangan mengklaim v1.3 sudah lengkap. Audit `ADMIN_DAN_ALERT.md`, migrasi SQLite schema 3, alert exporter persisten, dan tes benchmark.
2. **Gate Mode Admin**: uji UAC diterima/ditolak, jendela lama tutup lebih dahulu, tidak ada jendela ganda, collector/polling aktif tertolak, startup pada pemakai biasa vs Administrator, hilangnya proses induk lebih dini, waktu tunggu 20s, dan error penutupan. Rekam screenshot atau proses PID serta exit-code. Tampilkan pop-up sekali untuk kegagalan.
3. **Alert per exporter persisten**: identitas site, VRF, profil, IP exporter, domain, generasi sesi. State open→ack→recovered, dedupe/cooldown, retensi dan replay lintas restart. Bedakan template hilang, sequence gap, silent exporter, queue full, writer closed dan SQLite error. Jangan menyimpulkan router mati hanya dari tidak adanya datagram.
4. **Flow quality dan kernel drops**: pengukuran socket receive buffer/kernel bila API mendukung, label unavailable bila tidak, sampling, flow start/end dan source clock, replay dan fragment malformed. Lakukan benchmark minimal 10 exporter×2.000 perangkat×1 juta record dan laporkan receive/commit/drop/p95/RAM/disk/durasi stop.
5. **IPAM/topologi lanjutan**: tag/alias offline scoped, DHCPv6 bila RouterOS mendukung, pemisahan NDP/SLAAC, graf edge dengan bukti FDB/LLDP/MNDP/VLAN dan timestamp. Jangan inferensikan link fisik hanya dari subnet bersama.
6. **Packaging & Uji hardware**: paket Win x64 installer+portable, checksum SHA-256, upgrade/uninstall VM, DPI 100/125/150/200, Windows 10/11, RouterOS lab HTTPS read-only, dan MAC Realtek dibuktikan dari frame Ethernet di peer dengan rollback. Jangan menjalankan uji perubahan jaringan produksi.

## Persyaratan setiap batch

- Native Win32 tanpa WebView, Light Mode Indonesia, footer © WFS Project kecil, error/penting popup, dan tidak ada teks teknis di GUI.
- Pertahankan backup/restore IPv4/subnet/gateway/DNS/MAC, no-op MAC dan snapshot pemulihan.
- `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`, `cargo build --locked --release` serta `--smoke-ui` di Windows.
- Uji UAC hanya bila ada VM/hardware interaktif. Jangan samakan smoke runner dengan bukti UAC.
- Laporkan PASS/PARTIAL/BLOCKED/FAIL, head SHA, test/log, artefak dan risiko. Push fast-forward saja ke main bila diizinkan. Jaga Actions tidak berjalan setiap push.
