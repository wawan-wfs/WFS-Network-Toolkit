# Architecture — Network Intelligence 0.7.0

The 0.5.2 adapter configuration and recovery path is retained. Network Intelligence is a separate, manually refreshed read-only path. It never invokes the configuration helper or needs administrator elevation. Protected process names can be missing. There is no automated discovery, router-side mutation, packet payload collection, background monitoring, or telemetry upload.

| Component | Contract |
| --- | --- |
| Domain `src/intelligence/mod.rs` | Typed Windows snapshots, assessment, imported evidence validation, filter and CSV. Facts have Unix UTC timestamps; local attribution uses IP plus interface index. Scope and sensor are kept for imported evidence. |
| Collector `src/intelligence/windows.rs` | IP Helper IPv4/IPv6 unicast, neighbor and TCP/UDP tables. Process lookup is best effort and capped. WinHTTP direct HTTPS for probe/router, certificate trust and hostname checks, no redirects/proxy/cookies, explicit router authentication. |
| Router parser `src/intelligence/router.rs` | Only constant GET paths and field projections. Typed, bounded parsing, partial coverage, original/reply tuple preservation, gateway/default route and counter evidence. No commands derived from responses. |
| Win32 UI `src/bin/native/intelligence_window.rs` | One worker for explicit actions, bounded snapshot/filter/detail display, no routine pop-up spam. Important outcomes still use Windows dialogs. Flow buffer in memory, local snapshot file history on explicit save. No database migration or automatic polling in this release. |
| CLI | Offline local snapshot to a new JSON path. Explicit, one-time HTTPS probe via `--confirm`. Existing commands unchanged. |

## Evidence rules

- Local ARP/ND is a cache and may contain stale entries. It is not an active discovery operation or proof of LAN/internet connectivity.
- The HTTPS test goes through the default path selected by Windows (no forced family, adapter, or proxy). A 204 response with no body, verified TLS, and a unique source mapping is positive evidence for that source/endpoint at that time. A redirect, timeout, or failed certificate does not imply policy denial. Probes from other devices are not launched.
- Router conntrack records, default route, NAT fields and DHCP entries do not prove WAN traversal for a client. No inference based on public addressing alone. Explicit operator-imported WAN observations are labelled **Impor**, not verified probes, and use a 15-minute freshness window.
- Rate is an estimate between two manually collected complete interface snapshots of the same router, with comparable uptime and counters. Counter decreases, missing fields, changed interface metadata, or a time gap produce unknown values.
- Snapshot time, collection caps, missing table/permission, and transport errors are separate from measured values. Scope/VRF not reported by a source is explicitly unknown. IPs from separate router and import scopes are not merged.

## Limits and resources

One worker at a time, up to eight routers per session, up to 10,000 rows per RouterOS table and 8 MiB per response. WinHTTP phases have per-operation timeouts and body reads have an elapsed budget. The collector stops starting additional tables when its snapshot budget is exhausted. Windows endpoint buffers are capped at 16 MiB per table, retained rows at 50,000 per table, and process lookups at 2,048 unique PIDs. The UI shows the first 1,000 matching rows and the total matches. Use filters to narrow. These are limits, not benchmark results.

Router passwords are entered into the Windows credential dialog without persistence, passed to WinHTTP in memory, and the app-owned password buffer is cleared on drop. No credentials are exported. Use a dedicated read-only RouterOS account, a certificate trusted by Windows for the exact router hostname, and an already-configured HTTPS REST service.

References: [RouterOS REST](https://manual.mikrotik.com/docs/developer-guides/rest-api/), [RouterOS Conntrack](https://manual.mikrotik.com/docs/cli-reference/ip/firewall/connection/), [RouterOS Traffic Flow](https://manual.mikrotik.com/docs/diagnostics-monitoring-and-troubleshooting/traffic-flow/), [Windows IP Helper neighbors](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipnettable2), [Windows TCP](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable), [Windows UDP](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedudptable), [WinHTTP source/destination](https://learn.microsoft.com/en-us/windows/win32/api/winhttp/ns-winhttp-winhttp_connection_info).

## 0.7.0 Flow and history

The UDP worker binds a specifically configured local address after user confirmation. It checks exporter IP and domain before decoding, uses session/domain/template IDs to isolate definitions, and bounds datagrams/templates/records. IPFIX and NetFlow v9 observed data and imports are still separate from verified HTTPS. Credentials never enter the snapshot archive. History uses versioned JSON with staged writes and only compares matching sources. IPv4 firewall, NAT, bridge and VLAN reads use a strict view and do not mutate RouterOS. See [Flow setup](FLOW_SETUP.md).

## Arsip flow 0.8.0

Collector memilih profil berdasarkan IP sumber dan observation domain sebelum decoder memproses paket. Decoder menyekat template berdasarkan sesi, versi, domain dan ID. Event valid dikirim melalui antrean batch terbatas ke satu writer SQLite WAL per collector. Scope arsip mencakup profil, site, dan VRF. Fingerprint menggabungkan scope, sesi, versi/domain, digest datagram dan ordinal posisi record. UI menggunakan worker terpisah untuk query dan ekspor. Identitas file SQLite diperiksa sebelum mengubah schema, dengan pembaruan di transaksi writer. Ekspor memakai snapshot pembacaan yang konsisten. Lihat [panduan arsip](ARCHIVE_SETUP.md) untuk batas retensi, WAL dan penyamaran.

## Detail IP dan arsip v0.9

Worker Analisis mengambil satu read snapshot SQLite dan melakukan paling banyak 2.000 pemindaian record yang cocok. Identitas scope mencakup profil, site, VRF, socket exporter dan domain. Korelasi pasangan arah memakai scope yang sama, versi, tuple TCP/UDP dan ingress/egress terbalik serta jendela waktu ekspor dan terima. Bukti HTTPS lokal tidak dilebur dengan scope flow. Paginasi dan ekspor menggunakan objek Query terakhir yang berhasil diterapkan, bukan teks filter yang belum diterapkan.

API SQLite backup menyalin sumber bersama commit WAL ke file baru, dengan deadline, quick check, dan tanpa menimpa tujuan. Snapshot SQLite dibaca dengan batas per item, total, waktu, dan jumlah, lalu digabung dengan snapshot JSON berdasarkan hash isi. Retensi flow default dijalankan saat collector aktif, dengan pemeriksaan saat idle dan maksimum 10.000 record per siklus.

## Penyimpanan arsip v1.0

Writer menyimpan pengaturan lokal pada tabel tambahan yang kompatibel dengan arsip sebelumnya. Policy dibaca dalam transaksi insert sehingga kuota aktif berlaku pada proses writer berikutnya tanpa restart. Perawatan menggunakan jam monoton untuk jadwal serta UTC untuk cutoff, dan tidak bergantung pada kedatangan paket. DB utama dan WAL diukur terpisah. Pratinjau hapus mengikat jenis, rentang, ID dan fingerprint record. Validasi ulang dan penghapusan berjalan dalam satu transaksi IMMEDIATE.

Backup SQLite memakai SQLite Backup API dengan staging satu volume. Pemulihan memeriksa format, integritas, dan hash sumber sebelum menyalin, lalu memeriksa hasil sebelum publikasi tanpa overwrite. Salinan yang dibuka di panel GUI bersifat baca-saja dan tidak dipakai oleh collector. Tampilan histori tidak menggabungkan arsip utama ketika salinan aktif.

## Observabilitas RouterOS v1.1

HTTPS WinHTTP tetap menggunakan GET read-only dengan validasi sertifikat, tanpa redirect dan dengan batas per tabel. Worker memetakan observasi ke backend tampilan. Waktu tabel melekat pada bukti. VRF hanya label keanggotaan eksplisit dari respons lengkap. Server DHCP dipetakan ke interface bila tidak ambigu. Indikasi konflik memerlukan MAC berbeda pada interface sama dan bukti cukup mutakhir.

Deret counter bersifat ring buffer per sesi dan membedakan gap dari zero-rate. Lease history merekam observasi, tidak menyimpulkan waktu assignment. Alert lokal menggunakan perubahan counter, debounce/cooldown waktu monoton, tanpa popup, pengiriman eksternal, atau aksi jaringan.
