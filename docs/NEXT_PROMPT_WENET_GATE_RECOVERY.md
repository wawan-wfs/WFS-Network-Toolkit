# Checkpoint terbaru — setelah koreksi format dari run 45426915628

Gunakan HEAD main terbaru, bukan SHA lama. Artefak 14936888586 telah diperiksa. Baseline d511189e lulus 70 tes Rust, Clippy dan release build, tetapi tiga pemeriksaan format gagal. Koreksi berdasarkan diff telah diterapkan. Jalankan workflow manual pada HEAD baru; periksa setiap log termasuk ketiga format, CLI smoke, GUI smoke, NSIS dan checksum. Tidak ada klaim gate hijau sebelum run baru selesai. Jika gate lulus, lanjutkan P1 besar dari spesifikasi lengkap berikut. Jika gagal, perbaiki error aktual tanpa menurunkan gate. Pertahankan versi hingga verifikasi. Jangan rerun commit lama sebagai bukti HEAD baru.

---

# WeNet Toolkit by WFS Project — next large development batch

Read docs/GATE_RECOVERY.md, docs/NEXT_PROMPT_WENET.md, docs/V14_GATE_STATUS.md, docs/NEXT_PROMPT_V15_GATE_FIRST.md, docs/TEST_REPORT.md, docs/WENET_BRANDING.md. Resolve and verify actual main SHA. Candidate still 1.3.0-rc.1.

## P0 — unblock actual compiler, not another superficial patch
1. Read latest manual CI run matching current SHA. If no run exists, use manual Run workflow from GitHub UI or supported dispatch tool. Do not re-enable push/PR triggers, create dummy PRs, or rerun an old commit as current acceptance. Obtain wenet-gate-evidence report.json and logs. Fix all real errors, including formatting, Windows API/borrow/type errors and Clippy. Verify exact SHA after each source change; no claims without actual run. Local toolchain is acceptable if real tests run; use a fresh evidence directory. Keep Rust lockfile and existing tests.
2. Require all 10 gate runner checks plus read-only CLI, Win32 smoke, Windows x64 release build, NSIS package and checksums. Add tests for direct invalid profile config, duplicate IDs/domains, writer panic/stop and final alert flush. Review explicit stop warning, normal window shutdown, queue overload, UAC single-window handoff, backup/restore safety and installation upgrade. Test both baseline and new features, with no production network mutations. 
3. Verify fixture schema 1/2→4, schema 3 reject, WAL backup, exact alert state, replay and identity, retention, quota, clock rollback, partial writes and recovery. Benchmark 10 exporters × 2,000 IP × 1M records, three runs; record received, decoded, committed, drops, pending, RSS, DB/WAL, P95 and stop latency. Distinguish synthetic and physical evidence.

## P1 — substantive feature implementation only after build/regression passes
- Native dashboard: actual local/router/flow/alert/archive counts, source coverage, freshness, unknown, partial, empty, loading, errors; time series RX/TX, selectable scope/time and drilldown from IP to internet evidence/history/export. No fake status or sample data presented as live.
- Topology: native Win32 canvas, keyboard and pan/zoom, typed router/interface/bridge/VLAN/VRF/FDB/neighbor/route evidence edges and time/source; filter, limit and inspect; no unproved physical cabling.
- Advanced IPAM: scoped IPv4/v6 subnet, lease/ARP/ND/DHCPv6/PD, overlap, reservations metadata, alias/notes/tags and undo, historical assignment, utilization with unknown distinct from free, conflict provenance and redacted exports.
- MikroTik multi-router opt-in HTTPS read-only, TLS validation, capability per table, backoff/cancel, status/history, SNMPv3 authPriv and syslog only when scoped security and retention tested.
- Traffic: IPFIX/v9 sequence gap, rollover, restart, sampling, start/end, exporter generation, NAT provenance, kernel drop only when measured, retention/quota, scoped filter and secure exports. Do not infer access from two-way flow alone.
- UI: premium native Rust Win32 navy-teal, accessible keyboard, DPI 100/125/150/200, real dashboard and consistent navigation. Keep WeNet Toolkit by WFS Project, small credit, no WebView/Tauri/Electron; all original IPv4/DNS/MAC backup/restore/rollback and one-window Mode Admin.
- Physical VM and lab: fresh/upgrade/uninstall, UAC accept/cancel, Realtek peer MAC and rollback, RouterOS real read-only and exporter. Do not treat CI as hardware test.

## Delivery
Push verified fast-forward main only, manual GitHub Actions only. Full source ZIP pinned commit, actual logs and PASS/PARTIAL/BLOCKED/FAIL, installer/portable only if gate passes, checksum, changelog, next prompt and continuation button. Do not bump version or fabricate results.
