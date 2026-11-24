# WeNet Toolkit — checkpoint after P1 audit

Base HEAD: `4e2fce1224a8dca0b54ca5c31d189b699be54147` (descendant of requested 5da35be8). Brand WeNet Toolkit by WFS Project and version 1.3.0-rc.1 retained.

## Actual verification

- Manual CI run [45431125979](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45431125979) on **ae36e7293cf846ee639f2210775e71b1c8f7d850**: all 10 gate-runner checks, read-only CLI, native smoke and NSIS packaging passed. Rust 70 passed, 2 ignored; Python 18 passed (counts from prior checked-in evidence). Job 138576403983 log independently inspected: 10 PASS lines, release 74 s, native GUI PASS, NSIS output. Package artifact 14939820358 is for that SHA only; not for current HEAD.
- HEAD 4e2fce12 is one commit ahead, adds dashboard/subnet source. No CI run for this HEAD. No automatic triggers added.
- Fresh local Python 3.13.5 / SQLite 3.46.1: 9/9 tests, 0 failures, 0.095 s. The eight SQL files and test_alert_schema.py bytes were reconstructed and their Git blob SHA-1 hashes matched the current tree. No Rust or Win32 claim from this result.
- Local compiler unavailable (cargo, rustc, rustfmt absent); git HTTPS to GitHub failed DNS. Connected GitHub tools expose no dispatch of a new run. Therefore no new Rust gate or installer and no live router/NIC tests. Existing native code changes below are pending compilation, Clippy, format and smoke.

## Corrective source changes

- IPAM subnet counts accept only ARP/ND and active DHCPv4 bindings whose observation is within 60 seconds of the relevant address table. DHCP server mapping must be complete and aligned with both lease and address timestamps. Inactive configured leases are not counted as observed hosts. VRF labels require temporally coherent, unambiguous evidence. IPv6 remains explicitly partial because DHCPv6/PD is not collected. No free-address inference.
- Added Rust fixture tests for stale ARP, inactive/active lease, stale VRF and IPv4 /0 and IPv6 /128 boundaries. These new Rust tests have not run.
- Dashboard/storage distinguish not read, loading, absent DB, read failure, and successful measurement; invalidate cached state before reloading. Future timestamps are labelled ambiguous. No fake values. Existing error popup remains.
- Manual workflow explicitly checks archive-info exit code. Workflow remains workflow_dispatch only.

## Next gate

Run manual CI on latest main, read every log, fix formatting/compiler/lint/smoke issues, and publish new installer only after successful exact-SHA acceptance. Preserve full dashboard/subnet functionality, branding, legacy data and installer paths, Mode Admin, read-only router monitoring. Native graph canvas, persistent IPAM notes/tags, DHCPv6/PD, extended monitoring, benchmark and physical acceptance remain unfinished. No version bump or production-ready claim.

[Previous successful package](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45431125979/artifacts/14939820358)
