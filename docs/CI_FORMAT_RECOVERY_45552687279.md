# WeNet Toolkit — CI format recovery

## Actual evidence, 25 November 2026

Manual run [45552687279](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45552687279), commit `5db18a134ea4707371ce6076e8a89f49c2153f3b`, job 138997306010. Artifact [14994627726](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45552687279/artifacts/14994627726), 9,511 bytes; ZIP SHA-256 verified against GitHub: `92ef3778eeb61addc9befdac34c925557905c42e97514c576501f6e98c5bd63a`. All 11 entries readable; ZIP integrity passed.

| Gate | Result | Seconds |
|---|---|---:|
| Branding | PASS | 0.375 |
| SQLite | PASS | 0.500 |
| Gate runner | PASS | 0.329 |
| Rust version (1.100.0) | PASS | 0.640 |
| cargo fmt | FAIL | 3.969 |
| Win32 toolkit format | PASS | 0.734 |
| Win32 intelligence format | FAIL | 0.125 |
| Clippy -D warnings | PASS | 45.578 |
| Rust tests | PASS: 76 passed, 0 failed, 2 ignored | 31.938 |
| Release build | PASS | 74.687 |
| Read-only CLI, native GUI smoke, NSIS, package upload | SKIPPED | — |

## Corrective source

All 13 rustfmt diff hunks (2 network_map.rs, 2 overview.rs, 9 intelligence_window.rs) were applied to the exact baseline. No feature logic, dependency, schema, version, branding, workflow or test was intentionally changed. The corrective source has **not yet run CI**. Local Rust toolchain is unavailable. No new installer exists. Previous package at ae36e729 remains historical evidence only.

Run workflow_dispatch on new main; do not rerun the old SHA as acceptance of the correction. After all ten gates, CLI, GUI smoke, packaging and checksum validation pass, continue the full P1 plan. Physical UAC/VM, live RouterOS/Realtek and million-record benchmarks remain independent pending gates. Actions remain manual-only.
