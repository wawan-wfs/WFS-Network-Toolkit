# CI formatting recovery — 25 November 2026

Evidence: [manual run 45663046203](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45663046203), job 139377728479, commit ad3077ce33282a937a26e87fc0121b220c833347. Artifact [15045428626](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45663046203/artifacts/15045428626), 15022 bytes; downloaded ZIP SHA-256 matched a1732196556ba1bfa78184e6b7670455d3775ecb066d316cecd11412613f91b7; all 12 entries passed ZIP integrity. Report commit matches. Rust 1.100.0.

| Gate | Status | Seconds |
|---|---|---:|
| Branding | PASS | 0.375 |
| SQLite | PASS | 0.454 |
| Gate runner | PASS | 0.312 |
| IPAM SQL | PASS (7 tests) | 0.109 |
| Rust version | PASS | 0.516 |
| Cargo fmt | FAIL | 3.438 |
| Win32 toolkit fmt | FAIL | 0.609 |
| Win32 intelligence fmt | FAIL | 0.172 |
| Clippy | PASS | 40.14 |
| Rust tests | PASS (83 passed, 0 failed, 2 ignored) | 32.547 |
| Release build | PASS | 80.0 |
| CLI / native GUI smoke / NSIS / Windows package | SKIPPED | — |

Correction: applied all 45 rustfmt hunks from the artifact (dhcp6.rs 2, ipam_notes.rs 10, toolkit_window.rs 3, intelligence_window.rs 7, visual_window.rs 23). No intended functional change, no dependency/schema/branding/version change. Manual-only workflow remains intact. Corrective commit has not run CI; installer and screenshot are not available for it. Baseline c570b86a package is historical only. Gate-first instructions remain in NEXT_PROMPT_WENET_NEXT.md. Do not rerun the obsolete SHA to accept this correction; run workflow_dispatch on the newest main. Continue P1 only after all 11 gates, CLI, native smoke and packaging pass.
