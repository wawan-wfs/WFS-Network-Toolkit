# CI recovery — run 45672963967

Exact tested parent: 19d4686e8b04f32aec21d6434f3a5ec294777515. Run: https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45672963967 (attempt 1, failed). Evidence artifact 15049804007, SHA-256 a19892b3238cb46c9c82c78671ca2e4498ba17a37eee7beb3c241b84f4790122; downloaded ZIP digest verified.

9/12 independent gates PASS: branding, sqlite, gate_runner, ipam_metadata, dhcp6_history, rust_version, clippy, unit_tests, release_build. FAIL: format, format_win32_toolkit, format_win32_intel. 89 Rust tests passed, zero failed, two ignored. CLI, native smoke and NSIS packaging skipped; no installer or screenshot from this run.

All 43 rustfmt diff hunks (55 changed blocks, nine files) applied from the runner artifact to exact parent source, with old-block and replacement checksums verified. No feature or gate changes. New commit remains untested until a new manual dispatch on main; do not rerun the old SHA. No release claim. Continue P1 only after all 12 gates plus native smoke and package pass. See NEXT_PROMPT_WENET_NEXT.md.
