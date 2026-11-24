# WeNet Toolkit — gate recovery and evidence

Baseline 107135e2674a857df91b5ad71aac7ad272401d47. Cargo remains 1.3.0-rc.1. This is not a new Windows release.

## Current evidence
- Local Python gate-runner suite: 5 tests passed, 0 failures, 3.144 s. Tests simulate command success/failure, missing executable, timeout, continuation after failed gate, JSON consistency, stale evidence rejection and fail-closed empty gates.
- Local SQL regression suite rerun: 9/9 passed, 0.094 s, Python 3.13.5 / SQLite 3.46.1. The eight SQL files and test_alert_schema.py match repository Git blob hashes. Both runner files match tested local bytes (11 verified files in total).
- Local asset check: ICO 7 embedded PNG sizes 16–256, logo PNG/SVG/ICO Git blob SHA values match baseline. No Win32 LoadIconW test.
- Rust source adjustments (uncompiled): revalidate direct collector configuration before binding/opening archive; capture final receiver/alert/writer failures; return final statistics to GUI Stop; show warning on observed drops, pending rows or error. No automatic network mutation.
- BLOCKED: cargo/rustc/rustfmt absent; direct git ls-remote returned "Could not resolve host: github.com". No NSIS. Connector offers read and rerun of existing jobs but not manual workflow dispatch. Latest observed successful run 44755758137 was at 4bb5aca8, not the candidate.
- P1 dashboard/topology/IPAM/MikroTik/traffic/UI expansion is deferred until P0 passes, per requested order. No new executable. The SQL suite was rerun locally; Rust integration tests were not.

## Run the gate once
Open Actions → WeNet Toolkit Windows — manual build and tests → Run workflow → main. No push or PR triggers. The Python runner checks branding, SQL and runner self-tests, Rust version, format (including both native modules), Clippy, unit tests and release build independently even when an earlier gate fails. Download **wenet-gate-evidence** (report.json and one log per gate). The report is for build gates only; CLI smoke, GUI smoke, packaging and checksum still run afterwards, only if all previous steps succeed. The installer artifact is never uploaded from a failed workflow. Rustup setup failure still fails the workflow.
Local equivalent: from a complete checkout with Rust stable already installed, run python scripts/gate_runner.py --out gate-evidence-new. Use a fresh directory on rerun. Logs can contain local paths; do not publish them if sensitive. No formatter auto-writes source.
A timed-out command is a failure; child process descendants and Windows physical acceptance still require separate verification. Do not claim P1 completion or release from synthetic tests.
