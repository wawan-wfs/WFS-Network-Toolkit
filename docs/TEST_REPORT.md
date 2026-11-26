## Integrated P1 increment 12 — immutable confirmed transport config, revision-aware IPAM workflow and native UI refinement

TLS desktop bridge now pipes the exact confirmed config (new helper command syslog-tls-pipe), not a mutable config file path; stdin writer runs separately under process timeout. Certificate/key ACL and helper directory race acceptance still required. SNMP credential length validated before IPC, temporary buffers preallocated. IPAM subnet pivot now loads existing scope/CIDR metadata and captures current revision before populating editor; save checks expected revision rather than blindly treating existing key as new. Added read-only secure-history CLI and context-specific controls; refined shared light palette/buttons. SQL-only local test against secure_monitor_schema.sql and exact retention statements: 3000 inserts -> 2048 retained, max 256 per scope, five invalid records rejected, integrity_check ok. Rust, Win32 and security executable tests remain NOT RUN. No claim of full redesign or continuous collector. No CI/deployment started.

---

## Integrated P1 increment 11 — fail-closed native Secure Transport integration

Added native mode 33 with explicit SNMP authPriv GET and one-session mutual TLS actions, session-only Windows credential prompts, typed result validation and independent bounded SQLite summary history. A build must explicitly embed WENET_SECURE_HELPER_SHA256 and install the matching helper in a protected application directory; ordinary builds remain disabled. Bridge launches no shell, passes credentials through stdin, checks result identity/time and uses process deadlines. TLS report includes bind and observation timestamp. This is source integration only: root and companion uncompiled; helper packaging, ACL/TOCTOU security acceptance, dependency resolution and real agent tests pending. Continuous collector, full redesign and benchmark remain outstanding. No CI/deployment triggered.

---

## Integrated P1 increment 10 — executable security acceptance harnesses

Added TLS loopback fixture harness generating ephemeral trusted and foreign CA, server and client certs via OpenSSL. Runs seven actual cases against companion executable (authorized, absent cert, foreign CA, same CA unpinned, plaintext, truncated and invalid length). Added explicit authorized SNMPv3 lab harness: valid authPriv, wrong auth, wrong privacy and wrong user, no credentials persisted in report. Harness code committed; NOT RUN because companion executable cannot be compiled in current environment. Dependency lock, adversarial replay/source/downgrade, expiry and slow-peer cases, continuous collector and full UI/runtime acceptance remain blockers.

---

## Integrated P1 increment 9 — actual secure transport companion source, acceptance blocked

Added independent native Rust secure-transport crate using async-snmp 0.18.1 USM (SHA-256/AES-128 authPriv only, strict source and response shape, bounded exact read-only sysUpTime GET) and rustls 0.23.46 (mandatory WebPKI client CA validation plus exact certificate SHA-256 authorization, TLS 1.2/1.3 only, one-shot listener with absolute deadlines, root project's incremental Syslog framing parser, no raw payload persistence). Direct dependency versions pinned, parent lock unchanged; companion transitive Cargo.lock NOT generated due missing Rust/network. Source and unit tests NOT compiled or run; no security certification, installer integration or continuous service. Mandatory next: resolve and audit lock on trusted host, test real agent and negative SNMP cases, TLS valid/invalid/unknown CA/unpinned/expired/plaintext/truncated/slow cases, then integrate into native UI/monitoring and package only after all pass. No remote CI or deployment started.

---

## Integrated P1 increment 8 — indexed native graph virtualization and streaming offline analysis

Connected-component bands now carry exact node/link indexes; binary search selects visible bands in O(log components) before individual clip checks and hit tests. Added bounded offscreen GDI double-buffer fallback and F key focus on selected evidence. Added regression against brute force for 1,000 disconnected components. Syslog octet-counted parser now reads incremental fragments with an 8 KiB frame buffer, total byte/frame limits and truncation failure; .bin import integrated into native offline Syslog view. New native Replay Flow offline mode imports bounded JSONL and displays aggregate decoder diagnostics, no socket, no archive writes. Rust/Windows build and new tests NOT RUN: local toolchain absent and GitHub/crates DNS unavailable. Actual TLS listener and SNMPv3 authPriv still outstanding; no auth claim based on framing. Full redesign and acceptance pending.

---

## Integrated P1 increment 7 — durable Flow metadata and bounded selector options correlation

The optional Flow.provenance JSON field is stored in the existing atomic SQLite writer transaction with the original row; no new schema version, unchanged dedup fingerprint, legacy rows missing the field still deserialize. Removed separate collector provenance map to avoid snapshot races and double retention. Both live and archived native details read the same provenance. Unredacted JSON exports include reported provenance, redacted JSON excludes NAT identities and provenance object; CSV columns unchanged with sampling label only. IPFIX Options Template/Data Set parser supports single standard selectorId scope and same-datagram exact selector linkage, rejects ambiguous conflicting values and never infers a multiplier or carries options data across datagrams. Source tests for reopen, dedup, old JSON, redaction and options correlation added. No Rust compilation/CI; actual build and full regression remain pending. IANA registry https://www.iana.org/assignments/ipfix . SNMPv3 authPriv and authenticated TLS transport remain pending; no fake security implementation.

---

## Integrated P1 increment 6 — scoped IPAM metadata pivot and selectable embedded chart range

Native Subnet view creates an explicit draft of operator IPAM metadata from canonical authority, unique interface and time-aligned explicitly reported VRF only; opaque SHA-256 scope key is length-delimited and stable. No automatic save, no guessed local interface identity, no migration of legacy operator labels, no network mutation. Unknown scope cannot generate a linked draft. Dashboard adds keyboard-accessible existing native button for 30/60/120 sample range with actual selected-range P95 RX/TX, excluding missing measurements. Regression fixtures added for scope isolation and percentile boundaries. No new CI, no compilation, no acceptance claim. Remaining full-module redesign, real authenticated TLS and SNMPv3 transports, durable flow provenance and options-based sampling, hardware/runtime verification, benchmarks.

---

## Integrated P1 increment 5 — live Flow provenance, deterministic offline replay and framed Syslog

Source changes: bounded session-only IPFIX standard data-record sampling (legacy 34/35 and 305/306) and post-NAT fields (225–228, 281/282); original Flow record and SQLite schema unchanged. No sampling multiplier, no inferred NAT mapping, no option-template support, no vendor-field interpretation. Metadata remains associated with exact exporter/version/domain/datagram/ordinal and visible in native Flow detail; bounded collector counters. Offline JSONL datagram replay uses the same Decoder without opening a socket or writing archives. Strict bounds and receive ordering; CLI emits aggregate diagnostics only. New RFC 5425 octet-counting parser and offline CLI summary reject malformed/truncated framing; transport is NOT authenticated. No TLS listener or SNMPv3 client implemented. Field registry: https://www.iana.org/assignments/ipfix . Added Rust fixture tests for metadata, replay, framing. Rust toolchain unavailable locally; no new Rust tests, CI or installer run. Remaining: vetted SNMPv3 authPriv and mTLS listener, durable flow provenance, option-template sampling, dashboard range, typed IPAM, UI redesign, performance and full acceptance.

---

## Integrated P1 increment 4 — durable polling health + accepted P0 baseline

Verified main baseline 66c981152c0a226f8ded138f5fe5ffa745d32e81, Auto CI run 45758336730 attempt 1: 12/12 gates PASS; 89 Rust tests passed, 0 failed, 2 ignored; CLI and native GUI smoke PASS; NSIS build and package upload PASS. Artifact 15088827742 SHA-256 18b29b5691d2190d16dfc6b3719bee14c494b5ab57bd7fa2fa3234b9bb7fa17b and evidence 15088548742 SHA-256 751d365611d1bddc64583c1a59bdc0c8e360dcc13a80099a421f9035041cc58c verified locally with ZIP CRC. All five manifest entries matched including installer 895ca298265204cbb4651af79911fb3cbb0a966718ba36a92c59555d04692d4d and source ZIP b5d893395913ad5f2dd32d0fead4e0a3a70f63c5edb454b253b30768015dbc04. No screenshot or physical installation evidence. These binaries are BASELINE ONLY, not this P1 branch.

New source: independent SQLite journal poll-health-v1.sqlite3 for successful, partial and failed authorized HTTPS polling; bounded retention (512 per authority, 4096 total), categorized outcomes only, elapsed monotonic duration, separate archive-write status, no raw errors or secrets, no automated restart of polling. Native Histori kesehatan and CLI read-only page, added regression. Candidate Rust and Win32 build NOT RUN; no toolchain available in local environment. Existing main Auto CI untouched. Complete outstanding security integrations, typed IPAM, flow sampling/NAT, dashboard range and UI modernization before consolidated acceptance. No claim of SNMPv3 or TLS syslog implementation.

---

## Integrated P1 increment 3 — native history and recovery workflow

DHCPv6 history now has exclusive cursor paging via Lanjut, redacted aggregate export and explicitly confirmed full backup, plus restore to a new filename. IPAM native recovery uses the same no-overwrite verification, and save confirmation includes exact-scope overlapping prefix counts from loaded operator metadata. Export summary uses one read statement and validates all rows in that snapshot before publication. Active files and sidecars are excluded as restore destinations; no automatic activation. All changes source-only, uncompiled. Existing IPAM and DHCPv6 regression suites extend to these operations; no new CI has been started.

---

## Integrated P1 increment 2 — source only

Main-window GDI owner-drawn RX/TX chart strip uses selected dashboard row and native list selection notifications; compact client retains modal drilldown. Shared scale, missing-data discontinuities, observed zero, maximum label and fixed 60-sample window. Added layout regression. Flow diagnostic counters displayed in dashboard, and regression covers wrap/repeat/reorder/isolation/v9 restart. DHCPv6 standalone backup validates all captures, bounds and identity; recovery verifies fingerprint and publishes a new destination, with CLI and regression coverage. None of the new Rust/Win32 code has been compiled or run here. No claims of CI or installer acceptance.

Remaining: selectable time range and full chart keyboard/DPI smoke, native DHCPv6 paging and export/recovery controls, typed observed/operator IPAM mapping, full multi-router/SNMPv3/TLS security integration, sampling/NAT and replay, complete UI redesign, benchmark runs and release gates. Keep all on candidate branch until integrated development is ready for acceptance.

---

# P1 integrated development candidate — staged before CI

Base: 66c981152c0a226f8ded138f5fe5ffa745d32e81. Operator changed order on 2026-11-26: develop on a candidate branch first, consolidate and test after feature implementation. Main Auto CI remains unchanged. This is an unaccepted source candidate, not a release.

Implemented source: deterministic connected-component graph bands and offscreen edge culling; native text RX/TX preview in dashboard details (not full embedded GDI canvas); exclusive cursor DHCPv6 history with redacted aggregate export and CLI access; exact operator-scope IPAM overlap checks and independent no-overwrite recovery with revision validation; flow sequence/restart diagnostics (not loss counters or sampling correction); benchmark harness with three executions of actual million-row test and P50/P95/P99 query latency.

Added Rust regression cases for graph components, preview missing/zero, DHCPv6 cursor/redaction, IPAM overlap and recovery. Toolchain unavailable locally; these tests, rustfmt, Clippy, Windows build, runtime and benchmarks are NOT RUN. No installer/screenshot or hardware acceptance claimed.

Remaining P1: full embedded GDI chart and range/selection, typed observed/operator scope mapping and UI for overlap/recovery, DHCPv6 validated backup and native paging UI, full flow sampling/NAT provenance and replay tests, bounded multi-router health, trusted SNMPv3 authPriv and authenticated TLS Syslog implementation with pinned dependencies and security tests, all-module accessibility/DPI redesign, measured three million-row repetitions including memory/drops/stop. Do not implement custom crypto or misrepresent text preview as full chart. Complete remaining scope on candidate branch; then run all existing gates once for consolidated candidate, verify logs, artifacts and hashes before promotion. Keep no deployment/force push.

---

# Latest checkpoint — authorized automatic CI contract recovery (run 45757516983)

Exact tested parent: `e29aff717dacfb3080f449227ff1fa3306f08bd4`, run [45757516983](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45757516983), attempt 1, push. 11/12 gates PASS; branding FAIL only. All three rustfmt gates, Clippy, release build, SQLite, IPAM metadata and DHCPv6 history PASS; 89 Rust tests passed, 0 failed, 2 ignored. CLI, native smoke and installer skipped by fail-closed gating. Downloaded evidence artifact [15087638968](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45757516983/artifacts/15087638968), SHA-256 `f07c50bc5f36fdcf029b7c99908bb6a2c5c9e5098500224a0cf539f9af63089f`, matched metadata. The log identifies `test_ui_workflow_and_credit`, line 60, obsolete manual-only assertion. Other three branding tests passed. Recovery updates the CI contract rather than suppressing the gate. New exact commit remains NOT TESTED until its own run completes.

The repair candidate does not alter application source, gate runner or Windows packaging steps. No new installer or screenshot available before acceptance.

---

# Latest CI evidence — format recovery pending

Run [45672963967](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45672963967), attempt 1, exact parent 19d4686e8b04f32aec21d6434f3a5ec294777515: 9/12 gates PASS; three format gates FAIL; 89 Rust tests passed, 0 failed, 2 ignored; Clippy and release build PASS. CLI/native smoke/NSIS skipped. All 43 rustfmt hunks across nine files applied from verified artifact 15049804007. New exact SHA NOT TESTED. See [CI recovery evidence](CI_FORMAT_RECOVERY_45672963967.md).

Artifact ZIP SHA256 matched GitHub metadata. No new installer or screenshot. Baseline package remains separate.

---

# WeNet Toolkit — native graph, DHCPv6 history and IPAM backup candidate

## Accepted baseline evidence (2026-11-25)
- Manual CI run [45667059429](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45667059429), job 139391958085, exact commit a11ea99f2a0d96dadd22b3df2d1abe4eb0afd0f4. All 11 gates PASS. Rust 1.100.0; 83 passed, 0 failed, 2 ignored. Python branding 4, SQLite 9, gate runner 5, IPAM 7 tests passed. Release build 45.14s. CLI and native smoke passed including metadata fixture/editor/undo, graph and bandwidth viewer; NSIS and artifact upload passed. Physical installation/UAC/hardware not tested.
- Evidence artifact [15047952246](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45667059429/artifacts/15047952246), 7,990 bytes; SHA256 f9b2871b1159aa258c7b4ffed585733afbe61b6d55a23afb9c1587f52b4f63bf. Package [15047762535](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45667059429/artifacts/15047762535), 5,534,505 bytes; SHA256 ff8d1446df68ee21d172643e0e2f4226c350fb385de679c3c31ee2e6f82ea802. Both downloaded, ZIP CRC and hashes matched.
- Installer SHA256 95704ed1548504135a21165ec1d5890ded83bf5056645e2458dc814d469cc51b; GUI eb6293a9dc177de6e7a18f360931a7f6e6a82620b9e8a82b73b779c619c6925f; CLI c28c90205ee1247e1f888b244efd20b2bc6f1c82aebff24f7175f80c062160e6. All three matched package manifest. Evidence belongs only to accepted baseline, not new source.

## New candidate implementation (pending Rust/Windows CI)
- Shared graph model: bounded 1,000 evidence edges, typed nodes, explicit router authority, conservative interface/VRF scope isolation, grouped bridge/VLAN labels, no cross-router identity merging or physical-cabling inference. Native GDI viewer, zoom 40–200%, pan keyboard WASD/right drag, selection through node incidents, clipping and provenance. Graph remains a snapshot and layout is deterministic column-based, not automatic physical topology.
- Dashboard row opens exact selected RX/TX series directly; chart adds P95 per selected window and gaps. Resource row exposes measured CPU and RAM derived only from valid counters and source coverage/time. No summing different interfaces. Chart remains a separate native owned viewer, not embedded in the dashboard.
- DHCPv6 server REST GET based on official RouterOS documentation https://help.mikrotik.com/docs/spaces/ROS/pages/24805500/DHCP ; explicit unique server/interface mapping, complete table and <=60-second aligned time, listed VRF only (not proof of resolved VRF). No client identifiers or DUID. Optional tables remain last after existing traffic tables. New SQLite database dhcp6-history-v1.sqlite3 in legacy data directory, immutable timestamp keys, idempotent identical saves, conflicting snapshot rejected, max 512 rows/256 KiB per capture, 120 samples/router, 32 routers, 64 MiB aggregate payload, no silent eviction. UI records confirmed manually and reads latest 20 exact-router snapshots with coverage and detail up to 100 rows. Not a reconstructed continuous assignment interval.
- IPAM metadata export is aggregate JSON only when redact is checked; contains no scope/CIDR/notes; unchecked explicitly confirmed backup produces consistent SQLite copy via staged no-overwrite publication and integrity check. Restore UI and observed-to-operator scope identity integration are still pending.
- Offline syslog import (1 MiB UTF-8, 10,000 lines, header priority only, no message/host/date retention); grouped facility/severity and accepted/rejected counters, explicit unauthenticated source. No UDP/TCP listener, no remote polling or security claims. SNMPv3 authPriv and authenticated live syslog transport intentionally deferred until protocol/security test infrastructure available.
- Light-mode accent refinement and native viewer; old feature controls, installation identity, data/Flow schema and dependencies unchanged. New fixtures for graph, history, backup/export, syslog and Windows smoke. Additional independent SQL gate; 12 gates now required, none weakened.
- Local Rust/rustfmt unavailable. Candidate not compiled, linted or run on Windows in this turn. Formatting/compilation/GUI acceptance must be confirmed on exact new SHA. No screenshot artifact from baseline; no new installer claim.

## Actual candidate offline SQL evidence
Command: python test_dhcp6_history_schema.py (same 4 Git blob bytes as candidate).
Python 3.13.5 / SQLite 3.46.1: 7 passed, 0 failed, 0.205s.
- schema: 703ba99bb9378e245ceccbbded26af5544561995
- insert: 51de4aa46afc8601e96b224ef51deb68d4965cd9
- page: 65175b7ba18231e3fc1a5af05348722e139767e3
- test: 9dfcaf30edb100ac713dea4c13727b8fdb0943a0
Tests: identity, router cap, isolation/conflict, total-byte cap, bounded page, payload/stamp rollback, per-router cap. Does not verify Rust or runtime. All four candidate input blobs matched GitHub.

## Still incomplete
Embedded chart and full UI redesign, explicit scope-aware IPAM joins and restore, complete DHCPv6 history navigation and independent backup, more precise graph layout and accessibility, SNMPv3 authPriv, authenticated live syslog, flow sampling/sequence/provenance enhancements, 3x 1M-record benchmarks, VM/hardware acceptance and screenshots. Do not bump version or claim full feature parity until verified.

---

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

---


## IPAM operator metadata candidate

New independent `ipam-notes-v1.sqlite3` in the legacy data folder. Manual scope + canonical CIDR key; labels, tags, notes and administrative reservation are never observations or actual allocations. Save and undo append immutable revisions; optimistic expected revision and exact selected key, cap 4,096 keys / 16,384 revisions, no silent eviction. Existing Flow schema 4 is untouched. UI: select IPAM metadata lokal, use `scope|CIDR|label/reserved|alias|tag|catatan`, select exact current row and Isi editor before updating, then Simpan metadata; Undo metadata appends previous contents or inactive tombstone. Reset before creating another key. Read-only recovery prohibits edits. No DUID or credentials. Metadata DB must be backed up separately; no merge with observed scopes, redacted export or automatic allocation. Native UI and Rust tests not yet compiled. Shared SQL contract: 7/7 passed, 0.019 s, five matching input blob hashes; see evidence/IPAM_SQL_20261125.md. Native fixture smoke added for graph, chart and metadata; not run.

# WeNet Toolkit — visual intelligence and DHCPv6 candidate

Accepted baseline c570b86aac4403a59dab06d8b2323f1c7b385d0b: manual run 45632871037, 10/10 gates, 76 Rust tests passed, 2 ignored, Clippy, release build 46.453 s, native smoke, CLI and NSIS passed. Package 15032436398 SHA256 070e85749b40bbce3d21a6f78f17296a912098a21945be60a6243d3a672b0932; evidence 15031532196 SHA256 bd08d79fc0e67863a54bac7721da56efd3884790364db0783e22703ca74be758. Both downloaded and ZIP integrity verified; three EXE checksums match SHA256SUMS.txt. Evidence report.json matches exact commit. This is evidence for baseline ONLY.

New source: native GDI visual viewer with typed evidence relations, keyboard/mouse navigation, zoom by visible rows, scoped provenance; per-interface RX/TX chart with gap preservation, time scale, range navigation, true zero distinction, latest sample; new read-only DHCPv6 bindings table, /128 versus prefix, status/disabled/source coverage, no DUID persistence. Uses existing filtered list row order; no WebView or new dependencies. DHCPv6 path based on official RouterOS documentation https://help.mikrotik.com/docs/spaces/ROS/pages/24805500/DHCP. No merge with ARP/ND/SLAAC or existing lease history; no claim of free IP. No schema or install path change. New Rust tests and native visual formatting gate added. New source not compiled or run locally; Rust unavailable and terminal GitHub DNS failed. New Windows package not built; run workflow manually on exact new SHA.

Remaining: full multi-node merged graph/pan, observed-to-manual IPAM scope mapping and independent backup/export, DHCPv6 server/interface/VRF mapping and durable history, charts integrated in main dashboard, wider monitoring and flow provenance, UI accessibility/DPI, hardware and 1M benchmark. No production changes. No version bump until current candidate accepted.

---

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

---

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

---

# WeNet Toolkit — gate acceptance and P1 candidate

Manual run 45431125979 on ae36e7293cf846ee639f2210775e71b1c8f7d850: all 10 build gates, CLI, native GUI smoke and NSIS packaging passed. Rust 70 passed, 0 failed, 2 ignored; Python 18 passed. Release build 74 s. Native smoke log ends PASS. Package artifact 14939820358 and evidence 14938594329. Both artifact ZIP SHA-256 digests match GitHub metadata; all three executable SHA-256 checks match SHA256SUMS.txt. This acceptance applies to ae36e729 only, not new P1 code.

New source batch: dashboard with source coverage, local and router inventory, per-interface bandwidth samples and P95, collector/exporter health, archive measurement, and navigation to existing modules. New IPv4/IPv6 subnet inventory counts distinct observed addresses per explicit interface, caps 512 prefixes per source, does not infer free addresses or aggregate overlapping prefixes. Includes unit and GUI fixture checks. New source has not yet been compiled or executed; no new installer claimed. Physical UAC, installation upgrade, Realtek/MikroTik, benchmark and full graph canvas/DHCPv6 binding remain pending. Actions manual only.

[Successful CI](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45431125979) · [Package](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45431125979/artifacts/14939820358)

---

# WeNet Toolkit — native GUI gate recovery

Run manual [45429043158](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45429043158), commit e561f864e01e53a9c47fdb537cb8d51fab854dc5, job 138568955282. All ten build gates passed, including three format checks, Clippy, unit tests and release build (72.828 s); read-only CLI passed. Native GUI smoke exited 1 after approximately one second, not a timeout. Packaging skipped. The log did not contain the internal assertion error, so the exact failing assertion is not known.

Source inspection found a definite asynchronous test defect: selecting alert mode starts a SQLite worker but the old smoke test immediately asserted the completed panel and subsequently invoked other actions. The revised smoke waits for completion, tests a temporary archive with one alert, acknowledges it, checks persisted ACK, and verifies the open filter. The panel clears stale data while loading. GUI smoke now logs stage and internal failure to gate-evidence/native-ui-smoke.log; workflow prints it and still fails on a nonzero exit or missing log. No production archive is used by the alert test. This correction is uncompiled/unverified until the next manual run; do not assume the original exit 1 was solely caused by this defect. Installer remains unavailable. Keep all gates.

[Original evidence](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45429043158/artifacts/14937951808)

---

# WeNet Toolkit — pemeriksaan CI manual 45426915628

Baseline: d511189e7ef8e0ed169caa8c9e989a8d10d260f4. Run 45426915628 (workflow_dispatch), job 138561312745, artifact 14936888586. SHA256 ZIP: ec7c81a038b5a0bcc94b63b1b0f7e39c2beae60274ff9be347e49a5006b5664a. Semua 11 file artefak dibaca; hash cocok.

Windows Server 2025, Rust 1.100.0. PASS 7/10 gate: branding 4/4, SQLite 9/9, runner 5/5, rust version, Clippy, Rust unit tests 70 passed/0 failed/2 ignored, release build (81.641 s). FAIL: cargo fmt, rustfmt toolkit, rustfmt intelligence. CLI smoke, GUI smoke, NSIS dan upload paket dilewati. Tidak ada kesalahan compiler/Clippy/unit test pada run ini.

Perubahan: koreksi format pada tujuh source berdasarkan diff aktual dari tiga log format. Tidak ada perubahan fitur, versi, schema, workflow trigger, atau lockfile. Semua koreksi dicocokkan dengan source baseline; penerapan format tidak sama dengan menjalankan ulang rustfmt. Gate belum diverifikasi pada commit hasil koreksi. Run manual baru wajib. P1 menunggu seluruh gate lulus, termasuk GUI smoke dan installer. Tidak ada installer baru.

[Run asli](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45426915628) · [Artefak asli](https://github.com/wawan-wfs/WFS-Network-Toolkit/actions/runs/45426915628/artifacts/14936888586)

---

# WeNet Toolkit — latest gate recovery report

Baseline 107135e2674a857df91b5ad71aac7ad272401d47.

| Gate | Actual result |
|---|---|
| Python gate runner | PASS 5/5, 3.144 s (synthetic subprocess tests) |
| SQLite regression | PASS 9/9, 0.094 s; exact SQL and test script blob hashes verified |
| Branding asset bytes | PASS 7 ICO size headers, 3 matching asset Git hashes |
| Source safety adjustments | PARTIAL, not compiled |
| Rust/Clippy/format/Windows smoke/installer | BLOCKED (no toolchain; no current manual CI) |
| Network P1 features / lab / benchmark | NOT STARTED in this batch; P0 pending |

See [GATE_RECOVERY.md](GATE_RECOVERY.md). Historical reports below are not evidence of this commit.

---

# WeNet Toolkit — status batch rebranding

Baseline: 5da35be8cf0ba9869b6b6f0e33d4483a211f8998. Versi Cargo tetap 1.3.0-rc.1.

- PASS: ikon sumber dirender dan tujuh ukuran ICO (16,24,32,48,64,128,256) dibuka dengan Pillow; byte ikon dan logo PNG dicocokkan ke hash Git blob. Ini validasi berkas, bukan LoadIconW di Windows.
- PASS: pemeriksaan statis staged tree untuk nama produk, EXE, build resource, smoke test, shortcut, paket, workflow manual, kompatibilitas registry/data dan hash SQL/engine. Bukan kompilasi.
- PARTIAL: source UI native, palette, resource, installer, docs. Tes kontrak SQLite sebelumnya 9/9 pada baseline, source SQL tidak berubah; hasil historis bukan rerun di batch ini.
- BLOCKED: cargo/rustc/rustfmt tidak tersedia, jaringan container gagal DNS dan workflow manual belum dijalankan pada baseline terbaru. Run sukses yang ditemukan adalah commit 4bb5aca8, bukan kandidat.
- BLOCKED: Rust compilation/Clippy/unit test, smoke Win32, UAC, installer, upgrade/uninstall, benchmark UDP, lab fisik. Tidak tersedia paket executable baru.
- P1 fitur besar masih menunggu gate P0. Tidak ada perubahan pada konfigurasi jaringan produksi.

Lihat WENET_BRANDING.md dan NEXT_PROMPT_WENET.md.

---

# Batch v1.4 — laporan gate aktual

Baseline 22e97abcaee82f59feb46306c237b24d9b22d29c. Versi aplikasi tetap kandidat 1.3.0-rc.1.

| Gate | Status |
|---|---|
| Kontrak SQL yang dipakai oleh Rust | PASS — 9/9 tes Python/SQLite, 0 gagal, 0.099 detik pada container Linux, Python 3.13.5, SQLite 3.46.1. |
| Source Rust/GUI | PARTIAL — perubahan telah diintegrasikan tetapi belum dikompilasi. |
| Kompilasi, Clippy, Rust test, format, smoke GUI, NSIS | BLOCKED — toolchain tidak tersedia dan dispatch manual tidak tersedia melalui konektor. |
| Paket Windows, benchmark UDP, UAC, DPI, perangkat fisik | BLOCKED — tidak ada hasil baru. |
| Fitur P1 | NOT STARTED — menunggu gate P0, sesuai urutan permintaan. |

Rincian dan langkah manual: [V14_GATE_STATUS.md](V14_GATE_STATUS.md). Hasil di bawah merupakan riwayat, bukan verifikasi commit batch ini.

---

# WFS Network Toolkit 1.3.0-rc.1 — kandidat pemulihan

Baseline d468d19861a82e77d0786e8d3caaaf809931da1b. Source v1.3 lama tidak ditemukan; hasil ini rekonstruksi parsial.

| Gate | Hasil |
|---|---|
| PASS — kontrak SQLite offline | python scripts/test_alert_schema.py: 3 tes lulus (migrasi 1→4 dan 2→4, application_id, scope/sesi, ack idempotent, replay, backup, reopen, retensi, rollback). Python SQLite, bukan crate Rust. |
| PARTIAL — source | Monitor alert per scope dan ledger, handoff admin, pengaman queue, GUI native terhubung pada source; belum verifikasi executable. |
| BLOCKED — Rust/Windows | cargo/rustc/rustfmt tidak tersedia di lingkungan; GitHub Actions tetap manual dan tidak dijalankan. Tidak ada installer baru. |
| BLOCKED — schema 3 asli | Definisi arsip lama belum tersedia, sengaja ditolak. |
| BLOCKED — benchmark, VM/hardware | Benchmark satu juta record belum diulang. UAC interaktif, DPI, RouterOS, Realtek belum diuji. |

Rangkaian Rust test baru belum dijalankan. Tidak ada perubahan konfigurasi jaringan produksi. Source lama dan data pengguna tidak ditimpa.

---

# WFS Network Toolkit 1.2.1 — laporan uji

## Status verifikasi 1.2.1

- Perbaikan sumber ditargetkan pada repo `wawan-wfs/WFS-Network-Toolkit` yang ditemukan berisi source v1.2.0. Histori v1.3 dari repo `wawanwfs` **belum dipulihkan** di repo pengganti.
- Penambahan tes `archive_drop_categories_are_separate_and_sum_to_total` membuktikan penjumlahan penghitung untuk tiga alasan di level unit. Bukan bukti kehilangan paket kernel atau benchmark UDP di perangkat fisik.
- Mode Admin sekarang menjalankan child dengan parameter PID induk dan baru membuka GUI setelah induk berhenti. **Belum ada pengujian UAC interaktif** sampai mesin Windows tersedia. UAC batal harus meninggalkan jendela lama terbuka.
- Perubahan tidak menyentuh konfigurasi router, adaptor, firewall, atau profil jaringan untuk QA.

## Riwayat laporan 1.2.0

Baseline pengembangan v1.2 adalah `82a25d36e761d619b9f861785071b53cda493cd1`.

| Gate | Bukti |
| --- | --- |
| PASS — unit host | Fixture scheduler, pembatalan, backoff, klasifikasi kegagalan, migrasi schema 1 → 2, retensi, scope router, reload tren dan lease dari backup. |
| Windows CI | Format, Clippy, tes, smoke GUI fixture termasuk kontrol polling, serta paket installer/portable dan checksum. Status final ada di [Actions](https://github.com/wawanwfs/WFS-Network-Toolkit/actions/workflows/windows.yml). |
| PARTIAL — cakupan v1.2 | Histori filter UTC. Catatan/alias lokal, alert per exporter, DHCPv6, provenance flow dan graf topologi belum termasuk. |
| BLOCKED — perangkat dan VM | Belum ada verifikasi RouterOS live, Realtek fisik, upgrade/uninstall VM, atau multi-DPI. |

## Benchmark IPFIX loopback

Tes opsional: `cargo test --locked --offline --release --lib benchmark_udp_million_loopback -- --ignored --nocapture`.

Pengukuran baseline v1.1 pada Linux x64 pada lingkungan Intel Xeon Platinum 8573C dengan kuota arsip 1 GiB. Sepuluh soket UDP loopback dan observation domain terpisah mewakili 10 exporter sintetis; 2.000 IP perangkat, 80 record per datagram dan jeda 3 ms antardatagram. Bukan tes trafik eksternal atau hardware RouterOS.

| Metrik | Hasil |
| --- | --- |
| Terkirim, didekode, tersimpan | 1.000.000 masing-masing |
| Drop arsip / tidak terhitung | 0 / 0 |
| Waktu kirim / laju | 39,20 detik / sekitar 25.510 record per detik |
| Waktu stop collector | 211 ms |
| P95 inspeksi IP, 100 kueri setelah stop | 3,873 ms |
| DB / WAL | 904.785.920 byte setelah stop / 6.423.112 byte sebelum stop |

Tidak mengukur lag per record, RAM puncak, Windows UDP, ataupun beban tanpa jeda. Ini bukan jaminan throughput produksi.

---

## Arsip laporan 1.0.0

Baseline `aed2678a292e10772eda0d8737a6ccf00ec657d4`, 44 tes host lulus sebelum perubahan.

| Gate | Bukti |
| --- | --- |
| PASS — tes host | 50 tes, termasuk batas retensi, idle tanpa trafik, kuota kecil dan drop, backup WAL, salinan pemulihan, perubahan sumber, perlindungan tujuan dan pembatalan hapus jika record berubah. |
| Windows CI | Menjalankan format, Clippy, tes, GUI native dengan fixture, paket portable/NSIS, serta checksum. Lihat [Actions](https://github.com/wawanwfs/WFS-Network-Toolkit/actions/workflows/windows.yml). |
| PARTIAL — observabilitas | Topologi/IPAM, data start/end flow, tren counter, scheduler network dan alert belum diimplementasikan di versi ini. |
| PARTIAL — kondisi operasi | Pengujian kuota SQLite menggunakan fixture, bukan disk fisik penuh. Benchmark penyimpanan langsung lulus, tetapi belum mengukur lag, drop UDP atau waktu stop collector. Belum ada uji semua DPI, volume read-only fisik atau instal/upgrade/uninstall fisik. |
| BLOCKED — perangkat fisik | Tidak ada RouterOS live atau Realtek fisik di lingkungan pengembangan. Tidak ada pengujian pada jaringan produksi. |


## Benchmark penyimpanan sintetis

Dua pengulangan tes `cargo test --locked --offline --release --lib benchmark_archive_million -- --ignored --nocapture` pada Linux x64, Intel Xeon Platinum 8573C. Dataset berisi 1.000.000 record, 10 scope exporter, dan 2.000 IP perangkat. Batch 2.000 record masuk langsung ke SQLite dengan kuota 1 GiB, tanpa UDP.

| Metrik | Hasil |
| --- | --- |
| Tersimpan | 1.000.000 dari 1.000.000 pada kedua pengulangan |
| Waktu tulis | 34,54–36,46 detik |
| Throughput | 27.428–28.954 record/detik |
| P95 inspeksi IP | 5,84–8,97 ms pada 100 query, masing-masing 500 record |
| Ukuran sebelum tutup | DB 812.388.352 byte, WAL 21.971.992 byte |
| RAM puncak proses tes | 9.244 KiB pada satu pengulangan, di luar cache OS |

Angka bukan target kinerja Windows atau ingest UDP. Benchmark tidak mengukur lag antar perangkat, drop di jaringan, atau waktu stop collector. Dataset tidak muat pada kuota default 256 MiB.

---

## Arsip laporan 0.9.0

Baseline `895f28e4e6e1808d08896e843b96acee7f7fe4ff`, 40 tes host lulus sebelum perubahan.

| Gate | Bukti |
| --- | --- |
| PASS — tes host | 44 tes mencakup pivot dan ekspor dengan IP yang sama di beberapa scope, korelasi tuple/interface, waktu usang, beda sesi exporter, IPv6 dan batas ringkasan, backup WAL, deduplikasi histori dan kunci SQLite. |
| PASS — format/lint host | `cargo fmt --check`, format modul Win32, `cargo clippy --locked --all-targets -- -D warnings`. |
| PASS — cross-build Windows GNU x64 | Clippy target Windows, kompilasi tes tanpa menjalankannya, dan build release. |
| Windows CI | Workflow menjalankan format, Clippy, tes, build, CLI read-only, smoke GUI dengan fixture Detail IP/non-mutasi, dan paket NSIS/portable beserta checksum. Hasil per commit tercatat di [Actions](https://github.com/wawanwfs/WFS-Network-Toolkit/actions/workflows/windows.yml). |
| PARTIAL — operasional | Belum ada pilihan UI kuota/retensi dan recovery otomatis, uji sejuta record, uji disk penuh, topologi graf/IPAM, alert, atau verifikasi semua DPI. |
| BLOCKED — perangkat fisik | Belum ada uji RouterOS live, Realtek fisik, dan installer upgrade/uninstall pada mesin Windows 10/11 pengguna. |

---

## Arsip laporan 0.8.0

| Pemeriksaan | Cakupan |
| --- | --- |
| Suite host | 40 tes host lulus. Arsip persisten, identitas database, impor/ekspor, retensi dasar, query site/VRF, dan regresi yang sudah ada. |
| UDP loopback | Dua domain yang menggunakan alamat IP LAN sama, domain tak terdaftar ditolak, buka ulang database, dedup lintas restart dan satu ekspor tersamarkan. |
| Cross-build Windows GNU x64 | Format, Clippy host/Windows, kompilasi tes Windows tanpa menjalankannya, dan build release lulus dengan Rust 1.100. |
| Windows CI | Workflow menjalankan fmt, Clippy, test, CLI read-only dan smoke GUI, lalu membangun paket Windows. Hasil masing-masing run tercatat di [Actions](https://github.com/wawanwfs/WFS-Network-Toolkit/actions/workflows/windows.yml). |
| Di luar uji otomatis | RouterOS fisik, semua DPI, instal/upgrade/uninstall fisik, kehilangan daya, uji sejuta record, dan verifikasi frame Ethernet Realtek. |

Untuk menjalankan rangkaian yang sama, lihat [README](../README.md) dan workflow Windows. Uji perangkat fisik mengikuti [Hardware Acceptance](HARDWARE_ACCEPTANCE.md).

---

## Arsip laporan 0.7.0

| Pemeriksaan | Hasil |
| --- | --- |
| Baseline 0.6.0 | ZIP cocok dengan SHA-256 rilis dan lulus CRC. |
| Unit test host 0.7.0 | 35 lulus, termasuk IPFIX/NetFlow v9, UDP loopback, isolasi domain dan template, histori snapshot, retensi, diff parsial, serta parsing firewall/VLAN. |
| Format, lint, Windows cross-build | Lulus untuk target host dan Windows GNU x64. Binary unit test Windows berhasil dikompilasi, bukan dijalankan. |
| Build portable dan installer | Lulus. ZIP diuji dengan CRC, dan SHA-256 setiap EXE dibandingkan dengan daftar checksum dalam paket. |
| Windows GUI, HTTPS end-to-end, RouterOS live, dan Realtek | Belum diuji pada perangkat nyata. Tidak ada jaringan produksi yang diubah. |

Command yang dijalankan dari root source, dengan toolchain x64 Windows GNU dan MinGW tersedia:

```text
cargo fmt --check
rustfmt --edition 2024 --check src/bin/native/toolkit_window.rs src/bin/native/intelligence_window.rs
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
cargo clippy --locked --offline --target x86_64-pc-windows-gnu --all-targets -- -D warnings
cargo test --locked --offline --target x86_64-pc-windows-gnu --no-run
cargo build --locked --offline --release --target x86_64-pc-windows-gnu
makensis -DBIN_DIR=<absolute-path-to-windows-release> installer/WFS-Network-Toolkit.nsi
```

Gunakan `--smoke-ui` dari Windows untuk memeriksa tampilan tanpa mengubah jaringan atau membuka probe internet. Rencana uji router ada di [Capability Matrix](CAPABILITY_MATRIX.md) dan uji fisik di [Hardware Acceptance](HARDWARE_ACCEPTANCE.md).
