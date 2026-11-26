# WeNet Toolkit by WFS Project — Secure Transport candidate

Opt-in Rust companion, not installed, not a service, not called by the desktop. It uses the root project's actual Syslog framing parser. This is implementation source, **not a security acceptance or release**. Direct dependencies pinned (async-snmp 0.18.1, rustls 0.23.46, rustls-pemfile 2.2.0, Tokio 1.48.0, zeroize 1.8.2); transitive lockfile still requires resolution and audit on a trusted Rust host. The parent lockfile remains unchanged.

## Build / acceptance prerequisites

On an authorized machine with Rust and registry access: from this directory run cargo generate-lockfile; inspect the resolved dependency graph, licenses, MSRV and advisories, then commit this crate's Cargo.lock. Run cargo fmt, cargo clippy --locked --all-targets -- -D warnings, cargo test --locked, cargo build --locked --release. Run the TLS interoperability harness and an authorized SNMPv3 lab agent acceptance before packaging. A failed resolution, audit, negative case or test blocks promotion. Do not weaken the root 12 gates or automatically start this executable.

## SNMPv3

wenet-secure-transport snmpv3-get 192.0.2.10:161 --confirm

Pass a single small JSON object over a non-terminal protected stdin pipe with keys username, auth_password, privacy_password. Do not place credentials in argv, shell history, logs or committed files. Requires authorized agent with SHA-256/AES-128 authPriv; fixed read-only sysUpTime.0 OID. No SET, walk, community fallback, scan, or inferred reachability. Verify successful authPriv, wrong auth key, wrong privacy key, wrong source, downgraded response, replay/timeliness and bounded timeout against lab fixtures. Only the exact success response emits an observation. This is not yet a desktop polling provider or durable SNMP history.

## Mutual TLS Syslog

wenet-secure-transport syslog-tls-once config.json --confirm

Configuration keys: bind (explicit local IP:port), server_chain (PEM path), server_key (unencrypted PEM key path protected by OS ACL), client_ca (PEM trusted roots), allowed_client_sha256 (1–32 lowercase exact DER leaf SHA-256 fingerprints). Generate pins from the DER bytes of each authorized client cert; verify through an independent trusted channel. No wildcard bind, no anonymous peer, no plaintext, no early data, no automatic client trust, no resume. TLS 1.2/1.3 only. One connection and bounded accept/handshake/read deadline, octet-counted input up to 1 MiB, no raw messages stored. Close the TLS session normally after sending data. CA validity and peer pin are both required. No CRL provisioning, automatic certificate rotation, continuous listener, or desktop integration yet.

Protocol/library references: https://docs.rs/async-snmp/0.18.1/async_snmp/ ; https://docs.rs/rustls/0.23.46/rustls/server/struct.WebPkiClientVerifier.html ; https://docs.rs/rustls-pemfile/2.2.0/rustls_pemfile/ .
