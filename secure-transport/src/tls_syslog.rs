use crate::Result;
use rustls::{RootCertStore, ServerConfig, ServerConnection, StreamOwned, pki_types::{CertificateDer, PrivateKeyDer}, server::{NoServerSessionStorage, WebPkiClientVerifier}};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fs::File, io::{self, Cursor, Read, Write}, net::{SocketAddr, TcpListener, TcpStream}, path::{Path, PathBuf}, sync::Arc, thread, time::{Duration, Instant}};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    bind: SocketAddr,
    server_chain: PathBuf,
    server_key: PathBuf,
    client_ca: PathBuf,
    allowed_client_sha256: Vec<String>,
}
fn bounded_file(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|_| "File konfigurasi/sertifikat tidak dapat dibuka.")?;
    let meta = file.metadata().map_err(|_| "Metadata file gagal.")?;
    if !meta.is_file() || meta.len() > cap as u64 {
        return Err("File bukan reguler atau melewati batas.".into());
    }
    let mut bytes = Vec::new();
    file.take(cap as u64 + 1).read_to_end(&mut bytes).map_err(|_| "Baca file gagal.")?;
    if bytes.len() > cap {
        return Err("File melewati batas.".into());
    }
    Ok(bytes)
}
fn pins(values: &[String]) -> Result<BTreeSet<String>> {
    if !(1..=32).contains(&values.len()) {
        return Err("Diperlukan 1–32 pin SHA-256 sertifikat klien.".into());
    }
    let mut result = BTreeSet::new();
    for pin in values {
        if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !result.insert(pin.clone())
        {
            return Err("Pin sertifikat tidak kanonik atau duplikat.".into());
        }
    }
    Ok(result)
}
fn fingerprint(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}
fn certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let bytes = bounded_file(path, 1024 * 1024)?;
    let result = rustls_pemfile::certs(&mut Cursor::new(bytes))
        .collect::<io::Result<Vec<_>>>().map_err(|_| "PEM sertifikat tidak valid.")?;
    if !(1..=16).contains(&result.len()) {
        return Err("Jumlah sertifikat tidak valid.".into());
    }
    Ok(result)
}
fn key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let bytes = Zeroizing::new(bounded_file(path, 128 * 1024)?);
    let mut cursor = Cursor::new(bytes.as_slice());
    let key = rustls_pemfile::private_key(&mut cursor).map_err(|_| "PEM kunci tidak valid.")?
        .ok_or("Kunci server tidak ditemukan.")?;
    if rustls_pemfile::private_key(&mut cursor).map_err(|_| "PEM kunci tidak valid.")?.is_some() {
        return Err("Lebih dari satu kunci server.".into());
    }
    Ok(key)
}
fn server(config: &Config) -> Result<Arc<ServerConfig>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    for cert in certs(&config.client_ca)? {
        roots.add(cert).map_err(|_| "CA klien tidak valid.")?;
    }
    // Mandatory client certificate validation. No custom verifier or trust bypass.
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build().map_err(|_| "Client verifier gagal.")?;
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|_| "Versi TLS tidak tersedia.")?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs(&config.server_chain)?, key(&config.server_key)?)
        .map_err(|_| "Sertifikat/kunci server tidak cocok.")?;
    server.session_storage = Arc::new(NoServerSessionStorage {});
    server.send_tls13_tickets = 0;
    server.max_early_data_size = 0;
    Ok(Arc::new(server))
}

/// Absolute deadlines enforced per underlying read/write, not just an idle
/// timeout. A peer trickling bytes cannot prolong the session indefinitely.
struct DeadlineSocket {
    socket: TcpStream,
    deadline: Instant,
}
impl DeadlineSocket {
    fn remaining(&self) -> io::Result<Duration> {
        let duration = self.deadline.saturating_duration_since(Instant::now());
        if duration.is_zero() {
            Err(io::Error::new(io::ErrorKind::TimedOut, "deadline"))
        } else {
            Ok(duration)
        }
    }
}
impl Read for DeadlineSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.socket.set_read_timeout(Some(self.remaining()?))?;
        self.socket.read(buf)
    }
}
impl Write for DeadlineSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.set_write_timeout(Some(self.remaining()?))?;
        self.socket.flush()
    }
}
fn listener(bind: SocketAddr) -> Result<TcpListener> {
    if bind.port() == 0 || bind.ip().is_unspecified() || bind.ip().is_multicast()
        || matches!(bind.ip(), std::net::IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err("Bind TLS wajib alamat lokal spesifik.".into());
    }
    let listener = TcpListener::bind(bind).map_err(|_| "Bind TLS gagal.")?;
    listener.set_nonblocking(true).map_err(|_| "Mode listener gagal.")?;
    Ok(listener)
}
fn accept_before(listener: &TcpListener, deadline: Instant) -> Result<Option<TcpStream>> {
    loop {
        if Instant::now() >= deadline {
            return Ok(None);
        }
        match listener.accept() {
            Ok((socket, _)) => {
                socket.set_nonblocking(false).map_err(|_| "Mode socket gagal.")?;
                return Ok(Some(socket));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return Err("Accept TLS gagal.".into()),
        }
    }
}

/// One authenticated, authorized connection. Client trust chain is validated
/// by rustls/WebPKI; the exact leaf certificate must additionally be pinned.
/// No plaintext listener, no early data, no raw Syslog payload persistence.
pub fn receive_once(path: &Path) -> Result<Value> {
    let config: Config = serde_json::from_slice(&bounded_file(path, 16 * 1024)?)
        .map_err(|_| "Konfigurasi TLS tidak valid.")?;
    receive_config(config)
}
fn config_from_pipe() -> Result<Config> {
    use std::io::IsTerminal;
    let stdin = io::stdin();
    if stdin.is_terminal() { return Err("Konfigurasi TLS harus melalui pipe.".into()); }
    let mut data = Vec::new();
    stdin.lock().take(16_385).read_to_end(&mut data).map_err(|_| "Input TLS gagal.")?;
    if data.len() > 16_384 { return Err("Input TLS terlalu besar.".into()); }
    let config: Config = serde_json::from_slice(&data).map_err(|_| "Konfigurasi TLS tidak valid.")?;
    Ok(config)
}
pub fn receive_pipe() -> Result<Value> {
    receive_config(config_from_pipe()?)
}
fn receive_config(config: Config) -> Result<Value> {
    let allowed = pins(&config.allowed_client_sha256)?;
    let settings = server(&config)?;
    let listener = listener(config.bind)?;
    eprintln!("WeNet secure transport: menunggu satu koneksi pada {}", config.bind);
    let socket = accept_before(&listener, Instant::now() + Duration::from_secs(20))?
        .ok_or("Tidak ada koneksi TLS sebelum deadline.")?;
    receive_peer(socket, &config, settings, &allowed, Instant::now() + Duration::from_secs(24))
}
/// Bounded multi-connection listener. Reuses the validated server config,
/// but every new connection independently proves its client identity.
/// Only completed authenticated sessions are emitted; rejected peers do not
/// terminate the listener. No raw Syslog or untrusted diagnostic text in IPC.
pub fn collect_pipe() -> Result<()> {
    let config = config_from_pipe()?;
    let allowed = pins(&config.allowed_client_sha256)?;
    let settings = server(&config)?;
    let listener = listener(config.bind)?;
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut output = io::stdout().lock();
    let mut accepted = 0u32;
    let mut rejected = 0u32;
    for _ in 0..128 {
        let Some(socket) = accept_before(&listener, deadline)? else { break };
        match receive_peer(socket, &config, settings.clone(), &allowed, deadline) {
            Ok(report) => {
                serde_json::to_writer(&mut output, &report).map_err(|_| "Output collector gagal.")?;
                output.write_all(b"\n").and_then(|_| output.flush()).map_err(|_| "Output collector gagal.")?;
                accepted += 1;
            }
            Err(_) => {
                rejected += 1;
                // Sequential admission with a small rejection delay; bound
                // the number of attempts even under repeated hostile connects.
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    eprintln!("WeNet collector: {accepted} sesi diterima, {rejected} sesi ditolak.");
    Ok(())
}
fn receive_peer(socket: TcpStream, config: &Config, settings: Arc<ServerConfig>,
    allowed: &BTreeSet<String>, deadline: Instant) -> Result<Value> {
    let mut io = DeadlineSocket { socket, deadline: deadline.min(Instant::now() + Duration::from_secs(8)) };
    let mut connection = ServerConnection::new(settings).map_err(|_| "TLS gagal.")?;
    while connection.is_handshaking() {
        connection.complete_io(&mut io).map_err(|_| "Handshake TLS ditolak atau timeout.")?;
    }
    let leaf = connection.peer_certificates().and_then(|chain| chain.first())
        .ok_or("Sertifikat klien wajib.")?;
    let pin = fingerprint(leaf.as_ref());
    if !allowed.contains(&pin) {
        return Err("Sertifikat klien tidak diotorisasi.".into());
    }
    io.deadline = deadline.min(Instant::now() + Duration::from_secs(15));
    let mut tls = StreamOwned::new(connection, io);
    let summary = wfs_network_toolkit::intelligence::syslog::read_framed(&mut tls)
        .map_err(|_| "Framing Syslog TLS ditolak atau sesi tidak ditutup dengan benar.")?;
    tls.conn.send_close_notify();
    tls.flush().map_err(|_| "Penutupan TLS gagal.")?;
    let groups: Vec<_> = summary.groups.into_iter().map(|((format, facility, severity), count)| {
        json!({"format": format!("{format:?}"), "facility": facility, "severity": severity, "count": count})
    }).collect();
    Ok(json!({"schema": 1, "transport": "mutual_tls", "peer_certificate_sha256": pin,
        "bind": config.bind.to_string(), "observed_utc": wfs_network_toolkit::intelligence::now(),
        "accepted": summary.accepted, "rejected": summary.rejected, "groups": groups}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pins_are_exact_and_reject_invalid_configuration() {
        let good = fingerprint(b"fixture");
        assert!(pins(std::slice::from_ref(&good)).unwrap().contains(&good));
        assert!(pins(&[]).is_err());
        assert!(pins(&[good.clone(), good.clone()]).is_err());
        assert!(pins(&[good.to_uppercase()]).is_err());
        assert!(pins(&["not a fingerprint".into()]).is_err());
    }
}
