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
    #[serde(default)]
    client_crl: Option<PathBuf>,
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
    let mut verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone());
    if let Some(path) = &config.client_crl {
        let bytes = bounded_file(path, 1024 * 1024)?;
        let lists = rustls_pemfile::crls(&mut Cursor::new(bytes)).collect::<io::Result<Vec<_>>>()
            .map_err(|_| "PEM CRL tidak valid.")?;
        if !(1..=16).contains(&lists.len()) {
            return Err("CRL wajib berisi 1–16 daftar valid.".into());
        }
        // Unknown revocation status remains denied; enforce nextUpdate too.
        verifier = verifier.with_crls(lists).enforce_revocation_expiration();
    }
    let verifier = verifier.build().map_err(|_| "Client verifier gagal.")?;
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
    read_slice: Option<Duration>,
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
        let remaining=self.remaining()?;
        self.socket.set_read_timeout(Some(self.read_slice.map_or(remaining,|slice|slice.min(remaining))))?;
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
/// Bounded streaming collector. Every IPC batch contains only complete frames
/// from a verified connection. A terminal marker releases an admission slot.
pub fn collect_pipe() -> Result<()> {
    use std::sync::atomic::{AtomicUsize,Ordering};
    let config = Arc::new(config_from_pipe()?);
    let allowed = Arc::new(pins(&config.allowed_client_sha256)?);
    let settings = server(&config)?;
    let listener = listener(config.bind)?;
    let deadline = Instant::now() + Duration::from_secs(1800);
    let mut output = io::stdout().lock();
    let mut admissions = 0usize;
    let mut active = 0usize;
    let events=Arc::new(AtomicUsize::new(0));
    let (tx, rx) = std::sync::mpsc::sync_channel::<Option<Value>>(4);
    let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    eprintln!("WeNet collector streaming: {}",config.bind);
    loop {
        while let Ok(event) = rx.try_recv() {
            match event {
                Some(report) => {
                    serde_json::to_writer(&mut output,&report).map_err(|_| "Output collector gagal.")?;
                    output.write_all(b"\n").and_then(|_| output.flush()).map_err(|_| "Output collector gagal.")?;
                }
                None => { active-=1; }
            }
        }
        let mut i=0;
        while i<workers.len() {
            if workers[i].is_finished() {
                workers.swap_remove(i).join().map_err(|_| "Worker TLS gagal.")?;
            } else { i+=1; }
        }
        let exhausted=events.load(Ordering::Acquire)>=16_384;
        if (Instant::now() >= deadline || admissions >= 1024 || exhausted) && active == 0 { break; }
        if Instant::now() < deadline && admissions < 1024 && active < 4 && workers.len() < 4 && !exhausted {
            if let Some(socket)=accept_before(&listener,deadline.min(Instant::now()+Duration::from_millis(50)))? {
                let settings=settings.clone();
                let config=config.clone();
                let allowed=allowed.clone();
                let tx=tx.clone();
                let events=events.clone();
                let connection_id=(admissions+1) as u32;
                let worker=thread::Builder::new().name("wenet-tls-peer".into()).spawn(move || {
                    let emit=|report:Value| -> Result<()> {
                        events.fetch_update(Ordering::AcqRel,Ordering::Acquire,|n|(n<16_384).then_some(n+1))
                            .map_err(|_| "Batas event collector tercapai.")?;
                        tx.send(Some(report)).map_err(|_| "IPC collector ditutup.".into())
                    };
                    if stream_peer(socket,&config,settings,&allowed,deadline,connection_id,&emit).is_err() {
                        let _=emit(json!({"schema":1,"transport":"tls_rejected","bind":config.bind.to_string(),
                            "observed_utc":wfs_network_toolkit::intelligence::now(),
                            "reason":"handshake_or_authorization_or_framing"}));
                    }
                    let _=tx.send(None);
                }).map_err(|_| "Worker TLS tidak dapat dimulai.")?;
                workers.push(worker);
                admissions+=1;
                active+=1;
            }
        } else { thread::sleep(Duration::from_millis(25)); }
    }
    drop(rx);
    for worker in workers { worker.join().map_err(|_| "Worker TLS gagal.")?; }
    if events.load(Ordering::Acquire)>=16_384 { return Err("Batas event collector tercapai.".into()); }
    Ok(())
}

fn stream_peer(socket:TcpStream,config:&Config,settings:Arc<ServerConfig>,
    allowed:&BTreeSet<String>, deadline:Instant, connection_id:u32,
    emit:&impl Fn(Value)->Result<()>) -> Result<()> {
    use wfs_network_toolkit::intelligence::syslog::{FramedStream,Summary};
    let mut io=DeadlineSocket{socket,deadline:deadline.min(Instant::now()+Duration::from_secs(8)),read_slice:None};
    let mut connection=ServerConnection::new(settings).map_err(|_|"TLS gagal.")?;
    while connection.is_handshaking() {
        connection.complete_io(&mut io).map_err(|_|"Handshake TLS ditolak atau timeout.")?;
    }
    let leaf=connection.peer_certificates().and_then(|chain|chain.first()).ok_or("Sertifikat klien wajib.")?;
    let pin=fingerprint(leaf.as_ref());
    if !allowed.contains(&pin) { return Err("Sertifikat klien tidak diotorisasi.".into()); }
    io.deadline=deadline;
    io.read_slice=Some(Duration::from_secs(1));
    let mut tls=StreamOwned::new(connection,io);
    let mut parser=FramedStream::default();
    let mut bytes=[0u8;4096];
    let mut batch_id=0u32;
    let mut publish=|summary:Summary| -> Result<()> {
        batch_id+=1;
        let groups:Vec<_>=summary.groups.into_iter().map(|((format,facility,severity),count)|
            json!({"format":format!("{format:?}"),"facility":facility,"severity":severity,"count":count})).collect();
        emit(json!({"schema":1,"transport":"mutual_tls","bind":config.bind.to_string(),
            "peer_certificate_sha256":pin,"observed_utc":wfs_network_toolkit::intelligence::now(),
            "accepted":summary.accepted,"rejected":summary.rejected,"groups":groups,
            "stream":{"connection":connection_id,"batch":batch_id}}))
    };
    let mut last_read=Instant::now();
    let mut last_flush=last_read;
    let mut partial_since=None;
    let result=(|| -> Result<()> {
        loop {
            let now=Instant::now();
            if now>=deadline { return parser.complete(); }
            if now.duration_since(last_read)>=Duration::from_secs(60)
                || partial_since.is_some_and(|t:Instant|now.duration_since(t)>=Duration::from_secs(15)) {
                return Err("Deadline idle/frame tercapai.".into());
            }
            match tls.read(&mut bytes) {
                Ok(0) => { parser.complete()?; break; }
                Ok(n) => {
                    last_read=Instant::now();
                    let before=parser.in_frame();
                    parser.feed(&bytes[..n],&mut publish)?;
                    if parser.in_frame() {
                        if !before || partial_since.is_none() { partial_since=Some(last_read); }
                    } else { partial_since=None; }
                }
                Err(e) if matches!(e.kind(),io::ErrorKind::TimedOut|io::ErrorKind::WouldBlock|io::ErrorKind::Interrupted) => {}
                Err(_) => return Err("Baca TLS stream gagal.".into()),
            }
            if last_flush.elapsed()>=Duration::from_secs(2) {
                if let Some(summary)=parser.take_summary() { publish(summary)?; }
                last_flush=Instant::now();
            }
        }
        tls.conn.send_close_notify();
        tls.flush().map_err(|_|"Penutupan TLS gagal.".into())
    })();
    // Completed frames are independently valid even when the trailing frame
    // is truncated or the connection fails. Never publish partial raw bytes.
    if let Some(summary)=parser.take_summary() { publish(summary)?; }
    result
}
fn receive_peer(socket: TcpStream, config: &Config, settings: Arc<ServerConfig>,
    allowed: &BTreeSet<String>, deadline: Instant) -> Result<Value> {
    let mut io = DeadlineSocket { socket, deadline: deadline.min(Instant::now() + Duration::from_secs(8)), read_slice: None };
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
