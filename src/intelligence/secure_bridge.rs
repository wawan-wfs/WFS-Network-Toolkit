//! Windows-only opt-in bridge. No helper is enabled in ordinary builds.
//! The verified installer must protect the executable directory with OS ACLs.
use super::secure_monitor::{Report, MAX_REPORT, pin_valid, valid_address};
use crate::Result;
use sha2::{Digest, Sha256};
use std::{io::{Read, Write}, net::SocketAddr, os::windows::process::CommandExt, path::{Path, PathBuf}, process::{Command, Stdio}, time::{Duration, Instant}};

pub struct SecretBytes(pub Vec<u8>);
impl Drop for SecretBytes {
    fn drop(&mut self) {
        for byte in &mut self.0 { unsafe { std::ptr::write_volatile(byte,0); } }
    }
}
fn helper() -> Result<PathBuf> {
    let expected = option_env!("WENET_SECURE_HELPER_SHA256").filter(|s| pin_valid(s))
        .ok_or("Secure Transport belum diaktifkan oleh build acceptance.")?;
    let exe = std::env::current_exe().map_err(|_| "Path aplikasi tidak tersedia.")?;
    let path = exe.parent().ok_or("Folder aplikasi tidak tersedia.")?.join("wenet-secure-transport.exe");
    let metadata = std::fs::symlink_metadata(&path).map_err(|_| "Secure Transport tidak terpasang.")?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 * 1024 * 1024 {
        return Err("Secure Transport bukan executable reguler yang valid.".into());
    }
    use std::os::windows::fs::MetadataExt;
    if metadata.file_attributes() & 0x400 != 0 { return Err("Reparse point helper ditolak.".into()); }
    let mut file = std::fs::File::open(&path).map_err(|_| "Helper tidak dapat dibaca.")?;
    let mut hash = Sha256::new();
    let mut buf = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf).map_err(|_| "Baca helper gagal.")?;
        if n == 0 { break; }
        total += n as u64;
        if total > 64 * 1024 * 1024 { return Err("Helper melampaui batas.".into()); }
        hash.update(&buf[..n]);
    }
    let actual: String = hash.finalize().iter().map(|b| format!("{b:02x}")).collect();
    if actual != expected || total != metadata.len() { return Err("Checksum Secure Transport tidak cocok.".into()); }
    Ok(path)
}
pub fn available() -> Result<()> { helper().map(|_| ()) }

fn execute(args: &[&std::ffi::OsStr], secret: Option<SecretBytes>, seconds: u64) -> Result<Report> {
    let path = helper()?;
    let directory = path.parent().ok_or("Folder helper tidak tersedia.")?;
    let mut child = Command::new(&path).args(args).current_dir(directory)
        .stdin(if secret.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped()).stderr(Stdio::null())
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .spawn().map_err(|_| "Secure Transport gagal dimulai.")?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let result = (|| {
        let writer = if let Some(secret) = secret {
            if secret.0.len() > 16_384 { return Err("Input pipe melampaui batas.".into()); }
            let mut stdin = child.stdin.take().ok_or("Input pipe tidak tersedia.")?;
            Some(std::thread::spawn(move || stdin.write_all(&secret.0)))
        } else { None };
        let stdout = child.stdout.take().ok_or("Output helper tidak tersedia.")?;
        let reader = std::thread::spawn(move || {
            let mut data = Vec::new();
            stdout.take(MAX_REPORT as u64 + 1).read_to_end(&mut data).map(|_| data)
        });
        loop {
            if let Some(status) = child.try_wait().map_err(|_| "Status helper gagal.")? {
                if !status.success() { return Err("Secure Transport gagal atau koneksi ditolak.".into()); }
                if let Some(writer) = writer {
                    writer.join().map_err(|_| "Input helper terhenti.")?.map_err(|_| "Input helper gagal.")?;
                }
                let data = reader.join().map_err(|_| "Output helper terhenti.")?.map_err(|_| "Output helper gagal dibaca.")?;
                let report = Report::parse(&data)?;
                if report.stamp().abs_diff(super::now()) > 120 { return Err("Timestamp helper tidak sesuai sesi.".into()); }
                return Ok(report);
            }
            if Instant::now() >= deadline { return Err("Deadline Secure Transport tercapai.".into()); }
            std::thread::sleep(Duration::from_millis(25));
        }
    })();
    if result.is_err() { let _ = child.kill(); let _ = child.wait(); }
    result
}

pub fn snmp(target: SocketAddr, credentials: SecretBytes) -> Result<Report> {
    use std::ffi::OsStr;
    if !valid_address(target) { return Err("Target SNMP tidak valid.".into()); }
    let target_text = target.to_string();
    let r = execute(&[OsStr::new("snmpv3-get"), OsStr::new(&target_text), OsStr::new("--confirm")], Some(credentials), 22)?;
    if !matches!(&r, Report::Snmp { target: a, .. } if *a == target) { return Err("Identitas respons SNMP tidak cocok.".into()); }
    Ok(r)
}

#[derive(serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub bind: SocketAddr,
    pub server_chain: PathBuf,
    pub server_key: PathBuf,
    pub client_ca: PathBuf,
    pub allowed_client_sha256: Vec<String>,
}
impl TlsConfig {
    pub fn read(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|_| "Konfigurasi TLS tidak tersedia.")?;
        if !file.metadata().map_err(|_| "Metadata konfigurasi gagal.")?.is_file() { return Err("Konfigurasi TLS bukan file reguler.".into()); }
        let mut data = Vec::new();
        file.take(16_385).read_to_end(&mut data).map_err(|_| "Baca konfigurasi TLS gagal.")?;
        if data.len() > 16_384 { return Err("Konfigurasi TLS terlalu besar.".into()); }
        let c: Self = serde_json::from_slice(&data).map_err(|_| "Konfigurasi TLS tidak valid.")?;
        if !valid_address(c.bind) || !(1..=32).contains(&c.allowed_client_sha256.len())
            || c.allowed_client_sha256.iter().any(|p| !pin_valid(p))
            || c.allowed_client_sha256.iter().collect::<std::collections::BTreeSet<_>>().len() != c.allowed_client_sha256.len()
            || [&c.server_chain,&c.server_key,&c.client_ca].iter().any(|p| !p.is_absolute()) {
            return Err("Bind, path absolut atau pin TLS tidak valid.".into());
        }
        Ok(c)
    }
}
pub fn tls(path: &Path, expected: &TlsConfig) -> Result<Report> {
    use std::ffi::OsStr;
    let actual = TlsConfig::read(path)?;
    if actual.bind != expected.bind || actual.allowed_client_sha256 != expected.allowed_client_sha256
        || actual.server_chain != expected.server_chain || actual.server_key != expected.server_key
        || actual.client_ca != expected.client_ca { return Err("Konfigurasi TLS berubah; batalkan.".into()); }
    // Pass the exact confirmed configuration rather than a mutable file path.
    // The certificate/key files still require OS ACL protection.
    let mut payload = SecretBytes(Vec::with_capacity(16_384));
    serde_json::to_writer(&mut payload.0, expected).map_err(|_| "Serialisasi konfigurasi gagal.")?;
    let r = execute(&[OsStr::new("syslog-tls-pipe"),OsStr::new("--confirm")], Some(payload), 50)?;
    if !matches!(&r,Report::Tls{bind,peer_certificate_sha256,..} if *bind == expected.bind && expected.allowed_client_sha256.contains(peer_certificate_sha256)) {
        return Err("Identitas respons TLS tidak cocok.".into());
    }
    Ok(r)
}
