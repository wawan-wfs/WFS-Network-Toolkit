use crate::Result;
use async_snmp::{AuthProtocol, Client, PrivProtocol, ResponseShapePolicy, Retry, UsmConfig, Value, oid};
use serde::Deserialize;
use serde_json::{Value as Json, json};
use std::{io::{self, IsTerminal, Read}, net::{IpAddr, SocketAddr}, time::Duration};
use zeroize::{Zeroize, Zeroizing};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    username: String,
    auth_password: String,
    privacy_password: String,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        self.auth_password.zeroize();
        self.privacy_password.zeroize();
    }
}
impl Credentials {
    fn valid(&self) -> bool {
        (1..=32).contains(&self.username.len())
            && !self.username.chars().any(char::is_control)
            && (8..=128).contains(&self.auth_password.len())
            && (8..=128).contains(&self.privacy_password.len())
            && self.auth_password != self.privacy_password
    }
}
fn target(input: &str) -> Result<SocketAddr> {
    let addr: SocketAddr = input.parse().map_err(|_| "Target wajib IP:port eksplisit.")?;
    if addr.port() == 0 || addr.ip().is_unspecified() || addr.ip().is_multicast()
        || matches!(addr.ip(), IpAddr::V4(ip) if ip.is_broadcast())
    {
        return Err("Target SNMP tidak valid.".into());
    }
    Ok(addr)
}
fn credentials() -> Result<Credentials> {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return Err("Gunakan pipe credential aman; jangan masukkan password dalam argumen atau terminal.".into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    stdin.lock().take(4097).read_to_end(&mut bytes).map_err(|_| "Credential pipe gagal.")?;
    if bytes.len() > 4096 {
        return Err("Credential melampaui batas.".into());
    }
    let creds: Credentials = serde_json::from_slice(&bytes).map_err(|_| "Credential JSON tidak valid.")?;
    if !creds.valid() {
        return Err("Username/password SNMPv3 tidak valid; password berbeda, minimal 8 byte.".into());
    }
    Ok(creds)
}

/// GET only, explicit target, exact sysUpTime.0 identity and ASN.1 type.
/// All cryptographic USM processing is delegated to async-snmp; no downgrade.
pub fn get_once(input: &str) -> Result<Json> {
    let addr = target(input)?;
    let creds = credentials()?;
    let auth = UsmConfig::new(creds.username.clone())
        .auth_priv(
            AuthProtocol::Sha256, creds.auth_password.as_bytes(),
            PrivProtocol::Aes128, creds.privacy_password.as_bytes(),
        ).map_err(|_| "Konfigurasi USM authPriv ditolak.")?;
    drop(creds);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all().build().map_err(|_| "Runtime SNMP gagal.")?;
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(15), async {
            let client = Client::builder(addr, auth)
                .construction_timeout(Duration::from_secs(4))
                .request_timeout(Duration::from_secs(4))
                .send_timeout(Duration::from_secs(4))
                .retry(Retry::none())
                .strict_source(true)
                .allow_unauthenticated_v3_time_correction(false)
                .response_shape_policy(ResponseShapePolicy::Strict)
                .connect().await.map_err(|_| "Koneksi SNMPv3 gagal.")?;
            let uptime = oid!(1, 3, 6, 1, 2, 1, 1, 3, 0);
            let response = client.get(&uptime).await.map_err(|_| "GET authPriv gagal atau ditolak.")?;
            let binding = response.single().ok_or("Respons SNMP tidak tunggal.")?;
            if binding.oid != uptime {
                return Err("OID respons tidak cocok.".into());
            }
            let Value::TimeTicks(ticks) = &binding.value else {
                return Err("Tipe respons sysUpTime tidak cocok.".into());
            };
            Ok(json!({"schema": 1, "transport": "SNMPv3", "security": "authPriv",
                "auth_protocol": "SHA-256", "privacy_protocol": "AES-128",
                "target": addr.to_string(), "sys_uptime_ticks": ticks,
                "observed_utc": wfs_network_toolkit::intelligence::now()}))
        }).await.map_err(|_| "Deadline SNMPv3 tercapai.")?
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_ambiguous_targets_and_invalid_credentials() {
        for bad in ["0.0.0.0:161", "[::]:161", "224.0.0.1:161", "255.255.255.255:161",
            "192.0.2.1:0", "router.test:161", "192.0.2.1"] {
            assert!(target(bad).is_err());
        }
        assert!(target("192.0.2.1:161").is_ok());
        let mut c = Credentials { username: "monitor".into(), auth_password: "abcdefgh".into(),
            privacy_password: "ijklmnop".into() };
        assert!(c.valid());
        c.privacy_password = "abcdefgh".into();
        assert!(!c.valid());
        c.privacy_password = "short".into();
        assert!(!c.valid());
    }
}
