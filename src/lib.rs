pub mod adapter_state;
pub mod intelligence;
pub mod migration;
pub mod ui_layout;

use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt, net::Ipv4Addr, path::Path, str::FromStr};

#[cfg(windows)]
pub mod windows;

pub type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Mac([u8; 6]);
impl Mac {
    pub fn from_bytes(bytes: [u8; 6]) -> Result<Self> {
        if bytes == [0; 6] || bytes[0] & 1 != 0 {
            return Err("MAC nol, broadcast, atau multicast tidak valid".into());
        }
        Ok(Self(bytes))
    }
    pub fn compact(self) -> String {
        self.0.iter().map(|b| format!("{b:02X}")).collect()
    }
    pub fn locally_administered(self) -> bool {
        self.0[0] & 2 != 0
    }
}
impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, "-")?;
            }
            write!(f, "{b:02X}")?;
        }
        Ok(())
    }
}
impl FromStr for Mac {
    type Err = String;
    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        let b = s.as_bytes();
        let hex: Vec<u8> = match b.len() {
            12 => b.to_vec(),
            17 if b[2] == b'-' || b[2] == b':' => {
                if [2, 5, 8, 11, 14].iter().any(|&i| b[i] != b[2]) {
                    return Err("Pemisah MAC tidak konsisten".into());
                }
                b.iter()
                    .enumerate()
                    .filter_map(|(i, &x)| (i % 3 != 2).then_some(x))
                    .collect()
            }
            _ => return Err("MAC harus terdiri dari 12 digit heksadesimal".into()),
        };
        let mut out = [0; 6];
        for (i, pair) in hex.as_chunks::<2>().0.iter().enumerate() {
            let text = std::str::from_utf8(pair).map_err(|_| "MAC bukan heksadesimal")?;
            out[i] = u8::from_str_radix(text, 16).map_err(|_| "MAC bukan heksadesimal")?;
            if !pair.iter().all(u8::is_ascii_hexdigit) {
                return Err("MAC bukan heksadesimal".into());
            }
        }
        Self::from_bytes(out)
    }
}
impl TryFrom<String> for Mac {
    type Error = String;
    fn try_from(s: String) -> Result<Self> {
        s.parse()
    }
}
impl From<Mac> for String {
    fn from(m: Mac) -> Self {
        m.to_string()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Address {
    pub ip: Ipv4Addr,
    pub prefix: u8,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4 {
    pub dhcp: bool,
    pub addresses: Vec<Address>,
    pub gateway: Option<Ipv4Addr>,
    pub dns: Option<Vec<Ipv4Addr>>,
}
pub fn parse_mask(s: &str) -> Result<u8> {
    if let Ok(p) = s.parse::<u8>() {
        return (1..=32)
            .contains(&p)
            .then_some(p)
            .ok_or_else(|| "Prefix di luar 1..32".into());
    }
    let ip: Ipv4Addr = s.parse().map_err(|_| "Subnet mask tidak valid")?;
    let n = u32::from(ip);
    let p = n.leading_ones() as u8;
    if p == 0 || n != u32::from(mask(p)) {
        return Err("Subnet mask harus berurutan".into());
    }
    Ok(p)
}
pub fn mask(p: u8) -> Ipv4Addr {
    Ipv4Addr::from(if p == 0 {
        0
    } else {
        u32::MAX << (32 - p.min(32))
    })
}
pub fn usable(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified() && !ip.is_broadcast() && !ip.is_multicast() && !ip.is_loopback()
}
impl Ipv4 {
    pub fn validate(&self) -> Result<()> {
        if self.addresses.len() > 16 || (!self.dhcp && self.addresses.is_empty()) {
            return Err("IPv4 statis membutuhkan 1–16 alamat".into());
        }
        if self
            .addresses
            .iter()
            .any(|a| !(1..=32).contains(&a.prefix) || !usable(a.ip))
        {
            return Err("Alamat/prefix IPv4 tidak valid".into());
        }
        if self
            .addresses
            .iter()
            .map(|a| a.ip)
            .collect::<HashSet<_>>()
            .len()
            != self.addresses.len()
        {
            return Err("Alamat IPv4 ganda".into());
        }
        if self.dhcp && (!self.addresses.is_empty() || self.gateway.is_some()) {
            return Err("Jangan gunakan nilai lease sebagai konfigurasi DHCP".into());
        }
        if self.gateway.is_some_and(|g| !usable(g)) {
            return Err("Gateway tidak valid".into());
        }
        if self.dns.as_ref().is_some_and(|v| {
            v.is_empty()
                || v.len() > 16
                || v.iter().any(|&ip| !usable(ip))
                || v.iter().collect::<HashSet<_>>().len() != v.len()
        }) {
            return Err("DNS manual harus memuat 1–16 alamat IPv4 valid dan unik".into());
        }
        Ok(())
    }
    pub fn gateway_outside(&self) -> bool {
        self.gateway.is_some_and(|g| {
            !self.addresses.iter().any(|a| {
                (u32::from(a.ip) & u32::from(mask(a.prefix)))
                    == (u32::from(g) & u32::from(mask(a.prefix)))
            })
        })
    }
    pub fn matches(&self, other: &Self) -> bool {
        self.same_addressing(other) && self.dns == other.dns
    }
    pub fn same_addressing(&self, other: &Self) -> bool {
        self.dhcp == other.dhcp
            && self.gateway == other.gateway
            && self.addresses.iter().collect::<HashSet<_>>()
                == other.addresses.iter().collect::<HashSet<_>>()
    }
}
pub fn ipv4_commands(want: &Ipv4, previous: Option<&Ipv4>) -> Result<Vec<Vec<String>>> {
    want.validate()?;
    let mut commands = Vec::new();
    let address_changed = previous.is_none_or(|old| !old.same_addressing(want));
    if address_changed {
        let mut cmd = vec!["set".into(), "address".into()];
        if want.dhcp {
            cmd.push("source=dhcp".into());
        } else {
            let primary = want
                .gateway
                .and_then(|gateway| {
                    want.addresses.iter().position(|a| {
                        let m = u32::from(mask(a.prefix));
                        (u32::from(a.ip) & m) == (u32::from(gateway) & m)
                    })
                })
                .unwrap_or(0);
            let first = want.addresses[primary];
            cmd.extend([
                "source=static".into(),
                format!("address={}", first.ip),
                format!("mask={}", mask(first.prefix)),
                format!(
                    "gateway={}",
                    want.gateway
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "none".into())
                ),
            ]);
            commands.push(cmd);
            for (i, a) in want.addresses.iter().enumerate() {
                if i != primary {
                    commands.push(vec![
                        "add".into(),
                        "address".into(),
                        format!("address={}", a.ip),
                        format!("mask={}", mask(a.prefix)),
                    ]);
                }
            }
            cmd = Vec::new();
        }
        if !cmd.is_empty() {
            commands.push(cmd);
        }
    }
    if previous.is_none_or(|old| old.dns != want.dns) {
        commands.extend(dns_commands(want.dns.as_deref()));
    }
    Ok(commands)
}
fn dns_commands(dns: Option<&[Ipv4Addr]>) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    if let Some(dns) = dns.filter(|d| !d.is_empty()) {
        commands.push(vec![
            "set".into(),
            "dnsservers".into(),
            "source=static".into(),
            format!("address={}", dns[0]),
            "validate=no".into(),
        ]);
        for (i, ip) in dns.iter().enumerate().skip(1) {
            commands.push(vec![
                "add".into(),
                "dnsservers".into(),
                format!("address={ip}"),
                format!("index={}", i + 1),
                "validate=no".into(),
            ]);
        }
    } else {
        commands.push(vec![
            "set".into(),
            "dnsservers".into(),
            "source=dhcp".into(),
        ]);
    }
    commands
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backup {
    pub format: u8,
    pub source_id: String,
    pub source_name: String,
    pub ipv4: Option<Ipv4>,
    pub mac: Option<Mac>,
}
#[derive(Deserialize)]
struct Legacy {
    #[serde(rename = "FormatVersion")]
    format: u8,
    #[serde(rename = "IPv4")]
    ip: Ipv4Addr,
    #[serde(rename = "SubnetMask")]
    mask: String,
    #[serde(rename = "Gateway", default)]
    gateway: String,
    #[serde(rename = "DNS1", default)]
    dns1: String,
    #[serde(rename = "DNS2", default)]
    dns2: String,
}
pub fn read_backup(path: &Path) -> Result<(Backup, bool)> {
    let data = read_small(path)?;
    let v: serde_json::Value =
        serde_json::from_str(&data).map_err(|e| format!("JSON backup tidak valid: {e}"))?;
    if v.get("format").is_some() {
        let b: Backup =
            serde_json::from_str(&data).map_err(|e| format!("Format backup tidak valid: {e}"))?;
        if b.format != 1 {
            return Err("Versi backup tidak didukung".into());
        }
        if b.ipv4.is_none() && b.mac.is_none() {
            return Err("File tidak memuat IPv4/DNS maupun MAC.".into());
        }
        if b.source_name.chars().count() > 256 || b.source_name.chars().any(char::is_control) {
            return Err("Nama sumber pada profil tidak valid.".into());
        }
        if let Some(ref ip) = b.ipv4 {
            ip.validate()?;
        }
        return Ok((b, false));
    }
    let l: Legacy =
        serde_json::from_str(&data).map_err(|e| format!("Format backup lama tidak valid: {e}"))?;
    if l.format != 1 {
        return Err("Versi backup lama tidak didukung".into());
    }
    let dns = [l.dns1, l.dns2]
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| {
            s.trim()
                .parse()
                .map_err(|_| "DNS backup lama tidak valid".to_string())
        })
        .collect::<Result<Vec<_>>>()?;
    let ip = Ipv4 {
        dhcp: false,
        addresses: vec![Address {
            ip: l.ip,
            prefix: parse_mask(l.mask.trim())?,
        }],
        gateway: optional_ipv4(&l.gateway)?,
        dns: (!dns.is_empty()).then_some(dns),
    };
    ip.validate()?;
    Ok((
        Backup {
            format: 1,
            source_id: String::new(),
            source_name: "Backup IPv4 lama".into(),
            ipv4: Some(ip),
            mac: None,
        },
        true,
    ))
}
pub fn optional_ipv4(s: &str) -> Result<Option<Ipv4Addr>> {
    if s.trim().is_empty() {
        Ok(None)
    } else {
        s.trim()
            .parse()
            .map(Some)
            .map_err(|_| format!("IPv4 tidak valid: {s}"))
    }
}
pub fn read_small(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut out = String::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(262_145).read_to_string(&mut out))
        .map_err(|e| format!("Tidak bisa membaca {}: {e}", path.display()))?;
    if out.len() > 262_144 {
        return Err("Ukuran JSON melebihi 256 KiB".into());
    }
    Ok(out.trim_start_matches('\u{feff}').to_owned())
}
pub fn write_new_json(path: &Path, value: &impl Serialize) -> Result<()> {
    use std::io::Write;
    let data = serde_json::to_vec_pretty(value).map_err(|e| e.to_string())?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| format!("Tidak bisa membuat {}: {e}", path.display()))?;
    if let Err(e) = file.write_all(&data).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("Gagal menyimpan {}: {e}", path.display()));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacRequest {
    Keep,
    Set(Mac),
    Factory,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MacPlan {
    Skip,
    Set(Mac),
    Factory,
}
pub fn mac_plan(active: Option<Mac>, request: MacRequest) -> MacPlan {
    match request {
        MacRequest::Keep => MacPlan::Skip,
        MacRequest::Set(want) if active == Some(want) => MacPlan::Skip,
        MacRequest::Set(want) => MacPlan::Set(want),
        MacRequest::Factory => MacPlan::Factory,
    }
}

pub fn execute_transaction(
    mac_needed: bool,
    ip_needed: bool,
    mut apply_mac: impl FnMut() -> Result<()>,
    mut apply_ip: impl FnMut() -> Result<()>,
    mut restore_mac: impl FnMut() -> Result<()>,
    mut restore_ip: impl FnMut() -> Result<()>,
) -> Result<()> {
    if mac_needed && let Err(e) = apply_mac() {
        return Err(match restore_mac() {
            Ok(()) => format!("{e}\nMAC awal terverifikasi; IPv4 tidak diubah."),
            Err(r) => format!("{e}\nRECOVERY REQUIRED — MAC: {r}\nIPv4 tidak diubah."),
        });
    }
    if ip_needed && let Err(e) = apply_ip() {
        let m = if mac_needed { restore_mac() } else { Ok(()) };
        let i = restore_ip();
        return Err(match (m, i) {
            (Ok(()), Ok(())) => format!("{e}\nKonfigurasi awal terverifikasi."),
            (m, i) => format!(
                "{e}\nRECOVERY REQUIRED — MAC: {}; IPv4/DNS: {}",
                m.err().unwrap_or_else(|| "ok".into()),
                i.err().unwrap_or_else(|| "ok".into())
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mac_accepts_exact_and_local_without_rewriting() {
        let a: Mac = "B4-2E-99-73-36-B1".parse().unwrap();
        assert_eq!(a.compact(), "B42E997336B1");
        assert!(!a.locally_administered());
        assert!(
            "02:17:20:10:00:01"
                .parse::<Mac>()
                .unwrap()
                .locally_administered()
        );
        for bad in [
            "01:00:00:00:00:00",
            "FFFFFFFFFFFF",
            "000000000000",
            "02:AA-BB:00:00:11",
            "+2AABB000011",
            "02:é:FF:AA:BB:12",
        ] {
            assert!(bad.parse::<Mac>().is_err(), "{bad}");
        }
    }
    #[test]
    fn mac_equal_noop_but_reset_explicit() {
        let m = "B42E997336B1".parse().unwrap();
        assert_eq!(mac_plan(Some(m), MacRequest::Set(m)), MacPlan::Skip);
        assert_eq!(mac_plan(Some(m), MacRequest::Keep), MacPlan::Skip);
        assert_eq!(mac_plan(Some(m), MacRequest::Factory), MacPlan::Factory);
    }
    #[test]
    fn subnet_fixture() {
        let mut ip = Ipv4 {
            dhcp: false,
            addresses: vec![Address {
                ip: "172.20.95.190".parse().unwrap(),
                prefix: 16,
            }],
            gateway: Some("172.20.140.15".parse().unwrap()),
            dns: None,
        };
        assert!(!ip.gateway_outside());
        ip.addresses[0].prefix = 24;
        assert!(ip.gateway_outside());
        assert_eq!(parse_mask("255.255.0.0"), Ok(16));
        assert!(parse_mask("255.0.255.0").is_err());
    }
    #[test]
    fn mac_failure_never_writes_ip() {
        let e = execute_transaction(
            true,
            true,
            || Err("driver rejected".into()),
            || panic!("IP must be untouched"),
            || Ok(()),
            || panic!("IP must be untouched"),
        )
        .unwrap_err();
        assert!(e.contains("MAC awal terverifikasi"));
    }
    #[test]
    fn ip_failure_attempts_both_rollbacks_even_if_one_fails() {
        let trace = std::cell::RefCell::new(Vec::new());
        let e = execute_transaction(
            true,
            true,
            || {
                trace.borrow_mut().push("mac");
                Ok(())
            },
            || {
                trace.borrow_mut().push("ip");
                Err("dns failed".into())
            },
            || {
                trace.borrow_mut().push("undo mac");
                Err("restart".into())
            },
            || {
                trace.borrow_mut().push("undo ip");
                Ok(())
            },
        )
        .unwrap_err();
        assert_eq!(trace.into_inner(), vec!["mac", "ip", "undo mac", "undo ip"]);
        assert!(e.contains("RECOVERY REQUIRED"));
    }
    #[test]
    fn ip_only_never_calls_mac() {
        assert!(
            execute_transaction(
                false,
                true,
                || panic!(),
                || Ok(()),
                || panic!(),
                || panic!()
            )
            .is_ok()
        );
    }
    #[test]
    fn dhcp_refuses_lease_in_config() {
        let ip = Ipv4 {
            dhcp: true,
            addresses: vec![Address {
                ip: "192.168.1.7".parse().unwrap(),
                prefix: 24,
            }],
            gateway: None,
            dns: None,
        };
        assert!(ip.validate().is_err());
    }
    #[test]
    fn commands_keep_dhcp_lease_when_changing_only_dns() {
        let auto = Ipv4 {
            dhcp: true,
            addresses: vec![],
            gateway: None,
            dns: None,
        };
        let manual = Ipv4 {
            dns: Some(vec![
                "172.20.140.15".parse().unwrap(),
                "8.8.8.8".parse().unwrap(),
            ]),
            ..auto.clone()
        };
        let commands = ipv4_commands(&manual, Some(&auto)).unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(
            commands[0],
            [
                "set",
                "dnsservers",
                "source=static",
                "address=172.20.140.15",
                "validate=no"
            ]
        );
        assert_eq!(
            commands[1],
            [
                "add",
                "dnsservers",
                "address=8.8.8.8",
                "index=2",
                "validate=no"
            ]
        );
        assert_eq!(
            ipv4_commands(&auto, Some(&manual)).unwrap(),
            [vec!["set", "dnsservers", "source=dhcp"]]
        );
        assert!(ipv4_commands(&auto, Some(&auto)).unwrap().is_empty());
    }

    #[test]
    fn commands_select_gateway_subnet_and_preserve_secondary_addresses() {
        let ip = Ipv4 {
            dhcp: false,
            addresses: vec![
                Address {
                    ip: "192.168.1.50".parse().unwrap(),
                    prefix: 24,
                },
                Address {
                    ip: "172.20.95.190".parse().unwrap(),
                    prefix: 16,
                },
            ],
            gateway: Some("172.20.140.15".parse().unwrap()),
            dns: None,
        };
        let commands = ipv4_commands(&ip, None).unwrap();
        assert_eq!(commands.len(), 3);
        assert_eq!(
            commands[0],
            [
                "set",
                "address",
                "source=static",
                "address=172.20.95.190",
                "mask=255.255.0.0",
                "gateway=172.20.140.15"
            ]
        );
        assert_eq!(
            commands[1],
            [
                "add",
                "address",
                "address=192.168.1.50",
                "mask=255.255.255.0"
            ]
        );
    }

    #[test]
    fn legacy_bom_import_and_new_roundtrip() {
        let path =
            std::env::temp_dir().join(format!("wfs-test-{}-legacy.json", std::process::id()));
        std::fs::write(&path, "\u{feff}{\"FormatVersion\":1,\"IPv4\":\"172.20.95.190\",\"SubnetMask\":\"255.255.0.0\",\"Gateway\":\"172.20.140.15\",\"DNS1\":\"172.20.140.15\",\"DNS2\":\"8.8.8.8\"}").unwrap();
        let (b, legacy) = read_backup(&path).unwrap();
        assert!(legacy);
        assert_eq!(b.ipv4.as_ref().unwrap().addresses[0].prefix, 16);
        std::fs::remove_file(&path).unwrap();
        write_new_json(&path, &b).unwrap();
        assert!(write_new_json(&path, &b).is_err());
        assert!(!read_backup(&path).unwrap().1);
        std::fs::remove_file(&path).unwrap();
    }
    #[test]
    fn malformed_backup_cannot_be_prepared() {
        let path =
            std::env::temp_dir().join(format!("wfs-test-{}-malformed.json", std::process::id()));
        for (data, expected) in [
            (
                r#"{"format":1,"source_id":"","source_name":"Uji","ipv4":null,"mac":null}"#,
                "tidak memuat",
            ),
            (
                r#"{"format":1,"source_id":"","source_name":"Uji","ipv4":null,"mac":null,"mac":"02-00-00-00-00-01"}"#,
                "duplicate field",
            ),
            (
                r#"{"format":1,"source_id":"","source_name":"Uji\nLain","ipv4":null,"mac":"02-00-00-00-00-01"}"#,
                "Nama sumber",
            ),
        ] {
            std::fs::write(&path, data).unwrap();
            assert!(read_backup(&path).unwrap_err().contains(expected));
        }
        std::fs::remove_file(path).unwrap();
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Subnet {
    pub prefix: u8,
    pub mask: Ipv4Addr,
    pub network: Ipv4Addr,
    pub broadcast: Option<Ipv4Addr>,
    pub first: Ipv4Addr,
    pub last: Ipv4Addr,
    pub host_count: u64,
}
pub fn subnet(ip: Ipv4Addr, prefix: u8) -> Result<Subnet> {
    if !(1..=32).contains(&prefix) {
        return Err("Prefix di luar 1–32".into());
    }
    let mask = mask(prefix);
    let network = u32::from(ip) & u32::from(mask);
    let end = network | !u32::from(mask);
    let broadcast = (prefix < 31).then(|| Ipv4Addr::from(end));
    let offset = u32::from(prefix < 31);
    Ok(Subnet {
        prefix,
        mask,
        network: network.into(),
        broadcast,
        first: (network + offset).into(),
        last: (end - offset).into(),
        host_count: u64::from(end) - u64::from(network) + 1 - u64::from(offset) * 2,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    pub id: String,
    pub expected_mac: Option<Mac>,
    pub expected_ipv4: Option<Ipv4>,
    pub ip: Option<Ipv4>,
    pub mac: Option<Mac>,
    pub factory: bool,
    pub recover: bool,
    pub recovery_version: Option<String>,
}
impl Change {
    pub fn request(&self) -> Result<MacRequest> {
        if self.recover != self.recovery_version.is_some()
            || self.recovery_version.as_ref().is_some_and(|v| {
                v.split_once(':').is_none_or(|(stage, hash)| {
                    !matches!(stage, "0" | "1")
                        || hash.len() != 64
                        || !hash.bytes().all(|b| b.is_ascii_hexdigit())
                })
            })
            || self.factory && self.mac.is_some()
            || self.recover && (self.ip.is_some() || self.mac.is_some() || self.factory)
        {
            return Err("Jenis perubahan bertentangan".into());
        }
        if self.recover || self.factory || self.mac.is_some() || self.ip.is_some() {
            if let Some(ip) = &self.ip {
                ip.validate()?;
            }
            if self.ip.is_some() != self.expected_ipv4.is_some() {
                return Err("Snapshot pratinjau IPv4 tidak valid".into());
            }
            Ok(if self.factory {
                MacRequest::Factory
            } else if let Some(mac) = self.mac {
                MacRequest::Set(mac)
            } else {
                MacRequest::Keep
            })
        } else {
            Err("Tidak ada bidang yang dipilih".into())
        }
    }
    pub fn encode(&self) -> Result<String> {
        self.request()?;
        let bytes = serde_json::to_vec(self).map_err(|e| e.to_string())?;
        if bytes.len() > 4096 {
            return Err("Ukuran rencana perubahan terlalu besar".into());
        }
        Ok(bytes.into_iter().map(|b| format!("{b:02x}")).collect())
    }
    pub fn decode(s: &str) -> Result<Self> {
        if s.is_empty()
            || s.len() > 8192
            || !s.len().is_multiple_of(2)
            || !s.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("Payload perubahan tidak valid".into());
        }
        let bytes = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("validated hex"))
            .collect::<Vec<_>>();
        let change: Self = serde_json::from_slice(&bytes)
            .map_err(|e| format!("Rencana perubahan tidak valid: {e}"))?;
        change.request()?;
        Ok(change)
    }
}
#[cfg(test)]
mod v2_tests {
    use super::*;
    #[test]
    fn subnet_includes_gateway_and_handles_point_to_point() {
        let s = subnet("172.20.95.190".parse().unwrap(), 16).unwrap();
        assert_eq!(s.network.to_string(), "172.20.0.0");
        assert_eq!(s.host_count, 65534);
        let s = subnet("192.168.4.255".parse().unwrap(), 31).unwrap();
        assert_eq!(s.first.to_string(), "192.168.4.254");
        assert_eq!(s.last.to_string(), "192.168.4.255");
        assert_eq!(s.host_count, 2);
        assert_eq!(s.broadcast, None);
        assert_eq!(
            subnet("192.168.4.255".parse().unwrap(), 32)
                .unwrap()
                .host_count,
            1
        );
        assert!(subnet("192.168.4.255".parse().unwrap(), 0).is_err());
    }
    #[test]
    fn elevated_payload_is_bounded_typed_and_rejects_combined_recovery() {
        let mut c = Change {
            id: "{12345678-1111-2222-AAAA-333333333333}".into(),
            expected_mac: None,
            expected_ipv4: None,
            ip: None,
            mac: Some("02-17-20-10-00-01".parse().unwrap()),
            factory: false,
            recover: false,
            recovery_version: None,
        };
        let encoded = c.encode().unwrap();
        assert!(encoded.bytes().all(|v| v.is_ascii_hexdigit()));
        assert_eq!(Change::decode(&encoded).unwrap(), c);
        assert!(Change::decode("AA--").is_err());
        assert!(Change::decode(&"AA".repeat(4097)).is_err());
        c.recover = true;
        assert!(c.encode().is_err());
        c.mac = None;
        c.recovery_version = Some("0:invalid".into());
        assert!(c.encode().is_err());
        c.recovery_version = Some(format!("1:{}", "ae".repeat(32)));
        assert_eq!(Change::decode(&c.encode().unwrap()).unwrap(), c);
    }
}
