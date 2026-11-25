use crate::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt,
    net::{IpAddr, SocketAddr},
    time::{SystemTime, UNIX_EPOCH},
};

pub mod alert_ledger;
pub mod archive_ops;
pub mod collector_alerts;
pub mod device;
pub mod dhcp6;
pub mod dhcp6_history;
pub mod flow;
pub mod graph;
pub mod history;
pub mod interface_trend;
pub mod ipam_notes;
pub mod network_map;
pub mod overview;
pub mod polling;
pub mod router;
pub mod router_history;
pub mod store;
pub mod syslog;
pub mod visual;
#[cfg(windows)]
pub mod windows;

pub const LIMIT: usize = 50_000;
pub const FRESH_SECONDS: u64 = 900;

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn label(s: &str) -> String {
    s.chars()
        .take(160)
        .map(|c| {
            if c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}') {
                ' '
            } else {
                c
            }
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum EndpointState {
    Listening,
    Established,
    Attempt,
    Bound,
    Other(u32),
}
impl fmt::Display for EndpointState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Listening => f.write_str("Listening"),
            Self::Established => f.write_str("Established"),
            Self::Attempt => f.write_str("Handshake"),
            Self::Bound => f.write_str("Bound (UDP)"),
            Self::Other(n) => write!(f, "TCP {n}"),
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Endpoint {
    pub protocol: Protocol,
    pub local: SocketAddr,
    pub remote: Option<SocketAddr>,
    pub state: EndpointState,
    pub pid: u32,
    pub process: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Neighbor {
    pub ip: IpAddr,
    pub interface_index: u32,
    pub scope_id: u32,
    pub mac: Option<crate::Mac>,
    pub cache_state: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalAddress {
    pub ip: IpAddr,
    pub interface_index: u32,
    pub scope_id: u32,
    pub prefix: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Coverage {
    pub source: String,
    pub observed_at: u64,
    pub state: CoverageState,
    pub rows: usize,
    pub detail: Option<String>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CoverageState {
    CompleteSnapshot,
    Partial,
    Unavailable,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSnapshot {
    pub schema: u8,
    pub observed_at: u64,
    pub addresses: Vec<LocalAddress>,
    pub neighbors: Vec<Neighbor>,
    pub endpoints: Vec<Endpoint>,
    pub coverage: Vec<Coverage>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProbeOutcome {
    Verified,
    NoAttribution,
    UnexpectedResponse,
    TransportError,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Probe {
    pub observed_at: u64,
    pub elapsed_ms: u64,
    pub target: String,
    pub source: Option<SocketAddr>,
    pub destination: Option<SocketAddr>,
    pub interface_index: Option<u32>,
    pub http_status: Option<u32>,
    pub outcome: ProbeOutcome,
    pub detail: String,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Access {
    TestedHere,
    WanReplyObserved,
    WanAttemptObserved,
    LanOnlyObserved,
    Unknown,
    Stale,
}
impl fmt::Display for Access {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TestedHere => "Teruji dari PC ini",
            Self::WanReplyObserved => "Trafik WAN dua arah teramati",
            Self::WanAttemptObserved => "Hanya upaya WAN teramati",
            Self::LanOnlyObserved => "Hanya bukti LAN teramati",
            Self::Unknown => "Belum ada bukti",
            Self::Stale => "Bukti kedaluwarsa",
        })
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum EvidenceKind {
    WanReply,
    WanAttempt,
    Lan,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficEvidence {
    pub ip: IpAddr,
    pub scope: String,
    pub sensor: String,
    pub observed_at: u64,
    pub kind: EvidenceKind,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficImport {
    pub schema: u8,
    pub entries: Vec<TrafficEvidence>,
}
impl TrafficImport {
    pub fn parse(input: &str) -> Result<Self> {
        let mut f: Self =
            serde_json::from_str(input).map_err(|e| format!("Bukti tidak valid: {e}"))?;
        if f.schema != 1 || f.entries.len() > LIMIT {
            return Err("Versi atau jumlah bukti tidak didukung.".into());
        }
        for e in &mut f.entries {
            if e.scope.trim().is_empty()
                || e.sensor.trim().is_empty()
                || e.scope.len() > 120
                || e.sensor.len() > 120
                || e.scope.chars().any(char::is_control)
                || e.sensor.chars().any(char::is_control)
                || e.ip.is_unspecified()
                || e.ip.is_multicast()
                || e.ip.is_loopback()
            {
                return Err("Bukti memerlukan scope, sensor, dan IP unicast yang valid.".into());
            }
            e.scope = label(e.scope.trim());
            e.sensor = label(e.sensor.trim());
            if e.scope.trim().is_empty() || e.sensor.trim().is_empty() {
                return Err("Scope atau sensor kosong setelah sanitasi.".into());
            }
        }
        Ok(f)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Assessment {
    pub ip: IpAddr,
    pub scope: String,
    pub observed_at: u64,
    pub access: Access,
    pub evidence: String,
}
pub fn assess(snapshot: &LocalSnapshot, probe: Option<&Probe>, at: u64) -> Vec<Assessment> {
    let mut rows = BTreeMap::new();
    let observation_status = if at.saturating_sub(snapshot.observed_at) > FRESH_SECONDS {
        Access::Stale
    } else {
        Access::Unknown
    };
    for n in &snapshot.neighbors {
        // A cache entry is evidence of visibility, not proof of successful LAN traffic.
        rows.entry((n.ip, n.interface_index)).or_insert(Assessment {
            ip: n.ip,
            scope: format!("Windows / if#{}", n.interface_index),
            observed_at: snapshot.observed_at,
            access: observation_status,
            evidence: format!(
                "Cache ARP/ND ({}), bukan bukti akses internet",
                n.cache_state
            ),
        });
    }
    for a in &snapshot.addresses {
        rows.insert(
            (a.ip, a.interface_index),
            Assessment {
                ip: a.ip,
                scope: format!("Windows / if#{}", a.interface_index),
                observed_at: snapshot.observed_at,
                access: observation_status,
                evidence: "Alamat lokal, belum diuji".into(),
            },
        );
    }
    if let Some(p) = probe.filter(|p| p.outcome == ProbeOutcome::Verified && p.observed_at <= at)
        && let (Some(source), Some(index)) = (p.source, p.interface_index)
    {
        // No attribution from a probe on a router, another client, or an ambiguous NIC.
        if let Some(row) = rows.get_mut(&(source.ip(), index)).filter(|_| {
            snapshot
                .addresses
                .iter()
                .any(|a| a.ip == source.ip() && a.interface_index == index)
        }) {
            row.access = if at - p.observed_at <= FRESH_SECONDS {
                Access::TestedHere
            } else {
                Access::Stale
            };
            row.observed_at = p.observed_at;
            row.evidence = format!(
                "HTTPS {} (status {}), hanya untuk target ini",
                p.target,
                p.http_status.unwrap_or(0)
            );
        }
    }
    rows.into_values().collect()
}

pub fn assess_import(import: &TrafficImport, at: u64) -> Vec<Assessment> {
    assess_evidence(import, at, false)
}
pub fn assess_flow(import: &TrafficImport, at: u64) -> Vec<Assessment> {
    assess_evidence(import, at, true)
}
fn assess_evidence(import: &TrafficImport, at: u64, udp: bool) -> Vec<Assessment> {
    let mut selected = BTreeMap::<_, (&TrafficEvidence, u8)>::new();
    for e in &import.entries {
        if e.observed_at > at {
            continue;
        }
        let fresh = at - e.observed_at <= FRESH_SECONDS;
        let rank = if !fresh {
            0
        } else {
            match e.kind {
                EvidenceKind::Lan => 1,
                EvidenceKind::WanAttempt => 2,
                EvidenceKind::WanReply => 3,
            }
        };
        let key = (&e.scope, e.ip);
        if selected.get(&key).is_none_or(|(old, r)| {
            (rank, e.observed_at, &e.sensor) > (*r, old.observed_at, &old.sensor)
        }) {
            selected.insert(key, (e, rank));
        }
    }
    selected
        .into_values()
        .map(|(e, rank)| Assessment {
            ip: e.ip,
            scope: format!("{} / {}", if udp { "Flow" } else { "Impor" }, e.scope),
            observed_at: e.observed_at,
            access: match rank {
                3 => Access::WanReplyObserved,
                2 => Access::WanAttemptObserved,
                1 => Access::LanOnlyObserved,
                _ => Access::Stale,
            },
            evidence: format!(
                "{}: {} (bukan probe HTTPS)",
                if udp {
                    "Bukti collector"
                } else {
                    "Bukti eksternal yang diimpor"
                },
                e.sensor
            ),
        })
        .collect()
}

pub fn matches_filter(filter: &str, fields: &[&str]) -> bool {
    Search::new(filter).matches(fields)
}
pub struct Search(Vec<String>);
impl Search {
    pub fn new(filter: &str) -> Self {
        Self(filter.split_whitespace().map(str::to_lowercase).collect())
    }
    pub fn matches(&self, fields: &[&str]) -> bool {
        if self.0.is_empty() {
            return true;
        }
        let fields: Vec<_> = fields.iter().map(|v| v.to_lowercase()).collect();
        self.0
            .iter()
            .all(|word| fields.iter().any(|f| f.contains(word)))
    }
}
pub fn assessment_matches(filter: &str, a: &Assessment) -> bool {
    matches_filter(
        filter,
        &[
            &a.ip.to_string(),
            &a.scope,
            &a.access.to_string(),
            &a.evidence,
        ],
    )
}
pub fn csv_cell(s: &str) -> String {
    let inject = s
        .trim_start_matches(|c: char| c.is_whitespace() || c.is_control())
        .starts_with(['=', '+', '-', '@']);
    format!(
        "\"{}{}\"",
        if inject { "'" } else { "" },
        s.replace('"', "\"\"")
    )
}
pub fn assessments_csv(rows: &[Assessment], redact: bool) -> String {
    let mut out = String::from("ip,scope,observed_at_unix_utc,access,policy,evidence\r\n");
    let mut aliases = BTreeMap::new();
    for r in rows {
        let next = aliases.len() + 1;
        let ip = if redact {
            aliases
                .entry((&r.scope, r.ip))
                .or_insert_with(|| format!("IP-{next}"))
                .clone()
        } else {
            r.ip.to_string()
        };
        let fields = [
            ip,
            if redact {
                "Disamarkan".into()
            } else {
                r.scope.clone()
            },
            r.observed_at.to_string(),
            r.access.to_string(),
            "Tidak dapat disimpulkan".into(),
            if redact {
                "Detail bukti disamarkan".into()
            } else {
                r.evidence.clone()
            },
        ];
        out.push_str(
            &fields
                .iter()
                .map(|s| csv_cell(s))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verified_probe_applies_only_to_its_actual_source_and_expires() {
        let ip = "192.0.2.2".parse().unwrap();
        let snap = LocalSnapshot {
            schema: 1,
            observed_at: 1,
            addresses: vec![LocalAddress {
                ip,
                interface_index: 8,
                scope_id: 0,
                prefix: 24,
            }],
            neighbors: vec![Neighbor {
                ip: "192.0.2.3".parse().unwrap(),
                interface_index: 8,
                scope_id: 0,
                mac: None,
                cache_state: "Stale".into(),
            }],
            endpoints: vec![],
            coverage: vec![],
        };
        let mut probe = Probe {
            observed_at: 10,
            elapsed_ms: 10,
            target: "https://test.example/".into(),
            source: Some("192.0.2.2:1200".parse().unwrap()),
            destination: None,
            interface_index: Some(9),
            http_status: Some(200),
            outcome: ProbeOutcome::Verified,
            detail: String::new(),
        };
        assert!(
            assess(&snap, Some(&probe), 11)
                .iter()
                .all(|r| r.access == Access::Unknown)
        );
        probe.interface_index = Some(8);
        assert_eq!(
            assess(&snap, Some(&probe), 11)
                .iter()
                .filter(|r| r.access == Access::TestedHere)
                .count(),
            1
        );
        assert_eq!(assess(&snap, Some(&probe), 1000)[0].access, Access::Stale);
        probe.outcome = ProbeOutcome::UnexpectedResponse;
        assert_eq!(assess(&snap, Some(&probe), 11)[0].access, Access::Unknown);
    }
    #[test]
    fn distinct_sites_and_strength_are_preserved_without_calling_attempt_a_success() {
        let f = TrafficImport::parse(r#"{"schema":1,"entries":[{"ip":"192.0.2.2","scope":"A/VRF1","sensor":"lab","observed_at":100,"kind":"WanAttempt"},{"ip":"192.0.2.2","scope":"B/VRF1","sensor":"lab","observed_at":100,"kind":"WanReply"},{"ip":"192.0.2.2","scope":"B/VRF1","sensor":"lab","observed_at":101,"kind":"Lan"}]}"#).unwrap();
        let r = assess_import(&f, 110);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].access, Access::WanAttemptObserved);
        assert_eq!(r[1].access, Access::WanReplyObserved);
        assert!(!assessments_csv(&r, true).contains("192.0.2.2"));
        assert!(
            assess_import(&f, 1010)
                .iter()
                .all(|r| r.access == Access::Stale)
        );
    }
    #[test]
    fn status_import_rejects_unknown_fields_and_formula_cells_are_neutralized() {
        assert!(TrafficImport::parse(r#"{"schema":1,"entries":[],"password":"x"}"#).is_err());
        assert_eq!(csv_cell(" \t=SUM(1,2)"), "\"' \t=SUM(1,2)\"");
        assert!(matches_filter("tcp 443", &["TCP", "192.0.2.7:443"]));
        assert!(!matches_filter("tcp 444", &["TCP", "192.0.2.7:443"]));
    }
}
