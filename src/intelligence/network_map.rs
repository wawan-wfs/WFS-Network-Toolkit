//! Read-only RouterOS evidence. No subnet overlap or name similarity implies a link.
use super::{
    CoverageState,
    router::{RouterSnapshot, Table, exact, field, flag, number},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Row {
    table: Table,
    subject: String,
    value: String,
    context: Option<String>,
    disabled: bool,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct EvidenceTables(Vec<Row>);
fn list(row: &Value, key: &str) -> Option<Vec<String>> {
    let v = row.get(key)?;
    let raw = if let Some(s) = v.as_str() {
        s.split(',').collect::<Vec<_>>()
    } else {
        v.as_array()?
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()?
    };
    if raw.len() > 64
        || raw.iter().map(|v| v.len()).sum::<usize>() > 2048
        || raw.iter().any(|v| v.len() > 160 || super::label(v) != *v)
    {
        return None;
    }
    Some(
        raw.into_iter()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}
fn prefix(s: &str) -> Option<(IpAddr, u8)> {
    let (a, b) = s.split_once('/')?;
    let ip: IpAddr = a.parse().ok()?;
    let bits: u8 = b.parse().ok()?;
    (bits <= if ip.is_ipv4() { 32 } else { 128 }).then_some((ip, bits))
}
fn subnet(ip: IpAddr, bits: u8) -> String {
    let net = match ip {
        IpAddr::V4(ip) => IpAddr::from(std::net::Ipv4Addr::from(if bits == 0 {
            0
        } else {
            (u32::from(ip) >> (32 - bits)) << (32 - bits)
        })),
        IpAddr::V6(ip) => IpAddr::from(std::net::Ipv6Addr::from(if bits == 0 {
            0
        } else {
            (u128::from(ip) >> (128 - bits)) << (128 - bits)
        })),
    };
    format!("{net}/{bits}")
}
impl EvidenceTables {
    pub(crate) fn lease_scope(&self) -> Self {
        Self(
            self.0
                .iter()
                .filter(|row| matches!(row.table, Table::Vrf | Table::DhcpServer))
                .take(256)
                .cloned()
                .collect(),
        )
    }
    pub(crate) fn lease_scope_truncated(&self) -> bool {
        self.0
            .iter()
            .filter(|row| matches!(row.table, Table::Vrf | Table::DhcpServer))
            .nth(256)
            .is_some()
    }
    pub(crate) fn valid_lease_scope(&self) -> bool {
        self.0.len() <= 256
            && self
                .0
                .iter()
                .all(|r| matches!(r.table, Table::Vrf | Table::DhcpServer))
    }

    pub(super) fn push(&mut self, table: Table, row: &Value) -> bool {
        let mut insert = |subject, value, context, disabled| {
            self.0.push(Row {
                table,
                subject,
                value,
                context,
                disabled,
            });
        };
        let bad = flag(row, "disabled") == Some(true) || flag(row, "invalid") == Some(true);
        match table {
            Table::Vrf => {
                let (Some(name), Some(members)) = (exact(row, "name"), list(row, "interfaces"))
                else {
                    return false;
                };
                insert(name, members.join(","), None, bad);
            }
            Table::RoutingTable => {
                let Some(name) = exact(row, "name") else {
                    return false;
                };
                insert(
                    name,
                    flag(row, "fib").map_or("FIB tidak diketahui".into(), |v| format!("FIB {v}")),
                    None,
                    bad,
                );
            }
            Table::BridgeHost => {
                let (Some(mac), Some(port), Some(bridge)) = (
                    field(row, "mac-address").and_then(|v| v.parse::<crate::Mac>().ok()),
                    exact(row, "on-interface"),
                    exact(row, "bridge"),
                ) else {
                    return false;
                };
                let vid = number(row, "vid").filter(|n| *n >= 1 && *n <= 4094);
                insert(
                    mac.to_string(),
                    port,
                    Some(format!(
                        "Bridge {bridge} · VID {} · local {}",
                        vid.map_or("tidak diketahui".into(), |x| x.to_string()),
                        show_flag(flag(row, "local"))
                    )),
                    bad,
                );
            }
            Table::BridgeVlan => {
                let (Some(bridge), Some(vids)) = (exact(row, "bridge"), list(row, "vlan-ids"))
                else {
                    return false;
                };
                if vids.is_empty()
                    || vids.iter().any(|v| {
                        !v.split('-')
                            .all(|n| n.parse::<u16>().is_ok_and(|id| (1..=4094).contains(&id)))
                    })
                {
                    return false;
                }
                let present = |key| {
                    list(row, key).map_or("tidak diketahui".into(), |v| {
                        if v.is_empty() {
                            "—".into()
                        } else {
                            v.join(",")
                        }
                    })
                };
                insert(
                    format!("{bridge} / VLAN {}", vids.join(",")),
                    bridge.clone(),
                    Some(format!(
                        "Aktual tag {} / untag {}; konfigurasi tag {} / untag {}",
                        present("current-tagged"),
                        present("current-untagged"),
                        present("tagged"),
                        present("untagged")
                    )),
                    bad,
                );
            }
            Table::DhcpServer => {
                let (Some(name), Some(interface)) = (exact(row, "name"), exact(row, "interface"))
                else {
                    return false;
                };
                insert(name, interface, exact(row, "address-pool"), bad);
            }
            Table::Address4 | Table::Address6 => {
                let (Some(addr), Some(interface)) =
                    (exact(row, "address"), exact(row, "interface"))
                else {
                    return false;
                };
                let Some((ip, bits)) = prefix(&addr) else {
                    return false;
                };
                if ip.is_unspecified()
                    || ip.is_multicast()
                    || ip.is_ipv4() != (table == Table::Address4)
                {
                    return false;
                }
                let actual = exact(row, "actual-interface");
                insert(
                    format!("{ip}/{bits}"),
                    interface,
                    Some(format!(
                        "Subnet {} · interface aktual {}",
                        subnet(ip, bits),
                        actual.as_deref().unwrap_or("tidak diketahui")
                    )),
                    bad,
                );
            }
            Table::Pool4 | Table::Pool6 => {
                let Some(name) = exact(row, "name") else {
                    return false;
                };
                let (value, context) = if table == Table::Pool4 {
                    let Some(ranges) = list(row, "ranges") else {
                        return false;
                    };
                    if ranges.is_empty()
                        || ranges.iter().any(|r| {
                            let (a, b) = r.split_once('-').unwrap_or((r, r));
                            !a.parse::<std::net::Ipv4Addr>()
                                .ok()
                                .zip(b.parse::<std::net::Ipv4Addr>().ok())
                                .is_some_and(|(a, b)| a <= b)
                        })
                    {
                        return false;
                    }
                    (ranges.join(","), exact(row, "next-pool"))
                } else {
                    let Some(range) = field(row, "prefix")
                        .and_then(prefix)
                        .filter(|(ip, _)| ip.is_ipv6())
                    else {
                        return false;
                    };
                    let Some(length) = number(row, "prefix-length")
                        .filter(|n| (u64::from(range.1)..=128).contains(n))
                    else {
                        return false;
                    };
                    (
                        subnet(range.0, range.1),
                        Some(format!("Panjang delegasi /{length}")),
                    )
                };
                insert(name, value, context, bad);
            }
            Table::Neighbors => {
                let (Some(port), Some(name)) = (
                    exact(row, "interface"),
                    exact(row, "identity").or_else(|| {
                        field(row, "mac-address")
                            .and_then(|v| v.parse::<crate::Mac>().ok())
                            .map(|m| m.to_string())
                    }),
                ) else {
                    return false;
                };
                insert(name, port, exact(row, "discovered-by"), bad);
            }
            _ => return false,
        }
        true
    }
}

fn show_flag(flag: Option<bool>) -> &'static str {
    match flag {
        Some(true) => "ya",
        Some(false) => "tidak",
        None => "tidak diketahui",
    }
}

#[derive(Clone, Debug)]
pub struct Observation {
    pub subject: String,
    pub target: String,
    pub scope: String,
    pub basis: &'static str,
    pub source: &'static str,
    pub observed_at: u64,
    pub details: String,
}
fn observed(s: &RouterSnapshot, table: Table) -> Option<(u64, bool)> {
    let c = s.coverage.iter().rev().find(|c| c.source == table.name())?;
    (c.state != CoverageState::Unavailable)
        .then_some((c.observed_at, c.state == CoverageState::CompleteSnapshot))
}
struct Scoped<'a> {
    router: &'a RouterSnapshot,
    vrf: BTreeMap<&'a str, Option<&'a str>>,
    servers: BTreeMap<&'a str, Option<&'a str>>,
}
fn unique<'a>(map: &mut BTreeMap<&'a str, Option<&'a str>>, key: &'a str, value: &'a str) {
    map.entry(key)
        .and_modify(|v| {
            if *v != Some(value) {
                *v = None
            }
        })
        .or_insert(Some(value));
}
impl<'a> Scoped<'a> {
    fn new(s: &'a RouterSnapshot) -> Self {
        let mut out = Self {
            router: s,
            vrf: BTreeMap::new(),
            servers: BTreeMap::new(),
        };
        let vrf_complete = observed(s, Table::Vrf).is_some_and(|(_, full)| full);
        let dhcp_complete = observed(s, Table::DhcpServer).is_some_and(|(_, full)| full);
        for row in &s.network.0 {
            if row.table == Table::Vrf && vrf_complete && !row.disabled {
                // Never expand RouterOS "all", interface lists, or exclusions into inferred members.
                for port in row
                    .value
                    .split(',')
                    .filter(|n| !n.is_empty() && *n != "all" && !n.starts_with('!'))
                {
                    unique(&mut out.vrf, port, &row.subject);
                }
            }
            if row.table == Table::DhcpServer && dhcp_complete && !row.disabled {
                unique(&mut out.servers, &row.subject, &row.value);
            }
        }
        out
    }
    fn name(&self, interface: Option<&str>) -> String {
        let vrf = interface
            .and_then(|p| self.vrf.get(p).copied().flatten())
            .unwrap_or("tidak diketahui");
        format!(
            "{} · interface {} · VRF tercantum {vrf}",
            self.router.authority,
            interface.unwrap_or("tidak diketahui")
        )
    }
}
fn table_basis(table: Table) -> &'static str {
    match table {
        Table::BridgeHost => "MAC teramati",
        Table::Neighbors => "Tetangga teramati",
        Table::Address4 | Table::Address6 => "Alamat interface",
        Table::Pool4 | Table::Pool6 => "Pool dikonfigurasi",
        _ => "Relasi eksplisit",
    }
}
fn from_rows(scope: &Scoped<'_>, ipam: bool) -> Vec<Observation> {
    let mut out = vec![];
    for r in &scope.router.network.0 {
        let inventory = matches!(
            r.table,
            Table::Address4 | Table::Address6 | Table::Pool4 | Table::Pool6 | Table::DhcpServer
        );
        if inventory != ipam {
            continue;
        }
        let Some((time, complete)) = observed(scope.router, r.table) else {
            continue;
        };
        let interface = matches!(
            r.table,
            Table::DhcpServer
                | Table::Address4
                | Table::Address6
                | Table::BridgeHost
                | Table::Neighbors
        )
        .then_some(r.value.as_str());
        let detail = r.context.as_deref().unwrap_or("Tidak ada field tambahan.");
        out.push(Observation {
            subject: r.subject.clone(),
            target: r.value.clone(),
            scope: scope.name(interface),
            basis: table_basis(r.table),
            source: r.table.name(),
            observed_at: time,
            details: format!(
                "{detail}\nCakupan tabel: {}. {}",
                if complete {
                    "lengkap untuk respons ini"
                } else {
                    "parsial"
                },
                if r.disabled {
                    "Entri nonaktif/tidak valid."
                } else {
                    "Bukan bukti akses, link fisik, atau ketersediaan alamat."
                }
            ),
        });
    }
    out
}
pub fn topology(s: &RouterSnapshot) -> Vec<Observation> {
    let scope = Scoped::new(s);
    let mut out = from_rows(&scope, false);
    for r in &s.topology {
        let table = if r.kind == Table::BridgePorts.name() {
            Table::BridgePorts
        } else {
            Table::Vlan
        };
        if let Some((time, full)) = observed(s, table) {
            out.push(Observation {subject:r.subject.clone(),target:r.relation.clone(),
                scope:scope.name(Some(&r.relation)),basis:"Relasi eksplisit",source:table.name(),observed_at:time,
                details:format!("Field teramati {:?}. Respons {}. Bukan koneksi antarswitch yang terverifikasi.",r.fields,if full {"lengkap"} else {"parsial"})});
        }
    }
    for r in &s.default_routes {
        let table = if r.destination == "::/0" {
            Table::DefaultRoute6
        } else {
            Table::DefaultRoute4
        };
        if let Some((time, _)) = observed(s, table) {
            out.push(Observation {subject:r.destination.clone(),target:r.gateway.as_deref().unwrap_or("Gateway tidak diketahui").into(),
                scope:format!("{} · tabel {}",s.authority,r.table.as_deref().unwrap_or("tidak diketahui")),basis:"Rute logis",source:table.name(),observed_at:time,
                details:format!("Rute aktif {}. Tabel routing bukan bukti interface berada pada VRF tertentu. Next-hop {}.",
                    show_flag(r.active),r.immediate_gateway.as_deref().unwrap_or("tidak diketahui"))});
        }
    }
    out
}
type Correlation<'a> = BTreeMap<(IpAddr, &'a str), BTreeMap<String, (u64, &'static str)>>;
/// Changes in a captured session are observations, not reconstructed assignment intervals.
#[derive(Default)]
pub struct LeaseTimeline {
    pub events: std::collections::VecDeque<Observation>,
    pub limited: bool,
    previous: BTreeMap<(String, IpAddr), (String, u64)>,
    stamp: Option<u64>,
    identity: Option<String>,
}
impl LeaseTimeline {
    pub fn observe(&mut self, s: &RouterSnapshot) {
        let Some((stamp, complete)) = observed(s, Table::Lease) else {
            self.previous.clear();
            return;
        };
        if self.stamp.is_some_and(|old| old >= stamp) {
            return;
        }
        self.stamp = Some(stamp);
        if self.identity != s.identity || self.identity.is_none() {
            self.previous.clear();
            self.identity.clone_from(&s.identity);
        }

        if !complete {
            self.previous.clear();
            return;
        }
        let scope = Scoped::new(s);
        let mut seen: BTreeMap<(String, IpAddr), Option<String>> = BTreeMap::new();
        for h in &s.inventory {
            if !h.active_binding {
                continue;
            }
            if let (Some(server), Some(mac)) = (&h.location, h.mac) {
                let value = mac.to_string();
                seen.entry((server.clone(), h.ip))
                    .and_modify(|old| {
                        if old.as_ref() != Some(&value) {
                            *old = None;
                        }
                    })
                    .or_insert(Some(value));
            }
        }
        self.limited |= seen.len() > 2_000;
        let next = seen
            .into_iter()
            .take(2_000)
            .filter_map(|(key, mac)| mac.map(|m| (key, (m, stamp))))
            .collect::<BTreeMap<_, _>>();
        for ((server, ip), (mac, _)) in &next {
            let old = self.previous.get(&(server.clone(), *ip));
            if old.is_some_and(|(previous, _)| previous == mac) {
                continue;
            }
            if self.events.len() == 512 {
                self.events.pop_front();
                self.limited = true;
            }
            let intf = scope.servers.get(server.as_str()).copied().flatten();
            self.events.push_back(Observation {
                subject: ip.to_string(),
                target: mac.clone(),
                scope: scope.name(intf),
                source: Table::Lease.name(),
                observed_at: stamp,
                basis: if old.is_some() {
                    "MAC lease berubah"
                } else {
                    "Lease terlihat"
                },
                details: format!(
                    "Server {server}. {}. Snapshot selesai UTC {}. Pengamatan tidak menetapkan waktu awal/akhir assignment.",
                    old.map_or(
                        "Tidak ada pembanding yang memenuhi syarat".into(),
                        |(m, at)| format!("Pembanding {m} pada UTC {at}")
                    ),
                    s.observed_at
                ),
            });
        }
        self.previous = next;
    }
}

/// Count only observations with explicit interface attribution. DHCP server
/// names are resolved only from complete server configuration, not guessed.
pub fn subnets(s: &RouterSnapshot) -> super::overview::Subnets {
    let scope = Scoped::new(s);
    let mut index = super::overview::Index::default();
    for r in &s.network.0 {
        if !matches!(r.table, Table::Address4 | Table::Address6) || r.disabled {
            continue;
        }
        if let Some((stamp, complete)) = observed(s, r.table)
            && let Some((ip, bits)) = prefix(&r.subject)
        {
            // Other tables can be missing, so even a complete address response
            // never means that all assignments in this subnet are known.
            let partial = !complete
                || [Table::Arp, Table::Neighbor6, Table::Lease, Table::DhcpServer]
                    .iter()
                    .any(|t| !observed(s, *t).is_some_and(|(time, full)| {
                        full && time.abs_diff(stamp) <= 60
                    }));
            index.configure(
                r.value.clone(),
                scope.name(Some(&r.value)),
                ip,
                bits,
                stamp,
                partial,
            );
            index.observe(r.value.clone(), ip);
        }
    }
    for h in &s.inventory {
        let table = match h.source.as_str() {
            "DHCPv4" => Table::Lease,
            "ARP" => Table::Arp,
            _ => Table::Neighbor6,
        };
        let Some((stamp, _)) = observed(s, table) else {
            continue;
        };
        let interface = if h.source == "DHCPv4" {
            if !observed(s, Table::DhcpServer)
                .is_some_and(|(time, full)| full && time.abs_diff(stamp) <= 60)
            {
                continue;
            }
            h.location
                .as_deref()
                .and_then(|name| scope.servers.get(name).copied().flatten())
        } else {
            h.location.as_deref()
        };
        if let Some(interface) = interface {
            index.observe(interface.to_owned(), h.ip);
        }
    }
    index.finish()
}

pub fn inventory(s: &RouterSnapshot) -> Vec<Observation> {
    let scope = Scoped::new(s);
    let mut out = from_rows(&scope, true);
    let mut candidates: Correlation<'_> = BTreeMap::new();
    for h in &s.inventory {
        let dhcp = h.source == "DHCPv4";
        let table = if dhcp {
            Table::Lease
        } else if h.source == "ARP" {
            Table::Arp
        } else {
            Table::Neighbor6
        };
        let Some((time, full)) = observed(s, table) else {
            continue;
        };
        let intf = if dhcp {
            h.location
                .as_deref()
                .and_then(|x| scope.servers.get(x).copied().flatten())
        } else {
            h.location.as_deref()
        };
        let basis = if dhcp {
            if h.active_binding {
                "Lease aktif"
            } else {
                "Lease belum terbukti aktif"
            }
        } else {
            "Cache tetangga"
        };
        let link_local = matches!(h.ip,IpAddr::V6(v) if v.is_unicast_link_local());
        let ambiguity = if link_local && intf.is_none() {
            "IPv6 link-local tanpa interface bersifat ambigu."
        } else {
            "Bukan bukti alamat tersedia."
        };
        let mac = h
            .mac
            .map_or("MAC tidak diketahui".into(), |m| m.to_string());
        out.push(Observation {
            subject: h.ip.to_string(),
            target: format!(
                "{} · {mac}",
                h.host_name.as_deref().unwrap_or("Hostname tidak diketahui")
            ),
            scope: scope.name(intf),
            basis,
            source: table.name(),
            observed_at: time,
            details: format!(
                "{ambiguity}\nStatus {} · server/interface {} · sisa lease {}. {}.",
                h.status.as_deref().unwrap_or("tidak diketahui"),
                h.location.as_deref().unwrap_or("tidak diketahui"),
                h.expires_after.as_deref().unwrap_or("tidak diketahui"),
                if full {
                    "Respons lengkap"
                } else {
                    "Respons parsial"
                }
            ),
        });
        if full
            && (h.active_binding || h.reachable)
            && h.mac.is_some_and(|m| m.0 != [0; 6] && m.0[0] & 1 == 0)
            && let Some(interface) = intf
            && !h.ip.is_unspecified()
            && !h.ip.is_multicast()
            && !h.ip.is_loopback()
        {
            let entries = candidates.entry((h.ip, interface)).or_default();
            if entries.len() < 16 || entries.contains_key(&mac) {
                let current = entries.entry(mac).or_insert((time, table.name()));
                *current = (*current).max((time, table.name()));
            }
        }
    }
    for ((ip, interface), macs) in candidates {
        let max = macs.values().map(|(t, _)| *t).max().unwrap_or_default();
        let recent = macs
            .iter()
            .filter(|(_, (t, _))| max.saturating_sub(*t) <= 60)
            .collect::<Vec<_>>();
        if recent.len() < 2 {
            continue;
        }
        let hints = recent
            .iter()
            .map(|(m, (t, source))| format!("{m} · {source} · UTC {t}"))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join("\n");
        out.push(Observation {subject:ip.to_string(),target:format!("{} MAC pada satu interface",recent.len()),scope:scope.name(Some(interface)),
            basis:"Konflik terindikasi",source:"Korelasi observasi RouterOS",observed_at:max,
            details:format!("Bukti berjarak maksimal 60 detik. Bukan konfirmasi duplikasi dan tidak memicu perubahan.\n{hints}") });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::router::Authority;
    #[test]
    fn subnet_scope_keeps_identical_prefixes_separate() {
        let mut s = RouterSnapshot::new(&Authority::parse("fixture.example.test").unwrap(), 100);
        s.ingest(
            Table::Address4,
            Ok(br#"[{"address":"192.0.2.1/24","interface":"blue"},{"address":"192.0.2.1/24","interface":"red"},{"address":"198.51.100.1/24","interface":"off","disabled":true}]"#.to_vec()),
            100,
        );
        s.ingest(
            Table::Address6,
            Ok(br#"[{"address":"2001:db8::1/64","interface":"blue"}]"#.to_vec()),
            100,
        );
        let view = subnets(&s);
        assert_eq!(view.rows.len(), 3);
        let same: Vec<_> = view
            .rows
            .iter()
            .filter(|r| r.prefix.to_string() == "192.0.2.0/24")
            .collect();
        assert_eq!(same.len(), 2);
        assert_ne!(same[0].scope, same[1].scope);
        assert!(same.iter().all(|r| r.observed == 1 && r.partial));
        assert!(view.rows.iter().any(|r| r.prefix.to_string() == "2001:db8::/64"));
    }

    fn fixture() -> RouterSnapshot {
        let mut s = RouterSnapshot::new(&Authority::parse("r1.example.test").unwrap(), 100);
        s.identity = Some("fixture-router".into());
        let v: Value =
            serde_json::from_str(include_str!("../../fixtures/routeros-observations.json"))
                .unwrap();
        for (key, table) in [
            ("vrf", Table::Vrf),
            ("routing", Table::RoutingTable),
            ("ports", Table::BridgePorts),
            ("vlans", Table::Vlan),
            ("fdb", Table::BridgeHost),
            ("members", Table::BridgeVlan),
            ("servers", Table::DhcpServer),
            ("addresses4", Table::Address4),
            ("addresses6", Table::Address6),
            ("pools4", Table::Pool4),
            ("pools6", Table::Pool6),
            ("neighbors", Table::Neighbors),
            ("leases", Table::Lease),
            ("arp", Table::Arp),
            ("nd", Table::Neighbor6),
            ("route", Table::DefaultRoute4),
        ] {
            s.ingest(table, Ok(serde_json::to_vec(&v[key]).unwrap()), 80);
        }
        s
    }
    #[test]
    fn topology_retains_provenance_and_marks_partial_fdb() {
        let s = fixture();
        let edges = topology(&s);
        let fdb = edges
            .iter()
            .find(|r| r.source == Table::BridgeHost.name())
            .unwrap();
        assert_eq!(fdb.target, "ether2");
        assert!(fdb.details.contains("parsial"));
        assert_eq!(fdb.observed_at, 80);
        assert_eq!(fdb.basis, "MAC teramati");
        assert!(edges.iter().any(|r| r.subject == "switch-gedung"
            && r.details.contains("lldp")
            && !r.details.contains("do-not-copy")));
        assert!(
            edges
                .iter()
                .any(|r| r.basis == "Rute logis" && r.scope.ends_with("tabel blue"))
        );
        assert!(!edges.iter().any(|r| r.subject.contains("192.0.2")));
    }
    #[test]
    fn inventory_separates_vrf_and_expires_conflict_candidate_after_sixty_seconds() {
        let mut s = fixture();
        let data = inventory(&s);
        assert!(data.iter().any(|r| r.subject == "192.0.2.1/24"
            && r.details.contains("192.0.2.0/24")
            && r.scope.ends_with("blue")));
        assert!(
            data.iter()
                .any(|r| r.subject == "192.0.2.1/24" && r.scope.ends_with("red"))
        );
        assert!(
            data.iter()
                .any(|r| r.subject == "fe80::1" && r.details.contains("ambigu"))
        );
        let conflicts: Vec<_> = data
            .iter()
            .filter(|r| r.basis == "Konflik terindikasi")
            .collect();
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].details.contains("02-11-22-33-44-55"));
        assert!(conflicts[0].details.contains("02-11-22-33-44-66"));
        assert!(
            !conflicts[0].details.contains("02-11-22-33-44-77")
                && !conflicts[0].details.contains("02-11-22-33-44-88")
        );
        s.coverage
            .iter_mut()
            .find(|c| c.source == Table::Arp.name())
            .unwrap()
            .observed_at = 150;
        assert!(
            !inventory(&s)
                .iter()
                .any(|r| r.basis == "Konflik terindikasi")
        );
    }
    #[test]
    fn inaccessible_scope_table_never_infers_a_default_vrf_or_conflict() {
        let mut s = fixture();
        s.coverage
            .iter_mut()
            .find(|c| c.source == Table::Vrf.name())
            .unwrap()
            .state = CoverageState::Unavailable;
        s.coverage
            .iter_mut()
            .find(|c| c.source == Table::DhcpServer.name())
            .unwrap()
            .state = CoverageState::Partial;
        let rows = inventory(&s);
        assert!(
            rows.iter()
                .any(|r| r.basis == "Lease aktif" && r.scope.contains("interface tidak diketahui"))
        );
        assert!(
            !rows
                .iter()
                .any(|r| r.scope.ends_with("main") || r.basis == "Konflik terindikasi")
        );
    }
    #[test]
    fn lease_timeline_does_not_invent_expiry_on_partial_snapshot() {
        let mut s = fixture();
        let mut timeline = LeaseTimeline::default();
        timeline.observe(&s);
        assert_eq!(timeline.events.len(), 1);
        timeline.observe(&s);
        assert_eq!(timeline.events.len(), 1);
        let lease = s
            .coverage
            .iter_mut()
            .find(|c| c.source == Table::Lease.name())
            .unwrap();
        lease.observed_at = 120;
        s.inventory
            .iter_mut()
            .find(|h| h.active_binding)
            .unwrap()
            .mac = Some("02:11:22:33:44:66".parse().unwrap());
        timeline.observe(&s);
        assert_eq!(timeline.events.back().unwrap().basis, "MAC lease berubah");
        let lease = s
            .coverage
            .iter_mut()
            .find(|c| c.source == Table::Lease.name())
            .unwrap();
        lease.observed_at = 130;
        lease.state = CoverageState::Partial;
        timeline.observe(&s);
        assert_eq!(timeline.events.len(), 2);
    }
}
