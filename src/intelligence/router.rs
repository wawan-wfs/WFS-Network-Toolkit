use super::{Coverage, CoverageState, LIMIT, label};
use crate::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::{IpAddr, SocketAddr};
pub const ROUTER_TABLE_LIMIT: usize = 10_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Authority {
    pub host: String,
    pub port: u16,
}
impl Authority {
    pub fn parse(input: &str) -> Result<Self> {
        let raw = input.trim();
        let raw = raw.strip_prefix("https://").unwrap_or(raw);
        let raw = raw.strip_suffix('/').unwrap_or(raw);
        let (host, port) = if let Some(raw) = raw.strip_prefix('[') {
            let (v6, tail) = raw
                .split_once(']')
                .ok_or("IPv6 harus memakai tanda kurung siku.")?;
            let ip = v6
                .parse::<std::net::Ipv6Addr>()
                .map_err(|_| "IPv6 tidak valid.")?;
            if ip.is_unspecified() || ip.is_multicast() {
                return Err("Host router tidak valid.".into());
            }
            let port = if tail.is_empty() {
                443
            } else {
                parse_port(tail.strip_prefix(':').ok_or("Port tidak valid.")?)?
            };
            (v6, port)
        } else if let Some((host, port)) = raw.split_once(':') {
            (host, parse_port(port)?)
        } else {
            (raw, 443)
        };
        if host.is_empty()
            || host.len() > 253
            || (!host.contains(':')
                && !host.trim_end_matches('.').split('.').all(|part| {
                    !part.is_empty()
                        && part.len() <= 63
                        && !part.starts_with('-')
                        && !part.ends_with('-')
                        && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                }))
        {
            return Err(
                "Masukkan hostname/IP yang eksplisit tanpa path, query, atau kredensial.".into(),
            );
        }
        if host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|ip| ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast())
        {
            return Err("Host router tidak valid.".into());
        }
        Ok(Self {
            host: host.to_ascii_lowercase(),
            port,
        })
    }
    pub fn display(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}
fn parse_port(s: &str) -> Result<u16> {
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Port HTTPS tidak valid.".into());
    }
    s.parse::<u16>()
        .ok()
        .filter(|n| *n > 0)
        .ok_or_else(|| "Port HTTPS tidak valid.".into())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum Table {
    Identity,
    Resource,
    Interface,
    Lease,
    Arp,
    Neighbor6,
    DefaultRoute4,
    DefaultRoute6,
    Connections,
    BridgePorts,
    Vlan,
    Firewall,
    Nat,
    RoutingTable,
    Vrf,
    BridgeHost,
    BridgeVlan,
    DhcpServer,
    Address4,
    Address6,
    Pool4,
    Pool6,
    Neighbors,
}
impl Table {
    pub const ALL: [Self; 23] = [
        Self::Identity,
        Self::Resource,
        Self::Interface,
        Self::Lease,
        Self::Arp,
        Self::Neighbor6,
        Self::DefaultRoute4,
        Self::DefaultRoute6,
        Self::BridgePorts,
        Self::Vlan,
        Self::Firewall,
        Self::Nat,
        Self::RoutingTable,
        Self::Vrf,
        Self::BridgeHost,
        Self::BridgeVlan,
        Self::DhcpServer,
        Self::Address4,
        Self::Address6,
        Self::Pool4,
        Self::Pool6,
        Self::Neighbors,
        Self::Connections,
    ];
    pub fn evidence_tables() -> &'static [Self] {
        &[
            Self::RoutingTable,
            Self::Vrf,
            Self::BridgeHost,
            Self::BridgeVlan,
            Self::DhcpServer,
            Self::Address4,
            Self::Address6,
            Self::Pool4,
            Self::Pool6,
            Self::Neighbors,
        ]
    }
    pub fn path(self) -> &'static str {
        match self {
            Self::Identity => "/rest/system/identity?.proplist=name",
            Self::Resource => {
                "/rest/system/resource?.proplist=version,board-name,uptime,cpu-load,free-memory,total-memory"
            }
            Self::Interface => {
                "/rest/interface?.proplist=name,type,running,disabled,rx-byte,tx-byte"
            }
            Self::Lease => {
                "/rest/ip/dhcp-server/lease?.proplist=address,active-address,mac-address,active-mac-address,host-name,server,active-server,status,expires-after,dynamic"
            }
            Self::Arp => "/rest/ip/arp?.proplist=address,mac-address,interface,status,complete",
            Self::Neighbor6 => "/rest/ipv6/neighbor?.proplist=address,mac-address,interface,status",
            Self::DefaultRoute4 => {
                "/rest/ip/route?dst-address=0.0.0.0%2F0&.proplist=dst-address,gateway,immediate-gw,routing-table,active,distance"
            }
            Self::DefaultRoute6 => {
                "/rest/ipv6/route?dst-address=%3A%3A%2F0&.proplist=dst-address,gateway,immediate-gw,routing-table,active,distance"
            }
            Self::BridgePorts => {
                "/rest/interface/bridge/port?.proplist=.id,bridge,interface,pvid,disabled,hw"
            }
            Self::Vlan => {
                "/rest/interface/vlan?.proplist=.id,name,vlan-id,interface,running,disabled"
            }
            Self::Firewall => {
                "/rest/ip/firewall/filter?.proplist=.id,chain,action,disabled,dynamic,protocol,src-address,dst-address,src-address-list,dst-address-list,in-interface,out-interface,in-interface-list,out-interface-list,src-port,dst-port,bytes,packets"
            }
            Self::Nat => {
                "/rest/ip/firewall/nat?.proplist=.id,chain,action,disabled,dynamic,protocol,src-address,dst-address,in-interface,out-interface,src-port,dst-port,to-addresses,to-ports,bytes,packets"
            }
            Self::RoutingTable => "/rest/routing/table?.proplist=name,fib,disabled",
            Self::Vrf => "/rest/ip/vrf?.proplist=name,interfaces",
            Self::BridgeHost => {
                "/rest/interface/bridge/host?.proplist=mac-address,vid,bridge,on-interface,local,dynamic"
            }
            Self::BridgeVlan => {
                "/rest/interface/bridge/vlan?.proplist=bridge,vlan-ids,current-tagged,current-untagged,tagged,untagged"
            }
            Self::DhcpServer => {
                "/rest/ip/dhcp-server?.proplist=name,interface,address-pool,disabled,invalid"
            }
            Self::Address4 => {
                "/rest/ip/address?.proplist=address,interface,actual-interface,disabled,invalid"
            }
            Self::Address6 => {
                "/rest/ipv6/address?.proplist=address,interface,actual-interface,disabled,invalid"
            }
            Self::Pool4 => "/rest/ip/pool?.proplist=name,ranges,next-pool",
            Self::Pool6 => "/rest/ipv6/pool?.proplist=name,prefix,prefix-length",
            Self::Neighbors => {
                "/rest/ip/neighbor?.proplist=identity,interface,mac-address,discovered-by"
            }
            Self::Connections => {
                "/rest/ip/firewall/connection?.proplist=protocol,src-address,dst-address,reply-src-address,reply-dst-address,orig-bytes,repl-bytes,tcp-state,seen-reply,srcnat,dstnat,fasttrack,hw-offload"
            }
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Identity => "RouterOS Identity",
            Self::Resource => "RouterOS Resource",
            Self::Interface => "RouterOS Interfaces",
            Self::Lease => "RouterOS DHCPv4",
            Self::Arp => "RouterOS ARP",
            Self::Neighbor6 => "RouterOS IPv6 Neighbor",
            Self::DefaultRoute4 => "RouterOS Default Route IPv4",
            Self::DefaultRoute6 => "RouterOS Default Route IPv6",
            Self::Connections => "RouterOS Connection Tracking IPv4",
            Self::BridgePorts => "RouterOS Bridge Ports",
            Self::Vlan => "RouterOS VLAN Interfaces",
            Self::Firewall => "RouterOS Firewall Filter IPv4",
            Self::Nat => "RouterOS NAT IPv4",
            Self::RoutingTable => "RouterOS Routing Tables",
            Self::Vrf => "RouterOS VRF",
            Self::BridgeHost => "RouterOS Bridge FDB",
            Self::BridgeVlan => "RouterOS Bridge VLAN",
            Self::DhcpServer => "RouterOS DHCP Servers",
            Self::Address4 => "RouterOS IPv4 Addresses",
            Self::Address6 => "RouterOS IPv6 Addresses",
            Self::Pool4 => "RouterOS IPv4 Pools",
            Self::Pool6 => "RouterOS IPv6 Pools",
            Self::Neighbors => "RouterOS Discovery Neighbors",
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct RouterSnapshot {
    pub schema: u8,
    pub observed_at: u64,
    pub authority: String,
    pub identity: Option<String>,
    pub resource: Option<RouterResource>,
    pub interfaces: Vec<RouterInterface>,
    pub inventory: Vec<RouterHost>,
    pub default_routes: Vec<RouterRoute>,
    pub connections: Vec<RouterConnection>,
    pub coverage: Vec<Coverage>,
    pub topology: Vec<RouterConfigRow>,
    pub rules: Vec<RouterConfigRow>,
    #[serde(skip)]
    pub network: super::network_map::EvidenceTables,
}
impl RouterSnapshot {
    pub fn new(authority: &Authority, observed_at: u64) -> Self {
        Self {
            schema: 1,
            observed_at,
            authority: authority.display(),
            identity: None,
            resource: None,
            interfaces: vec![],
            inventory: vec![],
            default_routes: vec![],
            connections: vec![],
            coverage: vec![],
            topology: vec![],
            rules: vec![],
            network: Default::default(),
        }
    }
    pub fn ingest(&mut self, table: Table, result: Result<Vec<u8>>, stamp: u64) {
        let result = result.and_then(|data| self.ingest_json(table, &data));
        let (rows, state, detail) = match result {
            Ok((rows, rejected)) => (
                rows,
                if rejected == 0 {
                    CoverageState::CompleteSnapshot
                } else {
                    CoverageState::Partial
                },
                (rejected != 0).then(|| {
                    format!(
                        "{rejected} baris tanpa field wajib atau melewati batas tidak ditampilkan."
                    )
                }),
            ),
            Err(e) => (0, CoverageState::Unavailable, Some(e)),
        };
        self.coverage.push(Coverage {
            source: table.name().into(),
            observed_at: stamp,
            state,
            rows,
            detail,
        });
    }
    fn ingest_json(&mut self, table: Table, data: &[u8]) -> Result<(usize, usize)> {
        let payload: Value = serde_json::from_slice(data)
            .map_err(|_| "Respons RouterOS bukan JSON yang valid.".to_string())?;
        let rows = match payload {
            Value::Array(rows) => rows,
            // RouterOS versions may represent single-record system menus as an object.
            Value::Object(_) if matches!(table, Table::Identity | Table::Resource) => vec![payload],
            _ => return Err("Bentuk respons tidak sesuai tabel RouterOS.".into()),
        };
        let mut accepted = 0;
        let total = rows.len();
        for (index, row) in rows
            .into_iter()
            .take(LIMIT.min(ROUTER_TABLE_LIMIT))
            .enumerate()
        {
            let ok = match table {
                Table::Identity => {
                    if let Some(name) = field(&row, "name") {
                        self.identity = Some(label(name));
                        true
                    } else {
                        false
                    }
                }
                Table::Resource => {
                    if let Some(version) = field(&row, "version") {
                        self.resource = Some(RouterResource {
                            version: label(version),
                            board: clean(&row, "board-name"),
                            uptime: clean(&row, "uptime"),
                            cpu_percent: number(&row, "cpu-load"),
                            free_memory_bytes: number(&row, "free-memory"),
                            total_memory_bytes: number(&row, "total-memory"),
                        });
                        true
                    } else {
                        false
                    }
                }
                Table::Interface => {
                    if let Some(name) = field(&row, "name") {
                        self.interfaces.push(RouterInterface {
                            name: label(name),
                            kind: clean(&row, "type"),
                            running: flag(&row, "running"),
                            disabled: flag(&row, "disabled"),
                            rx_bytes: number(&row, "rx-byte"),
                            tx_bytes: number(&row, "tx-byte"),
                        });
                        true
                    } else {
                        false
                    }
                }
                Table::Lease | Table::Arp | Table::Neighbor6 => {
                    let lease = matches!(table, Table::Lease);
                    if let Some(ip) = field(&row, "active-address")
                        .and_then(|v| v.parse().ok())
                        .or_else(|| field(&row, "address").and_then(|v| v.parse().ok()))
                        .filter(|ip: &IpAddr| {
                            ip.is_ipv4() != (table == Table::Neighbor6)
                                && !ip.is_unspecified()
                                && !ip.is_multicast()
                        })
                    {
                        self.inventory.push(RouterHost {
                            ip,
                            mac: field(&row, "active-mac-address")
                                .and_then(|v| v.parse().ok())
                                .or_else(|| {
                                    field(&row, "mac-address").and_then(|v| v.parse().ok())
                                }),
                            host_name: clean(&row, "host-name"),
                            location: if lease {
                                exact(&row, "active-server").or_else(|| exact(&row, "server"))
                            } else {
                                exact(&row, "interface")
                            },
                            status: clean(&row, "status"),
                            active_binding: lease
                                && field(&row, "status") == Some("bound")
                                && field(&row, "active-address")
                                    .and_then(|v| v.parse::<IpAddr>().ok())
                                    == Some(ip)
                                && field(&row, "active-mac-address")
                                    .and_then(|v| v.parse::<crate::Mac>().ok())
                                    .is_some(),
                            expires_after: clean(&row, "expires-after"),
                            reachable: match table {
                                Table::Arp => {
                                    flag(&row, "complete") == Some(true)
                                        && field(&row, "status") == Some("reachable")
                                }
                                Table::Neighbor6 => field(&row, "status") == Some("reachable"),
                                _ => false,
                            },
                            source: match table {
                                Table::Lease => "DHCPv4",
                                Table::Arp => "ARP",
                                _ => "IPv6 ND",
                            }
                            .into(),
                        });
                        true
                    } else {
                        false
                    }
                }
                Table::DefaultRoute4 | Table::DefaultRoute6 => {
                    let expected = if matches!(table, Table::DefaultRoute4) {
                        "0.0.0.0/0"
                    } else {
                        "::/0"
                    };
                    if field(&row, "dst-address") == Some(expected) {
                        self.default_routes.push(RouterRoute {
                            destination: expected.into(),
                            gateway: clean(&row, "gateway"),
                            immediate_gateway: clean(&row, "immediate-gw"),
                            table: clean(&row, "routing-table"),
                            active: flag(&row, "active"),
                            distance: number(&row, "distance"),
                        });
                        true
                    } else {
                        false
                    }
                }
                Table::BridgePorts | Table::Vlan | Table::Firewall | Table::Nat => {
                    let id = field(&row, ".id");
                    let (a, b) = match table {
                        Table::BridgePorts => ("bridge", "interface"),
                        Table::Vlan => ("name", "interface"),
                        _ => ("chain", "action"),
                    };
                    if let (Some(id), Some(subject), Some(relation)) =
                        (id, field(&row, a), field(&row, b))
                    {
                        let mut fields = std::collections::BTreeMap::new();
                        for key in [
                            "pvid",
                            "hw",
                            "vlan-id",
                            "running",
                            "disabled",
                            "dynamic",
                            "protocol",
                            "src-address",
                            "dst-address",
                            "src-address-list",
                            "dst-address-list",
                            "in-interface",
                            "out-interface",
                            "in-interface-list",
                            "out-interface-list",
                            "src-port",
                            "dst-port",
                            "to-addresses",
                            "to-ports",
                            "bytes",
                            "packets",
                        ] {
                            if let Some(v) = clean(&row, key) {
                                fields.insert(key.to_string(), v);
                            } else if let Some(v) =
                                row.get(key).filter(|v| v.is_number() || v.is_boolean())
                            {
                                fields.insert(key.to_string(), v.to_string());
                            }
                        }
                        let item = RouterConfigRow {
                            id: label(id),
                            order: index + 1,
                            kind: table.name().into(),
                            subject: label(subject),
                            relation: label(relation),
                            fields,
                        };
                        if matches!(table, Table::BridgePorts | Table::Vlan) {
                            self.topology.push(item);
                        } else {
                            self.rules.push(item);
                        }
                        true
                    } else {
                        false
                    }
                }
                table if Table::evidence_tables().contains(&table) => {
                    self.network.push(table, &row)
                }
                Table::Connections => {
                    if let (Some(protocol), Some(source), Some(destination)) = (
                        field(&row, "protocol"),
                        field(&row, "src-address").and_then(tuple),
                        field(&row, "dst-address").and_then(tuple),
                    ) {
                        self.connections.push(RouterConnection {
                            protocol: label(protocol),
                            source,
                            destination,
                            reply_source: field(&row, "reply-src-address").and_then(tuple),
                            reply_destination: field(&row, "reply-dst-address").and_then(tuple),
                            original_bytes: number(&row, "orig-bytes"),
                            reply_bytes: number(&row, "repl-bytes"),
                            seen_reply: flag(&row, "seen-reply"),
                            source_nat: flag(&row, "srcnat"),
                            destination_nat: flag(&row, "dstnat"),
                            fasttrack: flag(&row, "fasttrack"),
                            hw_offload: flag(&row, "hw-offload"),
                            tcp_state: clean(&row, "tcp-state"),
                        });
                        true
                    } else {
                        false
                    }
                }
                _ => false,
            };
            if ok {
                accepted += 1;
            }
        }
        Ok((accepted, total - accepted))
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct RouterConfigRow {
    pub id: String,
    pub order: usize,
    pub kind: String,
    pub subject: String,
    pub relation: String,
    pub fields: std::collections::BTreeMap<String, String>,
}
pub(super) fn field<'a>(row: &'a Value, k: &str) -> Option<&'a str> {
    row.get(k)?.as_str().filter(|v| !v.trim().is_empty())
}
pub(super) fn exact(row: &Value, k: &str) -> Option<String> {
    let raw = field(row, k)?;
    (raw.len() <= 160 && label(raw) == raw).then(|| raw.to_owned())
}
pub(super) fn clean(row: &Value, k: &str) -> Option<String> {
    field(row, k).map(label)
}
pub(super) fn number(row: &Value, k: &str) -> Option<u64> {
    row.get(k)?.as_u64().or_else(|| field(row, k)?.parse().ok())
}
pub(super) fn flag(row: &Value, k: &str) -> Option<bool> {
    row.get(k)?.as_bool().or_else(|| match field(row, k)? {
        "true" | "yes" | "1" => Some(true),
        "false" | "no" | "0" => Some(false),
        _ => None,
    })
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouterResource {
    pub version: String,
    pub board: Option<String>,
    pub uptime: Option<String>,
    pub cpu_percent: Option<u64>,
    pub free_memory_bytes: Option<u64>,
    pub total_memory_bytes: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouterInterface {
    pub name: String,
    pub kind: Option<String>,
    pub running: Option<bool>,
    pub disabled: Option<bool>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
}
#[derive(Clone)]
pub struct InterfaceBaseline {
    authority: String,
    identity: Option<String>,
    pub(super) stamp: u64,
    uptime_seconds: u64,
    interfaces: Vec<RouterInterface>,
}
impl InterfaceBaseline {
    pub fn capture(s: &RouterSnapshot) -> Option<Self> {
        let stamp = s
            .coverage
            .iter()
            .find(|c| {
                c.source == Table::Interface.name() && c.state == CoverageState::CompleteSnapshot
            })?
            .observed_at;
        let uptime_seconds = uptime_seconds(s.resource.as_ref()?.uptime.as_deref()?)?;
        Some(Self {
            authority: s.authority.clone(),
            identity: s.identity.clone(),
            stamp,
            uptime_seconds,
            interfaces: s.interfaces.clone(),
        })
    }
}
fn uptime_seconds(value: &str) -> Option<u64> {
    let mut total = 0u64;
    let mut unit_start = 0;
    let mut previous_factor = u64::MAX;
    for (i, b) in value.bytes().enumerate() {
        if b.is_ascii_digit() {
            continue;
        }
        let factor = match b {
            b'w' => 604800,
            b'd' => 86400,
            b'h' => 3600,
            b'm' => 60,
            b's' => 1,
            _ => return None,
        };
        if factor >= previous_factor {
            return None;
        }
        let amount = value.get(unit_start..i)?.parse::<u64>().ok()?;
        total = total.checked_add(amount.checked_mul(factor)?)?;
        unit_start = i + 1;
        previous_factor = factor;
    }
    (unit_start != 0 && unit_start == value.len()).then_some(total)
}
/// A two-snapshot estimate, not a historical total. Reset or missing data is not zero.
pub fn interface_bitrate(
    previous: &InterfaceBaseline,
    latest: &RouterSnapshot,
    name: &str,
) -> Option<(Option<u64>, Option<u64>)> {
    if previous.authority != latest.authority || previous.identity != latest.identity {
        return None;
    }
    let stamp = |s: &RouterSnapshot| {
        s.coverage
            .iter()
            .find(|c| {
                c.source == Table::Interface.name() && c.state == CoverageState::CompleteSnapshot
            })
            .map(|c| c.observed_at)
    };
    let elapsed = stamp(latest)?.checked_sub(previous.stamp)?;
    if !(1..=super::FRESH_SECONDS).contains(&elapsed) {
        return None;
    }
    let uptime_delta = uptime_seconds(latest.resource.as_ref()?.uptime.as_deref()?)?
        .checked_sub(previous.uptime_seconds)?;
    if uptime_delta.abs_diff(elapsed) > 5 {
        return None;
    }
    fn unique<'a>(interfaces: &'a [RouterInterface], name: &str) -> Option<&'a RouterInterface> {
        let mut rows = interfaces.iter().filter(|i| i.name == name);
        let row = rows.next()?;
        rows.next().is_none().then_some(row)
    }
    let old = unique(&previous.interfaces, name)?;
    let new = unique(&latest.interfaces, name)?;
    if old.kind != new.kind
        || old.disabled != Some(false)
        || new.disabled != Some(false)
        || old.running != Some(true)
        || new.running != Some(true)
    {
        return None;
    }
    let rate = |prior: Option<u64>, next: Option<u64>| {
        let bits = u128::from(next?.checked_sub(prior?)?) * 8;
        u64::try_from(bits / u128::from(elapsed)).ok()
    };
    Some((
        rate(old.rx_bytes, new.rx_bytes),
        rate(old.tx_bytes, new.tx_bytes),
    ))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RouterHost {
    pub ip: IpAddr,
    pub mac: Option<crate::Mac>,
    pub host_name: Option<String>,
    pub location: Option<String>,
    pub status: Option<String>,
    pub active_binding: bool,
    pub expires_after: Option<String>,
    pub reachable: bool,
    pub source: String,
}
impl RouterHost {
    pub fn coverage_source(&self) -> &'static str {
        match self.source.as_str() {
            "DHCPv4" => Table::Lease.name(),
            "ARP" => Table::Arp.name(),
            _ => Table::Neighbor6.name(),
        }
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct RouterRoute {
    pub destination: String,
    pub gateway: Option<String>,
    pub immediate_gateway: Option<String>,
    pub table: Option<String>,
    pub active: Option<bool>,
    pub distance: Option<u64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct RouterConnection {
    pub protocol: String,
    pub source: Tuple,
    pub destination: Tuple,
    pub reply_source: Option<Tuple>,
    pub reply_destination: Option<Tuple>,
    pub original_bytes: Option<u64>,
    pub reply_bytes: Option<u64>,
    pub seen_reply: Option<bool>,
    pub source_nat: Option<bool>,
    pub destination_nat: Option<bool>,
    pub fasttrack: Option<bool>,
    pub hw_offload: Option<bool>,
    pub tcp_state: Option<String>,
}
#[derive(Clone, Copy, Debug, Serialize)]
pub struct Tuple {
    pub ip: IpAddr,
    pub port: Option<u16>,
}
impl std::fmt::Display for Tuple {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(port) = self.port {
            write!(f, "{}", SocketAddr::new(self.ip, port))
        } else {
            write!(f, "{}", self.ip)
        }
    }
}
fn tuple(s: &str) -> Option<Tuple> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        Some(Tuple {
            ip: addr.ip(),
            port: Some(addr.port()),
        })
    } else {
        s.parse().ok().map(|ip| Tuple { ip, port: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authority_does_not_accept_paths_userinfo_or_http() {
        for invalid in [
            "http://router",
            "router/rest",
            "x@y",
            "router?foo",
            "router:0",
            "router:65536",
            "router/../other",
            "router\\evil",
            "[::]",
            "a..b",
        ] {
            assert!(Authority::parse(invalid).is_err(), "{invalid}");
        }
        assert_eq!(
            Authority::parse("https://LAN.EXAMPLE:8443/")
                .unwrap()
                .display(),
            "lan.example:8443"
        );
        assert_eq!(
            Authority::parse("[2001:db8::1]").unwrap().display(),
            "[2001:db8::1]:443"
        );
        for table in Table::ALL {
            assert!(table.path().starts_with("/rest/") && !table.path().contains("password"));
        }
    }
    #[test]
    fn router_tuples_and_nat_are_observations_not_proof_of_internet() {
        let mut s = RouterSnapshot::new(&Authority::parse("router.example").unwrap(), 100);
        s.ingest(Table::Connections, Ok(br#"[{"protocol":"tcp","src-address":"192.0.2.2:1050","dst-address":"203.0.113.8:443","reply-src-address":"203.0.113.8:443","reply-dst-address":"198.51.100.5:9000","orig-bytes":"100","seen-reply":"yes","srcnat":"true","password":"DO-NOT-EXPORT"},{"protocol":"tcp","src-address":"invalid"}]"#.to_vec()), 101);
        assert_eq!(s.coverage[0].state, CoverageState::Partial);
        assert_eq!(s.connections[0].reply_destination.unwrap().port, Some(9000));
        assert_eq!(s.connections[0].source_nat, Some(true));
        assert!(!serde_json::to_string(&s).unwrap().contains("DO-NOT-EXPORT"));
        s.ingest(Table::Arp, Err("HTTP 403".into()), 101);
        assert_eq!(s.coverage[1].state, CoverageState::Unavailable);
    }
    #[test]
    fn parses_singleton_system_tables_and_only_accepts_default_routes() {
        let mut s = RouterSnapshot::new(&Authority::parse("router.example").unwrap(), 100);
        s.ingest(Table::Identity, Ok(br#"{"name":"lab"}"#.to_vec()), 100);
        s.ingest(Table::DefaultRoute6, Ok(br#"[{"dst-address":"::/0","routing-table":"main","gateway":"fe80::1%ether1","active":"true"},{"dst-address":"2001:db8::/32"}]"#.to_vec()), 101);
        assert_eq!(s.identity.as_deref(), Some("lab"));
        assert_eq!(s.default_routes.len(), 1);
        assert_eq!(s.default_routes[0].active, Some(true));
        assert_eq!(s.coverage[1].state, CoverageState::Partial);
    }
    #[test]
    fn bandwidth_uses_deltas_and_does_not_turn_a_reset_into_zero() {
        fn snapshot(stamp: u64, uptime: &str, rx: u64, tx: u64) -> RouterSnapshot {
            let mut s = RouterSnapshot::new(&Authority::parse("router.example").unwrap(), stamp);
            s.ingest(
                Table::Resource,
                Ok(format!(r#"[{{"version":"7.x","uptime":"{uptime}"}}]"#).into_bytes()),
                stamp,
            );
            s.ingest(Table::Interface, Ok(format!(r#"[{{"name":"ether1","running":true,"disabled":false,"rx-byte":"{rx}","tx-byte":"{tx}"}}]"#).into_bytes()), stamp);
            s
        }
        let base = InterfaceBaseline::capture(&snapshot(100, "2d1h5m", 1000, 2000)).unwrap();
        let next = snapshot(110, "2d1h5m10s", 2000, 100);
        assert_eq!(
            interface_bitrate(&base, &next, "ether1"),
            Some((Some(800), None))
        );
        assert_eq!(
            interface_bitrate(&base, &snapshot(110, "10s", 5000, 6000), "ether1"),
            None
        );
        assert_eq!(uptime_seconds("1m2h"), None);
    }
    #[test]
    fn firewall_and_vlan_are_allowlisted_snapshot_rows() {
        let mut r = RouterSnapshot::new(&Authority::parse("router.example").unwrap(), 100);
        r.ingest(Table::Firewall, Ok(br#"[{}, {".id":"*2","chain":"forward","action":"drop","bytes":"99","password":"private","comment":"not collected"}]"#.to_vec()),101);
        r.ingest(
            Table::Vlan,
            Ok(br#"[{".id":"*3","name":"vlan20","interface":"bridge","vlan-id":20}]"#.to_vec()),
            101,
        );
        assert_eq!(r.rules[0].order, 2);
        assert_eq!(r.topology[0].fields["vlan-id"], "20");
        assert!(!r.rules[0].fields.contains_key("password"));
        assert_eq!(r.coverage[0].state, CoverageState::Partial);
    }
}
