//! Read-only DHCPv6 bindings. Do not retain DUID, credentials or client identifiers.
use super::router::{exact, flag};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::Ipv6Addr;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub prefix: Ipv6Addr,
    pub bits: u8,
    pub server: String,
    pub status: Option<String>,
    pub disabled: Option<bool>,
    pub observed_at: u64,
}
impl Binding {
    pub fn parse(row: &Value, stamp: u64) -> Option<Self> {
        let raw = exact(row, "address")?;
        let (address, bits) = match raw.split_once('/') {
            Some((address, bits)) => (address, bits.parse::<u8>().ok()?),
            None => (raw.as_str(), 128),
        };
        let address: Ipv6Addr = address.parse().ok()?;
        if bits > 128 || address.is_unspecified() || address.is_multicast() {
            return None;
        }
        let mask = u128::MAX.checked_shl(u32::from(128 - bits)).unwrap_or(0);
        if u128::from(address) & mask != u128::from(address) {
            return None;
        }
        Some(Self {
            prefix: address,
            bits,
            server: exact(row, "server")?,
            status: exact(row, "status"),
            disabled: flag(row, "disabled"),
            observed_at: stamp,
        })
    }

    pub fn valid(&self) -> bool {
        let raw = serde_json::json!({
            "address": format!("{}/{}", self.prefix, self.bits),
            "server": self.server,
            "status": self.status,
            "disabled": self.disabled,
        });
        Self::parse(&raw, self.observed_at).as_ref() == Some(self)
    }

    pub fn kind(&self) -> &'static str {
        if self.bits == 128 {
            "Alamat DHCPv6"
        } else {
            "Prefix DHCPv6 / PD"
        }
    }

    pub fn state(&self) -> &'static str {
        match (self.disabled, self.status.as_deref()) {
            (Some(true), _) => "Nonaktif",
            (Some(false), Some("bound")) => "Bound teramati",
            (_, Some("bound")) => "Bound; flag nonaktif tidak diketahui",
            (_, Some(_)) => "Tidak terbukti bound",
            _ => "Status tidak diketahui",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Server {
    pub name: String,
    pub interface: String,
    pub disabled: Option<bool>,
    pub invalid: Option<bool>,
}
impl Server {
    pub fn parse(row: &Value) -> Option<Self> {
        Some(Self {
            name: exact(row, "name")?,
            interface: exact(row, "interface")?,
            disabled: flag(row, "disabled"),
            invalid: flag(row, "invalid"),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingScope {
    pub interface: Option<String>,
    pub vrf: Option<String>,
}
pub struct ScopeIndex {
    binding_stamp: Option<u64>,
    server_stamp: Option<u64>,
    vrf_stamp: Option<u64>,
    servers: std::collections::BTreeMap<String, Option<String>>,
    vrfs: std::collections::BTreeMap<String, Option<String>>,
}
impl ScopeIndex {
    pub fn new(snapshot: &super::router::RouterSnapshot) -> Self {
        use super::{CoverageState, router::Table};
        let stamp = |table: Table| {
            snapshot
                .coverage
                .iter()
                .rev()
                .find(|c| c.source == table.name())
                .filter(|c| c.state == CoverageState::CompleteSnapshot)
                .map(|c| c.observed_at)
        };
        let mut servers = std::collections::BTreeMap::new();
        for server in &snapshot.dhcp6_servers {
            let port = (server.disabled == Some(false) && server.invalid != Some(true))
                .then(|| server.interface.clone());
            servers
                .entry(server.name.clone())
                .and_modify(|v| *v = None)
                .or_insert(port);
        }
        let vrfs = super::network_map::explicit_vrfs(snapshot);
        Self {
            binding_stamp: stamp(Table::Dhcp6Binding),
            server_stamp: stamp(Table::Dhcp6Server),
            vrf_stamp: stamp(Table::Vrf),
            servers,
            vrfs,
        }
    }

    pub fn scope(&self, binding: &Binding) -> BindingScope {
        let mut scope = BindingScope {
            interface: None,
            vrf: None,
        };
        let aligned =
            |stamp: Option<u64>| stamp.is_some_and(|t| t.abs_diff(binding.observed_at) <= 60);
        if self.binding_stamp != Some(binding.observed_at) || !aligned(self.server_stamp) {
            return scope;
        }
        let Some(Some(port)) = self.servers.get(&binding.server) else {
            return scope;
        };
        scope.interface = Some(port.clone());
        if aligned(self.vrf_stamp) {
            scope.vrf = self.vrfs.get(port).cloned().flatten();
        }
        scope
    }
}

pub fn binding_scope(snapshot: &super::router::RouterSnapshot, binding: &Binding) -> BindingScope {
    ScopeIndex::new(snapshot).scope(binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn distinguishes_address_prefix_and_unknown() {
        let a = Binding::parse(&json!({"address":"2001:db8::10/128","server":"blue","status":"bound","disabled":false,"duid":"private"}), 40).unwrap();
        assert_eq!(a.kind(), "Alamat DHCPv6");
        assert_eq!(a.state(), "Bound teramati");
        assert!(!serde_json::to_string(&a).unwrap().contains("private"));
        let p = Binding::parse(
            &json!({"address":"2001:db8:1::/64","server":"red","status":"bound"}),
            41,
        )
        .unwrap();
        assert_eq!(p.kind(), "Prefix DHCPv6 / PD");
        assert_eq!(p.state(), "Bound; flag nonaktif tidak diketahui");
    }

    #[test]
    fn maps_only_aligned_complete_unique_server_and_vrf() {
        use super::super::router::{Authority, RouterSnapshot, Table};
        let mut s = RouterSnapshot::new(&Authority::parse("lab.example").unwrap(), 100);
        s.ingest(
            Table::Vrf,
            Ok(br#"[{"name":"blue","interfaces":"ether1"}]"#.to_vec()),
            100,
        );
        s.ingest(
            Table::Dhcp6Server,
            Ok(br#"[{"name":"dhcp","interface":"ether1","disabled":false}]"#.to_vec()),
            100,
        );
        s.ingest(Table::Dhcp6Binding, Ok(br#"[{"address":"2001:db8::/64","server":"dhcp","status":"bound","disabled":false}]"#.to_vec()), 160);
        let scope = binding_scope(&s, &s.dhcp6[0]);
        assert_eq!(scope.interface.as_deref(), Some("ether1"));
        assert_eq!(scope.vrf.as_deref(), Some("blue"));
        s.dhcp6[0].observed_at = 161;
        assert_eq!(binding_scope(&s, &s.dhcp6[0]).interface, None);
        s.dhcp6[0].observed_at = 160;
        s.dhcp6_servers.push(s.dhcp6_servers[0].clone());
        assert_eq!(binding_scope(&s, &s.dhcp6[0]).interface, None);
    }

    #[test]
    fn rejects_bad_prefix_and_missing_server() {
        for raw in [
            "192.0.2.1",
            "ff02::1",
            "2001:db8::1/64",
            "::/0",
            "2001:db8::/129",
        ] {
            assert!(Binding::parse(&json!({"address":raw,"server":"lab"}), 1).is_none());
        }
        assert!(Binding::parse(&json!({"address":"2001:db8::1"}), 1).is_none());
    }
}
