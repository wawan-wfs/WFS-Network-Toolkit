//! Read-only DHCPv6 bindings. Do not retain DUID, credentials or client identifiers.
use super::router::{exact, flag};
use serde::Serialize;
use serde_json::Value;
use std::net::Ipv6Addr;

#[derive(Clone, Debug, Serialize)]
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
        let p = Binding::parse(&json!({"address":"2001:db8:1::/64","server":"red","status":"bound"}), 41).unwrap();
        assert_eq!(p.kind(), "Prefix DHCPv6 / PD");
        assert_eq!(p.state(), "Bound; flag nonaktif tidak diketahui");
    }

    #[test]
    fn rejects_bad_prefix_and_missing_server() {
        for raw in ["192.0.2.1", "ff02::1", "2001:db8::1/64", "::/0", "2001:db8::/129"] {
            assert!(Binding::parse(&json!({"address":raw,"server":"lab"}), 1).is_none());
        }
        assert!(Binding::parse(&json!({"address":"2001:db8::1"}), 1).is_none());
    }
}
