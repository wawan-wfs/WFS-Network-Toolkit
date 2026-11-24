//! Read-only bounded subnet and coverage summaries. No claim of free addresses.
use super::{Coverage, CoverageState, LocalSnapshot};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Prefix {
    network: IpAddr,
    bits: u8,
}
impl Prefix {
    pub fn new(ip: IpAddr, bits: u8) -> Option<Self> {
        let network = match ip {
            IpAddr::V4(a) if bits <= 32 => {
                let mask = u32::MAX.checked_shl(u32::from(32 - bits)).unwrap_or(0);
                IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
            }
            IpAddr::V6(a) if bits <= 128 => {
                let mask = u128::MAX.checked_shl(u32::from(128 - bits)).unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
            }
            _ => return None,
        };
        Some(Self { network, bits })
    }
    pub fn contains(self, ip: IpAddr) -> bool {
        Self::new(ip, self.bits) == Some(self)
    }
    pub fn cardinality(self) -> String {
        let width = if self.network.is_ipv4() { 32 } else { 128 };
        1u128
            .checked_shl(u32::from(width - self.bits))
            .map_or_else(|| "2^128".into(), |n| n.to_string())
    }
    fn end(self) -> IpAddr {
        match self.network {
            IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from(
                u32::from(a) | u32::MAX.checked_shr(u32::from(self.bits)).unwrap_or(0),
            )),
            IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from(
                u128::from(a) | u128::MAX.checked_shr(u32::from(self.bits)).unwrap_or(0),
            )),
        }
    }
}
impl std::fmt::Display for Prefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.bits)
    }
}

#[derive(Default)]
pub struct CoverageSummary {
    pub complete: usize,
    pub partial: usize,
    pub unavailable: usize,
    pub stale: usize,
}
pub fn coverage(rows: &[Coverage], now: u64) -> CoverageSummary {
    let mut out = CoverageSummary::default();
    for row in rows {
        match row.state {
            CoverageState::CompleteSnapshot => out.complete += 1,
            CoverageState::Partial => out.partial += 1,
            CoverageState::Unavailable => out.unavailable += 1,
        }
        if row.observed_at > now || now - row.observed_at > super::FRESH_SECONDS {
            out.stale += 1;
        }
    }
    out
}

#[derive(Clone, Debug)]
pub struct SubnetRow {
    pub scope: String,
    pub prefix: Prefix,
    pub configured: usize,
    pub observed: usize,
    pub observed_at: u64,
    pub partial: bool,
}
#[derive(Default)]
pub struct Subnets {
    pub rows: Vec<SubnetRow>,
    pub limited: bool,
}
/// Scope keys are typed by the caller; never merge interface indexes or VRFs
/// merely because two subnets have the same prefix.
type PrefixData = (String, BTreeSet<IpAddr>, u64, bool);

pub(crate) struct Index<K: Ord> {
    prefixes: BTreeMap<(K, Prefix), PrefixData>,
    observed: BTreeMap<K, BTreeSet<IpAddr>>,
    limited: bool,
}
impl<K: Ord> Default for Index<K> {
    fn default() -> Self {
        Self {
            prefixes: BTreeMap::new(),
            observed: BTreeMap::new(),
            limited: false,
        }
    }
}
impl<K: Ord> Index<K> {
    pub(crate) fn configure(
        &mut self,
        key: K,
        label: String,
        ip: IpAddr,
        bits: u8,
        stamp: u64,
        partial: bool,
    ) {
        let Some(prefix) = Prefix::new(ip, bits) else {
            return;
        };
        let entry = (key, prefix);
        if self.prefixes.len() >= 512 && !self.prefixes.contains_key(&entry) {
            self.limited = true;
            return;
        }
        let row = self
            .prefixes
            .entry(entry)
            .or_insert_with(|| (label, BTreeSet::new(), stamp, partial));
        row.1.insert(ip);
        row.2 = row.2.min(stamp);
        row.3 |= partial;
    }
    pub(crate) fn observe(&mut self, key: K, ip: IpAddr) {
        if !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback() {
            self.observed.entry(key).or_default().insert(ip);
        }
    }
    pub(crate) fn finish(self) -> Subnets {
        // Sort once per scope, then use binary search for range counts.
        let observed: BTreeMap<_, Vec<_>> = self
            .observed
            .into_iter()
            .map(|(key, ips)| (key, ips.into_iter().collect()))
            .collect();
        let rows = self
            .prefixes
            .into_iter()
            .map(|((key, prefix), (scope, configured, observed_at, partial))| {
                let count = observed.get(&key).map_or(0, |ips| {
                    let lo = ips.partition_point(|ip| *ip < prefix.network);
                    let end = prefix.end();
                    let hi = ips.partition_point(|ip| *ip <= end);
                    hi - lo
                });
                SubnetRow {
                    scope,
                    prefix,
                    configured: configured.len(),
                    observed: count,
                    observed_at,
                    partial,
                }
            })
            .collect();
        Subnets {
            rows,
            limited: self.limited,
        }
    }
}

pub fn local_subnets(s: &LocalSnapshot) -> Subnets {
    let mut index = Index::default();
    let complete = !s.coverage.is_empty()
        && s.coverage
            .iter()
            .all(|c| c.state == CoverageState::CompleteSnapshot);
    for a in &s.addresses {
        if a.ip.is_unspecified() || a.ip.is_multicast() {
            continue;
        }
        index.configure(
            a.interface_index,
            format!("Windows / if#{}", a.interface_index),
            a.ip,
            a.prefix,
            s.observed_at,
            !complete,
        );
        index.observe(a.interface_index, a.ip);
    }
    for n in &s.neighbors {
        index.observe(n.interface_index, n.ip);
    }
    index.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_boundaries_and_ipv6_cardinality() {
        let p = Prefix::new("192.0.2.99".parse().unwrap(), 24).unwrap();
        assert_eq!(p.to_string(), "192.0.2.0/24");
        assert_eq!(p.cardinality(), "256");
        assert!(p.contains("192.0.2.255".parse().unwrap()));
        assert!(!p.contains("192.0.3.0".parse().unwrap()));
        let p = Prefix::new("2001:db8::123".parse().unwrap(), 64).unwrap();
        assert_eq!(p.cardinality(), "18446744073709551616");
        assert!(!p.contains("192.0.2.1".parse().unwrap()));
        assert_eq!(
            Prefix::new("::".parse().unwrap(), 0).unwrap().cardinality(),
            "2^128"
        );
        assert!(Prefix::new("::".parse().unwrap(), 129).is_none());
    }

    #[test]
    fn counts_deduplicate_and_never_merge_scopes() {
        let mut index = Index::default();
        let ip = "192.0.2.1".parse().unwrap();
        for k in [1, 2] {
            index.configure(k, format!("if#{k}"), ip, 24, 100, k == 2);
            index.observe(k, ip);
        }
        let other = "192.0.2.2".parse().unwrap();
        index.observe(1, other);
        index.observe(1, other);
        index.observe(1, "192.0.3.1".parse().unwrap());
        let out = index.finish();
        assert_eq!(out.rows.len(), 2);
        assert_eq!(out.rows[0].observed, 2);
        assert_eq!(out.rows[1].observed, 1);
        assert!(out.rows[1].partial);
    }

    #[test]
    fn bound_and_partial_coverage() {
        let mut index = Index::default();
        for k in 0..513 {
            index.configure(
                k,
                k.to_string(),
                "192.0.2.1".parse().unwrap(),
                24,
                0,
                true,
            );
        }
        let out = index.finish();
        assert_eq!(out.rows.len(), 512);
        assert!(out.limited);
        let rows = vec![Coverage {
            source: "fixture".into(),
            observed_at: 100,
            state: CoverageState::Partial,
            rows: 2,
            detail: None,
        }];
        let out = coverage(&rows, 99);
        assert_eq!(out.partial, 1);
        assert_eq!(out.stale, 1);
    }
}
