//! Persist only typed observations needed to rebuild trends and lease history.
use super::{
    Coverage, CoverageState,
    interface_trend::Trend,
    network_map::LeaseTimeline,
    router::{Authority, RouterHost, RouterInterface, RouterResource, RouterSnapshot, Table},
};
use serde::{Deserialize, Serialize};

pub const SAMPLES_PER_ROUTER: usize = 120;
pub const MAX_ROUTERS: usize = 32;
pub const MAX_BYTES: usize = 1_048_576;
pub const MAX_INTERFACES: usize = 512;
pub const MAX_LEASES: usize = 2_000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sample {
    pub authority: String,
    pub received_utc: u64,
    identity: Option<String>,
    resource: Option<RouterResource>,
    interfaces: Vec<RouterInterface>,
    leases: Vec<RouterHost>,
    coverage: Vec<Coverage>,
    scope: super::network_map::EvidenceTables,
}
impl Sample {
    pub fn capture(snapshot: &RouterSnapshot) -> Self {
        let interfaces: Vec<_> = snapshot
            .interfaces
            .iter()
            .take(MAX_INTERFACES)
            .cloned()
            .collect();
        let mut active = snapshot.inventory.iter().filter(|h| h.active_binding);
        let leases: Vec<_> = active.by_ref().take(MAX_LEASES).cloned().collect();
        let lease_clipped = active.next().is_some();
        let coverage = snapshot
            .coverage
            .iter()
            .filter(|t| {
                [
                    Table::Interface.name(),
                    Table::Lease.name(),
                    Table::Vrf.name(),
                    Table::DhcpServer.name(),
                ]
                .contains(&t.source.as_str())
            })
            .map(|c| {
                let clipped = match c.source.as_str() {
                    s if s == Table::Lease.name() => lease_clipped,
                    s if s == Table::Interface.name() => snapshot.interfaces.len() > MAX_INTERFACES,
                    _ => snapshot.network.lease_scope_truncated(),
                };
                // Do not persist transport errors, connection tracking, DNS names of clients, or REST bodies.
                Coverage {
                    source: c.source.clone(),
                    observed_at: c.observed_at,
                    state: if clipped {
                        CoverageState::Partial
                    } else {
                        c.state
                    },
                    rows: 0,
                    detail: None,
                }
            })
            .collect();
        Self {
            authority: snapshot.authority.clone(),
            received_utc: snapshot.observed_at,
            identity: snapshot.identity.clone(),
            resource: snapshot.resource.clone(),
            interfaces,
            leases: leases
                .into_iter()
                .map(|mut h| {
                    h.host_name = None;
                    h
                })
                .collect(),
            coverage,
            scope: snapshot.network.lease_scope(),
        }
    }
    pub(crate) fn replay(self, views: &mut Views) -> crate::Result<()> {
        let authority = Authority::parse(&self.authority)?;
        if authority.display() != self.authority
            || self.interfaces.len() > MAX_INTERFACES
            || self.leases.len() > MAX_LEASES
            || self.coverage.len() > 4
            || !self.scope.valid_lease_scope()
        {
            return Err("Observasi router tidak sesuai batas arsip.".into());
        }
        let mut s = RouterSnapshot::new(&authority, self.received_utc);
        s.identity = self.identity;
        s.resource = self.resource;
        s.interfaces = self.interfaces;
        s.inventory = self.leases;
        s.coverage = self.coverage;
        s.network = self.scope;
        views.trend.observe(&s);
        views.leases.observe(&s);
        Ok(())
    }
}
#[derive(Default)]
pub struct Views {
    pub trend: Trend,
    pub leases: LeaseTimeline,
    pub samples: usize,
}
