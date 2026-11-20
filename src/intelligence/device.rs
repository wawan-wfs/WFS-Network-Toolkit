//! Scope-preserving inspection of already collected metadata. No probes.
use super::{
    FRESH_SECONDS,
    flow::{Direction, Flow},
    store::{ArchiveRow, Query},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
};

pub const INSPECTION_LIMIT: usize = 2_000;
pub const SCOPE_LIMIT: usize = 128;

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Scope {
    pub profile: String,
    pub site: String,
    pub vrf: Option<String>,
    pub exporter: SocketAddr,
    pub domain: u32,
}

impl Scope {
    fn from_row(row: &ArchiveRow) -> Self {
        Self {
            profile: row.profile.clone(),
            site: row.site.clone(),
            vrf: row.vrf.clone(),
            exporter: row.flow.exporter,
            domain: row.flow.domain,
        }
    }
    pub fn query(&self, criteria: &Query) -> Query {
        Query {
            site: Some(self.site.clone()),
            vrf: self.vrf.clone(),
            without_vrf: self.vrf.is_none(),
            exporter: Some(self.exporter),
            domain: Some(self.domain),
            profile: Some(self.profile.clone()),
            ..criteria.clone()
        }
    }
    pub fn label(&self) -> String {
        format!(
            "{} / {} · {} · OD {} · {}",
            self.site,
            self.vrf.as_deref().unwrap_or("VRF tidak diketahui"),
            self.profile,
            self.domain,
            self.exporter
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WanObservation {
    Unproven,
    Outbound,
    Paired,
}

#[derive(Debug)]
pub struct ObservedScope {
    pub scope: Scope,
    pub count: usize,
    pub first: u64,
    pub last: u64,
    pub wan: WanObservation,
    pub evidence_at: Option<u64>,
    pub peers: Vec<(IpAddr, usize)>,
}
impl ObservedScope {
    pub fn access_label(&self, now: u64) -> &'static str {
        match self.wan {
            WanObservation::Unproven => "Bukti WAN belum cukup",
            _ if self
                .evidence_at
                .is_some_and(|at| now.saturating_sub(at) > FRESH_SECONDS) =>
            {
                "Observasi WAN historis"
            }
            WanObservation::Outbound => "Arah keluar WAN teramati",
            WanObservation::Paired => "Dua arah WAN teramati",
        }
    }
}

pub(super) type Tuple = (u16, u8, IpAddr, u16, IpAddr, u16, u32, u32);
pub(super) fn tuple(f: &Flow, reverse: bool) -> Option<Tuple> {
    let p = f.protocol.filter(|p| matches!(p, 6 | 17))?;
    let (sport, dport) = (
        f.source_port.filter(|s| *s > 0)?,
        f.destination_port.filter(|d| *d > 0)?,
    );
    let (ingress, egress) = (f.ingress.filter(|i| *i > 0)?, f.egress.filter(|i| *i > 0)?);
    if reverse {
        Some((
            f.version,
            p,
            f.destination,
            dport,
            f.source,
            sport,
            egress,
            ingress,
        ))
    } else {
        Some((
            f.version,
            p,
            f.source,
            sport,
            f.destination,
            dport,
            ingress,
            egress,
        ))
    }
}

#[derive(Default)]
struct Bucket {
    count: usize,
    first: Option<u64>,
    last: u64,
    peers: BTreeMap<IpAddr, usize>,
    outgoing: Vec<Flow>,
    replies: BTreeMap<Tuple, BTreeSet<(u64, u64)>>,
}

#[derive(Debug, Default)]
pub struct Inspection {
    pub examined: usize,
    pub partial: bool,
    pub scopes: Vec<ObservedScope>,
}
impl Inspection {
    pub fn analyze(ip: IpAddr, rows: impl IntoIterator<Item = ArchiveRow>, now: u64) -> Self {
        let mut buckets: BTreeMap<Scope, Bucket> = BTreeMap::new();
        let mut examined = 0;
        let mut partial = false;
        for row in rows {
            if examined == INSPECTION_LIMIT {
                partial = true;
                break;
            }
            examined += 1;
            let f = &row.flow;
            let peer = if f.source == ip {
                f.destination
            } else if f.destination == ip {
                f.source
            } else {
                continue;
            };
            let scope = Scope::from_row(&row);
            if buckets.len() == SCOPE_LIMIT && !buckets.contains_key(&scope) {
                partial = true;
                continue;
            }
            let b = buckets.entry(scope).or_default();
            b.count += 1;
            b.first = Some(b.first.map_or(f.received_at, |old| old.min(f.received_at)));
            b.last = b.last.max(f.received_at);
            *b.peers.entry(peer).or_default() += 1;
            if f.received_at > now
                || f.export_at == 0
                || f.export_at.abs_diff(f.received_at) > FRESH_SECONDS
            {
                continue;
            }
            match row.direction {
                Direction::FromLan if f.source == ip => b.outgoing.push(row.flow),
                Direction::ToLan if f.destination == ip => {
                    if let Some(t) = tuple(f, true) {
                        b.replies
                            .entry(t)
                            .or_default()
                            .insert((f.export_at, f.received_at));
                    }
                }
                _ => {}
            }
        }
        let mut scopes = Vec::new();
        for (scope, b) in buckets {
            let mut strongest = (0, 0);
            for f in b.outgoing {
                let paired = tuple(&f, false)
                    .and_then(|t| b.replies.get(&t))
                    .is_some_and(|times| {
                        times
                            .range(
                                (f.export_at.saturating_sub(300), 0)
                                    ..=(f.export_at.saturating_add(300), u64::MAX),
                            )
                            .any(|(_, received)| received.abs_diff(f.received_at) <= 300)
                    });
                // Timestamp belongs to the outgoing observation. A later single direction
                // should not be silently presented as a newly paired flow.
                let fresh = now.saturating_sub(f.received_at) <= FRESH_SECONDS;
                let rank = if paired { 2 } else { 1 };
                strongest = strongest.max(((u8::from(fresh) * 2) + rank, f.received_at));
            }
            let mut peers = b.peers.into_iter().collect::<Vec<_>>();
            peers.sort_unstable_by_key(|&(ip, count)| (std::cmp::Reverse(count), ip));
            peers.truncate(5);
            scopes.push(ObservedScope {
                scope,
                count: b.count,
                first: b.first.unwrap_or_default(),
                last: b.last,
                wan: match strongest.0 {
                    0 => WanObservation::Unproven,
                    1 | 3 => WanObservation::Outbound,
                    _ => WanObservation::Paired,
                },
                evidence_at: (strongest.0 != 0).then_some(strongest.1),
                peers,
            });
        }
        scopes.sort_unstable_by(|a, b| b.last.cmp(&a.last).then_with(|| a.scope.cmp(&b.scope)));
        Self {
            examined,
            partial,
            scopes,
        }
    }
}
