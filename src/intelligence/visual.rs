//! Bounded read-only visual models; no physical-link or reachability inference.
use super::{interface_trend::Point, network_map::Observation, router::Table};
use std::collections::VecDeque;

pub const MAX_EDGES: usize = 1000;
pub const MAX_POINTS: usize = 120;

#[derive(Clone, Debug)]
pub struct Edge {
    pub left: String,
    pub right: String,
    pub left_kind: &'static str,
    pub right_kind: &'static str,
    pub scope: String,
    pub authority: Option<String>,
    pub source: &'static str,
    pub utc: u64,
    pub details: String,
}
impl Edge {
    pub fn scoped(authority: &str, row: &Observation) -> Self {
        let mut edge = Self::from_observation(row);
        edge.authority = Some(authority.to_owned());
        edge
    }

    pub fn from_observation(row: &Observation) -> Self {
        let (left_kind, right_kind) = match row.source {
            s if s == Table::BridgePorts.name() => ("Bridge", "Interface"),
            s if s == Table::Vlan.name() => ("VLAN", "Interface"),
            s if s == Table::Vrf.name() => ("VRF", "Daftar interface"),
            s if s == Table::BridgeHost.name() => ("MAC FDB", "Interface"),
            s if s == Table::BridgeVlan.name() => ("Bridge / VLAN", "Bridge"),
            s if s == Table::Neighbors.name() => ("Neighbor", "Interface"),
            s if s == Table::RoutingTable.name() => ("Tabel rute", "Atribut FIB"),
            s if s == Table::DefaultRoute4.name() || s == Table::DefaultRoute6.name() => {
                ("Rute default", "Gateway")
            }
            _ => ("Entitas teramati", "Relasi teramati"),
        };
        Self {
            left: row.subject.clone(),
            right: row.target.clone(),
            left_kind,
            right_kind,
            scope: row.scope.clone(),
            authority: None,
            source: row.source,
            utc: row.observed_at,
            details: row.details.clone(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Series {
    pub label: String,
    pub points: Vec<Point>,
}
impl Series {
    pub fn new(label: String, points: &VecDeque<Point>) -> Self {
        let points = points
            .iter()
            .skip(points.len().saturating_sub(MAX_POINTS))
            .cloned()
            .collect();
        Self { label, points }
    }

    pub fn range(&self, end: usize, span: usize) -> &[Point] {
        let end = end.min(self.points.len());
        &self.points[end.saturating_sub(span)..end]
    }

    /// Native text preview with a common RX/TX scale. Missing data is '?',
    /// measured zero is '·'; no interpolation or aggregation is performed.
    pub fn preview(&self, span: usize) -> (String, String) {
        let points = self.range(self.points.len(), span.clamp(1, MAX_POINTS));
        let maximum = Self::max_value(points);
        let glyph = |value: Option<u64>| match value {
            None => '?',
            Some(0) => '·',
            Some(value) => {
                let level = Self::axis(value, maximum, 7).clamp(0, 7) as usize;
                ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'][level]
            }
        };
        (
            points.iter().map(|point| glyph(point.rx_bps)).collect(),
            points.iter().map(|point| glyph(point.tx_bps)).collect(),
        )
    }

    pub fn p95(points: &[Point], rx: bool) -> Option<u64> {
        let mut values: Vec<u64> = points.iter().filter_map(|p| if rx { p.rx_bps } else { p.tx_bps }).collect();
        if values.is_empty() {
            return None;
        }
        values.sort_unstable();
        Some(values[(values.len() * 95).div_ceil(100) - 1])
    }

    pub fn max_value(points: &[Point]) -> u64 {
        points
            .iter()
            .flat_map(|p| [p.rx_bps, p.tx_bps])
            .flatten()
            .max()
            .unwrap_or(0)
    }

    pub fn axis(value: u64, maximum: u64, extent: i32) -> i32 {
        let extent = extent.max(0) as u128;
        if maximum == 0 {
            return 0;
        }
        (u128::from(value.min(maximum)) * extent / u128::from(maximum)) as i32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn series_window_retains_zero_gap_and_u64_limits() {
        let mut points = VecDeque::new();
        for i in 0..130 {
            points.push_back(Point {
                utc: i,
                received_utc: i,
                interval_s: Some(1),
                rx_bps: (i != 128).then_some(0),
                tx_bps: Some(u64::MAX),
            });
        }
        let series = Series::new("lab".into(), &points);
        assert_eq!(series.points.len(), MAX_POINTS);
        let tail = series.range(120, 2);
        assert_eq!(tail[0].rx_bps, None);
        assert_eq!(tail[1].rx_bps, Some(0));
        assert_eq!(series.preview(2), ("?·".into(), "██".into()));
        assert_eq!(Series::p95(tail, true), Some(0));
        assert_eq!(Series::p95(tail, false), Some(u64::MAX));
        assert_eq!(Series::p95(&[], true), None);
        assert_eq!(Series::max_value(tail), u64::MAX);
        assert_eq!(Series::axis(u64::MAX, u64::MAX, 200), 200);
        assert!(series.range(0, 30).is_empty());
    }

    #[test]
    fn edge_keeps_scope_and_provenance() {
        let edge = Edge::from_observation(&Observation {
            subject: "MAC".into(),
            target: "ether1".into(),
            scope: "router A / blue".into(),
            basis: "MAC teramati",
            source: Table::BridgeHost.name(),
            observed_at: 42,
            details: "FDB bukan kabel fisik".into(),
        });
        assert_eq!((edge.left_kind, edge.right_kind), ("MAC FDB", "Interface"));
        assert_eq!(edge.scope, "router A / blue");
        assert_eq!(edge.utc, 42);
    }
}
