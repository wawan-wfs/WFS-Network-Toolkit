//! Bounded per-session history. Missing or reset counters are never presented as zero.
use super::router::{InterfaceBaseline, RouterSnapshot, interface_bitrate};
use std::{
    collections::{BTreeMap, VecDeque},
    time::Duration,
};

pub const LIMIT: usize = 120;
const MAX_INTERFACES: usize = 512;
const MAX_INTERVAL: Duration = Duration::from_secs(900);

#[derive(Clone, Debug)]
pub struct Point {
    pub utc: u64,
    pub received_utc: u64,
    pub interval_s: Option<u64>,
    pub rx_bps: Option<u64>,
    pub tx_bps: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Summary {
    pub intervals: usize,
    pub valid_intervals: usize,
    pub gaps: usize,
    pub p95_rx: Option<u64>,
    pub p95_tx: Option<u64>,
    pub peak_rx: Option<u64>,
    pub peak_tx: Option<u64>,
}

#[derive(Default)]
pub struct Trend {
    pub streams: BTreeMap<String, VecDeque<Point>>,
    pub limited: bool,
    prior: Option<InterfaceBaseline>,
    latest_stamp: Option<u64>,
}
impl Trend {
    pub fn observe(&mut self, current: &RouterSnapshot) {
        let next = InterfaceBaseline::capture(current);
        let stamp = next.as_ref().map_or(current.observed_at, |b| b.stamp);
        if self.latest_stamp.is_some_and(|old| old >= stamp) {
            return;
        }
        self.latest_stamp = Some(stamp);
        let names: std::collections::BTreeSet<&str> = self
            .streams
            .keys()
            .map(String::as_str)
            .chain(current.interfaces.iter().map(|i| i.name.as_str()))
            .collect();
        let matching: BTreeMap<_, _> =
            current
                .interfaces
                .iter()
                .fold(BTreeMap::<&str, usize>::new(), |mut counts, i| {
                    *counts.entry(&i.name).or_default() += 1;
                    counts
                });
        self.limited |= names.len() > MAX_INTERFACES;
        let names = names
            .iter()
            .copied()
            .filter(|n| self.streams.contains_key(*n))
            .chain(
                names
                    .iter()
                    .copied()
                    .filter(|n| !self.streams.contains_key(*n)),
            )
            .take(MAX_INTERFACES)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        for name in names {
            let usable = matching.get(name.as_str()) == Some(&1) && next.is_some();
            let interval_s = self
                .prior
                .as_ref()
                .and_then(|b| stamp.checked_sub(b.stamp))
                .filter(|d| *d > 0 && *d <= MAX_INTERVAL.as_secs());
            let (rx_bps, tx_bps) = if usable && interval_s.is_some() {
                self.prior
                    .as_ref()
                    .and_then(|b| interface_bitrate(b, current, &name))
                    .unwrap_or((None, None))
            } else {
                (None, None)
            };
            let points = self.streams.entry(name).or_default();
            if points.len() == LIMIT {
                points.pop_front();
            }
            points.push_back(Point {
                utc: stamp,
                received_utc: current.observed_at,
                interval_s,
                rx_bps,
                tx_bps,
            });
        }
        self.prior = next;
    }
}
pub fn summarize(points: &VecDeque<Point>) -> Summary {
    fn series(values: impl Iterator<Item = u64>) -> (Option<u64>, Option<u64>) {
        let mut xs: Vec<_> = values.collect();
        xs.sort_unstable();
        let n = xs.len();
        (
            n.checked_sub(1).map(|_| xs[(n * 95).div_ceil(100) - 1]),
            xs.last().copied(),
        )
    }
    let (p95_rx, peak_rx) = series(points.iter().filter_map(|p| p.rx_bps));
    let (p95_tx, peak_tx) = series(points.iter().filter_map(|p| p.tx_bps));
    Summary {
        intervals: points.len(),
        valid_intervals: points
            .iter()
            .filter(|p| p.rx_bps.is_some() && p.tx_bps.is_some())
            .count(),
        gaps: points
            .iter()
            .filter(|p| p.rx_bps.is_none() || p.tx_bps.is_none())
            .count(),
        p95_rx,
        p95_tx,
        peak_rx,
        peak_tx,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intelligence::router::{Authority, Table};
    fn sample(stamp: u64, uptime: u64, rx: u64, tx: u64) -> RouterSnapshot {
        let mut s = RouterSnapshot::new(&Authority::parse("fixture.example.test").unwrap(), stamp);
        s.ingest(
            Table::Resource,
            Ok(format!(r#"{{"version":"7.test","uptime":"{uptime}s"}}"#).into_bytes()),
            stamp,
        );
        s.ingest(Table::Interface,Ok(format!(r#"[{{"name":"ether1","type":"ether","running":true,"disabled":false,"rx-byte":"{rx}","tx-byte":"{tx}"}}]"#).into_bytes()),stamp);
        s
    }
    #[test]
    fn trend_marks_restart_missing_wrap_and_preserves_true_zero() {
        let mut t = Trend::default();
        for s in [
            sample(100, 1000, 100, 200),
            sample(110, 1010, 100, 250),
            sample(120, 1020, 90, 350),
            sample(130, 10, 91, 360),
            sample(140, 20, 200, 480),
        ] {
            t.observe(&s);
        }
        let points = &t.streams["ether1"];
        assert_eq!(points[1].rx_bps, Some(0));
        assert_eq!(points[1].tx_bps, Some(40));
        assert_eq!(points[2].rx_bps, None);
        assert_eq!(points[3].tx_bps, None);
        let summary = summarize(points);
        assert_eq!(
            (
                summary.valid_intervals,
                summary.gaps,
                summary.p95_tx,
                summary.peak_tx
            ),
            (2, 3, Some(96), Some(96))
        );
        let mut missing = sample(150, 30, 500, 500);
        missing.interfaces.clear();
        t.observe(&missing);
        assert_eq!(t.streams["ether1"].back().unwrap().tx_bps, None);
    }
    #[test]
    fn history_is_capped_and_ignores_old_samples() {
        let mut t = Trend::default();
        for i in 1..=130 {
            t.observe(&sample(i * 10, i * 10, i, i));
        }
        t.observe(&sample(10, 10, 0, 0));
        assert_eq!(t.streams["ether1"].len(), LIMIT);
        assert_eq!(t.streams["ether1"].back().unwrap().utc, 1300);
    }
}
