//! In-memory operational alerts from the running collector, never network actions.
use super::flow::Stats;
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum Signal {
    MissingTemplate,
    Dropped,
    Stale,
}
impl Signal {
    pub fn label(self) -> &'static str {
        match self {
            Self::MissingTemplate => "Template hilang",
            Self::Dropped => "Record arsip drop",
            Self::Stale => "Collector sepi",
        }
    }
}
#[derive(Clone, Debug)]
pub struct Event {
    pub id: u64,
    pub signal: Signal,
    pub utc: u64,
    pub total: u64,
    pub acknowledged: bool,
}
struct Pending {
    started: Instant,
    total: u64,
}
#[derive(Default)]
pub struct Alerts {
    pub events: VecDeque<Event>,
    pub limited: bool,
    pending: BTreeMap<Signal, Pending>,
    last_event: BTreeMap<Signal, Instant>,
    started: Option<Instant>,
    last_activity: Option<Instant>,
    accepted: u64,
    missing: u64,
    dropped: u64,
    stale: bool,
    next: u64,
}
impl Alerts {
    pub fn observe(&mut self, now: Instant, utc: u64, stats: &Stats) {
        const DEBOUNCE: Duration = Duration::from_secs(5);
        const COOLDOWN: Duration = Duration::from_secs(60);
        const IDLE: Duration = Duration::from_secs(300);
        let started = *self.started.get_or_insert(now);
        if stats.accepted_datagrams != self.accepted {
            self.last_activity = Some(now);
            self.accepted = stats.accepted_datagrams;
        }
        let stale = now.saturating_duration_since(self.last_activity.unwrap_or(started)) >= IDLE;
        if !stale {
            self.pending.remove(&Signal::Stale);
        }
        let changes = [
            (
                Signal::MissingTemplate,
                (stats.missing_templates > self.missing).then_some(stats.missing_templates),
            ),
            (
                Signal::Dropped,
                (stats.archive_dropped > self.dropped).then_some(stats.archive_dropped),
            ),
            (Signal::Stale, (stale && !self.stale).then_some(300)),
        ];
        self.missing = stats.missing_templates;
        self.dropped = stats.archive_dropped;
        self.stale = stale;
        for (signal, observed) in changes {
            if let Some(total) = observed {
                self.pending
                    .entry(signal)
                    .and_modify(|p| p.total = total)
                    .or_insert(Pending {
                        started: now,
                        total,
                    });
            }
            if self
                .pending
                .get(&signal)
                .is_some_and(|p| now.saturating_duration_since(p.started) >= DEBOUNCE)
                && self
                    .last_event
                    .get(&signal)
                    .is_none_or(|t| now.saturating_duration_since(*t) >= COOLDOWN)
                && let Some(p) = self.pending.remove(&signal)
            {
                self.last_event.insert(signal, now);
                if self.events.len() == 64 {
                    self.events.pop_front();
                    self.limited = true;
                }
                self.next += 1;
                self.events.push_back(Event {
                    id: self.next,
                    signal,
                    utc,
                    total: p.total,
                    acknowledged: false,
                });
            }
        }
    }
    pub fn acknowledge(&mut self, id: u64) {
        if let Some(event) = self.events.iter_mut().find(|e| e.id == id) {
            event.acknowledged = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn brief_signal_is_delayed_and_repeat_merges_until_cooldown() {
        let mut a = Alerts::default();
        let base = Instant::now();
        let at = |t| base + Duration::from_secs(t);
        a.observe(at(0), 100, &Stats::default());
        let mut s = Stats {
            archive_dropped: 1,
            ..Default::default()
        };
        a.observe(at(1), 101, &s);
        a.observe(at(5), 105, &s);
        assert!(a.events.is_empty());
        a.observe(at(6), 106, &s);
        let id = a.events[0].id;
        a.acknowledge(id);
        assert!(a.events[0].acknowledged);
        s.archive_dropped = 4;
        a.observe(at(30), 130, &s);
        a.observe(at(65), 165, &s);
        assert_eq!(a.events.len(), 1);
        a.observe(at(66), 166, &s);
        assert_eq!(a.events[1].total, 4);
        assert!(!a.events[1].acknowledged);
    }
    #[test]
    fn stale_pending_clears_if_datagram_activity_returns() {
        let mut a = Alerts::default();
        let base = Instant::now();
        let at = |t| base + Duration::from_secs(t);
        let mut s = Stats::default();
        a.observe(at(0), 100, &s);
        a.observe(at(300), 400, &s);
        s.accepted_datagrams = 1;
        a.observe(at(302), 402, &s);
        a.observe(at(308), 408, &s);
        assert!(a.events.is_empty());
        a.observe(at(602), 702, &s);
        a.observe(at(607), 707, &s);
        assert_eq!(a.events[0].signal, Signal::Stale);
    }
}
