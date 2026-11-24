//! Local alert ledger. Source counters are observations; an idle exporter is not a failed router.
use super::flow::Stats;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

pub const MAX_ALERTS: usize = 4096;
pub const PAGE: usize = 1000;
const DEBOUNCE: Duration = Duration::from_secs(5);
const IDLE: Duration = Duration::from_secs(300);

/// Explicit state tokens avoid substring matches (e.g. "Diakui" vs "Belum diakui").
pub fn parse_filter(input: &str) -> crate::Result<(&str, &'static str)> {
    let input = input.trim();
    if input.len() > 512 {
        return Err("Filter alert terlalu panjang.".into());
    }
    match input.to_ascii_lowercase().as_str() {
        "diakui" => return Ok(("", "ack")),
        "belum diakui" => return Ok(("", "open")),
        "pulih teramati" | "pulih" => return Ok(("", "recovered")),
        _ => {}
    }
    if let Some(rest) = input.strip_prefix("state=") {
        let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let status = match &rest[..end] {
            "all" => "all",
            "open" => "open",
            "ack" => "ack",
            "recovered" => "recovered",
            _ => return Err("Gunakan state=all/open/ack/recovered.".into()),
        };
        Ok((rest[end..].trim(), status))
    } else {
        Ok((input, "all"))
    }
}

#[derive(Clone, Debug)]
pub struct Record {
    pub id: i64,
    pub session: String,
    pub serial: i64,
    pub scope: String,
    pub signal: String,
    pub opened: i64,
    pub last_seen: i64,
    pub total: i64,
    pub acknowledged: Option<i64>,
    pub recovered: Option<i64>,
}
impl Record {
    pub fn status(&self) -> &'static str {
        if self.recovered.is_some() {
            "Pulih teramati"
        } else if self.acknowledged.is_some() {
            "Diakui"
        } else {
            "Belum diakui"
        }
    }
}

struct Source {
    previous: Stats,
    last_activity: Instant,
    quiet: bool,
    seen: bool,
}
struct Incident {
    first: Instant,
    first_utc: i64,
    last_problem: Instant,
    total: i64,
    event: Option<Record>,
}
pub(crate) struct Tracker {
    session: String,
    serial: i64,
    sources: BTreeMap<String, Source>,
    incidents: BTreeMap<(String, &'static str), Incident>,
    pub dirty: BTreeMap<i64, Record>,
    pub overflow: bool,
}
impl Tracker {
    pub fn new(session: String) -> Self {
        Self {
            session,
            serial: 0,
            sources: BTreeMap::new(),
            incidents: BTreeMap::new(),
            dirty: BTreeMap::new(),
            overflow: false,
        }
    }
    // One incident per signal and source; retain failed writes for a bounded retry.
    fn mark(
        &mut self,
        scope: &str,
        signal: &'static str,
        now: Instant,
        utc: i64,
        observation: (bool, bool, u64),
    ) {
        let (changed, clear, total) = observation;
        let key = (scope.to_owned(), signal);
        let total = total.min(i64::MAX as u64) as i64;
        if changed {
            let slot = self.incidents.entry(key.clone()).or_insert(Incident {
                first: now,
                first_utc: utc,
                last_problem: now,
                total,
                event: None,
            });
            slot.last_problem = now;
            slot.total = total;
        }
        let Some(slot) = self.incidents.get_mut(&key) else {
            return;
        };
        // Suppress a transient issue if positive evidence returns before debounce.
        if slot.event.is_none()
            && clear
            && !changed
            && now.saturating_duration_since(slot.first) < DEBOUNCE
        {
            self.incidents.remove(&key);
            return;
        }
        let mut pending = None;
        if slot.event.is_none() && now.saturating_duration_since(slot.first) >= DEBOUNCE {
            self.serial += 1;
            let event = Record {
                id: 0,
                session: self.session.clone(),
                serial: self.serial,
                scope: scope.to_owned(),
                signal: signal.into(),
                opened: slot.first_utc,
                last_seen: utc.max(slot.first_utc),
                total: slot.total,
                acknowledged: None,
                recovered: None,
            };
            pending = Some(event.clone());
            slot.event = Some(event);
        }
        let recovered =
            clear && !changed && now.saturating_duration_since(slot.last_problem) >= DEBOUNCE;
        if let Some(event) = slot.event.as_mut()
            && (changed || recovered)
        {
            event.last_seen = event.last_seen.max(utc);
            event.total = event.total.max(slot.total);
            if recovered {
                event.recovered = Some(event.last_seen);
            }
            pending = Some(event.clone());
        }
        if recovered {
            self.incidents.remove(&key);
        }
        if let Some(record) = pending {
            if self.dirty.len() < MAX_ALERTS || self.dirty.contains_key(&record.serial) {
                self.dirty.insert(record.serial, record);
            } else {
                self.overflow = true;
            }
        }
    }

    // At a deliberate collector stop, record outstanding observations that
    // would otherwise be lost inside the debounce interval. Do not mark them recovered.
    pub fn finish(&mut self, utc: u64) {
        let utc = utc.min(i64::MAX as u64) as i64;
        for ((scope, signal), incident) in &self.incidents {
            if incident.event.is_some() {
                continue;
            }
            self.serial += 1;
            let record = Record {
                id: 0,
                session: self.session.clone(),
                serial: self.serial,
                scope: scope.clone(),
                signal: (*signal).into(),
                opened: incident.first_utc,
                last_seen: utc.max(incident.first_utc),
                total: incident.total,
                acknowledged: None,
                recovered: None,
            };
            if self.dirty.len() < MAX_ALERTS {
                self.dirty.insert(record.serial, record);
            } else {
                self.overflow = true;
            }
        }
    }

    pub fn sample(&mut self, scope: &str, now: Instant, utc: u64, stats: &Stats, global: bool) {
        let utc = utc.min(i64::MAX as u64) as i64;
        let state = self.sources.entry(scope.to_owned()).or_insert(Source {
            previous: Stats::default(),
            last_activity: now,
            quiet: false,
            seen: false,
        });
        let previous = state.previous.clone();
        let progress = stats.accepted_datagrams > previous.accepted_datagrams;
        let first = !state.seen;
        if progress {
            state.last_activity = now;
            state.seen = true;
        }
        let quiet = now.saturating_duration_since(state.last_activity) >= IDLE;
        let new_quiet = quiet && !state.quiet;
        state.quiet = quiet;
        state.previous = stats.clone();
        if global {
            let written = stats.archived > previous.archived;
            for (name, value, old) in [
                (
                    "Antrean arsip penuh",
                    stats.archive_queue_full,
                    previous.archive_queue_full,
                ),
                (
                    "Writer tertutup",
                    stats.archive_writer_closed,
                    previous.archive_writer_closed,
                ),
                (
                    "Gagal tulis SQLite",
                    stats.archive_sqlite_failed,
                    previous.archive_sqlite_failed,
                ),
            ] {
                self.mark(
                    scope,
                    name,
                    now,
                    utc,
                    (value > old, written && value == old, value),
                );
            }
        } else {
            for (name, value, old) in [
                (
                    "Template hilang",
                    stats.missing_templates,
                    previous.missing_templates,
                ),
                ("Datagram ditolak parser", stats.invalid, previous.invalid),
                ("Datagram duplikat", stats.duplicate, previous.duplicate),
            ] {
                self.mark(
                    scope,
                    name,
                    now,
                    utc,
                    (value > old, progress && value == old, value),
                );
            }
            self.mark(
                scope,
                "Belum ada datagram diterima",
                now,
                utc,
                (new_quiet && first, progress, 300),
            );
            self.mark(
                scope,
                "Jeda observasi",
                now,
                utc,
                (new_quiet && !first, progress, 300),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn filter_state_is_exact() {
        assert_eq!(parse_filter("Diakui").unwrap(), ("", "ack"));
        assert_eq!(parse_filter("Belum diakui").unwrap(), ("", "open"));
        assert_eq!(
            parse_filter("state=recovered site/A").unwrap(),
            ("site/A", "recovered")
        );
        assert!(parse_filter("state=invalid").is_err());
        assert!(parse_filter(&"x".repeat(513)).is_err());
    }

    #[test]
    fn final_sample_retains_short_incident_without_false_recovery() {
        let base = Instant::now();
        let mut tracker = Tracker::new("test".into());
        let mut stats = Stats::default();
        tracker.sample("scope", base, 100, &stats, false);
        stats.missing_templates = 2;
        tracker.sample("scope", base + Duration::from_secs(1), 101, &stats, false);
        assert!(tracker.dirty.is_empty());
        tracker.finish(99);
        let record = tracker.dirty.values().next().unwrap();
        assert_eq!(record.opened, 101);
        assert_eq!(record.last_seen, 101);
        assert_eq!(record.total, 2);
        assert!(record.recovered.is_none());
    }

    #[test]
    fn scopes_debounce_recover_and_never_seen() {
        let base = Instant::now();
        let mut t = Tracker::new("fixture".into());
        let mut a = Stats::default();
        let b = Stats::default();
        t.sample("A", base, 100, &a, false);
        t.sample("B", base, 100, &b, false);
        a.missing_templates = 1;
        t.sample("A", base + Duration::from_secs(1), 101, &a, false);
        assert!(t.dirty.is_empty());
        t.sample("A", base + Duration::from_secs(6), 106, &a, false);
        assert_eq!(t.dirty.len(), 1);
        assert_eq!(t.dirty.values().next().unwrap().scope, "A");
        a.accepted_datagrams = 1;
        t.sample("A", base + Duration::from_secs(7), 107, &a, false);
        assert_eq!(t.dirty.values().next().unwrap().recovered, Some(107));
        t.sample("B", base + Duration::from_secs(300), 400, &b, false);
        t.sample("B", base + Duration::from_secs(305), 405, &b, false);
        assert!(
            t.dirty
                .values()
                .any(|r| r.scope == "B" && r.signal == "Belum ada datagram diterima")
        );
    }
}
