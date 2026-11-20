//! Monotonic, opt-in scheduling. No host discovery, networking or credentials here.
use crate::Result;
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub const MAX_TARGETS: usize = 8;
pub const MIN_INTERVAL: u64 = 60;
const GLOBAL_GAP: Duration = Duration::from_secs(15);

#[derive(Clone, Default)]
pub struct Cancel(Arc<AtomicBool>);
impl Cancel {
    pub fn request(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
    pub fn check(&self) -> Result<()> {
        if self.requested() {
            Err("Polling dibatalkan.".into())
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Complete,
    Partial,
    Auth,
    Tls,
    Forbidden,
    NotFound,
    Timeout,
    Other,
}
impl Outcome {
    pub fn from_failure(error: &str) -> Self {
        if error.contains("HTTP 401") {
            Self::Auth
        } else if error.contains("validasi TLS") || error.contains("Redirect") {
            Self::Tls
        } else if error.contains("HTTP 403") {
            Self::Forbidden
        } else if error.contains("HTTP 404") {
            Self::NotFound
        } else if error.contains("waktu habis")
            || error.contains("Batas waktu")
            || error.contains("Anggaran waktu")
        {
            Self::Timeout
        } else {
            Self::Other
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Complete => "Lengkap",
            Self::Partial => "Parsial",
            Self::Auth => "Autentikasi ditolak",
            Self::Tls => "TLS atau redirect ditolak",
            Self::Forbidden => "HTTP 403 · akses ditolak",
            Self::NotFound => "HTTP 404 · tidak tersedia",
            Self::Timeout => "Waktu habis",
            Self::Other => "Tidak dapat mengambil snapshot",
        }
    }
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Auth | Self::Tls | Self::Forbidden | Self::NotFound
        )
    }
}
pub struct Job {
    pub every: Duration,
    pub due: Instant,
    pub outcome: Option<Outcome>,
    pub paused: bool,
    failures: u32,
    order: u64,
}
#[derive(Default)]
pub struct Schedule {
    pub jobs: BTreeMap<String, Job>,
    active: Option<(String, Cancel)>,
    next_global: Option<Instant>,
    order: u64,
}
impl Schedule {
    pub fn configure(&mut self, key: String, seconds: u64, now: Instant) -> Result<()> {
        if !(MIN_INTERVAL..=3600).contains(&seconds) {
            return Err("Interval polling harus 60–3600 detik.".into());
        }
        if self.active_key() == Some(key.as_str()) {
            return Err("Tunggu permintaan aktif selesai.".into());
        }
        if !self.jobs.contains_key(&key) && self.jobs.len() >= MAX_TARGETS {
            return Err("Maksimal delapan target polling.".into());
        }
        self.order = self.order.wrapping_add(1);
        self.jobs.insert(
            key,
            Job {
                every: Duration::from_secs(seconds),
                due: now,
                outcome: None,
                paused: false,
                failures: 0,
                order: self.order,
            },
        );
        Ok(())
    }
    pub fn stop(&mut self, key: &str) {
        self.jobs.remove(key);
        if let Some((host, cancel)) = &self.active
            && host == key
        {
            cancel.request();
        }
    }
    pub fn active_key(&self) -> Option<&str> {
        self.active.as_ref().map(|(k, _)| k.as_str())
    }
    pub fn next(&mut self, now: Instant) -> Option<(String, Cancel)> {
        if self.active.is_some() || self.next_global.is_some_and(|due| now < due) {
            return None;
        }
        let key = self
            .jobs
            .iter()
            .filter(|(_, j)| !j.paused && j.due <= now)
            .min_by_key(|(_, j)| (j.due, j.order))
            .map(|(k, _)| k.clone())?;
        let cancel = Cancel::default();
        self.active = Some((key.clone(), cancel.clone()));
        Some((key, cancel))
    }
    /// Completes only the one active request; a stopped request does not rearm itself.
    pub fn complete(&mut self, now: Instant, outcome: Outcome) -> bool {
        let Some((key, cancel)) = self.active.take() else {
            return false;
        };
        self.next_global = Some(now + GLOBAL_GAP);
        if cancel.requested() {
            return false;
        }
        let Some(job) = self.jobs.get_mut(&key) else {
            return false;
        };
        job.outcome = Some(outcome);
        job.paused = outcome.terminal();
        job.failures = if outcome == Outcome::Complete {
            0
        } else {
            job.failures.saturating_add(1).min(5)
        };
        job.due = now + (job.every * (1 << job.failures)).min(Duration::from_secs(3600));
        true
    }
}
impl Drop for Schedule {
    fn drop(&mut self) {
        if let Some((_, c)) = &self.active {
            c.request();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn global_gap_backoff_and_end_of_cancel_are_enforced() {
        let n = Instant::now();
        let at = |s| n + Duration::from_secs(s);
        let mut q = Schedule::default();
        assert!(q.configure("small".into(), 59, n).is_err());
        q.configure("r1".into(), 60, n).unwrap();
        q.configure("r2".into(), 60, n).unwrap();
        let (key, c) = q.next(n).unwrap();
        assert_eq!(key, "r1");
        assert!(q.next(at(500)).is_none());
        q.stop("r1");
        assert!(c.requested());
        assert!(q.next(at(500)).is_none());
        assert!(!q.complete(at(5), Outcome::Complete));
        assert!(q.next(at(19)).is_none());
        assert_eq!(q.next(at(20)).unwrap().0, "r2");
        assert!(q.complete(at(22), Outcome::Timeout));
        assert!(q.next(at(141)).is_none());
        assert_eq!(q.next(at(142)).unwrap().0, "r2");
        q.complete(at(145), Outcome::Auth);
        assert!(q.jobs["r2"].paused);
        assert!(q.next(at(9999)).is_none());
    }
    #[test]
    fn status_categories_cover_http_and_transport() {
        assert_eq!(
            Outcome::from_failure("HTTP 404 — tabel tidak tersedia"),
            Outcome::NotFound
        );
        assert_eq!(
            Outcome::from_failure("kirim HTTPS: validasi TLS/sertifikat gagal"),
            Outcome::Tls
        );
        assert_eq!(
            Outcome::from_failure("terima HTTPS: waktu habis"),
            Outcome::Timeout
        );
    }
}
