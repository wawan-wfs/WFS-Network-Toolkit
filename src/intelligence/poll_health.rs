//! Separate bounded poll health journal. No credentials, raw response or error text.
use super::{polling::Outcome, router::Authority};
use crate::Result;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use serde::Serialize;
use std::{path::Path, time::Duration};

const APP_ID: i64 = 1464742224;
const SCHEMA: &str = include_str!("sql/poll_health_schema.sql");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveState {
    NotAttempted,
    Saved,
    Failed,
}
impl ArchiveState {
    fn code(self) -> i64 {
        match self {
            Self::NotAttempted => 0,
            Self::Saved => 1,
            Self::Failed => 2,
        }
    }
}
fn outcome_code(outcome: Outcome) -> i64 {
    match outcome {
        Outcome::Complete => 0,
        Outcome::Partial => 1,
        Outcome::Auth => 2,
        Outcome::Tls => 3,
        Outcome::Forbidden => 4,
        Outcome::NotFound => 5,
        Outcome::Timeout => 6,
        Outcome::Other => 7,
    }
}

fn error(e: impl std::fmt::Display) -> String {
    format!("Histori kesehatan polling: {e}")
}
fn valid_authority(authority: &str) -> Result<()> {
    if authority.len() > 512 || Authority::parse(authority)?.display() != authority {
        return Err("Authority histori polling tidak kanonik.".into());
    }
    Ok(())
}
fn verify(conn: &Connection) -> Result<()> {
    let id: i64 = conn
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(error)?;
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(error)?;
    if id != APP_ID || version != 1 {
        return Err("Database kesehatan polling tidak kompatibel.".into());
    }
    Ok(())
}
fn open(path: &Path, write: bool) -> Result<Connection> {
    let flags = if write {
        std::fs::create_dir_all(path.parent().ok_or("Path histori tidak valid.")?)
            .map_err(error)?;
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let mut conn = Connection::open_with_flags(path, flags).map_err(error)?;
    conn.busy_timeout(Duration::from_millis(1500)).map_err(error)?;
    conn.execute_batch("PRAGMA trusted_schema=OFF;").map_err(error)?;
    if write {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(error)?;
        let id: i64 = tx.pragma_query_value(None, "application_id", |r| r.get(0)).map_err(error)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0)).map_err(error)?;
        let tables: i64 = tx.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        ).map_err(error)?;
        if id == 0 && version == 0 && tables == 0 {
            tx.execute_batch(SCHEMA).map_err(error)?;
        }
        verify(&tx)?;
        tx.commit().map_err(error)?;
    } else {
        verify(&conn)?;
    }
    Ok(conn)
}

#[derive(Debug, Serialize)]
pub struct Record {
    pub id: i64,
    pub stamp: u64,
    pub elapsed_ms: u64,
    pub outcome: &'static str,
    pub archive_state: &'static str,
}

/// Retain at most 512 samples per router and 4096 overall. Eviction uses
/// insertion order, never wall-clock timestamps; all changes are atomic.
pub fn append(
    path: &Path,
    authority: &str,
    stamp: u64,
    elapsed_ms: u64,
    outcome: Outcome,
    archive: ArchiveState,
) -> Result<()> {
    valid_authority(authority)?;
    if stamp > i64::MAX as u64 || elapsed_ms > 3_600_000 {
        return Err("Waktu observasi polling di luar batas.".into());
    }
    let mut conn = open(path, true)?;
    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(error)?;
    tx.execute(
        "INSERT INTO poll_health(authority,stamp,elapsed_ms,outcome,archive_state) VALUES(?1,?2,?3,?4,?5)",
        params![authority, stamp as i64, elapsed_ms as i64, outcome_code(outcome), archive.code()],
    ).map_err(error)?;
    tx.execute(
        "DELETE FROM poll_health WHERE authority=?1 AND id IN
         (SELECT id FROM poll_health WHERE authority=?1 ORDER BY id DESC LIMIT -1 OFFSET 512)",
        [authority],
    ).map_err(error)?;
    tx.execute(
        "DELETE FROM poll_health WHERE id IN
         (SELECT id FROM poll_health ORDER BY id DESC LIMIT -1 OFFSET 4096)",
        [],
    ).map_err(error)?;
    tx.commit().map_err(error)
}

pub fn page(path: &Path, authority: &str) -> Result<Vec<Record>> {
    valid_authority(authority)?;
    if !path.try_exists().map_err(error)? {
        return Ok(Vec::new());
    }
    let conn = open(path, false)?;
    let mut statement = conn.prepare(
        "SELECT id,stamp,elapsed_ms,outcome,archive_state FROM poll_health
         WHERE authority=?1 ORDER BY id DESC LIMIT 100"
    ).map_err(error)?;
    let mut rows = statement.query([authority]).map_err(error)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().map_err(error)? {
        let id: i64 = row.get(0).map_err(error)?;
        let stamp: i64 = row.get(1).map_err(error)?;
        let elapsed_ms: i64 = row.get(2).map_err(error)?;
        let outcome: i64 = row.get(3).map_err(error)?;
        let archive: i64 = row.get(4).map_err(error)?;
        let labels = ["Lengkap", "Parsial", "Auth ditolak", "TLS ditolak",
            "HTTP 403", "HTTP 404", "Timeout", "Gagal lainnya"];
        let archives = ["Tidak dicoba", "Tersimpan", "Gagal disimpan"];
        if id <= 0 || stamp < 0 || !(0..=3_600_000).contains(&elapsed_ms)
            || !(0..=7).contains(&outcome) || !(0..=2).contains(&archive)
            || ((outcome <= 1) != (archive != 0))
        {
            return Err("Record histori polling tidak valid.".into());
        }
        out.push(Record {
            id,
            stamp: stamp as u64,
            elapsed_ms: elapsed_ms as u64,
            outcome: labels[outcome as usize],
            archive_state: archives[archive as usize],
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persists_outcomes_and_separates_scope_and_archive_failure() {
        let dir = std::env::temp_dir().join(format!("wenet-health-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let path = dir.join("health.sqlite3");
        assert!(page(&path, "r1.test:443").unwrap().is_empty());
        append(&path, "r1.test:443", 100, 42, Outcome::Complete, ArchiveState::Failed).unwrap();
        append(&path, "r1.test:443", 99, 80, Outcome::Tls, ArchiveState::NotAttempted).unwrap();
        append(&path, "r2.test:443", 100, 5, Outcome::Partial, ArchiveState::Saved).unwrap();
        assert!(append(&path, "r1.test:443", 101, 1, Outcome::Auth, ArchiveState::Saved).is_err());
        assert!(append(&path, "https://r1.test", 101, 1, Outcome::Other, ArchiveState::NotAttempted).is_err());
        let rows = page(&path, "r1.test:443").unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].stamp, 99);
        assert_eq!(rows[0].outcome, "TLS ditolak");
        assert_eq!(rows[1].archive_state, "Gagal disimpan");
        assert_eq!(page(&path, "r2.test:443").unwrap().len(), 1);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
