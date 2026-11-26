//! Separate immutable snapshots; no DUID, raw REST body or credentials.
use super::{
    CoverageState,
    dhcp6::{Binding, BindingScope, ScopeIndex},
    router::{Authority, RouterSnapshot, Table},
};
use crate::Result;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{path::Path, time::Duration};

const APP_ID: i64 = 1464742214;
const MAX_ROWS: usize = 512;
const MAX_BYTES: usize = 262144;
const SCHEMA: &str = include_str!("sql/dhcp6_history_schema.sql");
const INSERT: &str = include_str!("sql/dhcp6_history_insert.sql");
const PAGE: &str = include_str!("sql/dhcp6_history_page.sql");
const PAGE_BEFORE: &str = "SELECT stamp,payload FROM dhcp6_sample
WHERE authority=?1 AND stamp<?2 ORDER BY stamp DESC LIMIT 20";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub binding: Binding,
    pub scope: BindingScope,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    pub authority: String,
    pub stamp: u64,
    pub coverage: CoverageState,
    pub reported: usize,
    pub rows: Vec<Row>,
}
impl Capture {
    pub fn from_snapshot(s: &RouterSnapshot) -> Result<Self> {
        let c = s
            .coverage
            .iter()
            .rev()
            .find(|c| c.source == Table::Dhcp6Binding.name())
            .ok_or("Tabel DHCPv6 belum diminta.")?;
        let index = ScopeIndex::new(s);
        let rows: Vec<_> = if c.state == CoverageState::Unavailable {
            Vec::new()
        } else {
            s.dhcp6
                .iter()
                .filter(|b| b.observed_at == c.observed_at)
                .take(MAX_ROWS)
                .map(|b| Row {
                    binding: b.clone(),
                    scope: index.scope(b),
                })
                .collect()
        };
        let coverage = if c.state == CoverageState::CompleteSnapshot && c.rows != rows.len() {
            CoverageState::Partial
        } else {
            c.state
        };
        let capture = Self {
            authority: s.authority.clone(),
            stamp: c.observed_at,
            coverage,
            reported: c.rows,
            rows,
        };
        capture.validate()?;
        Ok(capture)
    }

    fn validate(&self) -> Result<()> {
        let label_ok = |s: &str| !s.is_empty() && s.len() <= 160 && super::label(s) == s;
        if self.authority.len() > 512
            || Authority::parse(&self.authority)?.display() != self.authority
            || self.stamp > i64::MAX as u64
            || self.rows.len() > MAX_ROWS
            || self.reported < self.rows.len()
            || (self.coverage == CoverageState::CompleteSnapshot
                && self.reported != self.rows.len())
            || (self.coverage == CoverageState::Unavailable
                && (!self.rows.is_empty() || self.reported != 0))
            || self.rows.iter().any(|r| {
                !r.binding.valid()
                    || r.binding.observed_at != self.stamp
                    || r.scope.interface.as_deref().is_some_and(|v| !label_ok(v))
                    || r.scope.vrf.as_deref().is_some_and(|v| !label_ok(v))
                    || (r.scope.vrf.is_some() && r.scope.interface.is_none())
            })
        {
            return Err("Snapshot DHCPv6 tidak valid.".into());
        }
        Ok(())
    }
}
fn error(e: impl std::fmt::Display) -> String {
    format!("Histori DHCPv6: {e}")
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
    conn.busy_timeout(Duration::from_millis(1500))
        .map_err(error)?;
    conn.execute_batch("PRAGMA trusted_schema=OFF;")
        .map_err(error)?;
    fn verify(conn: &Connection) -> Result<()> {
        let id: i64 = conn
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(error)?;
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(error)?;
        if id != APP_ID || version != 1 {
            return Err("Database histori DHCPv6 tidak kompatibel.".into());
        }
        Ok(())
    }
    if write {
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(error)?;
        let id: i64 = tx
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(error)?;
        let version: i64 = tx
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(error)?;
        let count: i64 = tx
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )
            .map_err(error)?;
        if id == 0 && version == 0 && count == 0 {
            tx.execute_batch(SCHEMA).map_err(error)?;
        }
        verify(&tx)?;
        tx.commit().map_err(error)?;
    } else {
        verify(&conn)?;
    }
    Ok(conn)
}

pub fn save(path: &Path, sample: &Capture) -> Result<()> {
    sample.validate()?;
    let payload = serde_json::to_string(sample).map_err(error)?;
    if payload.len() > MAX_BYTES {
        return Err("Snapshot DHCPv6 melewati batas 256 KiB; tidak disimpan.".into());
    }
    let mut conn = open(path, true)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(error)?;
    let stamp = sample.stamp as i64;
    let existing: Option<String> = tx
        .query_row(
            "SELECT payload FROM dhcp6_sample WHERE authority=?1 AND stamp=?2",
            params![sample.authority, stamp],
            |r| r.get(0),
        )
        .optional()
        .map_err(error)?;
    match existing {
        Some(old) if old == payload => {}
        Some(_) => return Err("Konflik snapshot dengan waktu sama; tidak ditimpa.".into()),
        None => {
            let n = tx
                .execute(INSERT, params![sample.authority, stamp, payload])
                .map_err(error)?;
            if n != 1 {
                return Err("Kapasitas histori DHCPv6 penuh (120 sampel/router, 32 router atau 64 MiB payload). Tidak ada histori dihapus.".into());
            }
        }
    }
    tx.commit().map_err(error)
}

pub fn page(path: &Path, authority: &str) -> Result<Vec<Capture>> {
    page_before(path, authority, None)
}

/// Stable descending keyset pagination; exclusive UTC cursor avoids duplicates.
pub fn page_before(
    path: &Path,
    authority: &str,
    before: Option<u64>,
) -> Result<Vec<Capture>> {
    if before.is_some_and(|stamp| stamp > i64::MAX as u64) {
        return Err("Cursor histori DHCPv6 tidak valid.".into());
    }
    if Authority::parse(authority)?.display() != authority {
        return Err("Authority histori tidak kanonik.".into());
    }
    if !path.try_exists().map_err(error)? {
        return Ok(vec![]);
    }
    let conn = open(path, false)?;
    let mut stmt = conn
        .prepare(if before.is_some() { PAGE_BEFORE } else { PAGE })
        .map_err(error)?;
    let mut rows = if let Some(stamp) = before {
        stmt.query(params![authority, stamp as i64])
    } else {
        stmt.query([authority])
    }
    .map_err(error)?;
    let mut out = Vec::new();
    while let Some(r) = rows.next().map_err(error)? {
        let stamp: i64 = r.get(0).map_err(error)?;
        let bytes = r.get_ref(1).map_err(error)?.as_str().map_err(error)?;
        if bytes.len() > MAX_BYTES || stamp < 0 {
            return Err("Payload histori DHCPv6 di luar batas.".into());
        }
        let capture: Capture = serde_json::from_str(bytes).map_err(error)?;
        capture.validate()?;
        if capture.authority != authority || capture.stamp != stamp as u64 {
            return Err("Identitas histori tidak cocok dengan key.".into());
        }
        out.push(capture);
    }
    Ok(out)
}

/// Export aggregate coverage only, without router identity, addresses or DUID.
pub fn export_summary(path: &Path, authority: &str, destination: &Path) -> Result<()> {
    use std::io::Write;
    if !path.try_exists().map_err(error)? {
        return Err("Histori DHCPv6 belum tersedia.".into());
    }
    let mut cursor = None;
    let mut counts = [0usize; 3];
    let mut stored = 0usize;
    let mut reported = 0usize;
    // Schema contract caps one router at 120 snapshots.
    for _ in 0..6 {
        let samples = page_before(path, authority, cursor)?;
        if samples.is_empty() {
            break;
        }
        cursor = samples.last().map(|s| s.stamp);
        for s in samples {
            counts[match s.coverage {
                CoverageState::CompleteSnapshot => 0,
                CoverageState::Partial => 1,
                CoverageState::Unavailable => 2,
            }] += 1;
            stored = stored.saturating_add(s.rows.len());
            reported = reported.saturating_add(s.reported);
        }
    }
    if !page_before(path, authority, cursor)?.is_empty() && cursor.is_some() {
        return Err("Histori melebihi batas atau berubah saat ekspor.".into());
    }
    let summary = serde_json::json!({
        "schema": 1,
        "complete_snapshots": counts[0],
        "partial_snapshots": counts[1],
        "unavailable_snapshots": counts[2],
        "stored_rows": stored,
        "reported_rows": reported,
        "basis": "historical snapshots; not unique assignments"
    });
    let stage = super::archive_ops::Stage::new(destination)?;
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&stage.file)
        .map_err(error)?;
    serde_json::to_writer_pretty(&mut file, &summary).map_err(error)?;
    file.write_all(b"\n").map_err(error)?;
    file.sync_all().map_err(error)?;
    drop(file);
    stage.publish(destination)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_coverage_conflicts_and_isolation() {
        let dir = std::env::temp_dir().join(format!(
            "wenet-dhcp6-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("history.sqlite3");
        let authority = Authority::parse("router.test").unwrap();
        let mut s = RouterSnapshot::new(&authority, 100);
        s.ingest(Table::Dhcp6Binding, Ok(br#"[{"address":"2001:db8::/64","server":"srv","status":"bound","duid":"PRIVATE"}]"#.to_vec()), 101);
        let sample = Capture::from_snapshot(&s).unwrap();
        assert!(!serde_json::to_string(&sample).unwrap().contains("PRIVATE"));
        save(&path, &sample).unwrap();
        save(&path, &sample).unwrap();
        let mut conflicting = sample.clone();
        conflicting.rows[0].binding.status = None;
        assert!(save(&path, &conflicting).is_err());
        let mut empty = RouterSnapshot::new(&authority, 102);
        empty.ingest(Table::Dhcp6Binding, Err("unavailable".into()), 102);
        save(&path, &Capture::from_snapshot(&empty).unwrap()).unwrap();
        let rows = page(&path, &authority.display()).unwrap();
        assert_eq!(rows.len(), 2);
        let older = page_before(&path, &authority.display(), Some(rows[0].stamp)).unwrap();
        assert_eq!(older.len(), 1);
        assert_eq!(older[0].stamp, rows[1].stamp);
        let summary = dir.join("summary.json");
        export_summary(&path, &authority.display(), &summary).unwrap();
        let json = std::fs::read_to_string(&summary).unwrap();
        assert!(!json.contains("router.test"));
        assert!(!json.contains("2001:db8"));
        assert!(export_summary(&path, &authority.display(), &summary).is_err());
        assert_eq!(rows[0].coverage, CoverageState::Unavailable);
        assert_eq!(rows[1].rows[0].binding.prefix.to_string(), "2001:db8::");
        assert!(
            page(&path, &Authority::parse("other.test").unwrap().display())
                .unwrap()
                .is_empty()
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}
