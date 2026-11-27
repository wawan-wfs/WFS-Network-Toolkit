//! Durable SNMP attempt outcome; failure does not imply a specific auth error.
use crate::Result;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use serde::Serialize;
use std::{net::SocketAddr,path::Path,time::Duration};

const SCHEMA: &str = include_str!("sql/secure_attempt_schema.sql");
fn error(e: impl std::fmt::Display) -> String { format!("Histori percobaan aman: {e}") }
fn open(path: &Path, write: bool) -> Result<Connection> {
    if write && let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(error)?;
    }
    let flags = if write { OpenFlags::SQLITE_OPEN_CREATE | OpenFlags::SQLITE_OPEN_READ_WRITE }
        else { OpenFlags::SQLITE_OPEN_READ_ONLY };
    let mut db = Connection::open_with_flags(path, flags).map_err(error)?;
    db.busy_timeout(Duration::from_millis(1500)).map_err(error)?;
    db.execute_batch("PRAGMA trusted_schema=OFF;").map_err(error)?;
    fn verify(db: &Connection) -> Result<()> {
        let id: i64 = db.pragma_query_value(None,"application_id",|r| r.get(0)).map_err(error)?;
        let v: i64 = db.pragma_query_value(None,"user_version",|r| r.get(0)).map_err(error)?;
        if id != 1464742226 || v != 1 { return Err("Database percobaan tidak kompatibel.".into()); }
        Ok(())
    }
    if write {
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(error)?;
        let id: i64 = tx.pragma_query_value(None,"application_id",|r| r.get(0)).map_err(error)?;
        let v: i64 = tx.pragma_query_value(None,"user_version",|r| r.get(0)).map_err(error)?;
        let n: i64 = tx.query_row("SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",[],|r| r.get(0)).map_err(error)?;
        if id == 0 && v == 0 && n == 0 { tx.execute_batch(SCHEMA).map_err(error)?; }
        verify(&tx)?;
        tx.commit().map_err(error)?;
    } else { verify(&db)?; }
    Ok(db)
}
pub fn append(path: &Path, target: SocketAddr, stamp: u64, elapsed_ms: u64, success: bool) -> Result<()> {
    if !super::secure_monitor::valid_address(target) || stamp > i64::MAX as u64 || elapsed_ms > 60_000 {
        return Err("Percobaan SNMP di luar batas.".into());
    }
    let mut db = open(path,true)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(error)?;
    let target = target.to_string();
    tx.execute("INSERT INTO secure_attempt(target,stamp,elapsed_ms,success) VALUES(?1,?2,?3,?4)",
        params![target,stamp as i64,elapsed_ms as i64,i64::from(success)]).map_err(error)?;
    tx.execute("DELETE FROM secure_attempt WHERE target=?1 AND id IN (SELECT id FROM secure_attempt WHERE target=?1 ORDER BY id DESC LIMIT -1 OFFSET 256)",[&target]).map_err(error)?;
    tx.execute("DELETE FROM secure_attempt WHERE id IN (SELECT id FROM secure_attempt ORDER BY id DESC LIMIT -1 OFFSET 2048)",[]).map_err(error)?;
    tx.commit().map_err(error)
}
#[derive(Debug, Serialize)]
pub struct Attempt {
    pub target: SocketAddr,
    pub stamp: u64,
    pub elapsed_ms: u64,
    pub success: bool,
}
pub fn page(path: &Path) -> Result<Vec<Attempt>> {
    if !path.try_exists().map_err(error)? { return Ok(Vec::new()); }
    let db = open(path,false)?;
    let mut stmt = db.prepare("SELECT target,stamp,elapsed_ms,success FROM secure_attempt ORDER BY id DESC LIMIT 100").map_err(error)?;
    let mut rows = stmt.query([]).map_err(error)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().map_err(error)? {
        let text: String = row.get(0).map_err(error)?;
        let target: SocketAddr = text.parse().map_err(error)?;
        let stamp: i64 = row.get(1).map_err(error)?;
        let ms: i64 = row.get(2).map_err(error)?;
        let status: i64 = row.get(3).map_err(error)?;
        if target.to_string() != text || !super::secure_monitor::valid_address(target) || stamp < 0
            || !(0..=60_000).contains(&ms) || !(0..=1).contains(&status) {
            return Err("Record percobaan tidak valid.".into());
        }
        out.push(Attempt {target,stamp:stamp as u64,elapsed_ms:ms as u64,success:status==1});
    }
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retains_attempts_and_reopens() {
        let dir = std::env::temp_dir().join(format!("wenet-secure-attempt-{}-{}",std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let path = dir.join("attempts.sqlite3");
        let target = "192.0.2.8:161".parse().unwrap();
        for i in 0..260 { append(&path,target,i,20,i%2==0).unwrap(); }
        let rows = page(&path).unwrap();
        assert_eq!(rows.len(),100);
        assert_eq!(rows[0].stamp,259);
        assert!(!rows[0].success);
        assert!(rows[1].success);
        let db = open(&path,false).unwrap();
        let count: i64 = db.query_row("SELECT count(*) FROM secure_attempt",[],|r|r.get(0)).unwrap();
        assert_eq!(count,256);
        drop(db);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
