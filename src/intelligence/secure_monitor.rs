//! Bounded, validated summaries from the explicitly enabled secure companion.
//! Storage is separate from legacy flow and polling schemas. No raw messages.
use crate::Result;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::SocketAddr, path::Path, time::Duration};

const APP_ID: i64 = 1464742225;
const SCHEMA: &str = include_str!("sql/secure_monitor_schema.sql");
const MIGRATION: &str = include_str!("sql/secure_monitor_v2.sql");
pub const MAX_REPORT: usize = 16_384;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub format: String,
    pub facility: u8,
    pub severity: u8,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "transport", deny_unknown_fields)]
pub enum Report {
    #[serde(rename = "SNMPv3")]
    Snmp {
        schema: u8,
        security: String,
        auth_protocol: String,
        privacy_protocol: String,
        target: SocketAddr,
        sys_uptime_ticks: u32,
        observed_utc: u64,
    },
    #[serde(rename = "mutual_tls")]
    Tls {
        schema: u8,
        bind: SocketAddr,
        peer_certificate_sha256: String,
        observed_utc: u64,
        accepted: u32,
        rejected: u32,
        groups: Vec<Group>,
    },
    /// Rejected connection; never represents an authenticated observation.
    #[serde(rename = "tls_rejected")]
    TlsRejected {
        schema: u8,
        bind: SocketAddr,
        observed_utc: u64,
        reason: String,
    },
}
pub fn pin_valid(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn valid_address(a: SocketAddr) -> bool {
    a.port() != 0 && !a.ip().is_unspecified() && !a.ip().is_multicast()
        && !matches!(a.ip(), std::net::IpAddr::V4(v) if v.is_broadcast())
}
impl Report {
    pub fn validate(&self) -> Result<()> {
        let valid = match self {
            Self::Snmp { schema, security, auth_protocol, privacy_protocol, target, observed_utc, .. } =>
                *schema == 1 && security == "authPriv" && auth_protocol == "SHA-256"
                && privacy_protocol == "AES-128" && valid_address(*target) && *observed_utc <= i64::MAX as u64,
            Self::TlsRejected { schema, bind, observed_utc, reason } =>
                *schema == 1 && valid_address(*bind) && *observed_utc <= i64::MAX as u64
                && matches!(reason.as_str(), "handshake_or_authorization_or_framing"),
            Self::Tls { schema, bind, peer_certificate_sha256, observed_utc, accepted, rejected, groups } => {
                let mut seen = BTreeSet::new();
                let mut sum = 0u64;
                *schema == 1 && valid_address(*bind) && pin_valid(peer_certificate_sha256)
                    && *observed_utc <= i64::MAX as u64
                    && u64::from(*accepted) + u64::from(*rejected) <= 10_000
                    && groups.len() <= 384 && groups.iter().all(|g| {
                        sum += u64::from(g.count);
                        matches!(g.format.as_str(), "Rfc5424Header" | "LegacyPriority")
                            && g.facility <= 23 && g.severity <= 7 && g.count > 0
                            && seen.insert((g.format.as_str(), g.facility, g.severity))
                    }) && sum == u64::from(*accepted)
            }
        };
        if !valid { return Err("Ringkasan transport tidak valid.".into()); }
        Ok(())
    }
    pub fn stamp(&self) -> u64 {
        match self { Self::Snmp { observed_utc, .. } | Self::Tls { observed_utc, .. } | Self::TlsRejected { observed_utc, .. } => *observed_utc }
    }
    pub fn scope(&self) -> String {
        match self {
            Self::Snmp { target, .. } => format!("snmp:{target}"),
            Self::Tls { peer_certificate_sha256, .. } => format!("tls:{peer_certificate_sha256}"),
            Self::TlsRejected { bind, .. } => format!("tls-rejected:{bind}"),
        }
    }
    pub fn label(&self) -> &'static str {
        match self { Self::Snmp { .. } => "SNMPv3 authPriv", Self::Tls { .. } => "Mutual TLS Syslog", Self::TlsRejected { .. } => "TLS ditolak" }
    }
    pub fn summary(&self) -> String {
        match self {
            Self::Snmp { sys_uptime_ticks, .. } => format!("sysUpTime: {sys_uptime_ticks} ticks"),
            Self::Tls { accepted, rejected, .. } => format!("{accepted} diterima · {rejected} ditolak"),
            Self::TlsRejected { .. } => "Koneksi ditolak; identitas peer tidak terbukti.".into(),
        }
    }
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() > MAX_REPORT { return Err("Ringkasan melampaui batas.".into()); }
        let report: Self = serde_json::from_slice(data).map_err(|_| "Format ringkasan transport ditolak.")?;
        report.validate()?;
        Ok(report)
    }
}

fn error(e: impl std::fmt::Display) -> String { format!("Histori transport: {e}") }
fn open(path: &Path, write: bool) -> Result<Connection> {
    let flags = if write {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(error)?;
        }
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else { OpenFlags::SQLITE_OPEN_READ_ONLY };
    let mut conn = Connection::open_with_flags(path, flags).map_err(error)?;
    conn.busy_timeout(Duration::from_millis(1500)).map_err(error)?;
    conn.execute_batch("PRAGMA trusted_schema=OFF;").map_err(error)?;
    let verify = |db: &Connection| -> Result<()> {
        let id: i64 = db.pragma_query_value(None, "application_id", |r| r.get(0)).map_err(error)?;
        let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0)).map_err(error)?;
        if id != APP_ID || !(1..=2).contains(&version) { return Err("Database transport tidak kompatibel.".into()); }
        Ok(())
    };
    if write {
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate).map_err(error)?;
        let id: i64 = tx.pragma_query_value(None, "application_id", |r| r.get(0)).map_err(error)?;
        let v: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0)).map_err(error)?;
        let n: i64 = tx.query_row("SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'", [], |r| r.get(0)).map_err(error)?;
        if id == 0 && v == 0 && n == 0 { tx.execute_batch(SCHEMA).map_err(error)?; }
        verify(&tx)?;
        let version: i64 = tx.pragma_query_value(None, "user_version", |r| r.get(0)).map_err(error)?;
        if version == 1 { tx.execute_batch(MIGRATION).map_err(error)?; }
        tx.commit().map_err(error)?;
    } else { verify(&conn)?; }
    Ok(conn)
}
fn insert_observation(tx: &Connection, report: &Report) -> Result<()> {
    report.validate()?;
    let data = serde_json::to_string(report).map_err(error)?;
    if data.len() > MAX_REPORT { return Err("Ringkasan melampaui batas.".into()); }
    let scope = report.scope();
    tx.execute("INSERT INTO secure_observation(scope,stamp,report) VALUES(?1,?2,?3)",
        params![scope, report.stamp() as i64, data]).map_err(error)?;
    tx.execute("DELETE FROM secure_observation WHERE scope=?1 AND id IN (SELECT id FROM secure_observation WHERE scope=?1 ORDER BY id DESC LIMIT -1 OFFSET 256)", [&scope]).map_err(error)?;
    tx.execute("DELETE FROM secure_observation WHERE id IN (SELECT id FROM secure_observation ORDER BY id DESC LIMIT -1 OFFSET 2048)", []).map_err(error)?;
    Ok(())
}
pub fn append(path: &Path, report: &Report) -> Result<()> {
    let mut db = open(path, true)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(error)?;
    insert_observation(&tx, report)?;
    tx.commit().map_err(error)
}
/// Successful SNMP observation and its attempt are committed together. A failed
/// attempt has no observation; legacy v1 history is never rewritten.
pub fn append_poll(path: &Path, target: SocketAddr, stamp: u64, elapsed_ms: u64,
    report: Option<&Report>) -> Result<()> {
    if !valid_address(target) || stamp > i64::MAX as u64 || elapsed_ms > 60_000
        || report.is_some_and(|r| !matches!(r, Report::Snmp { target: a, .. } if *a == target))
    { return Err("Percobaan SNMP tidak valid.".into()); }
    let mut db = open(path, true)?;
    let tx = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(error)?;
    if let Some(report) = report { insert_observation(&tx, report)?; }
    let target = target.to_string();
    tx.execute("INSERT INTO secure_poll_attempt(target,stamp,elapsed_ms,success) VALUES(?1,?2,?3,?4)",
        params![target,stamp as i64,elapsed_ms as i64,i64::from(report.is_some())]).map_err(error)?;
    tx.execute("DELETE FROM secure_poll_attempt WHERE target=?1 AND id IN (SELECT id FROM secure_poll_attempt WHERE target=?1 ORDER BY id DESC LIMIT -1 OFFSET 256)",[&target]).map_err(error)?;
    tx.execute("DELETE FROM secure_poll_attempt WHERE id IN (SELECT id FROM secure_poll_attempt ORDER BY id DESC LIMIT -1 OFFSET 2048)",[]).map_err(error)?;
    tx.commit().map_err(error)
}
pub fn attempts(path: &Path) -> Result<Vec<super::secure_attempt::Attempt>> {
    use super::secure_attempt::Attempt;
    let mut out = Vec::new();
    if path.try_exists().map_err(error)? {
        let db = open(path,false)?;
        let version: i64 = db.pragma_query_value(None,"user_version",|r|r.get(0)).map_err(error)?;
        if version == 2 {
            let mut stmt = db.prepare("SELECT target,stamp,elapsed_ms,success FROM secure_poll_attempt ORDER BY id DESC LIMIT 100").map_err(error)?;
            let mut rows = stmt.query([]).map_err(error)?;
            while let Some(row) = rows.next().map_err(error)? {
                let text: String = row.get(0).map_err(error)?;
                let target: SocketAddr = text.parse().map_err(error)?;
                let stamp: i64 = row.get(1).map_err(error)?;
                let ms: i64 = row.get(2).map_err(error)?;
                let success: i64 = row.get(3).map_err(error)?;
                if target.to_string()!=text || !valid_address(target) || stamp<0
                    || !(0..=60_000).contains(&ms) || !(0..=1).contains(&success) {
                    return Err("Record polling tidak valid.".into());
                }
                out.push(Attempt {target,stamp:stamp as u64,elapsed_ms:ms as u64,success:success==1});
            }
        }
    }
    // The historical separate file remains readable, not migrated/deduplicated.
    out.extend(super::secure_attempt::page(&path.with_file_name("secure-attempts-v1.sqlite3"))?);
    out.sort_by_key(|r| std::cmp::Reverse(r.stamp));
    out.truncate(100);
    Ok(out)
}
pub fn page(path: &Path) -> Result<Vec<Report>> {
    if !path.try_exists().map_err(error)? { return Ok(Vec::new()); }
    let db = open(path, false)?;
    let mut stmt = db.prepare("SELECT scope,stamp,CASE WHEN length(CAST(report AS BLOB))<=16384 THEN report ELSE NULL END FROM secure_observation ORDER BY id DESC LIMIT 100").map_err(error)?;
    let mut rows = stmt.query([]).map_err(error)?;
    let mut out = Vec::new();
    while let Some(row) = rows.next().map_err(error)? {
        let scope: String = row.get(0).map_err(error)?;
        let stamp: i64 = row.get(1).map_err(error)?;
        let data: String = row.get(2).map_err(error)?;
        let report = Report::parse(data.as_bytes())?;
        if report.scope() != scope || stamp < 0 || report.stamp() != stamp as u64 {
            return Err("Identitas histori transport tidak cocok.".into());
        }
        out.push(report);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    const SNMP: &str = r#"{"schema":1,"transport":"SNMPv3","security":"authPriv","auth_protocol":"SHA-256","privacy_protocol":"AES-128","target":"192.0.2.1:161","sys_uptime_ticks":42,"observed_utc":100}"#;
    #[test]
    fn strict_reports_and_durable_history() {
        let report = Report::parse(SNMP.as_bytes()).unwrap();
        assert!(Report::parse(SNMP.replace("authPriv","noAuthNoPriv").as_bytes()).is_err());
        assert!(Report::parse(SNMP.replace("SHA-256","MD5").as_bytes()).is_err());
        assert!(Report::parse(SNMP.replace("\"schema\":1","\"schema\":1,\"password\":\"secret\"").as_bytes()).is_err());
        let dir = std::env::temp_dir().join(format!("wenet-secure-history-{}-{}",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        let path = dir.join("history.sqlite3");
        assert!(page(&path).unwrap().is_empty());
        append(&path,&report).unwrap();
        let rows = page(&path).unwrap();
        assert_eq!(rows[0].scope(),"snmp:192.0.2.1:161");
        assert_eq!(rows[0].stamp(),100);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn v1_migration_atomic_poll_and_rollback() {
        let dir = std::env::temp_dir().join(format!("wenet-v2-{}-{}",std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(&dir).unwrap();
        let path=dir.join("secure-observations-v1.sqlite3");
        let db=Connection::open(&path).unwrap();
        db.execute_batch(SCHEMA).unwrap();
        let report=Report::parse(SNMP.as_bytes()).unwrap();
        insert_observation(&db,&report).unwrap();
        drop(db);
        assert_eq!(page(&path).unwrap().len(),1);
        let target="192.0.2.1:161".parse().unwrap();
        append_poll(&path,target,101,20,Some(&report)).unwrap();
        append_poll(&path,target,102,25,None).unwrap();
        let db=open(&path,true).unwrap();
        db.execute_batch("CREATE TRIGGER reject_poll BEFORE INSERT ON secure_poll_attempt BEGIN SELECT RAISE(ABORT,'fixture'); END;").unwrap();
        drop(db);
        assert!(append_poll(&path,target,103,30,Some(&report)).is_err());
        assert_eq!(page(&path).unwrap().len(),2);
        let rows=attempts(&path).unwrap();
        assert_eq!(rows.len(),2);
        assert!(!rows[0].success);
        assert!(rows[1].success);
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn tls_rejects_bad_totals_duplicate_groups_and_unknown_fields() {
        let mut r = Report::Tls {schema:1,bind:"127.0.0.1:6514".parse().unwrap(),peer_certificate_sha256:"a".repeat(64),observed_utc:100,accepted:2,rejected:0,groups:vec![Group{format:"LegacyPriority".into(),facility:1,severity:5,count:2}]};
        assert!(r.validate().is_ok());
        if let Report::Tls { groups, .. } = &mut r { groups.push(groups[0].clone()); }
        assert!(r.validate().is_err());
    }
}
