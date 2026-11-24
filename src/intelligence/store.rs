//! Versioned local archive; no packet payload or credentials cross this boundary.
use super::{
    archive_ops::{DELETE_LIMIT, DeletePreview, Kind, Policy, Stage},
    csv_cell,
    flow::{Direction, Flow},
    history::Snapshot,
};
use crate::Result;
use rusqlite::{
    Connection, OpenFlags, TransactionBehavior, params, params_from_iter, types::Value,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread,
    time::Duration,
};

pub const RETAIN_DAYS: u64 = 30;
pub const PAGE_SIZE: usize = 200;
pub const EXPORT_LIMIT: usize = 10_000;
const BATCH_SIZE: usize = 256;
// Bounded capacity; still report overload rather than silently discard it.
const QUEUE_BATCHES: usize = 256;

const VERSION: i64 = 4;
const APP_ID: i64 = 0x5746534E; // WFSN

fn error(e: impl std::fmt::Display) -> String {
    format!("Arsip SQLite: {e}")
}
fn sql_time(v: u64) -> i64 {
    v.min(i64::MAX as u64) as i64
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ArchiveRow {
    pub profile: String,
    pub site: String,
    pub vrf: Option<String>,
    pub direction: Direction,
    pub flow: Flow,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub struct Cursor {
    pub received: i64,
    pub id: i64,
}

fn filter_tokens(input: &str) -> Result<Vec<String>> {
    if input.len() > 1024 {
        return Err("Filter melampaui 1.024 byte.".into());
    }
    let mut tokens = vec![];
    let mut token = String::new();
    let mut quote = false;
    let mut escape = false;
    for ch in input.chars() {
        if escape {
            if !matches!(ch, '"' | '\\') {
                return Err("Escape filter tidak valid.".into());
            }
            token.push(ch);
            escape = false;
        } else if quote && ch == '\\' {
            escape = true;
        } else if ch == '"' {
            quote = !quote;
        } else if !quote && ch.is_whitespace() {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
        } else {
            token.push(ch);
        }
    }
    if quote || escape {
        return Err("Kutip filter belum ditutup.".into());
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    Ok(tokens)
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct Query {
    pub ip: Option<IpAddr>,
    pub site: Option<String>,
    pub vrf: Option<String>,
    pub without_vrf: bool,
    pub profile: Option<String>,
    pub port: Option<u16>,
    pub exporter: Option<SocketAddr>,
    pub domain: Option<u32>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub protocol: Option<u8>,
    pub interface: Option<u32>,
}
impl Query {
    /// Empty input shows the newest records. All clauses are typed and AND-combined.
    pub fn parse(s: &str) -> Result<Self> {
        let mut out = Self::default();
        let mut seen = std::collections::BTreeSet::new();
        let tokens = filter_tokens(s)?;
        for field in &tokens {
            let (key, value) = field.split_once('=').unwrap_or(("ip", field));
            if value.is_empty() || value.len() > 128 || !seen.insert(key) {
                return Err("Filter kosong, terlalu panjang, atau duplikat.".into());
            }
            match key {
                "ip" => out.ip = Some(value.parse().map_err(|_| "IP filter tidak valid.")?),
                "site" => out.site = Some(value.into()),
                "vrf" => out.vrf = Some(value.into()),
                "vrf-unknown" if value == "true" => out.without_vrf = true,
                "profile" => out.profile = Some(value.into()),
                "port" => out.port = Some(value.parse().map_err(|_| "Port tidak valid.")?),
                "exporter" => {
                    out.exporter = Some(value.parse().map_err(|_| "Gunakan exporter=IP:port.")?)
                }
                "domain" => out.domain = Some(value.parse().map_err(|_| "Domain tidak valid.")?),
                "since" => {
                    out.since = Some(value.parse().map_err(|_| "since memerlukan Unix UTC.")?)
                }
                "until" => {
                    out.until = Some(value.parse().map_err(|_| "until memerlukan Unix UTC.")?)
                }
                "protocol" => {
                    out.protocol = Some(
                        value
                            .parse()
                            .map_err(|_| "Gunakan nomor protokol, misalnya 6 atau 17.")?,
                    )
                }
                "if" => {
                    out.interface = Some(
                        value
                            .parse()
                            .map_err(|_| "if memerlukan indeks interface.")?,
                    )
                }
                _ => return Err(format!("Filter tidak dikenal: {key}")),
            }
        }
        if out.without_vrf && out.vrf.is_some() {
            return Err("Pilih vrf atau vrf-unknown, bukan keduanya.".into());
        }
        if out.since.zip(out.until).is_some_and(|(a, b)| a > b) {
            return Err("Rentang waktu terbalik.".into());
        }
        Ok(out)
    }
    pub fn is_ip_only(&self) -> bool {
        self.ip.is_some()
            && *self
                == Self {
                    ip: self.ip,
                    ..Self::default()
                }
    }
    fn clauses(&self) -> (Vec<&'static str>, Vec<Value>) {
        let mut keys = vec![];
        let mut val = vec![];
        if let Some(ip) = self.ip {
            keys.push("(source=? OR destination=?)");
            let ip = ip.to_string();
            val.push(ip.clone().into());
            val.push(ip.into());
        }
        for (key, s) in [
            ("site=?", self.site.clone()),
            ("profile=?", self.profile.clone()),
            ("vrf=?", self.vrf.clone()),
            ("exporter=?", self.exporter.map(|e| e.to_string())),
        ] {
            if let Some(s) = s {
                keys.push(key);
                val.push(s.into());
            }
        }
        for (key, n) in [
            ("domain=?", self.domain.map(i64::from)),
            ("received>=?", self.since.map(sql_time)),
            ("received<=?", self.until.map(sql_time)),
            ("protocol=?", self.protocol.map(i64::from)),
        ] {
            if let Some(n) = n {
                keys.push(key);
                val.push(n.into());
            }
        }
        if self.without_vrf {
            keys.push("vrf IS NULL");
        }
        if let Some(port) = self.port {
            keys.push("(json_extract(data,'$.flow.source_port')=? OR json_extract(data,'$.flow.destination_port')=?)");
            val.extend([i64::from(port).into(), i64::from(port).into()]);
        }
        if let Some(i) = self.interface {
            keys.push("(ingress=? OR egress=?)");
            val.extend([i64::from(i).into(), i64::from(i).into()]);
        }
        (keys, val)
    }
}
#[derive(Clone, Debug)]
pub struct Page {
    pub rows: Vec<ArchiveRow>,
    pub next: Option<Cursor>,
}
#[derive(Debug, Serialize)]
pub struct ArchiveHealth {
    pub measured_utc: u64,
    pub source_scopes: i64,
    pub flow_records: i64,
    pub snapshots: i64,
    pub first_flow_utc: Option<i64>,
    pub last_flow_utc: Option<i64>,
    pub main_bytes: u64,
    pub wal_bytes: u64,
    pub page_bytes: i64,
    pub limit_pages: i64,
    pub flow_retention_days: u64,
    pub configured_quota_mib: u64,
    pub snapshot_retention_days: u64,
}

pub struct Archive {
    conn: Connection,
}
impl Archive {
    fn verify(conn: &Connection, allow_empty: bool) -> Result<i64> {
        let version: i64 = conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(error)?;
        let id: i64 = conn
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(error)?;
        if matches!(version, 1 | 2 | VERSION) && id == APP_ID {
            return Ok(version);
        }
        if allow_empty && version == 0 && id == 0 {
            let objects: i64 = conn
                .query_row(
                    "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
                    [],
                    |r| r.get(0),
                )
                .map_err(error)?;
            if objects == 0 {
                return Ok(0);
            }
        }
        Err("Arsip bukan milik WeNet Toolkit (WFS Network Toolkit) atau versi schema tidak didukung.".into())
    }
    pub fn writer(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(error)?;
        }
        let mut conn = Connection::open(path).map_err(error)?;
        conn.busy_timeout(Duration::from_millis(1500))
            .map_err(error)?;
        conn.execute_batch("PRAGMA trusted_schema=OFF;")
            .map_err(error)?;
        Self::verify(&conn, true)?;
        let mode: String = conn
            .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
            .map_err(error)?;
        if !mode.eq_ignore_ascii_case("wal") {
            return Err("SQLite WAL tidak tersedia pada folder ini.".into());
        }
        conn.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA journal_size_limit=8388608; PRAGMA wal_autocheckpoint=1000;").map_err(error)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(error)?;
        let current = Self::verify(&tx, true)?;
        match current {
            0 => tx
                .execute_batch(include_str!("sql/001.sql"))
                .map_err(error)?,
            1 | 2 | VERSION => {}
            _ => return Err("Versi schema arsip tidak didukung.".into()),
        }
        tx.execute_batch("CREATE TABLE IF NOT EXISTS archive_policy (id INTEGER PRIMARY KEY CHECK(id=1),flow_days INTEGER NOT NULL,snapshot_days INTEGER NOT NULL,quota_mib INTEGER NOT NULL);").map_err(error)?;
        if current < 2 {
            tx.execute_batch(include_str!("sql/002.sql"))
                .map_err(error)?;
        }
        if current < VERSION {
            tx.execute_batch(include_str!("sql/004.sql")).map_err(error)?;
        }
        tx.commit().map_err(error)?;
        let archive = Self { conn };
        archive.apply_quota(archive.policy()?)?;
        Ok(archive)
    }
    pub fn reader(path: &Path) -> Result<Self> {
        let conn =
            Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(error)?;
        conn.busy_timeout(Duration::from_millis(1500))
            .map_err(error)?;
        conn.execute_batch("PRAGMA trusted_schema=OFF;")
            .map_err(error)?;
        Self::verify(&conn, false)?;
        Ok(Self { conn })
    }
    pub fn save_alerts(&mut self, records: &[super::alert_ledger::Record]) -> Result<()> {
        if records.len() > super::alert_ledger::MAX_ALERTS {
            return Err("Batch alert terlalu besar.".into());
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(error)?;
        let policy = Self::read_policy(&tx)?;
        Self::set_quota(&tx, policy)?;
        let cutoff = sql_time(super::now().saturating_sub(policy.snapshot_days * 86400));
        tx.execute(include_str!("sql/alert_prune.sql"), [cutoff])
            .map_err(error)?;
        for r in records.iter().filter(|r| r.last_seen >= cutoff) {
            if r.serial <= 0
                || r.total < 0
                || r.opened < 0
                || r.last_seen < r.opened
                || r.recovered.is_some_and(|v| v < r.opened || v > r.last_seen)
                || r.session.is_empty()
                || r.session.len() > 256
                || r.scope.is_empty()
                || r.scope.len() > 2048
                || r.signal.is_empty()
                || r.signal.len() > 128
            {
                return Err("Record alert tidak valid; batch dibatalkan.".into());
            }
            let changed = tx
                .execute(
                    include_str!("sql/alert_upsert.sql"),
                    params![
                        r.session, r.serial, r.scope, r.signal,
                        r.opened, r.last_seen, r.total, r.recovered
                    ],
                )
                .map_err(error)?;
            if changed != 1 {
                return Err("Identitas alert bertabrakan; batch dibatalkan.".into());
            }
        }
        tx.execute(
            include_str!("sql/alert_cap.sql"),
            [super::alert_ledger::MAX_ALERTS as i64],
        )
        .map_err(error)?;
        tx.commit().map_err(error)
    }

    pub fn alert_page(&self, filter: &str) -> Result<Vec<super::alert_ledger::Record>> {
        let (search, status) = super::alert_ledger::parse_filter(filter)?;
        if Self::verify(&self.conn, false)? < VERSION {
            return Ok(Vec::new());
        }
        let mut stmt = self.conn.prepare(include_str!("sql/alert_page.sql")).map_err(error)?;
        let rows = stmt
            .query_map(params![search, status, super::alert_ledger::PAGE as i64], |r| {
                Ok(super::alert_ledger::Record {
                    id: r.get(0)?,
                    session: r.get(1)?,
                    serial: r.get(2)?,
                    scope: r.get(3)?,
                    signal: r.get(4)?,
                    opened: r.get(5)?,
                    last_seen: r.get(6)?,
                    total: r.get(7)?,
                    acknowledged: r.get(8)?,
                    recovered: r.get(9)?,
                })
            })
            .map_err(error)?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(error)
    }

    // Open an existing archive without creating or migrating it on an ACK action.
    pub fn alert_writer(path: &Path) -> Result<Self> {
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(error)?;
        conn.busy_timeout(Duration::from_millis(1500)).map_err(error)?;
        conn.execute_batch("PRAGMA trusted_schema=OFF;").map_err(error)?;
        if Self::verify(&conn, false)? != VERSION {
            return Err("Arsip perlu dimigrasikan melalui operasi penyimpanan sebelum mengakui alert.".into());
        }
        Ok(Self { conn })
    }

    pub fn acknowledge_alert(&self, record: &super::alert_ledger::Record, utc: u64) -> Result<()> {
        let changed = self
            .conn
            .execute(
                include_str!("sql/alert_ack.sql"),
                params![
                    sql_time(utc), record.id, record.session, record.serial,
                    record.scope, record.signal, record.opened
                ],
            )
            .map_err(error)?;
        if changed != 1 {
            return Err("Alert sudah tidak tersedia. Muat ulang daftar.".into());
        }
        Ok(())
    }

    pub fn save_router_sample(&mut self, sample: &super::router_history::Sample) -> Result<()> {
        use super::router_history::{MAX_BYTES, MAX_ROUTERS, SAMPLES_PER_ROUTER};
        let payload = serde_json::to_string(sample).map_err(error)?;
        if payload.len() > MAX_BYTES {
            return Err("Sampel router melewati 1 MiB.".into());
        }
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(error)?;
        let policy = Self::read_policy(&tx)?;
        Self::set_quota(&tx, policy)?;
        let cutoff = sql_time(super::now().saturating_sub(policy.snapshot_days * 86400));
        if sql_time(sample.received_utc) < cutoff {
            return Err("Sampel sudah di luar retensi.".into());
        }
        tx.execute("DELETE FROM router_samples WHERE received < ?1", [cutoff])
            .map_err(error)?;
        let known: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM router_samples WHERE authority=?1)",
                [&sample.authority],
                |r| r.get(0),
            )
            .map_err(error)?;
        if !known {
            let count: i64 = tx
                .query_row(
                    "SELECT count(DISTINCT authority) FROM router_samples",
                    [],
                    |r| r.get(0),
                )
                .map_err(error)?;
            if count >= MAX_ROUTERS as i64 {
                return Err("Batas histori 32 router tercapai. Data lama tetap utuh.".into());
            }
        }
        tx.execute("INSERT INTO router_samples(authority,received,payload) VALUES (?1,?2,?3) ON CONFLICT(authority,received) DO NOTHING",
            params![&sample.authority,sql_time(sample.received_utc),payload]).map_err(error)?;
        tx.execute("DELETE FROM router_samples WHERE authority=?1 AND received IN (SELECT received FROM router_samples WHERE authority=?1 ORDER BY received DESC LIMIT -1 OFFSET ?2)",
            params![&sample.authority,SAMPLES_PER_ROUTER as i64]).map_err(error)?;
        tx.commit().map_err(error)
    }
    pub fn router_history(
        &self,
        authority: &super::router::Authority,
        start: u64,
        end: u64,
    ) -> Result<super::router_history::Views> {
        use super::router_history::{MAX_BYTES, SAMPLES_PER_ROUTER, Sample, Views};
        let mut out = Views::default();
        if end < start {
            return Err("Awal rentang tidak boleh melebihi akhir.".into());
        }
        if Self::verify(&self.conn, false)? < 2 {
            return Ok(out);
        }
        let start = start.max(super::now().saturating_sub(self.policy()?.snapshot_days * 86400));
        let mut stmt=self.conn.prepare("SELECT received, CASE WHEN length(CAST(payload AS BLOB))<=?5 THEN payload END
            FROM (SELECT received,payload FROM router_samples WHERE authority=?1 AND received BETWEEN ?2 AND ?3 ORDER BY received DESC LIMIT ?4) ORDER BY received ASC").map_err(error)?;
        let key = authority.display();
        let mut rows = stmt
            .query(params![
                &key,
                sql_time(start),
                sql_time(end),
                SAMPLES_PER_ROUTER as i64,
                MAX_BYTES as i64
            ])
            .map_err(error)?;
        while let Some(row) = rows.next().map_err(error)? {
            let received: i64 = row.get(0).map_err(error)?;
            let raw = row
                .get::<_, Option<String>>(1)
                .map_err(error)?
                .ok_or("Sampel arsip terlalu besar.")?;
            let sample: Sample = serde_json::from_str(&raw).map_err(error)?;
            if sample.authority != key || sql_time(sample.received_utc) != received {
                return Err("Identitas sampel tidak cocok dengan indeks.".into());
            }
            sample.replay(&mut out)?;
            out.samples += 1;
        }
        Ok(out)
    }
    pub fn policy(&self) -> Result<Policy> {
        Self::read_policy(&self.conn)
    }
    fn read_policy(conn: &Connection) -> Result<Policy> {
        use rusqlite::OptionalExtension;
        let exists = conn.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='archive_policy' AND type='table')", [], |r| r.get::<_,bool>(0)).map_err(error)?;
        if !exists {
            return Ok(Policy::default());
        }
        let row = conn
            .query_row(
                "SELECT flow_days,snapshot_days,quota_mib FROM archive_policy WHERE id=1",
                [],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(error)?;
        row.map_or_else(
            || Ok(Policy::default()),
            |(f, s, q)| Policy::new(f as u64, s as u64, q as u64),
        )
    }
    fn apply_quota(&self, policy: Policy) -> Result<()> {
        Self::set_quota(&self.conn, policy)
    }
    fn set_quota(conn: &Connection, policy: Policy) -> Result<()> {
        let page_size = conn
            .pragma_query_value(None, "page_size", |r| r.get::<_, i64>(0))
            .map_err(error)?;
        conn.pragma_update(None, "max_page_count", policy.pages(page_size))
            .map_err(error)
    }
    pub fn save_policy(&mut self, policy: Policy) -> Result<()> {
        let policy = Policy::new(policy.flow_days, policy.snapshot_days, policy.quota_mib)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(error)?;
        let page_size = tx
            .pragma_query_value(None, "page_size", |r| r.get::<_, i64>(0))
            .map_err(error)?;
        let page_count = tx
            .pragma_query_value(None, "page_count", |r| r.get::<_, i64>(0))
            .map_err(error)?;
        if policy.pages(page_size) < page_count {
            return Err("Kuota lebih kecil dari DB saat ini. Atur kuota yang lebih besar. Tidak ada data yang dihapus.".into());
        }
        tx.execute("INSERT INTO archive_policy VALUES(1,?1,?2,?3) ON CONFLICT(id) DO UPDATE SET flow_days=excluded.flow_days,snapshot_days=excluded.snapshot_days,quota_mib=excluded.quota_mib",
            params![policy.flow_days as i64,policy.snapshot_days as i64,policy.quota_mib as i64]).map_err(error)?;
        tx.commit().map_err(error)?;
        self.apply_quota(policy)
    }
    pub fn preview_delete(&self, kind: Kind, start: u64, end: u64) -> Result<DeletePreview> {
        Self::delete_set(&self.conn, kind, start, end).map(|(p, _)| p)
    }
    fn delete_set(
        conn: &Connection,
        kind: Kind,
        start: u64,
        end: u64,
    ) -> Result<(DeletePreview, Vec<i64>)> {
        if start > end || end > i64::MAX as u64 {
            return Err("Rentang UTC tidak valid.".into());
        }
        let (table, time) = kind.table();
        let mut statement = conn.prepare(&format!("SELECT id,fingerprint,{time} FROM {table} WHERE {time} BETWEEN ?1 AND ?2 ORDER BY {time},id LIMIT ?3")).map_err(error)?;
        let mut raw = statement
            .query(params![
                sql_time(start),
                sql_time(end),
                (DELETE_LIMIT + 1) as i64
            ])
            .map_err(error)?;
        let mut ids = vec![];
        let mut hash = Sha256::new();
        hash.update(table.as_bytes());
        hash.update(start.to_le_bytes());
        hash.update(end.to_le_bytes());
        while let Some(row) = raw.next().map_err(error)? {
            if ids.len() == DELETE_LIMIT {
                return Err("Lebih dari 10.000 record. Pilih rentang lebih sempit.".into());
            }
            let id: i64 = row.get(0).map_err(error)?;
            let identity: Vec<u8> = row.get(1).map_err(error)?;
            let stamp: i64 = row.get(2).map_err(error)?;
            if identity.len() != 32 {
                return Err("Identitas record arsip tidak valid.".into());
            }
            hash.update(id.to_le_bytes());
            hash.update(stamp.to_le_bytes());
            hash.update(identity);
            ids.push(id);
        }
        Ok((
            DeletePreview {
                kind,
                start,
                end,
                count: ids.len(),
                fingerprint: hash.finalize().into(),
            },
            ids,
        ))
    }
    pub fn delete_reviewed(&mut self, plan: &DeletePreview) -> Result<usize> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(error)?;
        let (current, ids) = Self::delete_set(&tx, plan.kind, plan.start, plan.end)?;
        if &current != plan {
            return Err(
                "Isi rentang berubah setelah pratinjau. Tidak ada record yang dihapus.".into(),
            );
        }
        let (table, _) = plan.kind.table();
        {
            let mut stmt = tx
                .prepare(&format!("DELETE FROM {table} WHERE id=?"))
                .map_err(error)?;
            for id in ids {
                stmt.execute([id]).map_err(error)?;
            }
        }
        tx.commit().map_err(error)?;
        Ok(plan.count)
    }
    pub fn insert(&mut self, batch: &[ArchiveRow]) -> Result<usize> {
        let tx = self.conn.transaction().map_err(error)?;
        Self::set_quota(&tx, Self::read_policy(&tx)?)?;
        let mut n = 0;
        {
            let mut stmt=tx.prepare_cached("INSERT INTO flow(fingerprint,profile,site,vrf,exporter,domain,version,received,source,destination,protocol,ingress,egress,data) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(fingerprint) DO NOTHING").map_err(error)?;
            for row in batch {
                let f = &row.flow;
                // Packet digest and record ordinal identify replays without collapsing equal tuples.
                let key = Sha256::digest(
                    serde_json::to_vec(&(
                        &row.profile,
                        &row.site,
                        &row.vrf,
                        f.exporter,
                        f.version,
                        f.domain,
                        f.datagram_hash,
                        f.ordinal,
                    ))
                    .map_err(error)?,
                );
                let data = serde_json::to_string(row).map_err(error)?;
                n += stmt
                    .execute(params![
                        &key[..],
                        row.profile,
                        row.site,
                        row.vrf,
                        f.exporter.to_string(),
                        f.domain,
                        f.version,
                        sql_time(f.received_at),
                        f.source.to_string(),
                        f.destination.to_string(),
                        f.protocol,
                        f.ingress,
                        f.egress,
                        data
                    ])
                    .map_err(error)?;
            }
        }
        tx.commit().map_err(error)?;
        Ok(n)
    }
    pub fn page(&self, q: &Query, after: Option<Cursor>, limit: usize) -> Result<Page> {
        let limit = limit.clamp(1, PAGE_SIZE);
        let (mut clauses, mut values) = q.clauses();
        if let Some(c) = after {
            clauses.push("(received,id)<(?,?)");
            values.push(c.received.into());
            values.push(c.id.into());
        }
        let filter = if clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", clauses.join(" AND "))
        };
        values.push(((limit + 1) as i64).into());
        let sql = format!(
            "SELECT id,received,data FROM flow {filter} ORDER BY received DESC,id DESC LIMIT ?"
        );
        let mut stmt = self.conn.prepare(&sql).map_err(error)?;
        let mut raw = stmt.query(params_from_iter(values)).map_err(error)?;
        let mut rows = Vec::new();
        let mut last = None;
        while let Some(r) = raw.next().map_err(error)? {
            if rows.len() == limit {
                return Ok(Page { rows, next: last });
            }
            let data: String = r.get(2).map_err(error)?;
            if data.len() > 8192 {
                return Err("Record arsip melampaui batas.".into());
            }
            rows.push(serde_json::from_str(&data).map_err(error)?);
            last = Some(Cursor {
                id: r.get(0).map_err(error)?,
                received: r.get(1).map_err(error)?,
            });
        }
        Ok(Page { rows, next: None })
    }
    pub fn inspect(&self, q: &Query, now: u64) -> Result<super::device::Inspection> {
        use super::device::{INSPECTION_LIMIT, Inspection};
        let ip = q.ip.ok_or("Masukkan IP yang akan diperiksa.")?;
        self.conn.execute_batch("BEGIN DEFERRED").map_err(error)?;
        let result = (|| {
            let mut rows = Vec::new();
            let mut cursor = None;
            loop {
                let page = self.page(q, cursor, INSPECTION_LIMIT - rows.len())?;
                rows.extend(page.rows);
                cursor = page.next;
                if rows.len() >= INSPECTION_LIMIT || cursor.is_none() {
                    break;
                }
            }
            let mut result = Inspection::analyze(ip, rows, now);
            result.partial |= cursor.is_some();
            Ok(result)
        })();
        let end = self.conn.execute_batch("ROLLBACK").map_err(error);
        match (result, end) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    }
    fn maintenance(&mut self, now: u64) -> Result<usize> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(error)?;
        let policy = Self::read_policy(&tx)?;
        Self::set_quota(&tx, policy)?;
        let flows = Self::prune_in(&tx, Kind::Flow, now, policy.flow_days)?;
        let snapshots = Self::prune_in(&tx, Kind::Snapshot, now, policy.snapshot_days)?;
        let router_samples = tx
            .execute(
                "DELETE FROM router_samples WHERE received < ?1",
                [sql_time(now.saturating_sub(policy.snapshot_days * 86400))],
            )
            .map_err(error)?;
        let alerts = tx.execute(
            include_str!("sql/alert_prune.sql"),
            [sql_time(now.saturating_sub(policy.snapshot_days * 86400))],
        ).map_err(error)?;
        tx.commit().map_err(error)?;
        Ok(flows + snapshots + router_samples + alerts)
    }
    pub fn prune(&self, now: u64, days: u64) -> Result<usize> {
        Self::prune_in(&self.conn, Kind::Flow, now, days)
    }
    fn prune_in(conn: &Connection, kind: Kind, now: u64, days: u64) -> Result<usize> {
        if !(1..=365).contains(&days) {
            return Err("Retensi harus 1–365 hari.".into());
        }
        let before = sql_time(now.saturating_sub(days * 86400));
        let (table, stamp) = kind.table();
        conn.execute(&format!("DELETE FROM {table} WHERE id IN (SELECT id FROM {table} WHERE {stamp} < ? ORDER BY {stamp} LIMIT 10000)"),[before]).map_err(error)
    }
    pub fn import(&mut self, snapshots: &[Snapshot]) -> Result<usize> {
        let tx = self.conn.transaction().map_err(error)?;
        Self::set_quota(&tx, Self::read_policy(&tx)?)?;
        let mut count = 0;
        for s in snapshots {
            let data = serde_json::to_string(s).map_err(error)?;
            if data.len() > 4 * 1024 * 1024 {
                return Err("Snapshot JSON terlalu besar.".into());
            }
            let digest = Sha256::digest(data.as_bytes());
            count+=tx.execute("INSERT INTO snapshots(fingerprint,source,observed,data) VALUES(?,?,?,?) ON CONFLICT(fingerprint) DO NOTHING",params![&digest[..],s.source,sql_time(s.observed_at),data]).map_err(error)?;
        }
        tx.commit().map_err(error)?;
        Ok(count)
    }
    pub fn history(&self, at: u64) -> Result<super::history::History> {
        const MAX_ITEM: i64 = 4 * 1024 * 1024;
        const MAX_TOTAL: i64 = 32 * 1024 * 1024;
        let mut stmt = self.conn.prepare(
            "SELECT observed, length(CAST(data AS BLOB)), CASE WHEN length(CAST(data AS BLOB)) <= ?1 THEN data ELSE NULL END FROM snapshots WHERE observed BETWEEN ?2 AND ?3 ORDER BY observed DESC,id DESC LIMIT 64"
        ).map_err(error)?;
        let mut entries = stmt
            .query(params![
                MAX_ITEM,
                sql_time(at.saturating_sub(self.policy()?.snapshot_days * 86400)),
                sql_time(at)
            ])
            .map_err(error)?;
        let mut h = super::history::History {
            snapshots: vec![],
            unreadable: 0,
        };
        let mut used = 0;
        while let Some(row) = entries.next().map_err(error)? {
            let stamp: i64 = row.get(0).map_err(error)?;
            let size: i64 = row.get(1).map_err(error)?;
            if size > MAX_ITEM || used + size > MAX_TOTAL {
                h.unreadable += 1;
                continue;
            }
            used += size;
            let data: String = row.get(2).map_err(error)?;
            let parsed = serde_json::from_str::<Snapshot>(&data).ok().filter(|s| {
                s.schema == 1
                    && s.observed_at == stamp as u64
                    && s.sections.len() <= 8
                    && s.sections.iter().all(|x| x.values.len() <= 1200)
            });
            if let Some(s) = parsed {
                h.snapshots.push(s);
            } else {
                h.unreadable += 1;
            }
        }
        Ok(h)
    }
    pub fn health(&self, path: &Path) -> Result<ArchiveHealth> {
        let file = |p: &Path, optional| match std::fs::metadata(p) {
            Ok(m) => Ok(m.len()),
            Err(e) if optional && e.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(e) => Err(error(e)),
        };
        let mut wal = path.as_os_str().to_owned();
        wal.push("-wal");
        let (flow_records, snapshots, first_flow_utc, last_flow_utc) = self.conn.query_row(
            "SELECT (SELECT count(*) FROM flow),(SELECT count(*) FROM snapshots),(SELECT min(received) FROM flow),(SELECT max(received) FROM flow)",
            [], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        ).map_err(error)?;
        let policy = self.policy()?;
        let page_bytes = self
            .conn
            .pragma_query_value(None, "page_size", |r| r.get(0))
            .map_err(error)?;
        let source_scopes = self
            .conn
            .query_row(
                "SELECT count(*) FROM (SELECT DISTINCT profile,site,vrf,exporter,domain FROM flow)",
                [],
                |r| r.get(0),
            )
            .map_err(error)?;
        Ok(ArchiveHealth {
            measured_utc: super::now(),
            source_scopes,
            flow_records,
            snapshots,
            first_flow_utc,
            last_flow_utc,
            main_bytes: file(path, false)?,
            wal_bytes: file(Path::new(&wal), true)?,
            page_bytes,
            limit_pages: policy.pages(page_bytes),
            flow_retention_days: policy.flow_days,
            configured_quota_mib: policy.quota_mib,
            snapshot_retention_days: policy.snapshot_days,
        })
    }
    pub fn check(&self) -> Result<()> {
        let status: String = self
            .conn
            .query_row("PRAGMA quick_check(1)", [], |r| r.get(0))
            .map_err(error)?;
        if status != "ok" {
            return Err(error(status));
        }
        self.counts()?;
        if Self::verify(&self.conn, false)? >= 2 {
            self.conn
                .query_row("SELECT count(*) FROM router_samples", [], |r| {
                    r.get::<_, i64>(0)
                })
                .map_err(error)?;
        }
        if Self::verify(&self.conn, false)? == VERSION {
            self.conn.query_row("SELECT count(*) FROM collector_alerts", [], |r| r.get::<_, i64>(0)).map_err(error)?;
        }

        Ok(())
    }
    pub(crate) fn check_standalone(&self) -> Result<()> {
        let mode: String = self
            .conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .map_err(error)?;
        if mode.eq_ignore_ascii_case("wal") {
            return Err(
                "Gunakan file dari fitur Backup SQLite, bukan arsip aktif dengan mode WAL.".into(),
            );
        }
        self.check()
    }
    pub fn backup_to(&self, path: &Path) -> Result<()> {
        use rusqlite::backup::{Backup, StepResult};
        use std::{fs::OpenOptions, time::Instant};
        if path.try_exists().map_err(error)? {
            return Err("Tujuan sudah ada; pilih nama baru.".into());
        }
        let stage = Stage::new(path)?;
        let output = &stage.file;
        drop(
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(output)
                .map_err(error)?,
        );
        (|| {
            let mut dest = Connection::open_with_flags(output, OpenFlags::SQLITE_OPEN_READ_WRITE)
                .map_err(error)?;
            {
                let copy = Backup::new(&self.conn, &mut dest).map_err(error)?;
                let deadline = Instant::now() + Duration::from_secs(30);
                loop {
                    if Instant::now() >= deadline {
                        return Err("Batas waktu backup SQLite tercapai; coba lagi setelah collector berhenti.".into());
                    }
                    match copy.step(128).map_err(error)? {
                        StepResult::Done => break,
                        StepResult::More => thread::yield_now(),
                        _ => thread::sleep(Duration::from_millis(25)),
                    }
                }
            }
            let mode: String = dest
                .query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))
                .map_err(error)?;
            if !mode.eq_ignore_ascii_case("delete") {
                return Err("Backup tidak dapat dipisahkan dari WAL.".into());
            }
            let backup = Archive { conn: dest };
            Self::verify(&backup.conn, false)?;
            backup.check()?;
            drop(backup);
            OpenOptions::new()
                .write(true)
                .open(output)
                .and_then(|f| f.sync_all())
                .map_err(error)?;
            stage.publish(path)
        })()
    }
    pub fn snapshot_summaries(&self) -> Result<Vec<(String, i64)>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT source,observed FROM snapshots ORDER BY observed DESC,id DESC LIMIT 64",
            )
            .map_err(error)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .map_err(error)?;
        rows.collect::<rusqlite::Result<_>>().map_err(error)
    }
    pub fn counts(&self) -> Result<(i64, i64)> {
        Ok((
            self.conn
                .query_row("SELECT count(*) FROM flow", [], |r| r.get(0))
                .map_err(error)?,
            self.conn
                .query_row("SELECT count(*) FROM snapshots", [], |r| r.get(0))
                .map_err(error)?,
        ))
    }
    pub fn export(
        &mut self,
        q: &Query,
        format: ExportFormat,
        redact: bool,
        out: &mut impl Write,
    ) -> Result<ExportSummary> {
        // Hold a consistent reader snapshot across pages without blocking WAL writers.
        self.conn.execute_batch("BEGIN DEFERRED").map_err(error)?;
        let result = self.export_inner(q, format, redact, out);
        let finish = self.conn.execute_batch("ROLLBACK").map_err(error);
        match (result, finish) {
            (Ok(s), Ok(())) => Ok(s),
            (Err(e), _) | (_, Err(e)) => Err(e),
        }
    }
    fn export_inner(
        &self,
        q: &Query,
        format: ExportFormat,
        redact: bool,
        out: &mut impl Write,
    ) -> Result<ExportSummary> {
        let mut total = 0;
        let mut cursor = None;
        let mut masks = std::collections::BTreeMap::<(String, Option<String>, IpAddr), u32>::new();
        let mut aliases = std::collections::BTreeMap::<String, u32>::new();
        let mut masked = |site: &str, vrf: &Option<String>, ip: IpAddr| {
            if !redact {
                return ip.to_string();
            }
            let id = masks.len() as u32 + 1;
            format!(
                "IP-{}",
                masks.entry((site.into(), vrf.clone(), ip)).or_insert(id)
            )
        };
        let mut scope = |kind: &str, value: &str| {
            if !redact {
                return value.to_owned();
            }
            let id = aliases.len() as u32 + 1;
            format!(
                "{kind}-{}",
                aliases.entry(format!("{kind}/{value}")).or_insert(id)
            )
        };
        match format {
            ExportFormat::Csv=>out.write_all(b"received_utc,export_utc,site,vrf,profile,exporter,domain,version,source,destination,source_port,destination_port,protocol,ingress,egress,reported_bytes,reported_packets,direction,sampling\r\n").map_err(error)?,
            ExportFormat::Json=>out.write_all(b"{\"schema\":1,\"rows\":[").map_err(error)?,
        }
        let truncated = loop {
            let page = self.page(q, cursor, (EXPORT_LIMIT - total).max(1))?;
            for r in page.rows {
                if total == EXPORT_LIMIT {
                    break;
                }
                let f = r.flow;
                let source = masked(&r.site, &r.vrf, f.source);
                let destination = masked(&r.site, &r.vrf, f.destination);
                let row = serde_json::json!({
                    "received_utc":f.received_at,"export_utc":f.export_at,"site":scope("SITE",&r.site),
                    "vrf":r.vrf.as_ref().map(|v|scope("VRF",v)),"profile":scope("PROFILE",&r.profile),
                    "exporter":scope("EXPORTER",&f.exporter.to_string()),"domain":f.domain,"version":f.version,
                    "source":source,"destination":destination,"source_port":f.source_port,"destination_port":f.destination_port,
                    "protocol":f.protocol,"ingress":f.ingress,"egress":f.egress,"reported_bytes":f.octets,"reported_packets":f.packets,
                    "direction":r.direction.as_str(),"sampling":"unknown"
                });
                match format {
                    ExportFormat::Csv => {
                        let keys = [
                            "received_utc",
                            "export_utc",
                            "site",
                            "vrf",
                            "profile",
                            "exporter",
                            "domain",
                            "version",
                            "source",
                            "destination",
                            "source_port",
                            "destination_port",
                            "protocol",
                            "ingress",
                            "egress",
                            "reported_bytes",
                            "reported_packets",
                            "direction",
                            "sampling",
                        ];
                        let cells = keys
                            .iter()
                            .map(|k| {
                                let v = &row[k];
                                csv_cell(&match v {
                                    serde_json::Value::String(s) => s.clone(),
                                    serde_json::Value::Null => String::new(),
                                    _ => v.to_string(),
                                })
                            })
                            .collect::<Vec<_>>()
                            .join(",");
                        write!(out, "{cells}\r\n").map_err(error)?;
                    }
                    ExportFormat::Json => {
                        if total > 0 {
                            out.write_all(b",").map_err(error)?;
                        }
                        serde_json::to_writer(&mut *out, &row).map_err(error)?;
                    }
                }
                total += 1;
            }
            if total == EXPORT_LIMIT {
                break page.next.is_some();
            }
            if let Some(next) = page.next {
                cursor = Some(next);
            } else {
                break false;
            }
        };
        if format == ExportFormat::Json {
            write!(out, "],\"truncated\":{truncated}}}").map_err(error)?;
        }
        Ok(ExportSummary { total, truncated })
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Csv,
    Json,
}
pub struct ExportSummary {
    pub total: usize,
    pub truncated: bool,
}

#[derive(Default)]
pub struct WriterStats {
    pub written: AtomicU64,
    pub duplicates: AtomicU64,
    pub dropped: AtomicU64,
    pub queue_full: AtomicU64,
    pub writer_closed: AtomicU64,
    pub sqlite_failed: AtomicU64,
    pub pruned: AtomicU64,
    pub pending_rows: AtomicU64,
    pub error: Mutex<Option<String>>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DropCause {
    QueueFull,
    WriterClosed,
    SqliteFailed,
}
impl WriterStats {
    fn note_drop(&self, cause: DropCause, rows: usize) {
        let count = rows as u64;
        self.dropped.fetch_add(count, Ordering::Relaxed);
        match cause {
            DropCause::QueueFull => self.queue_full.fetch_add(count, Ordering::Relaxed),
            DropCause::WriterClosed => self.writer_closed.fetch_add(count, Ordering::Relaxed),
            DropCause::SqliteFailed => self.sqlite_failed.fetch_add(count, Ordering::Relaxed),
        };
    }
}
pub struct Writer {
    tx: Option<SyncSender<Vec<ArchiveRow>>>,
    handle: Option<thread::JoinHandle<()>>,
    pub stats: Arc<WriterStats>,
}
impl Writer {
    pub fn start(path: &Path) -> Result<Self> {
        let mut db = Archive::writer(path)?;
        let (tx, rx) = mpsc::sync_channel::<Vec<ArchiveRow>>(QUEUE_BATCHES);
        let stats = Arc::new(WriterStats::default());
        let counters = stats.clone();
        let handle = thread::Builder::new()
            .name("wfs-flow-archive".into())
            .spawn(move || {
                let mut last_prune = None;
                loop {
                    if last_prune.is_none_or(|previous: std::time::Instant| {
                        previous.elapsed() >= Duration::from_secs(300)
                    }) {
                        last_prune = Some(std::time::Instant::now());
                        match db.maintenance(super::now()) {
                            Ok(n) => {
                                counters.pruned.fetch_add(n as u64, Ordering::Relaxed);
                            }
                            Err(e) => {
                                if let Ok(mut s) = counters.error.lock() {
                                    *s = Some(e);
                                }
                            }
                        }
                    }
                    let batch = match rx.recv_timeout(Duration::from_secs(60)) {
                        Ok(batch) => Some(batch),
                        Err(mpsc::RecvTimeoutError::Timeout) => None,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    if let Some(mut batch) = batch {
                        for more in rx.try_iter().take(3) {
                            batch.extend(more);
                        }
                        // Pending includes the transaction in flight until its result is known.
                        match db.insert(&batch) {
                            Ok(n) => {
                                counters.written.fetch_add(n as u64, Ordering::Relaxed);
                                counters
                                    .duplicates
                                    .fetch_add((batch.len() - n) as u64, Ordering::Relaxed);
                            }
                            Err(e) => {
                                counters.note_drop(DropCause::SqliteFailed, batch.len());
                                if let Ok(mut s) = counters.error.lock() {
                                    *s = Some(e);
                                }
                            }
                        }
                        counters
                            .pending_rows
                            .fetch_sub(batch.len() as u64, Ordering::Relaxed);
                    }
                }
                let _ = db.conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);");
            })
            .map_err(error)?;
        Ok(Self {
            tx: Some(tx),
            handle: Some(handle),
            stats,
        })
    }
    pub fn submit(&self, rows: impl IntoIterator<Item = ArchiveRow>) {
        let tx = self.tx.as_ref().expect("writer alive");
        let mut rows = rows.into_iter();
        loop {
            let batch: Vec<_> = rows.by_ref().take(BATCH_SIZE).collect();
            if batch.is_empty() {
                break;
            }
            self.stats
                .pending_rows
                .fetch_add(batch.len() as u64, Ordering::Relaxed);
            match tx.try_send(batch) {
                Ok(()) => {}
                Err(TrySendError::Full(v)) => {
                    self.stats.pending_rows.fetch_sub(v.len() as u64, Ordering::Relaxed);
                    self.stats.note_drop(DropCause::QueueFull, v.len());
                }
                Err(TrySendError::Disconnected(v)) => {
                    self.stats.pending_rows.fetch_sub(v.len() as u64, Ordering::Relaxed);
                    self.stats.note_drop(DropCause::WriterClosed, v.len());
                }
            }
        }
    }
}
impl Drop for Writer {
    fn drop(&mut self) {
        drop(self.tx.take());
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

#[cfg(windows)]
pub fn default_path() -> Result<std::path::PathBuf> {
    let dir = std::env::var_os("LOCALAPPDATA").ok_or("Folder data pengguna tidak tersedia.")?;
    Ok(std::path::PathBuf::from(dir)
        .join("WFS Network Toolkit")
        .join("flow-v1.sqlite3"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp_path() -> std::path::PathBuf {
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir()
            .join(format!(
                "wfs-db-{}-{}",
                std::process::id(),
                N.fetch_add(1, Ordering::Relaxed)
            ))
            .join("flow.sqlite3")
    }
    fn router_sample(
        at: u64,
        id: &str,
        bytes: u64,
        mac: &str,
    ) -> super::super::router_history::Sample {
        use super::super::{
            router::{Authority, RouterSnapshot, Table},
            router_history::Sample,
        };
        let auth = Authority::parse("router.fixture.test").unwrap();
        let mut snap = RouterSnapshot::new(&auth, at);
        snap.ingest(
            Table::Identity,
            Ok(format!(r#"{{"name":"{id}"}}"#).into_bytes()),
            at - 3,
        );
        snap.ingest(
            Table::Resource,
            Ok(format!(r#"{{"version":"7.test","uptime":"{}s"}}"#, at % 10_000).into_bytes()),
            at - 3,
        );
        snap.ingest(
            Table::Interface,
            Ok(
                format!(r#"[{{"name":"ether1","type":"ether","running":true,"disabled":false,"rx-byte":"{bytes}","tx-byte":"{bytes}"}}]"#)
                    .into_bytes(),
            ),
            at - 2,
        );
        snap.ingest(Table::Lease, Ok(format!(r#"[{{"active-address":"192.0.2.22","active-mac-address":"{mac}","active-server":"dhcp","status":"bound","host-name":"private-client-name"}}]"#).into_bytes()), at - 1);
        Sample::capture(&snap)
    }
    #[test]
    fn router_history_migrates_v1_and_roundtrips_read_only_backup() {
        use super::super::router::Authority;
        let path = temp_path();
        let backup = path.with_file_name("restored.sqlite3");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let v1 = Connection::open(&path).unwrap();
        v1.execute_batch(include_str!("sql/001.sql")).unwrap();
        drop(v1);
        let a = Authority::parse("router.fixture.test").unwrap();
        let other = Authority::parse("other.fixture.test").unwrap();
        let now = super::super::now();
        let base = now - now % 10_000 + 1000;
        let base = if base + 30 > now { base - 10_000 } else { base };
        let read = Archive::reader(&path).unwrap();
        assert_eq!(Archive::verify(&read.conn, false).unwrap(), 1);
        assert_eq!(read.router_history(&a, 0, now).unwrap().samples, 0);
        drop(read);
        let mut db = Archive::writer(&path).unwrap();
        assert_eq!(Archive::verify(&db.conn, false).unwrap(), VERSION);
        db.insert(&[row("legacy-kind", base, 0)]).unwrap();
        assert!(
            db.save_router_sample(&router_sample(
                base - 90 * 86400,
                "old",
                0,
                "02:00:00:00:00:01"
            ))
            .is_err()
        );
        let x = router_sample(base, "first", 100, "02:00:00:00:00:01");
        db.save_router_sample(&x).unwrap();
        db.save_router_sample(&x).unwrap();
        db.save_router_sample(&router_sample(base + 10, "first", 200, "02:00:00:00:00:02"))
            .unwrap();
        db.save_router_sample(&router_sample(
            base + 20,
            "replacement",
            300,
            "02:00:00:00:00:03",
        ))
        .unwrap();
        let n: i64 = db
            .conn
            .query_row(
                "SELECT count(*) FROM router_samples WHERE payload LIKE '%private-client-name%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 0);
        db.backup_to(&backup).unwrap();
        drop(db);
        for p in [&path, &backup] {
            let read = Archive::reader(p).unwrap();
            read.check().unwrap();
            assert_eq!(read.counts().unwrap().0, 1);
            assert_eq!(read.router_history(&other, 0, now).unwrap().samples, 0);
            assert_eq!(
                read.router_history(&a, base + 1, base + 10)
                    .unwrap()
                    .samples,
                1
            );
            let v = read.router_history(&a, 0, now).unwrap();
            assert_eq!(v.samples, 3);
            let pts = &v.trend.streams["ether1"];
            assert_eq!(
                (pts[1].utc, pts[1].received_utc, pts[1].rx_bps),
                (base + 8, base + 10, Some(80))
            );
            assert_eq!(pts[2].rx_bps, None);
            assert_eq!(
                v.leases.events.iter().map(|e| e.basis).collect::<Vec<_>>(),
                ["Lease terlihat", "MAC lease berubah", "Lease terlihat"]
            );
        }
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    #[test]
    fn router_history_caps_samples_keeps_newest_and_prunes_expired() {
        let path = temp_path();
        let mut db = Archive::writer(&path).unwrap();
        let now = super::super::now();
        let auth = super::super::router::Authority::parse("router.fixture.test").unwrap();
        let base = now - 1000;
        for j in 0..125 {
            db.save_router_sample(&router_sample(base + j, "first", j, "02:00:00:00:00:01"))
                .unwrap();
        }
        assert_eq!(db.router_history(&auth, base, now).unwrap().samples, 120);
        assert_eq!(db.router_history(&auth, base, base + 4).unwrap().samples, 0);
        db.conn
            .execute("INSERT INTO router_samples VALUES ('stale',1,'{}')", [])
            .unwrap();
        db.save_router_sample(&router_sample(now, "first", 500, "02:00:00:00:00:01"))
            .unwrap();
        let stale: i64 = db
            .conn
            .query_row(
                "SELECT count(*) FROM router_samples WHERE authority='stale'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stale, 0);
        drop(db);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    #[test]
    fn archive_drop_categories_are_separate_and_sum_to_total() {
        let stats = WriterStats::default();
        stats.note_drop(DropCause::QueueFull, 12);
        stats.note_drop(DropCause::WriterClosed, 3);
        stats.note_drop(DropCause::SqliteFailed, 5);
        assert_eq!(stats.queue_full.load(Ordering::Relaxed), 12);
        assert_eq!(stats.writer_closed.load(Ordering::Relaxed), 3);
        assert_eq!(stats.sqlite_failed.load(Ordering::Relaxed), 5);
        assert_eq!(stats.dropped.load(Ordering::Relaxed), 20);
    }

    #[test]
    fn ledger_migrates_v2_and_ack_survives_replay_and_backup() {
        use super::super::alert_ledger::Record;
        let path = temp_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let backup = path.with_file_name("ledger-backup.sqlite3");
        let old = Connection::open(&path).unwrap();
        old.execute_batch(include_str!("sql/001.sql")).unwrap();
        old.execute_batch(include_str!("sql/002.sql")).unwrap();
        drop(old);
        assert!(Archive::reader(&path).unwrap().alert_page("").unwrap().is_empty());
        assert!(Archive::alert_writer(&path).is_err());
        let mut db = Archive::writer(&path).unwrap();
        assert_eq!(Archive::verify(&db.conn, false).unwrap(), VERSION);
        let now = super::super::now();
        let mut rec = Record {
            id: 0,
            session: "fixture-a".into(),
            serial: 1,
            scope: "[site,vrf-a,router-a,192.0.2.1,9]".into(),
            signal: "Template hilang".into(),
            opened: now as i64,
            last_seen: now as i64,
            total: 1,
            acknowledged: None,
            recovered: None,
        };
        let mut other = rec.clone();
        other.serial = 2;
        other.scope = "[site,vrf-b,router-b,192.0.2.1,9]".into();
        db.save_alerts(&[rec.clone(), other]).unwrap();
        let mut page = db.alert_page("vrf-a").unwrap();
        assert_eq!(page.len(), 1);
        let saved = page.remove(0);
        db.acknowledge_alert(&saved, now + 1).unwrap();
        db.acknowledge_alert(&saved, now + 2).unwrap();
        rec.total = 5;
        rec.last_seen += 5;
        rec.recovered = Some(rec.last_seen);
        db.save_alerts(&[rec]).unwrap();
        db.backup_to(&backup).unwrap();
        drop(db);
        let read = Archive::reader(&backup).unwrap();
        let saved = read.alert_page("vrf-a").unwrap().remove(0);
        assert_eq!(saved.acknowledged, Some((now + 1) as i64));
        assert_eq!(saved.total, 5);
        assert_eq!(saved.status(), "Pulih teramati");
        assert!(read.acknowledge_alert(&saved, now + 10).is_err());
        assert_eq!(read.alert_page("vrf-b").unwrap().len(), 1);
        drop(read);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn unknown_legacy_schema_three_is_not_silently_migrated() {
        let path = temp_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let old = Connection::open(&path).unwrap();
        old.execute_batch(include_str!("sql/001.sql")).unwrap();
        old.execute_batch(include_str!("sql/002.sql")).unwrap();
        old.pragma_update(None, "user_version", 3).unwrap();
        drop(old);
        assert!(Archive::reader(&path).is_err());
        assert!(Archive::writer(&path).is_err());
        let raw = Connection::open(&path).unwrap();
        let version: i64 = raw.pragma_query_value(None, "user_version", |r| r.get(0)).unwrap();
        assert_eq!(version, 3);
        drop(raw);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    fn row(site: &str, received: u64, ordinal: u32) -> ArchiveRow {
        ArchiveRow {
            profile: format!("profile-{site}"),
            site: site.into(),
            vrf: Some("vrf1".into()),
            direction: Direction::FromLan,
            flow: Flow {
                exporter: "192.0.2.1:40000".parse().unwrap(),
                domain: 11,
                version: 10,
                export_at: received - 1,
                received_at: received,
                source: "10.0.0.3".parse().unwrap(),
                destination: "203.0.113.8".parse().unwrap(),
                source_port: Some(3000),
                destination_port: Some(443),
                protocol: Some(6),
                ingress: Some(2),
                egress: Some(3),
                octets: Some(u64::MAX),
                packets: Some(3),
                datagram_hash: [9; 32],
                ordinal,
            },
        }
    }
    fn inverted(mut r: ArchiveRow, ordinal: u32) -> ArchiveRow {
        r.flow.ordinal = ordinal;
        r.direction = Direction::ToLan;
        std::mem::swap(&mut r.flow.source, &mut r.flow.destination);
        std::mem::swap(&mut r.flow.source_port, &mut r.flow.destination_port);
        std::mem::swap(&mut r.flow.ingress, &mut r.flow.egress);
        r
    }

    #[test]
    #[ignore = "one-million-record storage benchmark"]
    fn benchmark_archive_million() {
        let path = temp_path();
        let mut db = Archive::writer(&path).unwrap();
        db.save_policy(Policy::new(30, 7, 1024).unwrap()).unwrap();
        let base = super::super::now() - 100_000;
        let begin = std::time::Instant::now();
        let mut written = 0;
        for offset in (0..1_000_000_u32).step_by(2_000) {
            let rows: Vec<_> = (offset..offset + 2_000)
                .map(|n| {
                    let device = n % 2000;
                    let exporter = device % 10;
                    let mut r = row(&format!("site-{exporter}"), base + u64::from(n / 10), n);
                    r.flow.exporter =
                        std::net::SocketAddr::from(([192, 0, 2, exporter as u8 + 1], 40000));
                    r.flow.domain = exporter;
                    r.flow.source = std::net::Ipv4Addr::new(
                        10,
                        0,
                        (device / 250) as u8,
                        (1 + device % 250) as u8,
                    )
                    .into();
                    r
                })
                .collect();
            written += db.insert(&rows).unwrap();
        }
        let duration = begin.elapsed();
        assert_eq!(written, 1_000_000);
        let read = Archive::reader(&path).unwrap();
        let health = read.health(&path).unwrap();
        assert_eq!(health.source_scopes, 10);
        let mut samples = vec![];
        for device in 0..100 {
            let ip = format!("10.0.0.{}", device + 1);
            let q = Query::parse(&ip).unwrap();
            let mark = std::time::Instant::now();
            assert_eq!(read.inspect(&q, super::super::now()).unwrap().examined, 500);
            samples.push(mark.elapsed().as_micros());
        }
        samples.sort_unstable();
        println!(
            "rows={written} scopes={} elapsed_ms={} rows_per_sec={:.0} db_bytes={} wal_bytes={} p95_inspect_us={}",
            health.source_scopes,
            duration.as_millis(),
            written as f64 / duration.as_secs_f64(),
            health.main_bytes,
            health.wal_bytes,
            samples[94]
        );
        drop((db, read));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn writer_maintains_expired_records_without_receiving_flow() {
        let path = temp_path();
        let now = super::super::now();
        let mut db = Archive::writer(&path).unwrap();
        db.save_policy(Policy::new(1, 1, 16).unwrap()).unwrap();
        db.insert(&[row("Idle", now - 172_800, 0)]).unwrap();
        drop(db);
        let writer = Writer::start(&path).unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(3);
        while writer.stats.pruned.load(Ordering::Relaxed) == 0 {
            assert!(std::time::Instant::now() < until);
            thread::sleep(Duration::from_millis(10));
        }
        drop(writer);
        assert_eq!(Archive::reader(&path).unwrap().counts().unwrap(), (0, 0));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn full_fixture_retains_active_writer_data_and_counts_failed_rows() {
        let path = temp_path();
        let mut db = Archive::writer(&path).unwrap();
        db.save_policy(Policy::new(30, 7, 16).unwrap()).unwrap();
        let stamp = super::super::now();
        db.insert(&[row("Keep", stamp, 0)]).unwrap();
        // Deliberately oversized rows are blocked by the small SQLite quota, not a full host disk.
        let mut too_large = row("Reject", stamp, 1);
        too_large.profile = "x".repeat(18 * 1024 * 1024);
        drop(db);
        let writer = Writer::start(&path).unwrap();
        let counters = writer.stats.clone();
        writer.submit([too_large]);
        drop(writer);
        assert_eq!(counters.dropped.load(Ordering::Relaxed), 1);
        assert_eq!(counters.pending_rows.load(Ordering::Relaxed), 0);
        assert!(
            counters
                .error
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|e| e.to_ascii_lowercase().contains("full"))
        );
        assert_eq!(Archive::reader(&path).unwrap().counts().unwrap(), (1, 0));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn policy_persists_and_prunes_snapshots_and_flow_independently() {
        let path = temp_path();
        assert!(Policy::parse("0 5 256").is_err());
        assert!(Policy::parse("1 366 16").is_err());
        assert!(Policy::parse("1 365 15").is_err());
        assert!(Policy::parse("365 1 1025").is_err());
        let policy = Policy::parse("1 2 16").unwrap();
        let mut db = Archive::writer(&path).unwrap();
        db.save_policy(policy).unwrap();
        let day = 86_400;
        let now = 10 * day;
        let rows = [row("A", now - 2 * day, 0), row("A", now - day, 1)];
        db.insert(&rows).unwrap();
        let snaps: Vec<Snapshot> = [now - 3 * day, now - 2 * day]
            .into_iter()
            .map(|observed_at| Snapshot {
                schema: 1,
                source: "Test".into(),
                observed_at,
                sections: vec![],
            })
            .collect();
        db.import(&snaps).unwrap();
        assert_eq!(db.maintenance(now).unwrap(), 2);
        drop(db);
        let reader = Archive::reader(&path).unwrap();
        assert_eq!(reader.policy().unwrap(), policy);
        assert_eq!(reader.counts().unwrap(), (1, 1));
        assert_eq!(reader.history(now).unwrap().snapshots.len(), 1);
        drop(reader);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn reviewed_delete_rolls_back_equal_count_if_the_records_changed() {
        let path = temp_path();
        let mut db = Archive::writer(&path).unwrap();
        db.insert(&[row("A", 100, 0), row("A", 200, 1)]).unwrap();
        let stale = db.preview_delete(Kind::Flow, 100, 100).unwrap();
        db.conn
            .execute("DELETE FROM flow WHERE received=100", [])
            .unwrap();
        db.insert(&[row("B", 100, 2)]).unwrap();
        let current = db.preview_delete(Kind::Flow, 100, 100).unwrap();
        assert_eq!(stale.count, current.count);
        assert_ne!(stale.binding(), current.binding());
        assert!(db.delete_reviewed(&stale).is_err());
        assert_eq!(db.counts().unwrap().0, 2);
        assert_eq!(db.delete_reviewed(&current).unwrap(), 1);
        let remaining = db.page(&Query::default(), None, 3).unwrap();
        assert_eq!(remaining.rows[0].flow.received_at, 200);
        drop(db);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn recovery_revalidates_source_and_never_replaces_destination() {
        use super::super::archive_ops::{RecoveryPlan, check_recovery_destination};
        let path = temp_path();
        let source = path.with_file_name("backup.sqlite3");
        let copy = path.with_file_name("restored.sqlite3");
        let mut db = Archive::writer(&path).unwrap();
        db.insert(&[row("Test", 100, 0)]).unwrap();
        db.backup_to(&source).unwrap();
        let plan = RecoveryPlan::inspect(&source).unwrap();
        assert!(plan.recover(&source, &path).is_err());
        assert!(check_recovery_destination(&path.with_file_name("FLOW.SQLITE3."), &path).is_err());
        assert!(
            check_recovery_destination(&path.with_file_name("flow.sqlite3-wal"), &path).is_err()
        );
        std::fs::write(&copy, b"destination from another process").unwrap();
        assert!(plan.recover(&source, &copy).is_err());
        assert_eq!(
            std::fs::read(&copy).unwrap(),
            b"destination from another process"
        );
        std::fs::remove_file(&copy).unwrap();
        plan.recover(&source, &copy).unwrap();
        assert_eq!(Archive::reader(&copy).unwrap().counts().unwrap(), (1, 0));
        std::fs::remove_file(&copy).unwrap();
        let f = std::fs::OpenOptions::new()
            .append(true)
            .open(&source)
            .unwrap();
        (&f).write_all(b"changed").unwrap();
        assert!(plan.recover(&source, &copy).is_err());
        assert!(!copy.exists());
        assert_eq!(db.counts().unwrap().0, 1);
        drop((f, db));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn full_archive_rejects_new_batch_without_evicting_committed_data() {
        let path = temp_path();
        let mut db = Archive::writer(&path).unwrap();
        let min = Policy::new(30, 7, 16).unwrap();
        db.save_policy(min).unwrap();
        let mut count = 0;
        for index in 0..400 {
            let chunk: Vec<_> = (0..256)
                .map(|n| {
                    let mut r = row("quota", 1_000, index * 256 + n);
                    r.profile = "p".repeat(128);
                    r
                })
                .collect();
            match db.insert(&chunk) {
                Ok(n) => count += n,
                Err(e) => {
                    assert!(e.to_ascii_lowercase().contains("full"), "{e}");
                    assert_eq!(db.counts().unwrap().0, count as i64);
                    assert!(count > 0);
                    db.save_policy(Policy::new(30, 7, 32).unwrap()).unwrap();
                    assert_eq!(db.insert(&chunk).unwrap(), chunk.len());
                    drop(db);
                    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
                    return;
                }
            }
        }
        panic!("quota was not exercised");
    }

    #[test]
    fn ip_journey_keeps_evidence_pivot_and_export_in_the_same_scope() {
        use super::super::device::WanObservation;
        let path = temp_path();
        let now = 10_000;
        let mut db = Archive::writer(&path).unwrap();
        let a = row("Kantor", now - 10, 0);
        let b = inverted(a.clone(), 1);
        let mut c = row("Gudang", now - 8, 2);
        c.vrf = None;
        let mut d = inverted(c.clone(), 3);
        d.vrf = Some("gedung-b".into());
        let mut e = inverted(c.clone(), 4);
        e.flow.egress = Some(8);
        let mut f = inverted(c.clone(), 5);
        f.flow.exporter = "192.0.2.1:40001".parse().unwrap();
        let old = row("Lama", now - 1_800, 6);
        let mut g = row("Salah jam", now - 7, 7);
        g.flow.export_at = now - 2_000;
        assert_eq!(db.insert(&[a, b, c, d, e, f, old, g]).unwrap(), 8);
        drop(db);
        let mut db = Archive::reader(&path).unwrap();
        let q = Query::parse("ip=10.0.0.3 port=443 protocol=6").unwrap();
        let v = db.inspect(&q, now).unwrap();
        assert_eq!(v.examined, 8);
        assert!(!v.partial);
        let get = |site: &str, vrf: Option<&str>, port: u16| {
            v.scopes
                .iter()
                .find(|s| {
                    s.scope.site == site
                        && s.scope.vrf.as_deref() == vrf
                        && s.scope.exporter.port() == port
                })
                .unwrap()
        };
        let office = get("Kantor", Some("vrf1"), 40000);
        assert_eq!(office.wan, WanObservation::Paired);
        assert_eq!(office.peers, vec![("203.0.113.8".parse().unwrap(), 2)]);
        let warehouse = get("Gudang", None, 40000);
        assert_eq!(warehouse.wan, WanObservation::Outbound);
        assert_eq!(
            get("Lama", Some("vrf1"), 40000).access_label(now),
            "Observasi WAN historis"
        );
        assert_eq!(
            get("Salah jam", Some("vrf1"), 40000).wan,
            WanObservation::Unproven
        );
        let pivot = warehouse.scope.query(&q);
        assert_eq!(db.page(&pivot, None, 10).unwrap().rows.len(), 2);
        let mut report = vec![];
        assert_eq!(
            db.export(&pivot, ExportFormat::Json, true, &mut report)
                .unwrap()
                .total,
            2
        );
        let report_text = String::from_utf8(report).unwrap();
        assert!(!report_text.contains("10.0.0.3") && !report_text.contains("Gudang"));
        assert!(Query::parse("vrf=one vrf-unknown=true").is_err());
        assert!(
            db.inspect(&Query::parse("ip=10.0.0.3 port=80").unwrap(), now)
                .unwrap()
                .scopes
                .is_empty()
        );
        drop(db);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn inspection_caps_its_scan_and_keeps_ipv6_scoped() {
        let path = temp_path();
        let mut db = Archive::writer(&path).unwrap();
        let host: IpAddr = "2001:db8:1::5".parse().unwrap();
        let rows: Vec<_> = (0..=super::super::device::INSPECTION_LIMIT)
            .map(|n| {
                let mut r = row("IPv6", 2000, n as u32);
                r.flow.source = host;
                r.flow.destination = "2001:db8:2::10".parse().unwrap();
                r
            })
            .collect();
        assert_eq!(db.insert(&rows).unwrap(), rows.len());
        let v = db
            .inspect(&Query::parse("2001:db8:1::5").unwrap(), 2000)
            .unwrap();
        assert!(v.partial);
        assert_eq!(v.examined, super::super::device::INSPECTION_LIMIT);
        assert_eq!(v.scopes[0].count, v.examined);
        drop(db);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn backup_reads_committed_wal_and_preserves_unrelated_destination() {
        use super::super::history::{History, Snapshot, merge};
        let path = temp_path();
        let dest = path.with_file_name("backup.sqlite3");
        let mut db = Archive::writer(&path).unwrap();
        db.conn
            .execute_batch("PRAGMA wal_autocheckpoint=0;")
            .unwrap();
        let snap = Snapshot {
            schema: 1,
            source: "PC ini".into(),
            observed_at: 300,
            sections: vec![],
        };
        db.import(std::slice::from_ref(&snap)).unwrap();
        db.insert(&[row("Site A", 300, 0)]).unwrap();
        assert!(path.with_file_name("flow.sqlite3-wal").exists());
        let reader = Archive::reader(&path).unwrap();
        let health = reader.health(&path).unwrap();
        assert_eq!(
            (
                health.flow_records,
                health.snapshots,
                health.first_flow_utc,
                health.last_flow_utc
            ),
            (1, 1, Some(300), Some(300))
        );
        assert!(health.main_bytes > 0 && health.wal_bytes > 0);
        reader.backup_to(&dest).unwrap();
        let saved = Archive::reader(&dest).unwrap();
        saved.check().unwrap();
        assert_eq!(saved.counts().unwrap(), (1, 1));
        let h = merge(
            History {
                snapshots: vec![snap],
                unreadable: 0,
            },
            saved.history(300).unwrap(),
        );
        assert_eq!(h.snapshots.len(), 1);
        assert!(
            saved
                .history(300 + super::super::history::RETENTION_SECONDS + 1)
                .unwrap()
                .snapshots
                .is_empty()
        );
        assert!(reader.backup_to(&dest).is_err());
        assert_eq!(saved.counts().unwrap(), (1, 1));
        drop((db, reader, saved));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn concurrent_write_lock_does_not_break_stable_read() {
        let path = temp_path();
        let mut db = Archive::writer(&path).unwrap();
        db.insert(&[row("A", 300, 0)]).unwrap();
        let mut writer_two = Archive::writer(&path).unwrap();
        writer_two
            .conn
            .busy_timeout(Duration::from_millis(30))
            .unwrap();
        let lock = db
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert_eq!(Archive::reader(&path).unwrap().counts().unwrap().0, 1);
        assert!(writer_two.insert(&[row("A", 301, 1)]).is_err());
        lock.rollback().unwrap();
        assert_eq!(writer_two.insert(&[row("A", 301, 1)]).unwrap(), 1);
        drop((db, writer_two));
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    #[test]
    fn quoted_filters_and_unrelated_database_are_safe() {
        assert_eq!(
            Query::parse(r#"site="Gudang Barat" vrf=green"#)
                .unwrap()
                .site
                .as_deref(),
            Some("Gudang Barat")
        );
        assert!(Query::parse(r#"site="belum selesai"#).is_err());
        assert!(Query::parse("site=a site=b").is_err());
        let path = temp_path();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch("CREATE TABLE unrelated (id INTEGER)")
            .unwrap();
        assert!(Archive::writer(&path).is_err());
        assert!(Archive::reader(&path).is_err());
        let mode: String = conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "delete");
        drop(conn);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }

    #[test]
    fn reopen_scope_replay_and_same_timestamp_pagination() {
        let path = temp_path();
        let mut db = Archive::writer(&path).unwrap();
        let a = row("SiteA", 1000, 0);
        let b = row("SiteA", 1000, 1);
        let c = row("SiteB", 1000, 0);
        assert_eq!(db.insert(&[a.clone(), b, c]).unwrap(), 3);
        assert_eq!(db.insert(&[a]).unwrap(), 0);
        drop(db);
        let db = Archive::reader(&path).unwrap();
        let q = Query::parse("10.0.0.3 site=SiteA vrf=vrf1 protocol=6 if=3 since=999 until=1000")
            .unwrap();
        let first = db.page(&q, None, 1).unwrap();
        let second = db.page(&q, first.next, 1).unwrap();
        assert_eq!(first.rows[0].flow.ordinal, 1);
        assert_eq!(second.rows[0].flow.ordinal, 0);
        assert!(second.next.is_none());
        assert_eq!(second.rows[0].flow.octets, Some(u64::MAX));
        assert_eq!(db.counts().unwrap(), (3, 0));
        drop(db);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    #[test]
    fn export_and_import_do_not_expose_addresses_when_redacted() {
        let path = temp_path();
        let mut db = Archive::writer(&path).unwrap();
        let a = row("=SiteA", 1000, 0);
        db.insert(&[a]).unwrap();
        let s = Snapshot {
            schema: 1,
            source: "PC ini".into(),
            observed_at: 9,
            sections: vec![],
        };
        assert_eq!(db.import(std::slice::from_ref(&s)).unwrap(), 1);
        assert_eq!(db.import(&[s]).unwrap(), 0);
        let mut buf = vec![];
        assert_eq!(
            db.export(&Query::default(), ExportFormat::Json, true, &mut buf)
                .unwrap()
                .total,
            1
        );
        let content = String::from_utf8(buf).unwrap();
        for term in ["10.0.0.3", "192.0.2.1", "vrf1", "=SiteA"] {
            assert!(!content.contains(term));
        }
        let val: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(val["rows"][0]["direction"], "LAN→WAN");
        let mut csv = vec![];
        db.export(&Query::default(), ExportFormat::Csv, false, &mut csv)
            .unwrap();
        assert!(String::from_utf8(csv).unwrap().contains("\"'=SiteA\""));
        assert_eq!(db.prune(3_000_000, 1).unwrap(), 1);
        assert_eq!(db.counts().unwrap(), (0, 1));
        drop(db);
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
    #[test]
    fn writer_drains_and_rejects_future_schema() {
        let path = temp_path();
        let w = Writer::start(&path).unwrap();
        w.submit([row("a", super::super::now(), 0)]);
        let stats = w.stats.clone();
        drop(w);
        assert_eq!(stats.written.load(Ordering::Relaxed), 1);
        let db = Archive::writer(&path).unwrap();
        db.conn.pragma_update(None, "user_version", 99).unwrap();
        drop(db);
        assert!(Archive::writer(&path).is_err());
        assert!(Archive::reader(&path).is_err());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
    }
}
