//! Explicit operator metadata, never an observed assignment or router mutation.
//! Independent database: no change to the flow archive schema or legacy paths.
use crate::Result;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::{net::IpAddr, path::Path, time::Duration};

const APP_ID: i64 = 1464742221;
const SCHEMA: &str = include_str!("sql/ipam_schema.sql");
const APPEND: &str = include_str!("sql/ipam_append.sql");
const CURRENT: &str = include_str!("sql/ipam_current.sql");
const EXACT: &str = include_str!("sql/ipam_exact.sql");

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Note {
    pub scope: String,
    pub cidr: String,
    pub revision: i64,
    pub recorded: i64,
    pub active: bool,
    pub reserved: bool,
    pub alias: String,
    pub tags: String,
    pub note: String,
}
fn error(e: impl std::fmt::Display) -> String {
    format!("IPAM metadata: {e}")
}
fn valid_text(s: &str, max: usize) -> bool {
    s.len() <= max
        && !s.contains('|')
        && !s.chars().any(|c| {
            c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
}
fn cidr(raw: &str) -> Option<String> {
    let (ip, bits) = raw.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    let bits: u8 = bits.parse().ok()?;
    let prefix = super::overview::Prefix::new(ip, bits)?;
    let canonical = prefix.to_string();
    // Reject host bits instead of silently editing a different subnet.
    (canonical == format!("{ip}/{bits}")).then_some(canonical)
}
impl Note {
    pub fn parse(input: &str) -> Result<Self> {
        let fields: Vec<_> = input.split('|').map(str::trim).collect();
        let [scope, prefix, status, alias, tags, note] = fields.as_slice() else {
            return Err("Format: scope|CIDR|label/reserved|alias|tag|catatan".into());
        };
        let reserved = match *status {
            "label" => false,
            "reserved" => true,
            _ => return Err("Status metadata harus label atau reserved.".into()),
        };
        let result = Self {
            scope: (*scope).into(),
            cidr: cidr(prefix).ok_or("CIDR harus alamat jaringan kanonik.")?,
            revision: 0,
            recorded: 0,
            active: true,
            reserved,
            alias: (*alias).into(),
            tags: (*tags).into(),
            note: (*note).into(),
        };
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<()> {
        if self.scope.is_empty()
            || !valid_text(&self.scope, 160)
            || !valid_text(&self.alias, 80)
            || !valid_text(&self.tags, 120)
            || !valid_text(&self.note, 240)
            || cidr(&self.cidr).as_deref() != Some(self.cidr.as_str())
        {
            return Err("Metadata IPAM tidak valid atau melebihi batas.".into());
        }
        Ok(())
    }

    pub fn editor(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}|{}",
            self.scope,
            self.cidr,
            if self.reserved { "reserved" } else { "label" },
            self.alias,
            self.tags,
            self.note,
        )
    }
}

fn read_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Note> {
    Ok(Note {
        scope: r.get(0)?,
        cidr: r.get(1)?,
        revision: r.get(2)?,
        recorded: r.get(3)?,
        active: r.get(4)?,
        reserved: r.get(5)?,
        alias: r.get(6)?,
        tags: r.get(7)?,
        note: r.get(8)?,
    })
}
fn verify(conn: &Connection) -> Result<()> {
    let id: i64 = conn
        .pragma_query_value(None, "application_id", |r| r.get(0))
        .map_err(error)?;
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .map_err(error)?;
    if id != APP_ID || version != 1 {
        return Err("Bukan database metadata IPAM WeNet yang kompatibel.".into());
    }
    Ok(())
}
fn open(path: &Path, write: bool) -> Result<Connection> {
    let flags = if write {
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    if write {
        std::fs::create_dir_all(path.parent().ok_or("Path IPAM tidak valid.")?).map_err(error)?;
    }
    let mut conn = Connection::open_with_flags(path, flags).map_err(error)?;
    conn.busy_timeout(Duration::from_millis(1500))
        .map_err(error)?;
    conn.execute_batch("PRAGMA trusted_schema=OFF;")
        .map_err(error)?;
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

pub fn page(path: &Path) -> Result<Vec<Note>> {
    if !path.try_exists().map_err(error)? {
        return Ok(Vec::new());
    }
    let conn = open(path, false)?;
    let mut stmt = conn.prepare(CURRENT).map_err(error)?;
    let rows = stmt.query_map([], read_row).map_err(error)?;
    let rows = rows
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(error)?;
    for row in &rows {
        row.validate()?;
    }
    Ok(rows)
}

fn append(conn: &Connection, note: &Note, expected: i64, now: u64) -> Result<()> {
    note.validate()?;
    if !(0..16384).contains(&expected) {
        return Err("Revisi tidak valid.".into());
    }
    let now = now.min(i64::MAX as u64) as i64;
    let changed = conn
        .execute(
            APPEND,
            params![
                note.scope,
                note.cidr,
                expected,
                now,
                note.active,
                note.reserved,
                note.alias,
                note.tags,
                note.note
            ],
        )
        .map_err(error)?;
    if changed != 1 {
        return Err(
            "Konflik revisi atau kapasitas metadata penuh. Muat ulang; tidak ada histori ditimpa."
                .into(),
        );
    }
    Ok(())
}
/// No identifiers, CIDRs, free text or timestamps are exported.
pub fn export_summary(path: &Path, dest: &Path) -> Result<()> {
    use std::io::Write;
    if !path.try_exists().map_err(error)? {
        return Err("Database IPAM belum tersedia.".into());
    }
    let rows = page(path)?;
    let active = rows.iter().filter(|r| r.active).count();
    let reserved = rows.iter().filter(|r| r.active && r.reserved).count();
    let report = serde_json::json!({
        "schema": 1,
        "basis": "operator metadata only; not observed assignments",
        "total_keys": rows.len(),
        "active_labels": active - reserved,
        "active_reservations": reserved,
        "inactive_keys": rows.len() - active,
    });
    let stage = super::archive_ops::Stage::new(dest)?;
    let mut file = std::fs::OpenOptions::new().create_new(true).write(true)
        .open(&stage.file).map_err(error)?;
    serde_json::to_writer_pretty(&mut file, &report).map_err(error)?;
    file.write_all(b"\n").map_err(error)?;
    file.sync_all().map_err(error)?;
    drop(file);
    stage.publish(dest)
}

pub fn backup(path: &Path, dest: &Path) -> Result<()> {
    use rusqlite::backup::{Backup, StepResult};
    use std::{fs::OpenOptions, time::Instant};
    let source = open(path, false)?;
    let stage = super::archive_ops::Stage::new(dest)?;
    drop(OpenOptions::new().create_new(true).write(true).open(&stage.file).map_err(error)?);
    let mut output = Connection::open_with_flags(&stage.file, OpenFlags::SQLITE_OPEN_READ_WRITE)
        .map_err(error)?;
    {
        let copy = Backup::new(&source, &mut output).map_err(error)?;
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if Instant::now() >= deadline {
                return Err("Batas waktu backup IPAM tercapai.".into());
            }
            match copy.step(128).map_err(error)? {
                StepResult::Done => break,
                StepResult::More => std::thread::yield_now(),
                _ => std::thread::sleep(Duration::from_millis(25)),
            }
        }
    }
    let mode: String = output.query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0)).map_err(error)?;
    if !mode.eq_ignore_ascii_case("delete") {
        return Err("Backup IPAM tidak mandiri.".into());
    }
    verify(&output)?;
    let integrity: String = output.query_row("PRAGMA integrity_check", [], |r| r.get(0)).map_err(error)?;
    if integrity != "ok" {
        return Err("Pemeriksaan integritas backup IPAM gagal.".into());
    }
    drop(output);
    OpenOptions::new().write(true).open(&stage.file).and_then(|f| f.sync_all()).map_err(error)?;
    stage.publish(dest)
}

pub fn save(path: &Path, note: &Note, expected: i64, now: u64) -> Result<()> {
    let mut conn = open(path, true)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(error)?;
    append(&tx, note, expected, now)?;
    tx.commit().map_err(error)
}

pub fn undo(path: &Path, current: &Note, now: u64) -> Result<()> {
    let mut conn = open(path, true)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(error)?;
    if current.revision < 1 {
        return Err("Tidak ada revisi untuk undo.".into());
    }
    let stored = tx
        .query_row(
            EXACT,
            params![current.scope, current.cidr, current.revision],
            read_row,
        )
        .optional()
        .map_err(error)?;
    if stored.as_ref() != Some(current) {
        return Err("Identitas revisi berubah; muat ulang.".into());
    }
    let previous = if current.revision == 1 {
        let mut tombstone = current.clone();
        tombstone.active = false;
        tombstone.reserved = false;
        tombstone.alias.clear();
        tombstone.tags.clear();
        tombstone.note.clear();
        tombstone
    } else {
        tx.query_row(
            EXACT,
            params![current.scope, current.cidr, current.revision - 1],
            read_row,
        )
        .map_err(error)?
    };
    append(&tx, &previous, current.revision, now)?;
    tx.commit().map_err(error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_requires_canonical_network_and_explicit_scope() {
        assert!(Note::parse("blue|192.0.2.1/24|label|a|b|c").is_err());
        assert!(Note::parse("|192.0.2.0/24|label|a|b|c").is_err());
        let row = Note::parse("blue|2001:db8::/64|reserved|Lab|tag|note").unwrap();
        assert!(row.reserved);
        assert_eq!(Note::parse(&row.editor()).unwrap(), row);
    }

    #[test]
    fn persisted_revisions_conflicts_scope_and_undo() {
        let dir = std::env::temp_dir().join(format!(
            "wenet-ipam-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("notes.sqlite3");
        assert!(page(&path).unwrap().is_empty());
        let mut a = Note::parse("blue|192.0.2.0/24|reserved|first|lab|note").unwrap();
        save(&path, &a, 0, 10).unwrap();
        assert!(save(&path, &a, 0, 11).is_err());
        let b = Note::parse("red|192.0.2.0/24|label|other||").unwrap();
        save(&path, &b, 0, 11).unwrap();
        a.alias = "second".into();
        save(&path, &a, 1, 12).unwrap();
        let rows = page(&path).unwrap();
        assert_eq!(rows.len(), 2);
        let latest = &rows[0];
        assert_eq!(latest.revision, 2);
        undo(&path, latest, 13).unwrap();
        assert!(undo(&path, latest, 14).is_err());
        let restored = page(&path).unwrap();
        assert_eq!(restored[0].revision, 3);
        assert_eq!(restored[0].alias, "first");
        undo(&path, &restored[1], 15).unwrap();
        assert!(!page(&path).unwrap()[1].active);
        let backup_path = dir.join("backup.sqlite3");
        backup(&path, &backup_path).unwrap();
        assert_eq!(page(&backup_path).unwrap(), page(&path).unwrap());
        assert!(backup(&path, &backup_path).is_err());
        let summary = dir.join("summary.json");
        export_summary(&path, &summary).unwrap();
        let text = std::fs::read_to_string(&summary).unwrap();
        for private in ["192.0.2", "blue", "first", "note\""] {
            assert!(!text.contains(private));
        }
        assert!(export_summary(&path, &summary).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
