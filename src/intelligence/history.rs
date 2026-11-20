//! Explicit per-user snapshot storage; never persists credentials or payloads.
use super::{
    CoverageState, LocalSnapshot,
    router::{RouterSnapshot, Table},
};
use crate::Result;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

const MAX_FILE: u64 = 4 * 1024 * 1024;
const MAX_FILES: usize = 64;
const MAX_TOTAL: u64 = 32 * 1024 * 1024;
pub const RETENTION_SECONDS: u64 = 7 * 86400;
static SERIAL: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub schema: u8,
    pub source: String,
    pub observed_at: u64,
    pub sections: Vec<Section>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Section {
    pub name: String,
    pub complete: bool,
    pub values: BTreeMap<String, String>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum Change {
    Added,
    MissingInSnapshot,
    Changed,
}
#[derive(Clone, Debug, Serialize)]
pub struct Difference {
    pub section: String,
    pub key: String,
    pub change: Change,
    pub before: Option<String>,
    pub after: Option<String>,
}
#[derive(Debug)]
pub struct History {
    pub snapshots: Vec<Snapshot>,
    pub unreadable: usize,
}
fn full(c: &[super::Coverage], name: &str) -> bool {
    c.iter()
        .any(|r| r.source == name && r.state == CoverageState::CompleteSnapshot)
}
fn section(name: &str, complete: bool, values: impl Iterator<Item = (String, String)>) -> Section {
    let mut rows = BTreeMap::new();
    let mut limited = false;
    for (key, value) in values {
        if rows.len() >= 1_200 && !rows.contains_key(&key) {
            limited = true;
            continue;
        }
        if rows.get(&key).is_some_and(|old| old != &value) {
            limited = true;
        }
        rows.insert(key, value);
    }
    Section {
        name: name.into(),
        complete: complete && !limited,
        values: rows,
    }
}
impl Snapshot {
    pub fn local(s: &LocalSnapshot) -> Self {
        let ports = s.endpoints.iter().filter(|e| {
            matches!(
                e.state,
                super::EndpointState::Listening | super::EndpointState::Bound
            )
        });
        Self {
            schema: 1,
            source: "PC ini".into(),
            observed_at: s.observed_at,
            sections: vec![
                section(
                    "Alamat lokal",
                    full(&s.coverage, "Windows Unicast IP"),
                    s.addresses.iter().map(|a| {
                        (
                            format!("{}%{} / if#{}", a.ip, a.scope_id, a.interface_index),
                            format!("Prefix /{}", a.prefix),
                        )
                    }),
                ),
                section(
                    "Layanan lokal",
                    [
                        "Windows TCPv4",
                        "Windows TCPv6",
                        "Windows UDPv4",
                        "Windows UDPv6",
                    ]
                    .iter()
                    .all(|n| full(&s.coverage, n)),
                    ports.map(|e| (format!("{:?} {}", e.protocol, e.local), e.state.to_string())),
                ),
                // Cache eviction does not establish that a neighbor is offline.
                section(
                    "Cache tetangga",
                    false,
                    s.neighbors.iter().map(|n| {
                        (
                            format!("{}%{} / if#{}", n.ip, n.scope_id, n.interface_index),
                            n.mac
                                .map_or_else(|| "MAC tidak diketahui".into(), |m| m.to_string()),
                        )
                    }),
                ),
            ],
        }
    }
    pub fn router(s: &RouterSnapshot) -> Self {
        Self {
            schema: 1,
            source: format!("MikroTik {}", s.authority),
            observed_at: s.observed_at,
            sections: vec![
                section(
                    "Interface",
                    full(&s.coverage, Table::Interface.name()),
                    s.interfaces.iter().map(|i| {
                        (
                            i.name.clone(),
                            format!(
                                "{:?} · running {:?} · disabled {:?}",
                                i.kind, i.running, i.disabled
                            ),
                        )
                    }),
                ),
                section(
                    "Rute default",
                    full(&s.coverage, Table::DefaultRoute4.name())
                        && full(&s.coverage, Table::DefaultRoute6.name()),
                    s.default_routes.iter().map(|r| {
                        (
                            format!("{} / {:?} / {:?}", r.destination, r.table, r.gateway),
                            format!(
                                "Next hop {:?} · aktif {:?} · distance {:?}",
                                r.immediate_gateway, r.active, r.distance
                            ),
                        )
                    }),
                ),
                section(
                    "Bridge / VLAN",
                    full(&s.coverage, Table::BridgePorts.name())
                        && full(&s.coverage, Table::Vlan.name()),
                    s.topology.iter().map(|r| {
                        (
                            format!("{} / {}", r.kind, r.id),
                            format!("{} → {} · {:?}", r.subject, r.relation, r.fields),
                        )
                    }),
                ),
                section(
                    "Firewall / NAT",
                    full(&s.coverage, Table::Firewall.name())
                        && full(&s.coverage, Table::Nat.name()),
                    s.rules.iter().map(|r| {
                        (
                            format!("{} / {}", r.kind, r.id),
                            format!(
                                "#{} · {} → {} · {}",
                                r.order,
                                r.subject,
                                r.relation,
                                r.fields
                                    .iter()
                                    .filter(|(k, _)| !matches!(k.as_str(), "bytes" | "packets"))
                                    .map(|(k, v)| format!("{k}={v}"))
                                    .collect::<Vec<_>>()
                                    .join(" · ")
                            ),
                        )
                    }),
                ),
                section(
                    "Inventaris IP",
                    false,
                    s.inventory.iter().map(|h| {
                        (
                            format!("{} / {} / {:?}", h.ip, h.source, h.location),
                            format!("MAC {:?} · host {:?}", h.mac, h.host_name),
                        )
                    }),
                ),
            ],
        }
    }
}
pub fn diff(before: &Snapshot, after: &Snapshot) -> Vec<Difference> {
    if before.source != after.source || before.observed_at > after.observed_at {
        return vec![];
    }
    let mut out = vec![];
    for new in &after.sections {
        let Some(old) = before.sections.iter().find(|x| x.name == new.name) else {
            continue;
        };
        let keys: BTreeSet<_> = old.values.keys().chain(new.values.keys()).collect();
        for key in keys {
            let (a, b) = (old.values.get(key), new.values.get(key));
            let c = match (a, b) {
                (None, Some(_)) if old.complete => Change::Added,
                (Some(_), None) if old.complete && new.complete => Change::MissingInSnapshot,
                (Some(x), Some(y)) if x != y => Change::Changed,
                _ => continue,
            };
            out.push(Difference {
                section: new.name.clone(),
                key: key.clone(),
                change: c,
                before: a.cloned(),
                after: b.cloned(),
            });
        }
    }
    out
}

fn names(dir: &Path) -> Result<Vec<(PathBuf, u64, u64)>> {
    let list = match fs::read_dir(dir) {
        Ok(l) => l,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.to_string()),
    };
    let mut entries = vec![];
    for entry in list {
        let e = entry.map_err(|e| e.to_string())?;
        let ty = e.file_type().map_err(|e| e.to_string())?;
        if !ty.is_file() {
            continue;
        }
        let n = e.file_name();
        let Some((stamp, id)) = n
            .to_str()
            .and_then(|n| n.strip_prefix("snapshot-"))
            .and_then(|n| n.strip_suffix(".json"))
            .and_then(|n| n.split_once('-'))
        else {
            continue;
        };
        if !id.bytes().all(|c| c.is_ascii_digit() || c == b'-') {
            continue;
        }
        let Ok(stamp) = stamp.parse::<u64>() else {
            continue;
        };
        let len = e.metadata().map_err(|e| e.to_string())?.len();
        entries.push((e.path(), stamp, len));
        if entries.len() > 4_096 {
            return Err("Terlalu banyak berkas histori dalam folder.".into());
        }
    }
    entries.sort_by(|a, b| (b.1, &b.0).cmp(&(a.1, &a.0)));
    Ok(entries)
}
pub fn load(dir: &Path, now: u64) -> Result<History> {
    let mut snapshots = vec![];
    let mut unreadable = 0;
    let mut used = 0u64;
    for (path, stamp, len) in names(dir)?
        .into_iter()
        .filter(|(_, s, _)| now.saturating_sub(*s) <= RETENTION_SECONDS)
        .take(MAX_FILES)
    {
        if len > MAX_FILE || used.saturating_add(len) > MAX_TOTAL {
            unreadable += 1;
            continue;
        }
        used += len;
        let mut data = vec![];
        let read = fs::File::open(path).and_then(|f| f.take(MAX_FILE + 1).read_to_end(&mut data));
        let valid = read
            .ok()
            .filter(|n| *n as u64 <= MAX_FILE)
            .and_then(|_| serde_json::from_slice::<Snapshot>(&data).ok())
            .filter(|s| {
                s.schema == 1
                    && s.observed_at == stamp
                    && s.sections.len() <= 8
                    && s.sections.iter().all(|x| x.values.len() <= 1_200)
            });
        if let Some(s) = valid {
            snapshots.push(s);
        } else {
            unreadable += 1;
        }
    }
    Ok(History {
        snapshots,
        unreadable,
    })
}
/// Merge the manual JSON store and explicitly imported SQLite snapshots.
pub fn merge(mut legacy: History, archive: History) -> History {
    let mut seen = BTreeSet::<[u8; 32]>::new();
    let mut candidates = std::mem::take(&mut legacy.snapshots);
    candidates.extend(archive.snapshots);
    candidates.sort_by_key(|s| std::cmp::Reverse(s.observed_at));
    legacy.unreadable += archive.unreadable;
    let mut size = 0_u64;
    for s in candidates {
        use sha2::{Digest, Sha256};
        if legacy.snapshots.len() == MAX_FILES {
            break;
        }
        let Ok(json) = serde_json::to_vec(&s) else {
            legacy.unreadable += 1;
            continue;
        };
        if seen.insert(Sha256::digest(&json).into()) {
            if size + json.len() as u64 > MAX_TOTAL {
                legacy.unreadable += 1;
                continue;
            }
            size += json.len() as u64;
            legacy.snapshots.push(s);
        }
    }
    legacy
}
pub fn save(dir: &Path, s: &Snapshot, now: u64) -> Result<()> {
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let data = serde_json::to_vec(s).map_err(|e| e.to_string())?;
    if data.len() as u64 > MAX_FILE {
        return Err("Snapshot melebihi 4 MiB.".into());
    }
    let seq = SERIAL.fetch_add(1, Ordering::Relaxed);
    let stem = format!("snapshot-{}-{}-{seq}", s.observed_at, std::process::id());
    let out = dir.join(format!("{stem}.json"));
    let partial = dir.join(format!("{stem}.part"));
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&partial)
        .map_err(|e| e.to_string())?;
    let result = file.write_all(&data).and_then(|_| file.sync_all());
    drop(file);
    if let Err(e) = result.and_then(|_| fs::rename(&partial, &out)) {
        let _ = fs::remove_file(&partial);
        return Err(e.to_string());
    }
    let mut n = 0;
    let mut bytes = 0u64;
    for (path, stamp, len) in names(dir)? {
        if now.saturating_sub(stamp) > RETENTION_SECONDS
            || n >= MAX_FILES
            || bytes.saturating_add(len) > MAX_TOTAL
        {
            fs::remove_file(path).map_err(|e| format!("Retensi histori: {e}"))?;
        } else {
            n += 1;
            bytes += len;
        }
    }
    Ok(())
}
/// Removes only this application's recognized history files, never arbitrary files.
pub fn clear(dir: &Path) -> Result<usize> {
    let entries = names(dir)?;
    for (file, _, _) in &entries {
        fs::remove_file(file).map_err(|e| format!("Gagal menghapus arsip: {e}"))?;
    }
    Ok(entries.len())
}
#[cfg(windows)]
pub fn default_dir() -> Result<PathBuf> {
    let dir = std::env::var_os("LOCALAPPDATA").ok_or("Folder data pengguna tidak tersedia.")?;
    Ok(PathBuf::from(dir)
        .join("WFS Network Toolkit")
        .join("observations-v1"))
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample(time: u64, complete: bool, rows: &[(&str, &str)]) -> Snapshot {
        Snapshot {
            schema: 1,
            source: "PC ini".into(),
            observed_at: time,
            sections: vec![section(
                "Alamat",
                complete,
                rows.iter().map(|(a, b)| (a.to_string(), b.to_string())),
            )],
        }
    }
    #[test]
    fn partial_snapshot_never_reports_disappearance() {
        let a = sample(1, true, &[("A", "satu"), ("B", "dua")]);
        let b = sample(2, false, &[("A", "tiga")]);
        let d = diff(&a, &b);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].change, Change::Changed);
        let b = sample(2, true, &[("C", "tiga")]);
        assert_eq!(
            diff(&a, &b)
                .iter()
                .filter(|x| x.change == Change::MissingInSnapshot)
                .count(),
            2
        );
    }
    #[test]
    fn history_reloads_and_prunes_without_reading_temp_files() {
        let d = std::env::temp_dir().join(format!(
            "wfs-history-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        let now = RETENTION_SECONDS + 50;
        save(&d, &sample(1, true, &[]), 1).unwrap();
        save(&d, &sample(now, true, &[("A", "x")]), now).unwrap();
        fs::write(d.join("snapshot-604850-812.part"), "partial").unwrap();
        let h = load(&d, now).unwrap();
        assert_eq!(h.snapshots.len(), 1);
        assert_eq!(h.unreadable, 0);
        assert_eq!(h.snapshots[0].sections[0].values["A"], "x");
        assert_eq!(fs::read_dir(&d).unwrap().count(), 2);
        assert_eq!(clear(&d).unwrap(), 1);
        assert_eq!(fs::read_dir(&d).unwrap().count(), 1);
        fs::remove_dir_all(d).unwrap();
    }
}
