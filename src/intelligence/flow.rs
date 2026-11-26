//! Passive UDP import. Flow records are observations, not packet captures.
use super::store::{ArchiveRow, Writer};
use super::{EvidenceKind, TrafficEvidence, TrafficImport};
use crate::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

pub const MAX_ROWS: usize = 10_000;
const TEMPLATE_TTL: u64 = 1_800;
const MAX_TEMPLATES: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Flow {
    pub exporter: SocketAddr,
    pub domain: u32,
    pub version: u16,
    pub export_at: u64,
    pub received_at: u64,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub protocol: Option<u8>,
    pub ingress: Option<u32>,
    pub egress: Option<u32>,
    pub octets: Option<u64>,
    pub packets: Option<u64>,
    pub datagram_hash: [u8; 32],
    pub ordinal: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Cidr {
    ip: IpAddr,
    prefix: u32,
}
impl Cidr {
    pub fn parse(s: &str) -> Result<Self> {
        let (ip, p) = s
            .trim()
            .split_once('/')
            .ok_or("Subnet LAN harus dalam format CIDR.")?;
        let ip: IpAddr = ip.parse().map_err(|_| "IP subnet tidak valid.")?;
        let prefix: u32 = p.parse().map_err(|_| "Prefix subnet tidak valid.")?;
        if prefix == 0 || prefix > if ip.is_ipv4() { 32 } else { 128 } {
            return Err("Prefix LAN tidak valid.".into());
        }
        Ok(Self { ip, prefix })
    }
    pub fn contains(self, ip: IpAddr) -> bool {
        match (self.ip, ip) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                (u32::from(a) ^ u32::from(b)).leading_zeros() >= self.prefix
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                (u128::from(a) ^ u128::from(b)).leading_zeros() >= self.prefix
            }
            _ => false,
        }
    }
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowConfig {
    pub schema: u8,
    pub bind: SocketAddr,
    pub exporter: IpAddr,
    pub site: String,
    pub wan_ifindex: u32,
    pub lan_cidrs: Vec<String>,
    pub observation_domain: u32,
}
impl FlowConfig {
    pub fn parse(s: &str) -> Result<Self> {
        let c: Self =
            serde_json::from_str(s).map_err(|e| format!("Profil collector tidak valid: {e}"))?;
        c.validate()?;
        Ok(c)
    }
    fn validate(&self) -> Result<()> {
        let c = self;
        if c.schema != 1
            || c.bind.ip().is_unspecified()
            || c.bind.ip().is_multicast()
            || c.bind.port() == 0
            || c.exporter.is_unspecified()
            || c.exporter.is_multicast()
            || c.bind.is_ipv4() != c.exporter.is_ipv4()
            || c.wan_ifindex == 0
            || c.site.trim().is_empty()
            || c.site.len() > 80
            || super::label(&c.site) != c.site
            || !(1..=16).contains(&c.lan_cidrs.len())
        {
            return Err("Profil memerlukan alamat bind spesifik, exporter, site, WAN ifIndex, dan subnet LAN yang valid.".into());
        }
        c.cidrs()?;
        Ok(())
    }
    fn cidrs(&self) -> Result<Vec<Cidr>> {
        self.lan_cidrs.iter().map(|s| Cidr::parse(s)).collect()
    }
}

#[derive(Clone)]
struct Field {
    id: u16,
    length: u16,
    enterprise: bool,
}
#[derive(Clone)]
struct Template {
    fields: Vec<Field>,
    updated: u64,
    min: usize,
    supported: bool,
}
type Session = (SocketAddr, u16, u32);
type Key = (Session, u16);
#[derive(Default)]
pub struct Decoder {
    templates: HashMap<Key, Template>,
    recent: VecDeque<(Session, [u8; 32])>,
    v9_clock: HashMap<Session, (u32, u32)>,
    sequence_clock: HashMap<Session, (u32, u32)>,
}
#[derive(Default)]
pub struct Batch {
    pub flows: Vec<Flow>,
    pub missing: u32,
    pub skipped: u32,
    pub duplicate: bool,
    pub sequence_reordered: bool,
    pub sequence_repeated: bool,
    pub generation_restart: bool,
}
fn take<'a>(p: &mut &'a [u8], n: usize) -> Result<&'a [u8]> {
    if n > p.len() {
        return Err("Paket flow terpotong.".into());
    }
    let (a, b) = p.split_at(n);
    *p = b;
    Ok(a)
}
fn u16b(p: &mut &[u8]) -> Result<u16> {
    Ok(u16::from_be_bytes(take(p, 2)?.try_into().unwrap()))
}
fn u32b(p: &mut &[u8]) -> Result<u32> {
    Ok(u32::from_be_bytes(take(p, 4)?.try_into().unwrap()))
}
fn zero_padding(p: &[u8]) -> bool {
    p.len() <= 3 && p.iter().all(|&x| x == 0)
}
fn integer(p: &[u8]) -> Option<u64> {
    if p.is_empty() || p.len() > 8 {
        return None;
    }
    Some(p.iter().fold(0, |a, &b| (a << 8) | u64::from(b)))
}
impl Decoder {
    pub fn ingest(&mut self, exporter: SocketAddr, mut packet: &[u8], stamp: u64) -> Result<Batch> {
        let digest: [u8; 32] = Sha256::digest(packet).into();
        let size = packet.len();
        let version = u16b(&mut packet)?;
        let length = u16b(&mut packet)?;
        let uptime = match version {
            9 => Some(u32b(&mut packet)?),
            10 if usize::from(length) == size => None,
            10 => return Err("Ukuran pesan IPFIX tidak cocok.".into()),
            _ => return Err("Versi bukan IPFIX atau NetFlow v9.".into()),
        };
        let exported = u32b(&mut packet)?;
        let sequence = u32b(&mut packet)?;
        let domain = u32b(&mut packet)?;
        let session = (exporter, version, domain);
        let key = (session, digest);
        if self.recent.contains(&key) {
            return Ok(Batch {
                duplicate: true,
                ..Default::default()
            });
        }
        // Build changes in a packet-local overlay. A malformed datagram cannot change templates.
        // v9 sysUptime rollback on a newer export invalidates the old session templates.
        let restart = uptime
            .zip(self.v9_clock.get(&session))
            .is_some_and(|(up, &(last_export, old_up))| exported > last_export && up < old_up);
        let mut staged: HashMap<Key, Template> = HashMap::new();
        let mut batch = Batch::default();
        let mut set_count = 0_u32;
        while !packet.is_empty() {
            set_count += 1;
            if set_count > 128 {
                return Err("Terlalu banyak set dalam satu datagram.".into());
            }
            let id = u16b(&mut packet)?;
            let n = usize::from(u16b(&mut packet)?);
            let mut set = take(
                &mut packet,
                n.checked_sub(4).ok_or("Panjang set tidak valid.")?,
            )?;
            if (version == 10 && id == 2) || (version == 9 && id == 0) {
                while !set.is_empty() && !zero_padding(set) {
                    let tid = u16b(&mut set)?;
                    let count = u16b(&mut set)?;
                    if tid < 256 || !(1..=128).contains(&count) || staged.len() >= 128 {
                        return Err("Template atau withdrawal UDP tidak didukung.".into());
                    }
                    let mut fields = Vec::with_capacity(count as usize);
                    let mut min = 0;
                    let mut addresses = [false; 4];
                    for _ in 0..count {
                        let raw = u16b(&mut set)?;
                        let length = u16b(&mut set)?;
                        if length == 0 || (version == 9 && length == u16::MAX) {
                            return Err("Lebar field flow tidak valid.".into());
                        }
                        let enterprise = version == 10 && raw & 0x8000 != 0;
                        let fid = if enterprise {
                            let _ = u32b(&mut set)?;
                            raw & 0x7fff
                        } else {
                            raw
                        };
                        min += if length == u16::MAX {
                            1
                        } else {
                            usize::from(length)
                        };
                        if !enterprise {
                            match (fid, length) {
                                (8, 4) => addresses[0] = true,
                                (12, 4) => addresses[1] = true,
                                (27, 16) => addresses[2] = true,
                                (28, 16) => addresses[3] = true,
                                _ => {}
                            }
                        }
                        fields.push(Field {
                            id: fid,
                            length,
                            enterprise,
                        });
                    }
                    if min > 65_535 {
                        return Err("Template terlalu besar.".into());
                    }
                    let supported =
                        (addresses[0] && addresses[1]) || (addresses[2] && addresses[3]);
                    staged.insert(
                        (session, tid),
                        Template {
                            fields,
                            updated: stamp,
                            min,
                            supported,
                        },
                    );
                }
            } else if id >= 256 {
                let tpl = staged
                    .get(&(session, id))
                    .or_else(|| {
                        (!restart)
                            .then(|| self.templates.get(&(session, id)))
                            .flatten()
                    })
                    .filter(|t| stamp.saturating_sub(t.updated) <= TEMPLATE_TTL);
                let Some(tpl) = tpl else {
                    batch.missing += 1;
                    continue;
                };
                if !tpl.supported {
                    batch.skipped += 1;
                    continue;
                }
                let mut record = 0_u32;
                while !set.is_empty() {
                    if set.len() < tpl.min && zero_padding(set) {
                        break;
                    }
                    if batch.flows.len() >= 8_192 {
                        return Err("Batas baris per datagram tercapai.".into());
                    }
                    let mut v4 = (None, None);
                    let mut v6 = (None, None);
                    let (
                        mut sport,
                        mut dport,
                        mut proto,
                        mut ingress,
                        mut egress,
                        mut octets,
                        mut packets,
                    ) = (None, None, None, None, None, None, None);
                    for f in &tpl.fields {
                        let len = if f.length == u16::MAX {
                            let first = take(&mut set, 1)?[0];
                            if first == 255 {
                                usize::from(u16b(&mut set)?)
                            } else {
                                usize::from(first)
                            }
                        } else {
                            usize::from(f.length)
                        };
                        let v = take(&mut set, len)?;
                        if f.enterprise {
                            continue;
                        }
                        match f.id {
                            8 => {
                                v4.0 = <[u8; 4]>::try_from(v)
                                    .ok()
                                    .map(|x| IpAddr::V4(Ipv4Addr::from(x)))
                            }
                            12 => {
                                v4.1 = <[u8; 4]>::try_from(v)
                                    .ok()
                                    .map(|x| IpAddr::V4(Ipv4Addr::from(x)))
                            }
                            27 => {
                                v6.0 = <[u8; 16]>::try_from(v)
                                    .ok()
                                    .map(|x| IpAddr::V6(Ipv6Addr::from(x)))
                            }
                            28 => {
                                v6.1 = <[u8; 16]>::try_from(v)
                                    .ok()
                                    .map(|x| IpAddr::V6(Ipv6Addr::from(x)))
                            }
                            7 => sport = integer(v).and_then(|n| u16::try_from(n).ok()),
                            11 => dport = integer(v).and_then(|n| u16::try_from(n).ok()),
                            4 => proto = integer(v).and_then(|n| u8::try_from(n).ok()),
                            10 => ingress = integer(v).and_then(|n| u32::try_from(n).ok()),
                            14 => egress = integer(v).and_then(|n| u32::try_from(n).ok()),
                            1 => octets = integer(v),
                            2 => packets = integer(v),
                            _ => {}
                        }
                    }
                    let usable = |a: &IpAddr| !a.is_unspecified() && !a.is_multicast();
                    let pair =
                        v4.0.zip(v4.1)
                            .filter(|(a, b)| usable(a) && usable(b))
                            .or_else(|| v6.0.zip(v6.1).filter(|(a, b)| usable(a) && usable(b)));
                    if let Some((source, destination)) = pair {
                        batch.flows.push(Flow {
                            exporter,
                            domain,
                            version,
                            export_at: u64::from(exported),
                            received_at: stamp,
                            source,
                            destination,
                            source_port: sport,
                            destination_port: dport,
                            protocol: proto,
                            ingress,
                            egress,
                            octets,
                            packets,
                            datagram_hash: digest,
                            ordinal: (set_count << 16) | record,
                        });
                    } else {
                        batch.skipped += 1;
                    }
                    record += 1;
                }
            } else {
                batch.skipped += 1;
            } // options/sampling are not interpreted
        }
        // Commit diagnostic state only after successful decoding. Same sequence
        // can be valid (IPFIX template-only messages); never count it as loss.
        batch.generation_restart = restart;
        if self.sequence_clock.len() >= 512 && !self.sequence_clock.contains_key(&session) {
            self.sequence_clock.clear();
        }
        if let Some(&(old_export, old_sequence)) = self.sequence_clock.get(&session) {
            if !restart {
                let delta = sequence.wrapping_sub(old_sequence);
                batch.sequence_repeated = delta == 0;
                batch.sequence_reordered = exported < old_export || delta >= (1 << 31);
            }
        }
        if restart || !batch.sequence_reordered {
            self.sequence_clock.insert(session, (exported, sequence));
        }
        self.templates.retain(|k, t| {
            stamp.saturating_sub(t.updated) <= TEMPLATE_TTL && (!restart || k.0 != session)
        });
        for (k, v) in staged {
            if self.templates.len() >= MAX_TEMPLATES
                && !self.templates.contains_key(&k)
                && let Some(old) = self
                    .templates
                    .iter()
                    .min_by_key(|(_, t)| t.updated)
                    .map(|(k, _)| *k)
            {
                self.templates.remove(&old);
            }
            self.templates.insert(k, v);
        }
        if let Some(up) = uptime {
            if self.v9_clock.len() >= 512 && !self.v9_clock.contains_key(&session) {
                self.v9_clock.clear();
            }
            if self
                .v9_clock
                .get(&session)
                .is_none_or(|(old, _)| exported >= *old)
            {
                self.v9_clock.insert(session, (exported, up));
            }
        }
        if self.recent.len() >= 512 {
            self.recent.pop_front();
        }
        self.recent.push_back(key);
        Ok(batch)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroupFile {
    schema: u8,
    bind: SocketAddr,
    exporters: Vec<ExporterFile>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExporterFile {
    id: String,
    exporter: IpAddr,
    site: String,
    vrf: Option<String>,
    wan_ifindex: u32,
    lan_cidrs: Vec<String>,
    observation_domain: u32,
}
#[derive(Clone, Debug)]
pub struct Profile {
    pub id: String,
    pub vrf: Option<String>,
    pub config: FlowConfig,
}
#[derive(Clone, Debug)]
pub struct CollectorConfig {
    pub bind: SocketAddr,
    pub profiles: Vec<Profile>,
}
impl CollectorConfig {
    fn legacy(c: FlowConfig) -> Self {
        let id = format!("legacy:{}:{}:{}", c.site, c.exporter, c.observation_domain);
        Self {
            bind: c.bind,
            profiles: vec![Profile {
                id,
                vrf: None,
                config: c,
            }],
        }
    }
    pub fn parse(s: &str) -> Result<Self> {
        let probe: serde_json::Value =
            serde_json::from_str(s).map_err(|e| format!("Profil collector tidak valid: {e}"))?;
        if probe.get("schema").and_then(serde_json::Value::as_u64) == Some(1) {
            return FlowConfig::parse(s).map(Self::legacy);
        }
        let f: GroupFile = serde_json::from_str(s)
            .map_err(|e| format!("Profil multi-exporter tidak valid: {e}"))?;
        if f.schema != 2 || !(1..=16).contains(&f.exporters.len()) {
            return Err("Diperlukan schema 2 dengan 1–16 exporter.".into());
        }
        let mut ids = std::collections::HashSet::new();
        let mut keys = std::collections::HashSet::new();
        let mut profiles = vec![];
        for e in f.exporters {
            if e.id.is_empty()
                || e.id.len() > 64
                || !e
                    .id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_".contains(&c))
                || e.vrf
                    .as_ref()
                    .is_some_and(|v| v.trim().is_empty() || v.len() > 80 || super::label(v) != *v)
                || !ids.insert(e.id.clone())
                || !keys.insert((e.exporter, e.observation_domain))
            {
                return Err(
                    "ID, VRF, atau pasangan IP/domain exporter tidak valid atau ganda.".into(),
                );
            }
            let config = FlowConfig {
                schema: 1,
                bind: f.bind,
                exporter: e.exporter,
                site: e.site,
                wan_ifindex: e.wan_ifindex,
                lan_cidrs: e.lan_cidrs,
                observation_domain: e.observation_domain,
            };
            config.validate()?;
            profiles.push(Profile {
                id: e.id,
                vrf: e.vrf,
                config,
            });
        }
        Ok(Self {
            bind: f.bind,
            profiles,
        })
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Stats {
    pub accepted_datagrams: u64,
    pub wrong_source: u64,
    pub invalid: u64,
    pub duplicate: u64,
    pub skipped: u64,
    pub missing_templates: u64,
    pub sequence_reordered: u64,
    pub sequence_repeated: u64,
    pub generation_restarts: u64,
    pub retained: usize,
    pub evicted: u64,
    pub last_received: Option<u64>,
    pub error: Option<String>,
    pub archived: u64,
    pub archive_dropped: u64,
    pub archive_queue_full: u64,
    pub archive_writer_closed: u64,
    pub archive_sqlite_failed: u64,
    pub archive_pending: u64,
    pub archive_duplicate: u64,
    pub archive_pruned: u64,
    pub archive_error: Option<String>,
    pub alert_error: Option<String>,
}
#[derive(Default)]
struct Buffer {
    stats: Stats,
    profile_stats: BTreeMap<(IpAddr, u32), Stats>,
    flows: VecDeque<Flow>,
}
pub struct Collector {
    pub config: CollectorConfig,
    archive_stats: Option<Arc<super::store::WriterStats>>,
    data: Arc<Mutex<Buffer>>,
    stop: Arc<AtomicBool>,
    alert_stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
    alert_worker: Option<thread::JoinHandle<()>>,
}
impl Drop for Collector {
    fn drop(&mut self) {
        self.shutdown();
    }
}
impl Collector {
    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take()
            && worker.join().is_err()
            && let Ok(mut data) = self.data.lock()
        {
            data.stats.error = Some("Worker UDP terhenti tidak normal.".into());
        }
        // Wait for the receiver-owned writer before sampling final counters.
        self.alert_stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.alert_worker.take() {
            worker.thread().unpark();
            if worker.join().is_err()
                && let Ok(mut data) = self.data.lock()
            {
                data.stats.alert_error = Some("Worker alert terhenti tidak normal.".into());
            }
        }
    }

    /// Explicit stop preserves final errors for the caller before dropping buffers.
    pub fn stop(mut self) -> Stats {
        self.shutdown();
        self.stats()
    }
}
fn monitor_alerts(
    path: &Path,
    profiles: &[Profile],
    state: &Mutex<Buffer>,
    cancel: &AtomicBool,
    counters: Option<&super::store::WriterStats>,
) {
    use super::{alert_ledger::Tracker, store::Archive};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut tracker = Tracker::new(format!("{}-{nonce}", std::process::id()));
    let scopes: Vec<_> = profiles
        .iter()
        .map(|p| {
            let scope = serde_json::to_string(&(
                &p.config.site,
                &p.vrf,
                &p.id,
                p.config.exporter,
                p.config.observation_domain,
            ))
            .expect("profile scope can be encoded");
            ((p.config.exporter, p.config.observation_domain), scope)
        })
        .collect();
    loop {
        let now = Instant::now();
        let utc = super::now();
        let final_sample = cancel.load(Ordering::Relaxed);
        let (snapshot, listener_failed) = match state.lock() {
            Ok(s) => (s.profile_stats.clone(), s.stats.error.is_some()),
            Err(_) => return,
        };
        // A failed listener cannot prove exporter silence or recovery.
        if !listener_failed {
            for (key, scope) in &scopes {
                if let Some(stats) = snapshot.get(key) {
                    tracker.sample(scope, now, utc, stats, false);
                }
            }
        }
        if let Some(w) = counters {
            let stats = Stats {
                archived: w.written.load(Ordering::Relaxed),
                archive_queue_full: w.queue_full.load(Ordering::Relaxed),
                archive_writer_closed: w.writer_closed.load(Ordering::Relaxed),
                archive_sqlite_failed: w.sqlite_failed.load(Ordering::Relaxed),
                ..Default::default()
            };
            tracker.sample("Collector (semua exporter)", now, utc, &stats, true);
        }
        if final_sample {
            tracker.finish(utc);
        }
        if !tracker.dirty.is_empty() {
            let rows: Vec<_> = tracker.dirty.values().cloned().collect();
            // The flow writer has already opened/migrated the primary archive.
            // Never create a new database on a monitor retry.
            let result = Archive::alert_writer(path).and_then(|mut db| db.save_alerts(&rows));
            if let Ok(mut s) = state.lock() {
                s.stats.alert_error = match result {
                    Ok(()) => {
                        tracker.dirty.clear();
                        tracker
                            .overflow
                            .then(|| "Antrean alert pernah penuh; histori parsial.".into())
                    }
                    Err(e) => Some(format!("Alert belum tersimpan: {e}")),
                };
            }
        }
        if final_sample {
            break;
        }
        thread::park_timeout(Duration::from_secs(1));
    }
}

impl Collector {
    pub fn start(config: FlowConfig) -> Result<Self> {
        Self::start_group(CollectorConfig::legacy(config), None)
    }
    pub fn start_group(config: CollectorConfig, archive: Option<&Path>) -> Result<Self> {
        // Public configuration fields may be constructed without the JSON parser.
        // Revalidate before binding a socket or opening/migrating any archive.
        if !(1..=16).contains(&config.profiles.len()) {
            return Err("Diperlukan 1–16 profil exporter.".into());
        }
        let mut allowed = HashMap::new();
        let mut ids = std::collections::HashSet::new();
        for p in &config.profiles {
            p.config.validate()?;
            if p.config.bind != config.bind
                || p.id.is_empty()
                || p.id.len() > 256
                || super::label(&p.id) != p.id
                || p.vrf
                    .as_ref()
                    .is_some_and(|v| v.trim().is_empty() || v.len() > 80 || super::label(v) != *v)
                || !ids.insert(&p.id)
                || allowed
                    .insert(
                        (p.config.exporter, p.config.observation_domain),
                        (p.clone(), p.config.cidrs()?),
                    )
                    .is_some()
            {
                return Err(
                    "Profil tidak valid, bind berbeda, atau identitas exporter ganda.".into(),
                );
            }
        }
        let sock = UdpSocket::bind(config.bind)
            .map_err(|e| format!("Listener UDP tidak bisa dibuka: {e}"))?;
        let writer = archive.map(Writer::start).transpose()?;
        let archive_stats = writer.as_ref().map(|w| w.stats.clone());
        sock.set_read_timeout(Some(Duration::from_millis(300)))
            .map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let alert_stop = Arc::new(AtomicBool::new(false));
        let data = Arc::new(Mutex::new(Buffer {
            profile_stats: allowed.keys().map(|key| (*key, Stats::default())).collect(),
            ..Default::default()
        }));
        let (cancel, out) = (stop.clone(), data.clone());
        let worker = thread::Builder::new()
            .name("wfs-flow-udp".into())
            .spawn(move || {
                let mut decoder = Decoder::default();
                let mut datagram = [0; 65535];
                while !cancel.load(Ordering::Relaxed) {
                    match sock.recv_from(&mut datagram) {
                        Ok((n, peer)) => {
                            let mut data = match out.lock() {
                                Ok(v) => v,
                                Err(_) => return,
                            };
                            let version = datagram[..n].get(..2);
                            let offset = if version == Some(&[0, 10]) {
                                12
                            } else if version == Some(&[0, 9]) {
                                16
                            } else {
                                0
                            };
                            if offset == 0 || n < offset + 4 {
                                data.stats.invalid += 1;
                                continue;
                            }
                            let domain = u32::from_be_bytes(
                                datagram[offset..offset + 4].try_into().unwrap(),
                            );
                            let Some((profile, lan)) = allowed.get(&(peer.ip(), domain)) else {
                                data.stats.wrong_source += 1;
                                continue;
                            };
                            let now = super::now();
                            drop(data);
                            let decoded = decoder.ingest(peer, &datagram[..n], now);
                            if let (Ok(b), Some(w)) = (&decoded, &writer) {
                                w.submit(b.flows.iter().map(|f| ArchiveRow {
                                    profile: profile.id.clone(),
                                    site: profile.config.site.clone(),
                                    vrf: profile.vrf.clone(),
                                    direction: direction(f, &profile.config, lan),
                                    flow: f.clone(),
                                }));
                            }
                            let Ok(mut data) = out.lock() else { return };
                            // Attribution is valid only after the allowlisted IP/domain match.
                            if let Some(stats) = data.profile_stats.get_mut(&(peer.ip(), domain)) {
                                match &decoded {
                                    Ok(b) if b.duplicate => stats.duplicate += 1,
                                    Ok(b) => {
                                        stats.accepted_datagrams += 1;
                                        stats.last_received = Some(now);
                                        stats.missing_templates += u64::from(b.missing);
                                        stats.skipped += u64::from(b.skipped);
                                        stats.sequence_reordered += u64::from(b.sequence_reordered);
                                        stats.sequence_repeated += u64::from(b.sequence_repeated);
                                        stats.generation_restarts += u64::from(b.generation_restart);
                                    }
                                    Err(_) => stats.invalid += 1,
                                }
                            }
                            match decoded {
                                Ok(b) if b.duplicate => data.stats.duplicate += 1,
                                Ok(b) => {
                                    data.stats.accepted_datagrams += 1;
                                    data.stats.last_received = Some(now);
                                    data.stats.missing_templates += u64::from(b.missing);
                                    data.stats.skipped += u64::from(b.skipped);
                                    data.stats.sequence_reordered += u64::from(b.sequence_reordered);
                                    data.stats.sequence_repeated += u64::from(b.sequence_repeated);
                                    data.stats.generation_restarts += u64::from(b.generation_restart);
                                    for f in b.flows {
                                        if data.flows.len() == MAX_ROWS {
                                            data.flows.pop_front();
                                            data.stats.evicted += 1;
                                        }
                                        data.flows.push_back(f);
                                    }
                                }
                                Err(_) => data.stats.invalid += 1,
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::TimedOut
                                    | std::io::ErrorKind::WouldBlock
                                    | std::io::ErrorKind::Interrupted
                            ) => {}
                        Err(e) => {
                            if let Ok(mut b) = out.lock() {
                                b.stats.error = Some(e.to_string());
                            }
                            break;
                        }
                    }
                }
            })
            .map_err(|e| e.to_string())?;
        let alert_worker = if let Some(path) = archive {
            let path = path.to_path_buf();
            let profiles = config.profiles.clone();
            let state = data.clone();
            let cancel = alert_stop.clone();
            let counters = archive_stats.clone();
            match thread::Builder::new()
                .name("wfs-alert-ledger".into())
                .spawn(move || {
                    monitor_alerts(&path, &profiles, &state, &cancel, counters.as_deref());
                }) {
                Ok(handle) => Some(handle),
                Err(e) => {
                    stop.store(true, Ordering::Relaxed);
                    let _ = worker.join();
                    return Err(format!("Monitor alert tidak dapat dimulai: {e}"));
                }
            }
        } else {
            None
        };
        Ok(Self {
            config,
            archive_stats,
            data,
            stop,
            alert_stop,
            worker: Some(worker),
            alert_worker,
        })
    }
    pub fn stats(&self) -> Stats {
        self.read_buffer(false).0
    }

    pub fn source_stats(&self) -> Vec<(String, Stats)> {
        let Ok(b) = self.data.lock() else {
            return Vec::new();
        };
        self.config
            .profiles
            .iter()
            .filter_map(|p| {
                let stats = b
                    .profile_stats
                    .get(&(p.config.exporter, p.config.observation_domain))?;
                let label = format!(
                    "{} / {} / {} / {} #{}",
                    p.config.site,
                    p.vrf.as_deref().unwrap_or("VRF tidak diketahui"),
                    p.id,
                    p.config.exporter,
                    p.config.observation_domain
                );
                Some((label, stats.clone()))
            })
            .collect()
    }
    pub fn snapshot(&self) -> (Stats, Vec<Flow>) {
        self.read_buffer(true)
    }
    fn read_buffer(&self, include_flows: bool) -> (Stats, Vec<Flow>) {
        let Ok(b) = self.data.lock() else {
            return (
                Stats {
                    error: Some("Buffer collector tidak tersedia.".into()),
                    ..Default::default()
                },
                vec![],
            );
        };
        let mut stats = b.stats.clone();
        stats.retained = b.flows.len();
        if let Some(a) = &self.archive_stats {
            stats.archived = a.written.load(Ordering::Relaxed);
            stats.archive_dropped = a.dropped.load(Ordering::Relaxed);
            stats.archive_queue_full = a.queue_full.load(Ordering::Relaxed);
            stats.archive_writer_closed = a.writer_closed.load(Ordering::Relaxed);
            stats.archive_sqlite_failed = a.sqlite_failed.load(Ordering::Relaxed);
            stats.archive_pending = a.pending_rows.load(Ordering::Relaxed);
            stats.archive_duplicate = a.duplicates.load(Ordering::Relaxed);
            stats.archive_pruned = a.pruned.load(Ordering::Relaxed);
            stats.archive_error = a.error.lock().ok().and_then(|v| v.clone());
        }
        (
            stats,
            if include_flows {
                b.flows.iter().cloned().collect()
            } else {
                vec![]
            },
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Direction {
    FromLan,
    ToLan,
    Unknown,
}
impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FromLan => "LAN→WAN",
            Self::ToLan => "WAN→LAN",
            Self::Unknown => "Tidak diketahui",
        }
    }
}
pub fn direction(f: &Flow, cfg: &FlowConfig, lan: &[Cidr]) -> Direction {
    let source = lan.iter().any(|x| x.contains(f.source));
    let dest = lan.iter().any(|x| x.contains(f.destination));
    match (source, dest, f.ingress, f.egress) {
        (true, false, Some(i), Some(e))
            if i != 0 && i != cfg.wan_ifindex && e == cfg.wan_ifindex =>
        {
            Direction::FromLan
        }
        (false, true, Some(i), Some(e))
            if e != 0 && e != cfg.wan_ifindex && i == cfg.wan_ifindex =>
        {
            Direction::ToLan
        }
        _ => Direction::Unknown,
    }
}
type Tuple = (SocketAddr, super::device::Tuple);
pub fn wan_evidence(cfg: &FlowConfig, rows: &[Flow], now: u64) -> TrafficImport {
    let Ok(lan) = cfg.cidrs() else {
        return TrafficImport {
            schema: 1,
            entries: vec![],
        };
    };
    let mut replies: HashMap<Tuple, Vec<(u64, u64)>> = HashMap::new();
    let mut outgoing: Vec<(&Flow, Option<Tuple>)> = vec![];
    for f in rows {
        if f.exporter.ip() != cfg.exporter
            || f.domain != cfg.observation_domain
            || f.received_at > now
            || now - f.received_at > super::FRESH_SECONDS
            || f.export_at.abs_diff(f.received_at) > super::FRESH_SECONDS
        {
            continue;
        }
        match direction(f, cfg, &lan) {
            Direction::FromLan => {
                let t = super::device::tuple(f, false).map(|t| (f.exporter, t));
                outgoing.push((f, t));
            }
            Direction::ToLan => {
                if let Some(t) = super::device::tuple(f, true) {
                    replies
                        .entry((f.exporter, t))
                        .or_default()
                        .push((f.export_at, f.received_at));
                }
            }
            Direction::Unknown => {}
        }
    }
    let mut ips = BTreeMap::<IpAddr, (bool, u64)>::new();
    for (f, t) in outgoing {
        let bidir = t.and_then(|k| replies.get(&k)).is_some_and(|times| {
            times.iter().any(|(exported, received)| {
                exported.abs_diff(f.export_at) <= 300 && received.abs_diff(f.received_at) <= 300
            })
        });
        ips.entry(f.source)
            .and_modify(|x| *x = (*x).max((bidir, f.received_at)))
            .or_insert((bidir, f.received_at));
    }
    TrafficImport {
        schema: 1,
        entries: ips
            .into_iter()
            .map(|(ip, (reply, observed_at))| TrafficEvidence {
                ip,
                scope: format!(
                    "{} / OD {} / WAN if#{}",
                    cfg.site, cfg.observation_domain, cfg.wan_ifindex
                ),
                sensor: format!(
                    "UDP Flow {} (direksi diverifikasi dari ifIndex; sampling tidak diketahui)",
                    cfg.exporter
                ),
                observed_at,
                kind: if reply {
                    EvidenceKind::WanReply
                } else {
                    EvidenceKind::WanAttempt
                },
            })
            .collect(),
    }
}
pub fn summarize(rows: &[Flow]) -> Vec<PeerSummary> {
    type PeerKey = (SocketAddr, u16, u32, IpAddr, IpAddr);
    let mut peers = BTreeMap::<PeerKey, (u64, u64, u64)>::new();
    for f in rows {
        let entry = peers
            .entry((f.exporter, f.version, f.domain, f.source, f.destination))
            .or_default();
        entry.0 += 1;
        if let Some(o) = f.octets {
            entry.1 += 1;
            entry.2 = entry.2.saturating_add(o);
        }
    }
    let mut result: Vec<_> = peers
        .into_iter()
        .map(
            |((exporter, version, domain, source, destination), (records, counted, octets))| {
                PeerSummary {
                    exporter,
                    version,
                    domain,
                    source,
                    destination,
                    records,
                    counted,
                    octets,
                }
            },
        )
        .collect();
    result.sort_by_key(|p| std::cmp::Reverse((p.octets, p.records)));
    result
}
#[derive(Debug, Serialize)]
pub struct PeerSummary {
    pub exporter: SocketAddr,
    pub version: u16,
    pub domain: u32,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub records: u64,
    pub counted: u64,
    pub octets: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    fn set(id: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = id.to_be_bytes().to_vec();
        out.extend(((payload.len() + 4) as u16).to_be_bytes());
        out.extend(payload);
        out
    }
    fn packet(v: u16, domain: u32, seq: u32, stamp: u32, uptime: u32, sets: &[Vec<u8>]) -> Vec<u8> {
        let mut p = v.to_be_bytes().to_vec();
        if v == 9 {
            p.extend((sets.len() as u16).to_be_bytes());
            p.extend(uptime.to_be_bytes());
        } else {
            p.extend(((16 + sets.iter().map(Vec::len).sum::<usize>()) as u16).to_be_bytes());
        }
        p.extend(stamp.to_be_bytes());
        p.extend(seq.to_be_bytes());
        p.extend(domain.to_be_bytes());
        for s in sets {
            p.extend(s);
        }
        p
    }
    fn template(v: u16) -> Vec<u8> {
        let fields = [
            (8u16, 4u16),
            (12, 4),
            (7, 2),
            (11, 2),
            (4, 1),
            (10, 4),
            (14, 4),
            (1, 8),
            (2, 4),
        ];
        let mut t = 256u16.to_be_bytes().to_vec();
        t.extend((fields.len() as u16).to_be_bytes());
        for (id, len) in fields {
            t.extend(id.to_be_bytes());
            t.extend(len.to_be_bytes());
        }
        set(if v == 9 { 0 } else { 2 }, &t)
    }
    fn data(reverse: bool) -> Vec<u8> {
        let (a, b) = ([192, 0, 2, 4], [203, 0, 113, 90]);
        let (src, dst, s, d, i, e) = if reverse {
            (b, a, 443u16, 31000u16, 3u32, 2u32)
        } else {
            (a, b, 31000, 443, 2, 3)
        };
        let mut p = src.to_vec();
        p.extend(dst);
        p.extend(s.to_be_bytes());
        p.extend(d.to_be_bytes());
        p.push(6);
        p.extend(i.to_be_bytes());
        p.extend(e.to_be_bytes());
        p.extend(200u64.to_be_bytes());
        p.extend(2u32.to_be_bytes());
        set(256, &p)
    }
    fn cfg() -> FlowConfig {
        FlowConfig::parse(r#"{"schema":1,"bind":"127.0.0.1:4739","exporter":"127.0.0.1","site":"Lab","wan_ifindex":3,"lan_cidrs":["192.0.2.0/24"],"observation_domain":11}"#).unwrap()
    }
    #[test]
    fn collector_rejects_unvalidated_profiles_before_opening_archive() {
        let mut invalid = cfg();
        invalid.bind = "0.0.0.0:4739".parse().unwrap();
        assert!(Collector::start(invalid).is_err());
        let mut group = CollectorConfig::legacy(cfg());
        group.profiles.push(group.profiles[0].clone());
        assert!(Collector::start_group(group, None).is_err());
        let mut group = CollectorConfig::legacy(cfg());
        group.bind = "127.0.0.1:4740".parse().unwrap();
        assert!(Collector::start_group(group, None).is_err());
        let mut group = CollectorConfig::legacy(cfg());
        group.profiles.clear();
        assert!(Collector::start_group(group, None).is_err());
    }

    #[test]
    fn parses_both_protocols_and_only_attributes_a_matching_wan_pair() {
        for v in [9, 10] {
            let exp = "127.0.0.1:55000".parse().unwrap();
            let mut d = Decoder::default();
            let p = packet(v, 11, 1, 100, 1000, &[template(v), data(false)]);
            let mut a = d.ingest(exp, &p, 100).unwrap().flows;
            assert_eq!(a[0].octets, Some(200));
            assert_eq!(
                wan_evidence(&cfg(), &a, 102).entries[0].kind,
                EvidenceKind::WanAttempt
            );
            assert!(d.ingest(exp, &p, 101).unwrap().duplicate);
            a.extend(
                d.ingest(exp, &packet(v, 11, 2, 101, 2000, &[data(true)]), 101)
                    .unwrap()
                    .flows,
            );
            assert_eq!(
                wan_evidence(&cfg(), &a, 102).entries[0].kind,
                EvidenceKind::WanReply
            );
            a[1].ingress = Some(5);
            assert_eq!(
                wan_evidence(&cfg(), &a, 102).entries[0].kind,
                EvidenceKind::WanAttempt
            );
            assert_eq!(summarize(&a)[0].octets, 200);
        }
    }
    #[test]
    fn isolation_expiry_restart_and_atomic_parse() {
        let exp = "127.0.0.1:55000".parse().unwrap();
        let mut d = Decoder::default();
        let invalid = packet(10, 11, 1, 100, 0, &[template(10), vec![1, 0, 0, 2]]);
        assert!(d.ingest(exp, &invalid, 100).is_err());
        assert_eq!(
            d.ingest(exp, &packet(10, 11, 2, 100, 0, &[data(false)]), 100)
                .unwrap()
                .missing,
            1
        );
        d.ingest(exp, &packet(9, 11, 1, 100, 3000, &[template(9)]), 100)
            .unwrap();
        assert_eq!(
            d.ingest(exp, &packet(9, 12, 2, 100, 0, &[data(false)]), 100)
                .unwrap()
                .missing,
            1
        );
        assert_eq!(
            d.ingest(exp, &packet(9, 11, 2, 101, 100, &[data(false)]), 101)
                .unwrap()
                .missing,
            1
        );
        d.ingest(exp, &packet(10, 11, 3, 101, 0, &[template(10)]), 101)
            .unwrap();
        assert_eq!(
            d.ingest(exp, &packet(10, 11, 4, 2001, 0, &[data(false)]), 2001)
                .unwrap()
                .missing,
            1
        );
    }
    #[test]
    fn two_domains_archive_across_restart_and_deduplicate() {
        use crate::intelligence::store::{Archive, ExportFormat, Query};
        let path = std::env::temp_dir().join(format!("wfs-flow-e2e-{}", rand_suffix()));
        let db = path.join("flow.db");
        let ephemeral = UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind = ephemeral.local_addr().unwrap();
        let config = CollectorConfig::parse(&format!(r#"{{"schema":2,"bind":"{bind}","exporters":[
            {{"id":"edge-a","exporter":"127.0.0.1","site":"A","vrf":"blue","wan_ifindex":3,"lan_cidrs":["192.0.2.0/24"],"observation_domain":11}},
            {{"id":"edge-b","exporter":"127.0.0.1","site":"B","vrf":"green","wan_ifindex":3,"lan_cidrs":["192.0.2.0/24"],"observation_domain":12}}
        ]}}"#)).unwrap();
        drop(ephemeral);
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        for _ in 0..2 {
            let c = Collector::start_group(config.clone(), Some(&db)).unwrap();
            for domain in [11, 12, 99] {
                sender
                    .send_to(
                        &packet(10, domain, 1, 100, 0, &[template(10), data(false)]),
                        bind,
                    )
                    .unwrap();
            }
            let until = Instant::now() + Duration::from_secs(5);
            loop {
                let (stats, _) = c.snapshot();
                if stats.accepted_datagrams == 2 && stats.wrong_source == 1 {
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "flow fixture was not received: {stats:?}"
                );
                thread::sleep(Duration::from_millis(10));
            }
            drop(c);
            let archive = Archive::reader(&db).unwrap();
            assert_eq!(archive.counts().unwrap(), (2, 0));
        }
        let mut archive = Archive::reader(&db).unwrap();
        let q = Query::parse("ip=192.0.2.4 site=B vrf=green domain=12 protocol=6 if=3").unwrap();
        let p = archive.page(&q, None, 10).unwrap();
        assert_eq!(p.rows.len(), 1);
        assert_eq!(p.rows[0].profile, "edge-b");
        let mut buf = vec![];
        assert_eq!(
            archive
                .export(&q, ExportFormat::Csv, true, &mut buf)
                .unwrap()
                .total,
            1
        );
        assert!(!String::from_utf8(buf).unwrap().contains("192.0.2.4"));
        drop(archive);
        std::fs::remove_dir_all(path).unwrap();
    }

    fn rand_suffix() -> String {
        format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        )
    }
    #[test]
    #[ignore = "one-million-record UDP loopback benchmark"]
    fn benchmark_udp_million_loopback() {
        use crate::intelligence::archive_ops::Policy;
        use crate::intelligence::store::{Archive, Query};
        const ROWS: usize = 1_000_000;
        const PER_PACKET: usize = 80;
        let path = std::env::temp_dir().join(format!("wfs-udp-bench-{}", rand_suffix()));
        let dbpath = path.join("benchmark.sqlite3");
        Archive::writer(&dbpath)
            .unwrap()
            .save_policy(Policy::new(30, 7, 1024).unwrap())
            .unwrap();
        let reservation = UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind = reservation.local_addr().unwrap();
        drop(reservation);
        let mut cfgs = vec![];
        let mut sockets = vec![];
        for i in 0..10 {
            let mut c = cfg();
            c.bind = bind;
            c.observation_domain = i + 1;
            c.site = format!("lab-{i}");
            c.lan_cidrs = vec!["10.0.0.0/16".into()];
            cfgs.push(Profile {
                id: format!("test-{i}"),
                vrf: None,
                config: c,
            });
            sockets.push(UdpSocket::bind("127.0.0.1:0").unwrap());
        }
        let col = Collector::start_group(
            CollectorConfig {
                bind,
                profiles: cfgs,
            },
            Some(&dbpath),
        )
        .unwrap();
        let one = data(false);
        let start = Instant::now();
        // Fixture uses one physical loopback address, ten distinct UDP source ports/domains.
        for (i, sock) in sockets.iter().enumerate() {
            sock.send_to(
                &packet(
                    10,
                    i as u32 + 1,
                    0,
                    super::super::now() as u32,
                    0,
                    &[template(10)],
                ),
                bind,
            )
            .unwrap();
        }
        loop {
            if col.stats().accepted_datagrams == 10 {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(3),
                "loopback template setup did not finish"
            );
            thread::sleep(Duration::from_millis(10));
        }
        let send = Instant::now();
        for j in 0..(ROWS / PER_PACKET) {
            let source = j % 10;
            let mut payload = vec![];
            for k in 0..PER_PACKET {
                let dev = ((j / 10) * PER_PACKET + k) % 2000;
                payload.extend([10, 0, (dev / 250) as u8, (1 + dev % 250) as u8]);
                payload.extend(&one[8..]);
            }
            let bytes = packet(
                10,
                source as u32 + 1,
                j as u32 + 1,
                super::super::now() as u32,
                0,
                &[set(256, &payload)],
            );
            sockets[source].send_to(&bytes, bind).unwrap();
            thread::sleep(Duration::from_millis(3));
        }
        let sent = send.elapsed();
        let finish = Instant::now();
        let target = (ROWS / PER_PACKET) as u64 + 10;
        while finish.elapsed() < Duration::from_secs(5) {
            let s = col.stats();
            if s.accepted_datagrams == target
                && s.archive_pending == 0
                && s.archived + s.archive_dropped == ROWS as u64
            {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        let stats = col.stats();
        let settle = finish.elapsed();
        let pre_shutdown = Archive::reader(&dbpath).unwrap().health(&dbpath).unwrap();
        let stop = Instant::now();
        drop(col);
        let stop = stop.elapsed();
        let db = Archive::reader(&dbpath).unwrap();
        let health = db.health(&dbpath).unwrap();
        let stored = health.flow_records as usize;
        assert_eq!(health.source_scopes, 10);
        assert!(stored > 0 && stored <= ROWS);
        let mut samples = vec![];
        for n in 1..=100 {
            let q = Query::parse(&format!("10.0.0.{n}")).unwrap();
            let at = Instant::now();
            let _ = db.inspect(&q, super::super::now()).unwrap();
            samples.push(at.elapsed().as_micros());
        }
        samples.sort_unstable();
        let decoded = (stats.accepted_datagrams.saturating_sub(10) as usize) * PER_PACKET;
        println!(
            "sent={ROWS} decoded={decoded} stored={stored} archive_drop={} unresolved={} profiles=10 send_ms={} settle_ms={} stop_ms={} p95_us={} db_bytes={} live_wal_bytes={}",
            stats.archive_dropped,
            ROWS - stored,
            sent.as_millis(),
            settle.as_millis(),
            stop.as_millis(),
            samples[94],
            health.main_bytes,
            pre_shutdown.wal_bytes
        );
        assert_eq!(
            u64::try_from(stored).unwrap() + stats.archive_dropped,
            decoded as u64
        );
        drop(db);
        std::fs::remove_dir_all(path).unwrap();
    }
    #[test]
    fn loopback_udp_receive_is_end_to_end() {
        let ephemeral = UdpSocket::bind("127.0.0.1:0").unwrap();
        let bind = ephemeral.local_addr().unwrap();
        drop(ephemeral);
        let mut cfg = cfg();
        cfg.bind = bind;
        let c = Collector::start(cfg).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        tx.send_to(
            &packet(10, 12, 1, 100, 0, &[template(10), data(false)]),
            bind,
        )
        .unwrap();
        tx.send_to(
            &packet(10, 11, 1, 100, 0, &[template(10), data(false)]),
            bind,
        )
        .unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            let (stats, rows) = c.snapshot();
            if !rows.is_empty() && stats.wrong_source == 1 {
                assert_eq!(stats.accepted_datagrams, 1);
                break;
            }
            assert!(Instant::now() < until, "collector did not accept fixture");
            thread::sleep(Duration::from_millis(10));
        }
    }
}
