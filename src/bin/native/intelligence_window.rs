use wfs_network_toolkit::intelligence::{
    self as ni, Assessment, Coverage, EndpointState, LocalSnapshot, Probe, TrafficImport,
    alert_ledger::Record as AlertRecord,
    archive_ops::{DeletePreview, Kind, Policy, RecoveryPlan, check_recovery_destination},
    device::{Inspection, ObservedScope},
    flow::{self, Collector, CollectorConfig},
    history,
    interface_trend::{self, Trend},
    network_map::{self, LeaseTimeline, Observation},
    overview,
    polling::{Outcome, Schedule},
    router::{Authority, InterfaceBaseline, RouterSnapshot, interface_bitrate},
    router_history::{Sample, Views},
    store::{self, Archive, Cursor, ExportFormat, Query},
    windows as nw,
};
use windows_sys::Win32::Security::Credentials::*;

const INTEL_MODE: i32 = 220;
const INTEL_FILTER: i32 = 221;
const INTEL_SEARCH: i32 = 222;
const INTEL_REFRESH: i32 = 223;
const INTEL_PROBE: i32 = 224;
const INTEL_IMPORT: i32 = 225;
const INTEL_HOST: i32 = 226;
const INTEL_ROUTER: i32 = 227;
const INTEL_TABLE: i32 = 228;
const INTEL_STATUS: i32 = 229;
const INTEL_DETAILS: i32 = 230;
const INTEL_EXPORT: i32 = 231;
const INTEL_REDACT: i32 = 232;
const INTEL_RESET_FILTER: i32 = 233;
const INTEL_FLOW: i32 = 234;
const INTEL_STOP: i32 = 235;
const INTEL_RECORD: i32 = 236;
const INTEL_HISTORY: i32 = 237;
const INTEL_MORE: i32 = 238;
const INTEL_IP_JOURNEY: i32 = 239;
const INTEL_BACK: i32 = 240;
const ARCHIVE_MODE: usize = 16;
const DEVICE_MODE: usize = 17;
const STORAGE_MODE: usize = 18;
const TOPOLOGY_MODE: usize = 19;
const IPAM_MODE: usize = 20;
const TREND_MODE: usize = 21;
const LEASE_MODE: usize = 22;
const ALERT_MODE: usize = 23;
const POLL_MODE: usize = 24;
const DASHBOARD_MODE: usize = 25;
const SUBNET_MODE: usize = 26;
const INTEL_MODES: [&str; 27] = [
    "Akses Internet",
    "Perangkat & alamat",
    "Endpoint Windows",
    "Koneksi MikroTik",
    "Interface MikroTik",
    "Kesehatan sumber",
    "Sistem MikroTik",
    "Layanan lokal",
    "Rute default MikroTik",
    "Flow IPFIX / NetFlow",
    "Mitra trafik",
    "Histori snapshot",
    "Perubahan jaringan",
    "Status collector",
    "Bridge & VLAN MikroTik",
    "Firewall & NAT MikroTik",
    "Arsip flow SQLite",
    "Detail IP",
    "Penyimpanan arsip",
    "Topologi RouterOS",
    "IPAM observasi",
    "Tren interface",
    "Histori lease sesi",
    "Alert collector",
    "Polling RouterOS",
    "Dashboard jaringan",
    "Ringkasan subnet IPv4/IPv6",
];
const INTEL_ROW_LIMIT: usize = 1_000;

type RouterData = (Box<RouterSnapshot>, Vec<Observation>, Vec<Observation>);
type PollResult = std::result::Result<(RouterData, Outcome, Option<String>), Outcome>;
fn prepare_router(s: RouterSnapshot) -> RouterData {
    let topology = network_map::topology(&s);
    let inventory = network_map::inventory(&s);
    (Box::new(s), topology, inventory)
}
type IntelResult = Result<IntelReply>;
enum IntelReply {
    Local(Box<LocalSnapshot>),
    Probe(Box<(LocalSnapshot, Probe)>),
    Router(RouterData),
    RouterHistory(String, Box<Views>),
    RouterArchived,
    Import(TrafficImport),
    Export(PathBuf),
    Collector(Collector),
    History(history::History),
    Stopped(Box<flow::Stats>),
    Alerts(PathBuf, Vec<AlertRecord>),
    Archive(store::Page, Box<Query>),
    Device(Inspection, Box<Query>, String),
    Storage(Option<Box<store::ArchiveHealth>>),
    PolicySaved(Policy),
    BackupSaved(PathBuf),
    RecoveryPreview(PathBuf, RecoveryPlan),
    RecoverySaved(PathBuf),
    DeletePreview(DeletePreview),
    Deleted(usize),
    SnapshotsImported(usize),
    ArchiveExport(PathBuf, store::ExportSummary),
}

#[derive(Default)]
struct IntelState {
    local: Option<Box<LocalSnapshot>>,
    probe: Option<Probe>,
    routers: std::collections::BTreeMap<String, Box<RouterSnapshot>>,
    imported: Option<TrafficImport>,
    network_views: std::collections::BTreeMap<String, (Vec<Observation>, Vec<Observation>)>,
    trends: std::collections::BTreeMap<String, Trend>,
    lease_timelines: std::collections::BTreeMap<String, LeaseTimeline>,
    previous_interfaces: std::collections::BTreeMap<String, InterfaceBaseline>,
    work: Option<Receiver<IntelResult>>,
    details: Vec<String>,
    filter: String,
    collector: Option<Collector>,
    alert_rows: Vec<AlertRecord>,
    alert_path: Option<PathBuf>,
    history: Option<history::History>,
    archived: Option<store::Page>,
    archive_query: Option<Query>,
    device: Option<(Inspection, Query)>,
    device_input: String,
    device_applied_input: String,
    pivot_scope: Option<String>,
    visible_ips: Vec<Option<std::net::IpAddr>>,
    previous_mode: Option<(usize, String)>,
    mode: usize,
    archive_override: Option<PathBuf>,
    recovery_view: Option<PathBuf>,
    storage: Option<Box<store::ArchiveHealth>>,
    storage_loaded: bool,
    storage_smoke: bool,
    storage_smoke_error: Option<String>,
    schedule: Schedule,
    poll_auth: std::collections::BTreeMap<String, (Authority, std::sync::Arc<nw::Credentials>)>,
    poll_rx: Option<Receiver<PollResult>>,
    poll_save_errors: std::collections::BTreeMap<String, String>,
    router_history: Option<(String, Box<Views>)>,
    dashboard_targets: Vec<usize>,
}
impl IntelState {
    fn assessments(&self) -> Vec<Assessment> {
        let at = ni::now();
        let mut rows = self
            .local
            .as_ref()
            .map_or_else(Vec::new, |s| ni::assess(s, self.probe.as_ref(), at));
        if let Some(import) = &self.imported {
            rows.extend(ni::assess_import(import, at));
        }
        if let Some(c) = &self.collector {
            let (_, flows) = c.snapshot();
            for p in &c.config.profiles {
                let mut evidence = flow::wan_evidence(&p.config, &flows, at);
                for e in &mut evidence.entries {
                    e.scope = format!(
                        "{} / {} / {}",
                        p.id,
                        p.vrf.as_deref().unwrap_or("VRF tidak diketahui"),
                        e.scope
                    );
                }
                rows.extend(ni::assess_flow(&evidence, at));
            }
        }
        for router in self.routers.values() {
            let mut seen = std::collections::BTreeSet::new();
            for host in &router.inventory {
                let ip = host.ip;
                let origin = host.source.as_str();
                let loc = host
                    .location
                    .as_deref()
                    .unwrap_or("interface tidak diketahui");
                if seen.insert((ip, origin, loc)) {
                    let observed_at = router
                        .coverage
                        .iter()
                        .find(|c| c.source == host.coverage_source())
                        .map_or(router.observed_at, |c| c.observed_at);
                    rows.push(Assessment {
                        ip,
                        scope: format!(
                            "{} / {origin} / {loc} (VRF tidak diketahui)",
                            router.authority
                        ),
                        observed_at,
                        access: if at.saturating_sub(observed_at) > ni::FRESH_SECONDS {
                            ni::Access::Stale
                        } else {
                            ni::Access::Unknown
                        },
                        evidence: "Inventaris router bukan bukti akses internet.".into(),
                    });
                }
            }
        }
        rows
    }
}

fn ask_router_credentials(h: HWND, authority: &Authority) -> Result<Option<nw::Credentials>> {
    let caption = w::wide("Kredensial MikroTik — hanya sesi ini");
    let message = w::wide("Masukkan akun khusus baca. Password tidak disimpan.");
    let target = w::wide(&authority.display());
    let ui = CREDUI_INFOW {
        cbSize: size_of::<CREDUI_INFOW>() as u32,
        hwndParent: h,
        pszMessageText: message.as_ptr(),
        pszCaptionText: caption.as_ptr(),
        ..Default::default()
    };
    let mut auth = nw::Credentials {
        user: vec![0; 514],
        password: vec![0; 514],
    };
    let mut save = 0;
    let code = unsafe {
        CredUIPromptForCredentialsW(
            &ui,
            target.as_ptr(),
            null(),
            0,
            auth.user.as_mut_ptr(),
            auth.user.len() as u32,
            auth.password.as_mut_ptr(),
            auth.password.len() as u32,
            &mut save,
            CREDUI_FLAGS_GENERIC_CREDENTIALS
                | CREDUI_FLAGS_ALWAYS_SHOW_UI
                | CREDUI_FLAGS_DO_NOT_PERSIST
                | CREDUI_FLAGS_EXCLUDE_CERTIFICATES,
        )
    };
    if code == ERROR_CANCELLED {
        return Ok(None);
    }
    if code != 0 {
        return Err(format!("Dialog kredensial gagal (Windows {code})."));
    }
    if auth.user[0] == 0 || auth.password[0] == 0 {
        return Err("Isi username dan password akun baca.".into());
    }
    Ok(Some(auth))
}

fn format_probe(p: &Probe) -> String {
    let source = p
        .source
        .map_or_else(|| "tidak diketahui".into(), |a| a.to_string());
    let destination = p
        .destination
        .map_or_else(|| "tidak diketahui".into(), |a| a.to_string());
    format!(
        "{}\n{}\n\nSumber: {source}\nTujuan: {destination}\nInterface: {}\nHTTP: {}\nDurasi: {} ms\nUTC (Unix): {}",
        p.target,
        p.detail,
        p.interface_index
            .map_or_else(|| "—".into(), |i| i.to_string()),
        p.http_status.map_or_else(|| "—".into(), |s| s.to_string()),
        p.elapsed_ms,
        p.observed_at
    )
}
fn display_opt<T: ToString>(v: Option<T>) -> String {
    v.map_or_else(|| "—".into(), |v| v.to_string())
}

fn read_limited(path: &std::path::Path, limit: u64) -> Result<String> {
    use std::io::Read;
    let mut data = String::new();
    std::fs::File::open(path)
        .and_then(|f| f.take(limit + 1).read_to_string(&mut data))
        .map_err(|e| format!("Tidak dapat membaca JSON: {e}"))?;
    if data.len() as u64 > limit {
        return Err("Ukuran JSON melebihi batas.".into());
    }
    Ok(data.trim_start_matches('\u{feff}').to_owned())
}

fn combined_history(
    at: u64,
    path: &std::path::Path,
    include_legacy: bool,
) -> Result<history::History> {
    let legacy = if include_legacy {
        history::load(&history::default_dir()?, at)?
    } else {
        history::History {
            snapshots: vec![],
            unreadable: 0,
        }
    };
    if path.try_exists().map_err(|e| e.to_string())? {
        Ok(history::merge(legacy, Archive::reader(path)?.history(at)?))
    } else {
        Ok(legacy)
    }
}

fn format_ip_scope(ip: std::net::IpAddr, row: &ObservedScope, partial: bool, now: u64) -> String {
    let peers = row
        .peers
        .iter()
        .map(|(ip, n)| format!("{ip} · {n} record"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "{ip} · IPv{}\n{}\n{} · UTC {}\n{} record{} · UTC {} – {}\n\nMitra teramati pada hasil yang diperiksa\n{peers}\n\nTidak membuktikan kebijakan firewall, keterjangkauan menyeluruh, atau identitas perangkat. Sampling tidak diketahui.",
        if ip.is_ipv4() { 4 } else { 6 },
        row.scope.label(),
        row.access_label(now),
        display_opt(row.evidence_at),
        row.count,
        if partial { " (parsial)" } else { "" },
        row.first,
        row.last
    )
}

impl Native {
    fn create_intel(&mut self) -> Result<()> {
        self.widget(
            "COMBOBOX",
            "",
            INTEL_MODE,
            Some(Page::Intel),
            0,
            WS_TABSTOP | CBS_DROPDOWNLIST as u32 | WS_VSCROLL,
            [228, 188, 180, 194],
        )?;
        self.options(INTEL_MODE, &INTEL_MODES);
        self.edit(INTEL_FILTER, Page::Intel, [417, 187, -760, 29], 1024)?;
        send_native(
            self.h(INTEL_FILTER),
            EM_SETCUEBANNER,
            0,
            w::wide("Cari IP, port, PID…").as_ptr() as isize,
        );
        self.button("Cari", INTEL_SEARCH, Some(Page::Intel), [-332, 184, 60, 34])?;
        self.button(
            "Reset",
            INTEL_RESET_FILTER,
            Some(Page::Intel),
            [-265, 184, 65, 34],
        )?;
        self.button(
            "Data Windows",
            INTEL_REFRESH,
            Some(Page::Intel),
            [-192, 184, 164, 34],
        )?;
        self.edit(INTEL_HOST, Page::Intel, [228, 230, -746, 30], 255)?;
        send_native(
            self.h(INTEL_HOST),
            EM_SETCUEBANNER,
            0,
            w::wide("Hostname/IP MikroTik").as_ptr() as isize,
        );
        self.button(
            "Baca MikroTik",
            INTEL_ROUTER,
            Some(Page::Intel),
            [-510, 226, 124, 36],
        )?;
        self.button(
            "Uji HTTPS PC ini",
            INTEL_PROBE,
            Some(Page::Intel),
            [-378, 226, 147, 36],
        )?;
        self.button(
            "Impor bukti",
            INTEL_IMPORT,
            Some(Page::Intel),
            [-223, 226, 100, 36],
        )?;
        self.button(
            "Detail",
            INTEL_DETAILS,
            Some(Page::Intel),
            [-115, 226, 87, 36],
        )?;
        self.table(
            INTEL_TABLE,
            Page::Intel,
            [228, 273, -256, -391],
            &[
                "Objek / Sumber",
                "Tujuan / Cakupan",
                "Status / Bukti",
                "Detail ringkas",
            ],
        )?;
        self.text(
            "Pilih Data Windows atau tambahkan sumber data yang berizin.",
            INTEL_STATUS,
            Some(Page::Intel),
            0,
            [228, -113, -554, 30],
        )?;
        self.checkbox("Samarkan", INTEL_REDACT, Page::Intel, [228, -80, 130, 24])?;
        send_native(self.h(INTEL_REDACT), BM_SETCHECK, 1, 0);
        self.button(
            "Ekspor Akses CSV",
            INTEL_EXPORT,
            Some(Page::Intel),
            [365, -82, 126, 30],
        )?;
        self.button(
            "Flow UDP…",
            INTEL_FLOW,
            Some(Page::Intel),
            [498, -82, 81, 30],
        )?;
        self.button("Stop", INTEL_STOP, Some(Page::Intel), [586, -82, 49, 30])?;
        self.button(
            "Simpan",
            INTEL_RECORD,
            Some(Page::Intel),
            [642, -82, 72, 30],
        )?;
        self.button(
            "Histori",
            INTEL_HISTORY,
            Some(Page::Intel),
            [721, -82, 82, 30],
        )?;
        self.button(
            "Detail IP",
            INTEL_IP_JOURNEY,
            Some(Page::Intel),
            [-217, -121, 90, 25],
        )?;
        self.button(
            "Kembali",
            INTEL_BACK,
            Some(Page::Intel),
            [-319, -121, 94, 25],
        )?;
        self.button(
            "Lanjut",
            INTEL_MORE,
            Some(Page::Intel),
            [-119, -121, 91, 25],
        )?;
        unsafe {
            ShowWindow(self.h(INTEL_MORE), SW_HIDE);
            ShowWindow(self.h(INTEL_IP_JOURNEY), SW_HIDE);
            ShowWindow(self.h(INTEL_BACK), SW_HIDE);
        }
        Ok(())
    }
    fn primary_archive_path(&self) -> Result<PathBuf> {
        self.intel
            .archive_override
            .clone()
            .map_or_else(store::default_path, Ok)
    }
    fn archive_path(&self) -> Result<PathBuf> {
        self.intel
            .recovery_view
            .clone()
            .map_or_else(|| self.primary_archive_path(), Ok)
    }
    fn load_storage(&mut self) -> Result<()> {
        let path = self.archive_path()?;
        if selection(self.h(INTEL_MODE)) == DASHBOARD_MODE {
            self.intel.storage = None;
            self.intel.storage_loaded = false;
            self.render_intel();
        }
        self.start_intel(move || {
            let info = if path.try_exists().map_err(|e| e.to_string())? {
                Some(Box::new(Archive::reader(&path)?.health(&path)?))
            } else {
                None
            };
            Ok(IntelReply::Storage(info))
        })
    }
    fn invalidate_archive_views(&mut self) {
        self.intel.archived = None;
        self.intel.archive_query = None;
        self.intel.device = None;
        self.intel.pivot_scope = None;
        self.intel.history = None;
        self.intel.router_history = None;
        self.intel.storage_loaded = false;
        self.intel.storage = None;
        self.intel.alert_rows.clear();
        self.intel.alert_path = None;
    }
    fn storage_action(&mut self, id: i32) -> Result<bool> {
        const FILTER: &str = "SQLite WFS (*.sqlite3)\0*.sqlite3\0";
        let read_only = self.intel.recovery_view.is_some();
        match id {
            INTEL_SEARCH => self.load_storage()?,
            INTEL_RESET_FILTER => {
                self.intel.recovery_view = None;
                set(self.h(INTEL_FILTER), "");
                self.invalidate_archive_views();
                self.load_storage()?;
            }
            INTEL_EXPORT => {
                let src = self.archive_path()?;
                if let Some(dest) =
                    typed_file_dialog(self.hwnd, true, "WFS-Backup.sqlite3", FILTER, "sqlite3")?
                    && popup(
                        self.hwnd,
                        "Simpan backup metadata tanpa penyamaran ke file baru?",
                        MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING,
                    ) == IDYES
                {
                    check_recovery_destination(&dest, &self.primary_archive_path()?)?;
                    self.start_intel(move || {
                        Archive::reader(&src)?.backup_to(&dest)?;
                        Ok(IntelReply::BackupSaved(dest))
                    })?;
                }
            }
            INTEL_RECORD if !read_only => {
                let cfg = Policy::parse(&get(self.h(INTEL_FILTER)))?;
                if popup(
                    self.hwnd,
                    &format!(
                        "Simpan pengaturan ini?\n\n{}\n\nCollector akan menghapus hanya record yang melewati retensi pada siklus perawatan berikutnya. Backup dahulu bila perlu.",
                        cfg.summary()
                    ),
                    MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING,
                ) == IDYES
                {
                    let path = self.primary_archive_path()?;
                    self.start_intel(move || {
                        Archive::writer(&path)?.save_policy(cfg)?;
                        Ok(IntelReply::PolicySaved(cfg))
                    })?;
                }
            }
            INTEL_IMPORT if !read_only => {
                if popup(
                    self.hwnd,
                    "Salin snapshot JSON lokal yang masih dalam retensi lama ke SQLite? File sumber tidak diubah.",
                    MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION,
                ) == IDYES
                {
                    let path = self.primary_archive_path()?;
                    self.start_intel(move || {
                        let h = history::load(&history::default_dir()?, ni::now())?;
                        let n = if h.snapshots.is_empty() {
                            0
                        } else {
                            Archive::writer(&path)?.import(&h.snapshots)?
                        };
                        Ok(IntelReply::SnapshotsImported(n))
                    })?;
                }
            }
            INTEL_HOST | INTEL_FILTER => return Ok(false),
            INTEL_ROUTER => {
                if let Some(path) = typed_file_dialog(self.hwnd, false, "", FILTER, "sqlite3")? {
                    self.start_intel(move || {
                        let plan = RecoveryPlan::inspect(&path)?;
                        Ok(IntelReply::RecoveryPreview(path, plan))
                    })?;
                }
            }
            INTEL_PROBE if !read_only && self.intel.collector.is_none() => {
                let raw = get(self.h(INTEL_FILTER));
                let mut fields = raw.split_ascii_whitespace();
                let kind = Kind::parse(fields.next().unwrap_or_default())?;
                let start = fields
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("Masukkan UTC awal dalam detik Unix.")?;
                let end = fields
                    .next()
                    .and_then(|v| v.parse().ok())
                    .ok_or("Masukkan UTC akhir dalam detik Unix.")?;
                if fields.next().is_some() {
                    return Err("Gunakan: flow|snapshot UTC-awal UTC-akhir.".into());
                }
                let path = self.primary_archive_path()?;
                self.start_intel(move || {
                    Archive::reader(&path)?
                        .preview_delete(kind, start, end)
                        .map(IntelReply::DeletePreview)
                })?;
            }
            INTEL_RECORD | INTEL_IMPORT | INTEL_PROBE => {
                return Err(
                    "Tindakan tidak tersedia pada salinan atau saat collector aktif.".into(),
                );
            }
            _ => return Ok(false),
        }
        Ok(true)
    }
    fn load_archive(&mut self, q: Query, cursor: Option<Cursor>) -> Result<()> {
        let path = self.archive_path()?;
        self.start_intel(move || {
            let p = if path.try_exists().map_err(|e| e.to_string())? {
                Archive::reader(&path)?.page(&q, cursor, store::PAGE_SIZE)?
            } else {
                store::Page {
                    rows: vec![],
                    next: None,
                }
            };
            Ok(IntelReply::Archive(p, Box::new(q)))
        })
    }
    fn load_device(&mut self) -> Result<()> {
        let applied_input = self.intel.device_input.clone();
        let q = Query::parse(&applied_input)?;
        q.ip.ok_or("Masukkan satu alamat IP, misalnya ip=192.0.2.21.")?;
        let path = self.archive_path()?;
        self.start_intel(move || {
            let view = if path.try_exists().map_err(|e| e.to_string())? {
                Archive::reader(&path)?.inspect(&q, ni::now())?
            } else {
                Inspection::default()
            };
            Ok(IntelReply::Device(view, Box::new(q), applied_input))
        })
    }
    fn selected_intel_row(&self) -> Option<usize> {
        usize::try_from(send_native(
            self.h(INTEL_TABLE),
            LVM_GETNEXTITEM,
            usize::MAX,
            LVNI_SELECTED as isize,
        ))
        .ok()
    }
    fn apply_router(&mut self, (s, topology, inventory): RouterData) {
        self.intel
            .network_views
            .insert(s.authority.clone(), (topology, inventory));
        self.intel
            .trends
            .entry(s.authority.clone())
            .or_default()
            .observe(&s);
        self.intel
            .lease_timelines
            .entry(s.authority.clone())
            .or_default()
            .observe(&s);
        if let Some(old) = self.intel.routers.insert(s.authority.clone(), s) {
            if let Some(baseline) = InterfaceBaseline::capture(&old) {
                self.intel
                    .previous_interfaces
                    .insert(old.authority.clone(), baseline);
            } else {
                self.intel.previous_interfaces.remove(&old.authority);
            }
        }
    }
    fn poll_router_step(&mut self) {
        let now = std::time::Instant::now();
        if let Some(rx) = &self.intel.poll_rx {
            let reply = match rx.try_recv() {
                Ok(reply) => reply,
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => Err(Outcome::Other),
            };
            self.intel.poll_rx = None;
            let key = self
                .intel
                .schedule
                .active_key()
                .unwrap_or_default()
                .to_owned();
            let outcome = match &reply {
                Ok((_, status, _)) => *status,
                Err(status) => *status,
            };
            if self.intel.schedule.complete(now, outcome) {
                if outcome.terminal() {
                    self.intel.poll_auth.remove(&key);
                }
                self.intel.poll_save_errors.remove(&key);
                if let Ok((data, _, warning)) = reply {
                    self.apply_router(data);
                    if let Some(w) = warning {
                        self.intel.poll_save_errors.insert(key, w);
                    }
                }
            }
            if self.page == Page::Intel
                && self.intel.router_history.is_none()
                && matches!(
                    selection(self.h(INTEL_MODE)),
                    POLL_MODE
                        | 5
                        | TOPOLOGY_MODE
                        | IPAM_MODE
                        | TREND_MODE
                        | LEASE_MODE
                        | DASHBOARD_MODE
                        | SUBNET_MODE
                )
                && self.intel.work.is_none()
            {
                self.render_intel();
                self.controls();
            }
        }
        if self.intel.work.is_some() {
            return;
        }
        let Some((key, cancel)) = self.intel.schedule.next(now) else {
            return;
        };
        let Some((authority, auth)) = self.intel.poll_auth.get(&key).cloned() else {
            self.intel.schedule.stop(&key);
            self.intel.schedule.complete(now, Outcome::Other);
            return;
        };
        let path = self.primary_archive_path();
        let (tx, rx) = mpsc::channel();
        let worker=thread::Builder::new().name("wfs-router-poll".into()).spawn(move||{
            let result=nw::router_snapshot_cancel(&authority,&auth,&cancel).map_err(|e|Outcome::from_failure(&e)).map(|s|{
                let outcome=if s.coverage.iter().all(|c|c.state==ni::CoverageState::CompleteSnapshot) {Outcome::Complete} else {Outcome::Partial};
                let archive=cancel.check().and_then(|_|{
                    let path=path?;
                    let mut db=Archive::writer(&path)?;
                    cancel.check()?;
                    db.save_router_sample(&Sample::capture(&s))
                });
                let data=prepare_router(s);
                (data,outcome,archive.err().map(|_|"Histori tidak tersimpan. Periksa izin, kuota atau kunci SQLite.".into()))
            });
            let _=tx.send(result);
        });
        if worker.is_ok() {
            self.intel.poll_rx = Some(rx);
        } else {
            self.intel.schedule.complete(now, Outcome::Other);
        }
        if self.page == Page::Intel
            && matches!(selection(self.h(INTEL_MODE)), POLL_MODE | DASHBOARD_MODE)
        {
            self.render_intel();
            self.controls();
        }
    }
    fn configure_polling(&mut self) -> Result<()> {
        let authority = Authority::parse(&get(self.h(INTEL_HOST)))?;
        let key = authority.display();
        let interval = get(self.h(INTEL_FILTER));
        let seconds = if interval.trim().is_empty() {
            120
        } else {
            interval
                .trim()
                .parse::<u64>()
                .map_err(|_| "Interval polling berupa detik.")?
        };
        if !(ni::polling::MIN_INTERVAL..=3600).contains(&seconds) {
            return Err("Interval polling harus 60–3600 detik.".into());
        }
        if self.intel.schedule.active_key() == Some(key.as_str()) {
            return Err("Tunggu permintaan target selesai sebelum mengatur ulang.".into());
        }
        let known = self
            .intel
            .routers
            .keys()
            .chain(self.intel.schedule.jobs.keys())
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        if known.len() >= ni::polling::MAX_TARGETS && !known.contains(key.as_str()) {
            return Err("Maksimal delapan router dalam satu sesi.".into());
        }
        if popup(
            self.hwnd,
            &format!(
                "Aktifkan pembacaan HTTPS GET ke {key} setiap {seconds} detik atau lebih? Sampel interface dan DHCP akan disimpan lokal. Kata sandi hanya tersimpan selama jadwal aktif."
            ),
            MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION,
        ) == IDYES
            && let Some(auth) = ask_router_credentials(self.hwnd, &authority)?
        {
            self.intel
                .schedule
                .configure(key.clone(), seconds, std::time::Instant::now())?;
            self.intel
                .poll_auth
                .insert(key, (authority, std::sync::Arc::new(auth)));
            self.render_intel();
        }
        Ok(())
    }
    fn archived_router_views(&mut self) -> Result<()> {
        let authority = Authority::parse(&get(self.h(INTEL_HOST)))?;
        let key = authority.display();
        let raw = get(self.h(INTEL_FILTER));
        let limits = raw
            .split_ascii_whitespace()
            .map(str::parse::<u64>)
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| "Rentang memakai dua angka detik Unix UTC.")?;
        let (since, until) = match limits.as_slice() {
            [] => (0, ni::now()),
            [s, e] => (*s, *e),
            _ => {
                return Err(
                    "Masukkan UTC awal dan akhir, atau kosongkan untuk retensi aktif.".into(),
                );
            }
        };
        let path = self.archive_path()?;
        self.start_intel(move || {
            let views = if path.try_exists().map_err(|e| e.to_string())? {
                Archive::reader(&path)?.router_history(&authority, since, until)?
            } else {
                Views::default()
            };
            Ok(IntelReply::RouterHistory(key, Box::new(views)))
        })
    }
    fn load_alerts(&mut self, filter: String) -> Result<()> {
        let path = self.archive_path()?;
        self.intel.alert_rows.clear();
        self.intel.alert_path = None;
        self.start_intel(move || {
            let rows = if path.try_exists().map_err(|e| e.to_string())? {
                Archive::reader(&path)?.alert_page(&filter)?
            } else {
                Vec::new()
            };
            Ok(IntelReply::Alerts(path, rows))
        })?;
        // Clear stale rows from the previous mode while the worker is running.
        self.render_intel();
        Ok(())
    }
    fn intel_mode_labels(&self, mode: usize) {
        let storage = mode == STORAGE_MODE;
        for (id, active, regular) in [
            (
                INTEL_EXPORT,
                "Backup SQLite…",
                if mode == ARCHIVE_MODE {
                    "Ekspor arsip…"
                } else {
                    "Ekspor Akses CSV"
                },
            ),
            (INTEL_SEARCH, "Muat", "Cari"),
            (INTEL_RESET_FILTER, "Reset", "Reset"),
            (INTEL_ROUTER, "Pulihkan salinan…", "Baca MikroTik"),
            (INTEL_PROBE, "Tinjau hapus…", "Uji HTTPS PC ini"),
            (INTEL_IMPORT, "Impor JSON", "Impor bukti"),
            (INTEL_RECORD, "Atur", "Simpan"),
            (INTEL_HISTORY, "Histori", "Histori"),
        ] {
            set(self.h(id), if storage { active } else { regular });
        }
        set(
            self.h(INTEL_IP_JOURNEY),
            match mode {
                DEVICE_MODE => "Koneksi",
                DASHBOARD_MODE => "Buka modul",
                _ => "Detail IP",
            },
        );
        if mode == POLL_MODE {
            set(self.h(INTEL_ROUTER), "Mulai polling");
            set(self.h(INTEL_PROBE), "Hentikan target");
        }
        if matches!(mode, TREND_MODE | LEASE_MODE) {
            set(self.h(INTEL_HISTORY), "Arsip UTC");
            set(self.h(INTEL_RECORD), "Sampel");
        }
        if mode == ALERT_MODE {
            set(self.h(INTEL_RECORD), "Akui");
        }
        send_native(
            self.h(INTEL_FILTER),
            EM_SETCUEBANNER,
            0,
            w::wide(match mode {
                ARCHIVE_MODE => "ip=… port=… site=…",
                DEVICE_MODE => "ip=… site=… since=…",
                STORAGE_MODE => "30 7 256  |  flow UTC-awal UTC-akhir",
                POLL_MODE => "Interval detik (default 120)",
                TREND_MODE | LEASE_MODE => "Filter sesi atau dua detik UTC untuk Arsip",
                ALERT_MODE => "state=open/ack/recovered + site/VRF",
                DASHBOARD_MODE | SUBNET_MODE => "Cari sumber, scope atau subnet",
                _ => "Cari IP, port, PID…",
            })
            .as_ptr() as isize,
        );
    }
    fn start_intel(&mut self, task: impl FnOnce() -> IntelResult + Send + 'static) -> Result<()> {
        let (tx, rx) = mpsc::channel();
        thread::Builder::new()
            .name("wfs-network-observation".into())
            .spawn(move || {
                let _ = tx.send(task());
            })
            .map_err(|e| format!("Tidak bisa memulai pekerjaan analisis: {e}"))?;
        self.intel.work = Some(rx);
        self.set_notice("Mengambil data analisis…");
        self.controls();
        Ok(())
    }
    fn finish_intel(&mut self) {
        let Some(rx) = &self.intel.work else { return };
        let result = match rx.try_recv() {
            Ok(v) => v,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err("Pekerjaan analisis terhenti.".into()),
        };
        self.intel.work = None;
        let mut notice = None;
        let mut reload_storage = false;
        match result {
            Ok(IntelReply::RouterHistory(key, views)) => {
                self.intel.filter.clear();
                self.intel.router_history = Some((key, views));
            }
            Ok(IntelReply::RouterArchived) => {
                notice = Some(Notice::Information(
                    "Sampel tren dan lease disimpan ke arsip utama.".into(),
                ))
            }
            Ok(IntelReply::Local(s)) => self.intel.local = Some(s),
            Ok(IntelReply::Probe(p)) => {
                let (snapshot, probe) = *p;
                let message = format_probe(&probe);
                notice = Some(match probe.outcome {
                    ni::ProbeOutcome::Verified => Notice::Information(message),
                    ni::ProbeOutcome::TransportError => Notice::Error(message),
                    _ => Notice::Warning(message),
                });
                self.intel.local = Some(Box::new(snapshot));
                self.intel.probe = Some(probe);
                select(self.h(INTEL_MODE), 0);
            }
            Ok(IntelReply::Router((s, topology, inventory))) => {
                self.apply_router((s, topology, inventory));
                if !matches!(
                    selection(self.h(INTEL_MODE)),
                    TOPOLOGY_MODE
                        | IPAM_MODE
                        | TREND_MODE
                        | LEASE_MODE
                        | DASHBOARD_MODE
                        | SUBNET_MODE
                ) {
                    select(self.h(INTEL_MODE), 6);
                }
            }
            Ok(IntelReply::Import(i)) => {
                self.intel.imported = Some(i);
                select(self.h(INTEL_MODE), 0);
            }
            Ok(IntelReply::Collector(c)) => {
                self.intel.alert_rows.clear();
                self.intel.alert_path = None;
                self.intel.collector = Some(c);
                select(self.h(INTEL_MODE), 13);
            }
            Ok(IntelReply::Stopped(stats)) => {
                self.intel.alert_rows.clear();
                self.intel.alert_path = None;
                let summary = format!(
                    "Collector dihentikan. Arsip ditulis {} · duplikat {} · drop {} · tertunda {}.",
                    stats.archived,
                    stats.archive_duplicate,
                    stats.archive_dropped,
                    stats.archive_pending
                );
                let errors = [
                    stats.error.as_deref(),
                    stats.archive_error.as_deref(),
                    stats.alert_error.as_deref(),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
                if !errors.is_empty() || stats.archive_dropped != 0 || stats.archive_pending != 0 {
                    notice = Some(Notice::Warning(format!(
                        "{summary}\nHistori mungkin parsial.\n{}",
                        errors.join("\n")
                    )));
                } else {
                    self.set_notice(&summary);
                }
            }
            Ok(IntelReply::Alerts(path, rows)) => {
                if self.archive_path().is_ok_and(|current| current == path) {
                    self.intel.alert_path = Some(path);
                    self.intel.alert_rows = rows;
                }
            }
            Ok(IntelReply::Archive(p, q)) => {
                self.intel.archived = Some(p);
                self.intel.archive_query = Some(*q);
            }
            Ok(IntelReply::Device(view, q, applied_input)) => {
                self.intel.device_applied_input = applied_input;
                self.intel.device = Some((view, *q));
            }
            Ok(IntelReply::Storage(info)) => {
                self.intel.storage = info;
                self.intel.storage_loaded = true;
            }
            Ok(IntelReply::PolicySaved(cfg)) => {
                reload_storage = true;
                notice = Some(Notice::Information(format!(
                    "Pengaturan disimpan.\n{}",
                    cfg.summary()
                )));
            }
            Ok(IntelReply::BackupSaved(path)) => {
                notice = Some(Notice::Information(format!(
                    "Backup terverifikasi: {}",
                    path.display()
                )));
            }
            Ok(IntelReply::RecoveryPreview(source, plan)) => {
                let message = format!(
                    "Salinan valid: {} flow dan {} snapshot.\n\nSimpan sebagai file baru dan buka sebagai arsip baca-saja? Arsip utama tidak akan ditimpa.",
                    plan.flows, plan.snapshots
                );
                let next = (|| -> Result<()> {
                    if popup(
                        self.hwnd,
                        &message,
                        MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION,
                    ) == IDYES
                        && let Some(dest) = typed_file_dialog(
                            self.hwnd,
                            true,
                            "WFS-Recovery.sqlite3",
                            "SQLite WFS (*.sqlite3)\0*.sqlite3\0",
                            "sqlite3",
                        )?
                    {
                        check_recovery_destination(&dest, &self.primary_archive_path()?)?;
                        self.start_intel(move || {
                            plan.recover(&source, &dest)?;
                            Ok(IntelReply::RecoverySaved(dest))
                        })?;
                    }
                    Ok(())
                })();
                if let Err(e) = next {
                    notice = Some(Notice::Error(e));
                }
            }
            Ok(IntelReply::RecoverySaved(path)) => {
                self.invalidate_archive_views();
                self.intel.recovery_view = Some(path.clone());
                reload_storage = true;
                notice = Some(Notice::Information(format!(
                    "Salinan dipulihkan dan dibuka baca-saja: {}",
                    path.display()
                )));
            }
            Ok(IntelReply::DeletePreview(plan)) => {
                if plan.count == 0 {
                    notice = Some(Notice::Information(
                        "Tidak ada record dalam rentang tersebut.".into(),
                    ));
                } else {
                    let message = format!(
                        "Hapus {} record {:?} dengan waktu terima/observasi {}–{} (Unix UTC)?\n\nTindakan ini tidak menghapus file JSON lama dan dibatalkan jika isi rentang berubah. Buat backup bila dibutuhkan.",
                        plan.count, plan.kind, plan.start, plan.end
                    );
                    let next = (|| -> Result<()> {
                        if popup(
                            self.hwnd,
                            &message,
                            MB_YESNO | MB_DEFBUTTON2 | MB_ICONWARNING,
                        ) == IDYES
                        {
                            let path = self.primary_archive_path()?;
                            self.start_intel(move || {
                                Archive::writer(&path)?
                                    .delete_reviewed(&plan)
                                    .map(IntelReply::Deleted)
                            })?;
                        }
                        Ok(())
                    })();
                    if let Err(e) = next {
                        notice = Some(Notice::Error(e));
                    }
                }
            }
            Ok(IntelReply::Deleted(count)) => {
                self.invalidate_archive_views();
                reload_storage = true;
                notice = Some(Notice::Information(format!(
                    "{count} record arsip dihapus."
                )));
            }
            Ok(IntelReply::SnapshotsImported(count)) => {
                self.intel.history = None;
                reload_storage = true;
                notice = Some(Notice::Information(format!(
                    "{count} snapshot baru disalin ke SQLite."
                )));
            }
            Ok(IntelReply::ArchiveExport(path, out)) => {
                let suffix = if out.truncated {
                    "\nBatas 10.000 baris tercapai. Persempit filter untuk sisa data."
                } else {
                    ""
                };
                let msg = format!("{} baris disimpan di {}{suffix}", out.total, path.display());
                notice = Some(if out.truncated {
                    Notice::Warning(msg)
                } else {
                    Notice::Information(msg)
                });
            }
            Ok(IntelReply::History(h)) => {
                self.intel.history = Some(h);
                select(self.h(INTEL_MODE), 11);
            }
            Ok(IntelReply::Export(path)) => {
                notice = Some(Notice::Information(format!(
                    "Laporan CSV disimpan di {}",
                    path.display()
                )))
            }
            Err(e) if self.intel.storage_smoke => self.intel.storage_smoke_error = Some(e),
            Err(e) => notice = Some(Notice::Error(e)),
        }
        self.intel.mode = selection(self.h(INTEL_MODE));
        self.intel_mode_labels(self.intel.mode);
        if self.intel.work.is_none() {
            self.set_notice("Siap.");
        }
        self.render_intel();
        self.controls();
        if let Some(message) = notice {
            self.present_notice(message);
        }
        if reload_storage && let Err(e) = self.load_storage() {
            self.present_notice(Notice::Error(e));
        }
    }
    fn intel_action(&mut self, id: i32) -> Result<()> {
        if selection(self.h(INTEL_MODE)) == STORAGE_MODE && self.storage_action(id)? {
            return Ok(());
        }
        match id {
            INTEL_MODE => {
                let mode = selection(self.h(INTEL_MODE));
                if mode != self.intel.mode {
                    self.intel.router_history = None;
                    self.intel.previous_mode = None;
                    self.intel.pivot_scope = None;
                    self.intel.filter.clear();
                    if mode == ALERT_MODE {
                        self.intel.alert_rows.clear();
                        self.intel.alert_path = None;
                    }
                    let input = if mode == DEVICE_MODE {
                        self.intel.device_input.as_str()
                    } else {
                        ""
                    };
                    set(self.h(INTEL_FILTER), input);
                    self.intel.mode = mode;
                }
                self.intel_mode_labels(mode);
                if mode == ARCHIVE_MODE {
                    self.intel.archived = None;
                    self.intel.archive_query = None;
                    self.load_archive(Query::default(), None)?;
                } else if matches!(mode, STORAGE_MODE | DASHBOARD_MODE) {
                    self.load_storage()?;
                } else if mode == ALERT_MODE {
                    self.load_alerts(self.intel.filter.clone())?;
                } else {
                    self.render_intel();
                }
            }
            INTEL_SEARCH | INTEL_RESET_FILTER => {
                if id == INTEL_RESET_FILTER {
                    self.intel.router_history = None;
                    set(self.h(INTEL_FILTER), "");
                }
                let input = get(self.h(INTEL_FILTER));
                match selection(self.h(INTEL_MODE)) {
                    ARCHIVE_MODE => {
                        let mut q = Query::parse(&input)?;
                        if self.intel.pivot_scope.is_some()
                            && let Some(scope) = self.intel.archive_query.as_ref()
                        {
                            // In a pivot the immutable scope and IP cannot be broadened from the edit box.
                            q.ip = scope.ip;
                            q.site.clone_from(&scope.site);
                            q.vrf.clone_from(&scope.vrf);
                            q.without_vrf = scope.without_vrf;
                            q.profile.clone_from(&scope.profile);
                            q.exporter = scope.exporter;
                            q.domain = scope.domain;
                        }
                        self.intel.filter = input;
                        self.load_archive(q, None)?;
                    }
                    DEVICE_MODE => {
                        self.intel.device_input = input;
                        if id == INTEL_RESET_FILTER {
                            self.intel.device = None;
                            self.render_intel();
                        } else {
                            self.load_device()?;
                        }
                    }
                    POLL_MODE => self.render_intel(),
                    DASHBOARD_MODE => {
                        self.intel.filter = input;
                        self.load_storage()?;
                    }
                    ALERT_MODE => {
                        self.intel.filter = input.clone();
                        self.load_alerts(input)?;
                    }
                    _ => {
                        self.intel.filter = input;
                        self.render_intel();
                    }
                }
            }
            INTEL_MORE => {
                if let Some(next) = self.intel.archived.as_ref().and_then(|p| p.next)
                    && let Some(q) = &self.intel.archive_query
                {
                    self.load_archive(q.clone(), Some(next))?;
                }
            }
            INTEL_IP_JOURNEY => {
                let mode = selection(self.h(INTEL_MODE));
                let index = self
                    .selected_intel_row()
                    .ok_or("Pilih satu baris terlebih dahulu.")?;
                if mode == DASHBOARD_MODE {
                    let target = *self
                        .intel
                        .dashboard_targets
                        .get(index)
                        .ok_or("Pilih baris dashboard.")?;
                    select(self.h(INTEL_MODE), target);
                    self.intel_action(INTEL_MODE)?;
                } else if mode == DEVICE_MODE {
                    let (view, q) = self
                        .intel
                        .device
                        .as_ref()
                        .ok_or("Cari satu alamat IP dahulu.")?;
                    let scoped = view
                        .scopes
                        .get(index)
                        .ok_or("Pilih baris scope arsip, bukan bukti lokal.")?;
                    let override_query = scoped.scope.query(q);
                    let label = scoped.scope.label();
                    self.intel.archived = None;
                    self.intel.archive_query = Some(override_query.clone());
                    self.intel.pivot_scope = Some(label);
                    self.intel.filter = self.intel.device_applied_input.clone();
                    set(self.h(INTEL_FILTER), &self.intel.filter);
                    select(self.h(INTEL_MODE), ARCHIVE_MODE);
                    self.intel.mode = ARCHIVE_MODE;
                    self.intel_mode_labels(ARCHIVE_MODE);
                    self.render_intel();
                    self.load_archive(override_query, None)?;
                } else if matches!(mode, 0 | 1) {
                    let ip = self
                        .intel
                        .visible_ips
                        .get(index)
                        .copied()
                        .flatten()
                        .ok_or("Baris tidak memuat alamat IP.")?;
                    self.intel.previous_mode = Some((mode, self.intel.filter.clone()));
                    self.intel.device_input = format!("ip={ip}");
                    self.intel.device = None;
                    set(self.h(INTEL_FILTER), &self.intel.device_input);
                    select(self.h(INTEL_MODE), DEVICE_MODE);
                    self.intel.mode = DEVICE_MODE;
                    self.intel_mode_labels(DEVICE_MODE);
                    self.render_intel();
                    self.load_device()?;
                }
            }
            INTEL_BACK => {
                let mode = selection(self.h(INTEL_MODE));
                if mode == ARCHIVE_MODE && self.intel.pivot_scope.take().is_some() {
                    select(self.h(INTEL_MODE), DEVICE_MODE);
                    set(self.h(INTEL_FILTER), &self.intel.device_input);
                    self.intel.mode = DEVICE_MODE;
                } else if mode == DEVICE_MODE
                    && let Some((previous, filter)) = self.intel.previous_mode.take()
                {
                    select(self.h(INTEL_MODE), previous);
                    self.intel.mode = previous;
                    self.intel.filter = filter;
                    set(self.h(INTEL_FILTER), &self.intel.filter);
                }
                self.intel_mode_labels(self.intel.mode);
                self.render_intel();
            }
            INTEL_REFRESH => {
                self.start_intel(|| Ok(IntelReply::Local(Box::new(nw::local_snapshot()))))?
            }
            INTEL_PROBE if selection(self.h(INTEL_MODE)) == POLL_MODE => {
                let key = Authority::parse(&get(self.h(INTEL_HOST)))?.display();
                self.intel.schedule.stop(&key);
                self.intel.poll_auth.remove(&key);
                self.intel.poll_save_errors.remove(&key);
                self.render_intel();
            }
            INTEL_PROBE => {
                let text = format!(
                    "Uji HTTPS satu kali dari PC ini melalui rute Windows. Hasil hanya berlaku untuk IP sumber yang terukur dan tujuan ini.\n\n{}\n\nJalankan?",
                    nw::PROBE_TARGET
                );
                if popup(self.hwnd, &text, MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION) == IDYES {
                    self.start_intel(|| {
                        let probe = nw::probe_https();
                        Ok(IntelReply::Probe(Box::new((nw::local_snapshot(), probe))))
                    })?;
                }
            }
            INTEL_ROUTER if selection(self.h(INTEL_MODE)) == POLL_MODE => {
                self.configure_polling()?
            }
            INTEL_ROUTER => {
                if self.intel.schedule.active_key().is_some() {
                    return Err(
                        "Polling sedang aktif. Tunggu permintaan selesai atau hentikan target."
                            .into(),
                    );
                }
                let authority = Authority::parse(&get(self.h(INTEL_HOST)))?;
                let key = authority.display();
                let known = self
                    .intel
                    .routers
                    .keys()
                    .chain(self.intel.schedule.jobs.keys())
                    .map(String::as_str)
                    .collect::<std::collections::BTreeSet<_>>();
                if !known.contains(key.as_str()) && known.len() >= ni::polling::MAX_TARGETS {
                    return Err("Maksimal delapan router dalam satu sesi.".into());
                }
                if let Some(auth) = ask_router_credentials(self.hwnd, &authority)? {
                    self.intel.router_history = None;
                    self.start_intel(move || {
                        nw::router_snapshot(authority, auth)
                            .map(prepare_router)
                            .map(IntelReply::Router)
                    })?;
                }
            }
            INTEL_IMPORT => {
                if let Some(path) = typed_file_dialog(
                    self.hwnd,
                    false,
                    "",
                    "Bukti trafik JSON (*.json)\0*.json\0",
                    "json",
                )? {
                    self.start_intel(move || {
                        use std::io::Read;
                        let mut data = String::new();
                        std::fs::File::open(path)
                            .and_then(|f| f.take(8 * 1024 * 1024 + 1).read_to_string(&mut data))
                            .map_err(|e| format!("Gagal membaca bukti JSON: {e}"))?;
                        if data.len() > 8 * 1024 * 1024 {
                            return Err("Bukti JSON melebihi 8 MiB.".into());
                        }
                        TrafficImport::parse(data.trim_start_matches('\u{feff}'))
                            .map(IntelReply::Import)
                    })?;
                }
            }
            INTEL_FLOW => {
                if let Some(path) = typed_file_dialog(
                    self.hwnd,
                    false,
                    "",
                    "Profil collector JSON (*.json)\0*.json\0",
                    "json",
                )? {
                    let config = CollectorConfig::parse(&read_limited(&path, 16_384)?)?;
                    let peers = config
                        .profiles
                        .iter()
                        .map(|p| {
                            format!(
                                "{} / {} / domain {}",
                                p.id, p.config.exporter, p.config.observation_domain
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    let msg = format!(
                        "Buka listener UDP di {} untuk {} exporter?\n\n{peers}\n\nArsip utama mengikuti retensi yang dapat diubah di Penyimpanan arsip. UDP tidak autentik. Batasi firewall Windows ke alamat exporter yang terdaftar.",
                        config.bind,
                        config.profiles.len()
                    );
                    if popup(self.hwnd, &msg, MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) == IDYES {
                        self.start_intel(move || {
                            let path = store::default_path()?;
                            Collector::start_group(config, Some(&path)).map(IntelReply::Collector)
                        })?;
                    }
                }
            }
            INTEL_STOP => {
                if let Some(collector) = self.intel.collector.take() {
                    self.start_intel(move || Ok(IntelReply::Stopped(Box::new(collector.stop()))))?;
                }
            }
            INTEL_HISTORY if matches!(selection(self.h(INTEL_MODE)), TREND_MODE | LEASE_MODE) => {
                self.archived_router_views()?
            }
            INTEL_HISTORY => {
                let path = self.archive_path()?;
                let include_legacy = self.intel.recovery_view.is_none();
                self.start_intel(move || {
                    combined_history(ni::now(), &path, include_legacy).map(IntelReply::History)
                })?
            }
            INTEL_RECORD if matches!(selection(self.h(INTEL_MODE)), TREND_MODE | LEASE_MODE) => {
                if self.intel.recovery_view.is_some() {
                    return Err("Salinan pemulihan hanya baca.".into());
                }
                let key = Authority::parse(&get(self.h(INTEL_HOST)))?.display();
                let snapshot = self
                    .intel
                    .routers
                    .get(&key)
                    .ok_or("Baca router yang dimaksud terlebih dahulu.")?;
                let sample = Sample::capture(snapshot);
                let path = self.primary_archive_path()?;
                self.start_intel(move || {
                    Archive::writer(&path)?.save_router_sample(&sample)?;
                    Ok(IntelReply::RouterArchived)
                })?;
            }
            INTEL_RECORD if selection(self.h(INTEL_MODE)) == ALERT_MODE => {
                if self.intel.recovery_view.is_some() {
                    return Err("Salinan arsip hanya-baca.".into());
                }
                let path = self.primary_archive_path()?;
                if self.intel.alert_path.as_ref() != Some(&path) {
                    return Err("Muat ulang alert dari arsip utama.".into());
                }
                let row = self
                    .selected_intel_row()
                    .ok_or("Pilih alert yang ingin diakui.")?;
                let record = self
                    .intel
                    .alert_rows
                    .get(row)
                    .cloned()
                    .ok_or("Alert tidak tersedia.")?;
                let filter = self.intel.filter.clone();
                self.start_intel(move || {
                    let db = Archive::alert_writer(&path)?;
                    db.acknowledge_alert(&record, ni::now())?;
                    let rows = db.alert_page(&filter)?;
                    Ok(IntelReply::Alerts(path, rows))
                })?;
            }
            INTEL_RECORD => {
                let path = self.archive_path()?;
                if self.intel.recovery_view.is_some() {
                    return Err("Kembali ke arsip utama sebelum menyimpan snapshot.".into());
                }
                let mut snapshots = Vec::new();
                if let Some(local) = &self.intel.local {
                    snapshots.push(history::Snapshot::local(local));
                }
                snapshots.extend(
                    self.intel
                        .routers
                        .values()
                        .map(|r| history::Snapshot::router(r)),
                );
                if snapshots.is_empty() {
                    return Err("Belum ada snapshot Windows atau MikroTik.".into());
                }
                if popup(
                    self.hwnd,
                    "Simpan snapshot perangkat, alamat, layanan, dan interface ke folder data pengguna Windows? Arsip ini tidak disamarkan dan tidak memuat password.",
                    MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2,
                ) == IDYES
                {
                    self.start_intel(move || {
                        let dir = history::default_dir()?;
                        let now = ni::now();
                        for s in &snapshots {
                            history::save(&dir, s, now)?;
                        }
                        combined_history(now, &path, true).map(IntelReply::History)
                    })?;
                }
            }
            INTEL_DETAILS => {
                let i = send_native(
                    self.h(INTEL_TABLE),
                    LVM_GETNEXTITEM,
                    usize::MAX,
                    LVNI_SELECTED as isize,
                );
                if let Some(details) = self.intel.details.get(i as usize) {
                    self.present_notice(Notice::Information(details.clone()));
                } else {
                    self.present_notice(Notice::Information(
                        "Pilih baris untuk melihat sumber dan bukti.".into(),
                    ));
                }
            }
            INTEL_EXPORT => {
                if selection(self.h(INTEL_MODE)) == ARCHIVE_MODE {
                    let q = self
                        .intel
                        .archive_query
                        .clone()
                        .ok_or("Jalankan pencarian arsip dahulu.")?;
                    let Some(path) = typed_file_dialog(
                        self.hwnd,
                        true,
                        "WFS-Flow.csv",
                        "CSV (*.csv)\0*.csv\0JSON (*.json)\0*.json\0",
                        "",
                    )?
                    else {
                        return Ok(());
                    };
                    let format = match path
                        .extension()
                        .and_then(|e| e.to_str())
                        .map(str::to_ascii_lowercase)
                        .as_deref()
                    {
                        Some("csv") => ExportFormat::Csv,
                        Some("json") => ExportFormat::Json,
                        _ => {
                            return Err("Pilih nama berkas dengan ekstensi .csv atau .json.".into());
                        }
                    };
                    let redact = checked(self.h(INTEL_REDACT));
                    let archive_path = self.archive_path()?;
                    self.start_intel(move || {
                        let mut db = Archive::reader(&archive_path)?;
                        let mut f = std::fs::OpenOptions::new()
                            .create_new(true)
                            .write(true)
                            .open(&path)
                            .map_err(|e| e.to_string())?;
                        let result = {
                            let mut out = std::io::BufWriter::new(&mut f);
                            use std::io::Write;
                            db.export(&q, format, redact, &mut out)
                                .and_then(|s| out.flush().map(|_| s).map_err(|e| e.to_string()))
                        }
                        .and_then(|s| f.sync_all().map(|_| s).map_err(|e| e.to_string()));
                        if result.is_err() {
                            drop(f);
                            let _ = std::fs::remove_file(&path);
                        }
                        result.map(|s| IntelReply::ArchiveExport(path, s))
                    })?;
                    return Ok(());
                }

                let mut rows = self.intel.assessments();
                rows.retain(|a| ni::assessment_matches(&self.intel.filter, a));
                if rows.is_empty() {
                    return Err("Belum ada baris Akses Internet untuk diekspor.".into());
                }
                if let Some(path) = analysis_csv_dialog(self.hwnd)? {
                    let redact = checked(self.h(INTEL_REDACT));
                    self.start_intel(move || {
                        use std::io::Write;
                        let mut file = std::fs::OpenOptions::new()
                            .create_new(true)
                            .write(true)
                            .open(&path)
                            .map_err(|e| format!("Pilih nama laporan baru: {e}"))?;
                        if let Err(e) = file
                            .write_all(ni::assessments_csv(&rows, redact).as_bytes())
                            .and_then(|_| file.sync_all())
                        {
                            drop(file);
                            let _ = std::fs::remove_file(&path);
                            return Err(format!("Gagal menulis laporan: {e}"));
                        }
                        Ok(IntelReply::Export(path))
                    })?;
                }
            }
            _ => unreachable!("unknown intelligence action"),
        }
        Ok(())
    }

    fn render_intel(&mut self) {
        let mode = selection(self.h(INTEL_MODE));
        let mut visible = Vec::new();
        let mut details = Vec::new();
        let mut matched = 0usize;
        let search = ni::Search::new(&self.intel.filter);
        let mut push = |values: [String; 4], detail: &dyn Fn() -> String| {
            let fields = values.each_ref().map(String::as_str);
            if matches!(mode, ARCHIVE_MODE | DEVICE_MODE | STORAGE_MODE | ALERT_MODE)
                || search.matches(&fields)
            {
                matched += 1;
                if visible.len() < INTEL_ROW_LIMIT {
                    visible.push(Vec::from(values));
                    details.push(detail());
                }
            }
        };
        let age = |stamp: u64| {
            if ni::now().saturating_sub(stamp) > ni::FRESH_SECONDS {
                "historis"
            } else {
                "snapshot"
            }
        };
        let detail_source = |c: &Coverage| {
            format!(
                "{}\nStatus: {:?}\nBaris: {}\nUTC (Unix): {}\n{}",
                c.source,
                c.state,
                c.rows,
                c.observed_at,
                c.detail
                    .as_deref()
                    .unwrap_or("Cakupan terbatas pada sumber dan waktu pengambilan.")
            )
        };
        let local = self.intel.local.as_deref();
        let mut dashboard_targets = Vec::new();
        let description = match mode {
            DASHBOARD_MODE => {
                let mut row = |values: [String; 4], detail: String, target: usize| {
                    if search.matches(&values.each_ref().map(String::as_str))
                        && dashboard_targets.len() < INTEL_ROW_LIMIT
                    {
                        dashboard_targets.push(target);
                    }
                    push(values, &|| detail.clone());
                };
                let now = ni::now();
                if let Some(s) = local {
                    let c = overview::coverage(&s.coverage, now);
                    row(
                        [
                            "Windows lokal".into(),
                            format!("{} alamat · {} cache", s.addresses.len(), s.neighbors.len()),
                            format!("{} lengkap / {} parsial", c.complete, c.partial),
                            format!("{} endpoint · UTC {}", s.endpoints.len(), s.observed_at),
                        ],
                        format!(
                            "{} sumber tidak tersedia, {} kedaluwarsa atau waktu ambigu. Cache bukan bukti perangkat online.",
                            c.unavailable, c.stale
                        ),
                        1,
                    );
                } else {
                    row(
                        [
                            "Windows lokal".into(),
                            "Belum dibaca".into(),
                            "Tidak diketahui".into(),
                            "Muat ulang".into(),
                        ],
                        "Gunakan Muat ulang untuk snapshot read-only PC ini.".into(),
                        1,
                    );
                }
                for (key, s) in &self.intel.routers {
                    let c = overview::coverage(&s.coverage, now);
                    let poll = self.intel.schedule.jobs.get(key);
                    row(
                        [
                            "MikroTik".into(),
                            key.clone(),
                            format!("{} lengkap / {} parsial / {} gagal", c.complete, c.partial, c.unavailable),
                            format!("{} observasi IP · UTC {}", s.inventory.len(), s.observed_at),
                        ],
                        format!(
                            "{} interface, {} koneksi, {} sumber historis/ambigu. Polling: {:?}. Tidak menyatakan router online dari snapshot.",
                            s.interfaces.len(), s.connections.len(), c.stale, poll.and_then(|p| p.outcome)
                        ),
                        5,
                    );
                    if let Some(trend) = self.intel.trends.get(key) {
                        for (name, points) in &trend.streams {
                            let summary = interface_trend::summarize(points);
                            if let Some(last) = points.back() {
                                row(
                                    [
                                        "Bandwidth interface".into(),
                                        format!("{key} / {name}"),
                                        format!("RX {} bps · TX {} bps", display_opt(last.rx_bps), display_opt(last.tx_bps)),
                                        format!("UTC {} · {} gap", last.utc, summary.gaps),
                                    ],
                                    format!(
                                        "P95 RX {} bps · TX {} bps. {} interval valid. Gap tidak dihitung nol; tidak menjumlahkan interface yang mungkin membawa trafik sama.",
                                        display_opt(summary.p95_rx), display_opt(summary.p95_tx), summary.valid_intervals
                                    ),
                                    TREND_MODE,
                                );
                            }
                        }
                    }
                }
                if let Some(c) = &self.intel.collector {
                    let stats = c.stats();
                    row(
                        [
                            "Collector Flow".into(),
                            format!("{} datagram", stats.accepted_datagrams),
                            format!("{} drop · {} antre", stats.archive_dropped, stats.archive_pending),
                            format!("{} record tersimpan", stats.archived),
                        ],
                        format!(
                            "Antrean penuh {} · writer tertutup {} · SQLite gagal {}. Error: {:?} / {:?} / {:?}. Tidak mengukur drop kernel.",
                            stats.archive_queue_full, stats.archive_writer_closed, stats.archive_sqlite_failed,
                            stats.error, stats.archive_error, stats.alert_error
                        ),
                        13,
                    );
                    for (scope, stats) in c.source_stats() {
                        row(
                            [
                                "Exporter".into(),
                                scope,
                                format!("{} diterima", stats.accepted_datagrams),
                                format!("{} template hilang · UTC {}", stats.missing_templates, display_opt(stats.last_received)),
                            ],
                            "Counter sesi per profil/domain; tidak membuktikan keterjangkauan atau volume trafik unik.".into(),
                            13,
                        );
                    }
                } else {
                    row(
                        [
                            "Collector Flow".into(),
                            "Tidak aktif".into(),
                            "Tidak diketahui".into(),
                            "Mulai hanya dengan izin".into(),
                        ],
                        "Tidak ada penerimaan UDP pada sesi ini.".into(),
                        13,
                    );
                }
                if let Some(s) = &self.intel.storage {
                    row(
                        [
                            "Arsip SQLite".into(),
                            format!("{} record · {} scope", s.flow_records, s.source_scopes),
                            format!("{} snapshot", s.snapshots),
                            format!("UTC {}", s.measured_utc),
                        ],
                        format!(
                            "Snapshot arsip {}. Database {} byte, WAL {} byte. Muat ulang untuk pengukuran baru.",
                            if self.intel.recovery_view.is_some() { "baca-saja" } else { "utama" },
                            s.main_bytes, s.wal_bytes
                        ),
                        STORAGE_MODE,
                    );
                } else {
                    row(
                        [
                            "Arsip SQLite".into(),
                            "Belum tersedia".into(),
                            "Tidak diketahui".into(),
                            "Cari untuk membaca".into(),
                        ],
                        "Tidak ada hasil pengukuran arsip yang dapat ditampilkan.".into(),
                        STORAGE_MODE,
                    );
                }
                row(
                    [
                        "Alert Center".into(),
                        "Buka histori".into(),
                        "Bukan jumlah total".into(),
                        "Filter & ACK".into(),
                    ],
                    "Ledger dibaca ketika modul dibuka; tidak menggunakan jumlah halaman terfilter sebagai jumlah semua alert.".into(),
                    ALERT_MODE,
                );
                row(
                    [
                        "IPAM subnet".into(),
                        "IPv4 dan IPv6".into(),
                        "Observasi".into(),
                        "Buka modul".into(),
                    ],
                    "Inventaris berdasarkan interface, bukan daftar alamat bebas.".into(),
                    SUBNET_MODE,
                );
                "Dashboard snapshot. Pilih baris dan Buka modul. Tidak ada klaim jaringan sehat dari data yang tidak tersedia."
            }
            SUBNET_MODE => {
                let mut groups = Vec::new();
                if let Some(s) = local {
                    groups.push(overview::local_subnets(s));
                }
                groups.extend(self.intel.routers.values().map(|s| network_map::subnets(s)));
                let limited = groups.iter().any(|g| g.limited);
                for r in groups.iter().flat_map(|g| &g.rows) {
                    push(
                        [
                            r.prefix.to_string(),
                            r.scope.clone(),
                            format!("{} konfigurasi · {} IP teramati", r.configured, r.observed),
                            if r.partial {
                                "Cakupan parsial"
                            } else {
                                "Snapshot sumber"
                            }
                            .into(),
                        ],
                        &|| format!(
                            "Subnet {} · {}\n{} alamat dalam prefix (termasuk alamat khusus). {} konfigurasi interface; {} IP unik teramati pada scope. UTC {}. Tidak teramati ≠ bebas. Tidak ada pemindaian atau reservasi otomatis. Prefix bertumpang tindih tidak dijumlahkan.",
                            r.prefix, r.scope, r.prefix.cardinality(), r.configured, r.observed, r.observed_at
                        ),
                    );
                }
                if limited {
                    "Batas 512 prefix per sumber tercapai. Hasil parsial. Tidak teramati bukan berarti bebas."
                } else {
                    "Subnet per interface IPv4/IPv6. Hitung IP teramati, bukan utilisasi pasti atau alamat bebas."
                }
            }
            0 => {
                for a in self.intel.assessments() {
                    push(
                        [
                            a.ip.to_string(),
                            a.scope.clone(),
                            a.access.to_string(),
                            a.evidence.clone(),
                        ],
                        &|| {
                            format!(
                                "IP {}\nCakupan: {}\nHasil: {}\nKebijakan: Tidak dapat disimpulkan\nBukti: {}\nUTC (Unix): {}",
                                a.ip, a.scope, a.access, a.evidence, a.observed_at
                            )
                        },
                    );
                }
                "Tidak terlihat bukan diblokir. Hasil probe hanya berlaku untuk IP sumber dan target yang tercatat."
            }
            1 => {
                if let Some(s) = local {
                    for a in &s.addresses {
                        push(
                            [
                                format!("{}/{}", a.ip, a.prefix),
                                format!("Windows / if#{}", a.interface_index),
                                "Alamat lokal".into(),
                                age(s.observed_at).into(),
                            ],
                            &|| {
                                format!(
                                    "Alamat {}/{}\nSumber: Windows Unicast IP\nInterface: {} · scope {}\nUTC (Unix): {}",
                                    a.ip, a.prefix, a.interface_index, a.scope_id, s.observed_at
                                )
                            },
                        );
                    }
                    for n in &s.neighbors {
                        push(
                            [
                                n.ip.to_string(),
                                format!("Windows / if#{}", n.interface_index),
                                format!("ARP/ND · {}", n.cache_state),
                                display_opt(n.mac),
                            ],
                            &|| {
                                format!(
                                    "Alamat {}\nSumber: cache Windows ARP/ND\nInterface: {} · scope {}\nMAC: {}\nUTC (Unix): {}\nBukan pemindaian jaringan atau bukti perangkat online.",
                                    n.ip,
                                    n.interface_index,
                                    n.scope_id,
                                    display_opt(n.mac),
                                    s.observed_at
                                )
                            },
                        );
                    }
                }
                for s in self.intel.routers.values() {
                    for n in &s.inventory {
                        let stamp = s
                            .coverage
                            .iter()
                            .find(|c| c.source == n.coverage_source())
                            .map_or(s.observed_at, |c| c.observed_at);
                        push(
                            [
                                n.ip.to_string(),
                                format!(
                                    "{} / {}",
                                    s.authority,
                                    n.location.as_deref().unwrap_or("—")
                                ),
                                format!("{} · {}", n.source, n.status.as_deref().unwrap_or("—")),
                                format!(
                                    "{} · {}",
                                    n.host_name.as_deref().unwrap_or("—"),
                                    display_opt(n.mac)
                                ),
                            ],
                            &|| {
                                format!(
                                    "IP {}\nRouter: {}\nSumber: {}\nLokasi: {}\nMAC: {}\nHostname: {}\nStatus: {}\nUTC (Unix): {}\nVRF tidak diketahui.",
                                    n.ip,
                                    s.authority,
                                    n.source,
                                    n.location.as_deref().unwrap_or("—"),
                                    display_opt(n.mac),
                                    n.host_name.as_deref().unwrap_or("—"),
                                    n.status.as_deref().unwrap_or("—"),
                                    stamp
                                )
                            },
                        );
                    }
                }
                "Inventaris dari alamat lokal, cache ARP/ND dan DHCP/ARP/ND router. Tidak memindai perangkat."
            }
            2 | 7 => {
                if let Some(s) = local {
                    for e in &s.endpoints {
                        if mode == 7
                            && !matches!(e.state, EndpointState::Listening | EndpointState::Bound)
                        {
                            continue;
                        }
                        let proto = format!("{:?}", e.protocol);
                        let remote = display_opt(e.remote);
                        let process = e.process.as_deref().unwrap_or("Nama tidak tersedia");
                        push(
                            [
                                e.local.to_string(),
                                remote.clone(),
                                format!("{proto} · {}", e.state),
                                format!("{process} · PID {}", e.pid),
                            ],
                            &|| {
                                format!(
                                    "Sumber: tabel {proto} PC ini\nLokal: {}\nRemote: {remote}\nStatus: {}\nProses: {process} · PID {}\nUTC (Unix): {}\nUDP lokal tidak memiliki tuple tujuan. Port tidak membuktikan jenis aplikasi atau akses dari luar.",
                                    e.local, e.state, e.pid, s.observed_at
                                )
                            },
                        );
                    }
                }
                if mode == 7 {
                    "Socket TCP listening dan UDP bound pada PC ini. Bukan bukti layanan dapat diakses dari luar."
                } else {
                    "Snapshot soket Windows. TCP menampilkan peer jika tersedia. UDP hanya menampilkan alamat bind."
                }
            }
            3 => {
                for s in self.intel.routers.values() {
                    let stamp = s
                        .coverage
                        .iter()
                        .find(|c| c.source == "RouterOS Connection Tracking IPv4")
                        .map_or(s.observed_at, |c| c.observed_at);
                    for c in &s.connections {
                        let status = format!(
                            "{} · {} · {}{}",
                            c.protocol,
                            c.tcp_state.as_deref().unwrap_or("—"),
                            if c.seen_reply == Some(true) {
                                "reply teramati"
                            } else {
                                "reply belum terbukti"
                            },
                            if c.source_nat == Some(true) || c.destination_nat == Some(true) {
                                " · NAT"
                            } else {
                                ""
                            }
                        );
                        push(
                            [
                                c.source.to_string(),
                                c.destination.to_string(),
                                status,
                                s.authority.clone(),
                            ],
                            &|| {
                                format!(
                                    "Sumber: conntrack IPv4 {}\nOriginal: {} → {}\nReply: {} → {}\nBytes original/reply: {} / {}\nSeen reply: {:?}\nSNAT/DNAT: {:?} / {:?}\nFastTrack/offload: {:?} / {:?}\nUTC (Unix): {}\nScope interface WAN dan VRF tidak tersedia. Conntrack saja bukan bukti akses internet.",
                                    s.authority,
                                    c.source,
                                    c.destination,
                                    display_opt(c.reply_source),
                                    display_opt(c.reply_destination),
                                    display_opt(c.original_bytes),
                                    display_opt(c.reply_bytes),
                                    c.seen_reply,
                                    c.source_nat,
                                    c.destination_nat,
                                    c.fasttrack,
                                    c.hw_offload,
                                    stamp
                                )
                            },
                        );
                    }
                }
                "Conntrack MikroTik IPv4, bukan riwayat flow lengkap atau bukti bahwa tujuan berada di WAN."
            }
            4 => {
                for s in self.intel.routers.values() {
                    let stamp = s
                        .coverage
                        .iter()
                        .find(|c| c.source == "RouterOS Interfaces")
                        .map_or(s.observed_at, |c| c.observed_at);
                    for i in &s.interfaces {
                        let rates = self
                            .intel
                            .previous_interfaces
                            .get(&s.authority)
                            .and_then(|old| interface_bitrate(old, s, &i.name))
                            .map_or_else(
                                || "Butuh dua snapshot".into(),
                                |(rx, tx)| {
                                    format!("RX {} / TX {} bit/s", display_opt(rx), display_opt(tx))
                                },
                            );
                        let counters = format!(
                            "RX {} / TX {} B",
                            display_opt(i.rx_bytes),
                            display_opt(i.tx_bytes)
                        );
                        push(
                            [
                                i.name.clone(),
                                s.authority.clone(),
                                format!(
                                    "Running: {} · Disabled: {}",
                                    display_opt(i.running),
                                    display_opt(i.disabled)
                                ),
                                rates.clone(),
                            ],
                            &|| {
                                format!(
                                    "Sumber: interface RouterOS {}\nInterface: {}\nTipe: {}\n{counters}\n{rates}\nUTC (Unix): {}\nLaju dihitung dari dua snapshot. Reset counter atau data tidak lengkap tidak dianggap nol.",
                                    s.authority,
                                    i.name,
                                    i.kind.as_deref().unwrap_or("—"),
                                    stamp
                                )
                            },
                        );
                    }
                }
                "Baca MikroTik dua kali dalam 15 menit untuk estimasi bit/s. Gunakan Detail untuk counter mentah."
            }
            5 => {
                if let Some(s) = local {
                    for c in &s.coverage {
                        push(
                            [
                                c.source.clone(),
                                "PC ini".into(),
                                format!("{:?} · {}", c.state, age(c.observed_at)),
                                c.rows.to_string(),
                            ],
                            &|| detail_source(c),
                        );
                    }
                }
                for s in self.intel.routers.values() {
                    for c in &s.coverage {
                        push(
                            [
                                c.source.clone(),
                                s.authority.clone(),
                                format!("{:?} · {}", c.state, age(c.observed_at)),
                                c.rows.to_string(),
                            ],
                            &|| detail_source(c),
                        );
                    }
                }
                if let Some(imported) = &self.intel.imported {
                    push(
                        [
                            "Bukti JSON".into(),
                            "Sumber eksternal".into(),
                            "Impor manual".into(),
                            imported.entries.len().to_string(),
                        ],
                        &|| {
                            "Status diturunkan dari data yang disediakan operator, bukan telemetri yang diverifikasi aplikasi.".into()
                        },
                    );
                }
                "Status mengacu pada satu snapshot. Sumber yang tidak tersedia tidak dihitung sebagai nol."
            }
            6 => {
                for s in self.intel.routers.values() {
                    if let Some(v) = &s.resource {
                        push(
                            [
                                s.identity.clone().unwrap_or_else(|| s.authority.clone()),
                                s.authority.clone(),
                                format!(
                                    "RouterOS {} · CPU {}%",
                                    v.version,
                                    display_opt(v.cpu_percent)
                                ),
                                v.board.clone().unwrap_or_else(|| "—".into()),
                            ],
                            &|| {
                                format!(
                                    "Router: {}\nVersi: {}\nUptime: {}\nCPU: {}%\nMemori bebas/total: {} / {} B\nUTC (Unix): {}\nSumber: RouterOS REST HTTPS.",
                                    s.authority,
                                    v.version,
                                    v.uptime.as_deref().unwrap_or("—"),
                                    display_opt(v.cpu_percent),
                                    display_opt(v.free_memory_bytes),
                                    display_opt(v.total_memory_bytes),
                                    s.coverage
                                        .iter()
                                        .find(|c| c.source == "RouterOS Resource")
                                        .map_or(s.observed_at, |c| c.observed_at)
                                )
                            },
                        );
                    }
                }
                "Sistem MikroTik dari REST HTTPS dengan akun khusus baca. Lihat Kesehatan sumber jika data tidak tersedia."
            }
            8 => {
                for s in self.intel.routers.values() {
                    for r in &s.default_routes {
                        let stamp = s
                            .coverage
                            .iter()
                            .find(|c| {
                                c.source
                                    == if r.destination == "0.0.0.0/0" {
                                        "RouterOS Default Route IPv4"
                                    } else {
                                        "RouterOS Default Route IPv6"
                                    }
                            })
                            .map_or(s.observed_at, |c| c.observed_at);
                        let gateway = r.gateway.as_deref().unwrap_or("—");
                        let table = r.table.as_deref().unwrap_or("tidak diketahui");
                        push(
                            [
                                r.destination.clone(),
                                gateway.into(),
                                format!("{table} · aktif {}", display_opt(r.active)),
                                s.authority.clone(),
                            ],
                            &|| {
                                format!(
                                    "Router: {}\nRute: {}\nGateway: {gateway}\nNext hop: {}\nTabel: {table}\nAktif: {}\nDistance: {}\nUTC (Unix): {stamp}\nAdanya rute tidak membuktikan akses internet klien.",
                                    s.authority,
                                    r.destination,
                                    r.immediate_gateway.as_deref().unwrap_or("—"),
                                    display_opt(r.active),
                                    display_opt(r.distance)
                                )
                            },
                        );
                    }
                }
                "Rute default IPv4/IPv6 yang dilaporkan router. Bukan simulasi jalur atau aturan per klien."
            }
            9 | 10 | 13 => {
                if let Some(collector) = &self.intel.collector {
                    let (stat, rows) = collector.snapshot();
                    match mode {
                        9 => {
                            for f in rows.iter().rev() {
                                let source = f.source_port.map_or_else(
                                    || f.source.to_string(),
                                    |p| std::net::SocketAddr::new(f.source, p).to_string(),
                                );
                                let dest = f.destination_port.map_or_else(
                                    || f.destination.to_string(),
                                    |p| std::net::SocketAddr::new(f.destination, p).to_string(),
                                );
                                let transport = if f.version == 9 {
                                    "NetFlow v9"
                                } else {
                                    "IPFIX"
                                };
                                push(
                                    [
                                        source.clone(),
                                        dest.clone(),
                                        format!(
                                            "{transport} / protokol {}",
                                            display_opt(f.protocol)
                                        ),
                                        format!("{} byte", display_opt(f.octets)),
                                    ],
                                    &|| {
                                        format!(
                                            "{source} → {dest}\nExporter {} · domain {}\nInterface masuk/keluar {} / {}\nByte/paket {} / {}\nExport UTC {} · diterima UTC {}\nSampling tidak diketahui. Tidak menghitung trafik yang tidak dikirim exporter.",
                                            f.exporter,
                                            f.domain,
                                            display_opt(f.ingress),
                                            display_opt(f.egress),
                                            display_opt(f.octets),
                                            display_opt(f.packets),
                                            f.export_at,
                                            f.received_at
                                        )
                                    },
                                );
                            }
                        }
                        10 => {
                            for f in flow::summarize(&rows) {
                                push(
                                    [
                                        f.source.to_string(),
                                        f.destination.to_string(),
                                        format!("{} record", f.records),
                                        if f.counted == 0 {
                                            "Byte tidak tersedia".into()
                                        } else {
                                            format!("{} byte terlapor", f.octets)
                                        },
                                    ],
                                    &|| {
                                        format!(
                                            "Exporter {} · domain {} · versi {}\n{} → {}\n{} record; {} memiliki counter byte.\nAgregat metadata dalam buffer sesi, bukan total jaringan.",
                                            f.exporter,
                                            f.domain,
                                            f.version,
                                            f.source,
                                            f.destination,
                                            f.records,
                                            f.counted
                                        )
                                    },
                                );
                            }
                        }
                        _ => {
                            let status = if stat.error.is_some() {
                                "Gagal"
                            } else {
                                "Listener aktif"
                            };
                            push(
                                [
                                    collector.config.bind.to_string(),
                                    format!("{} profil", collector.config.profiles.len()),
                                    status.into(),
                                    format!("{} sesi · {} arsip", stat.retained, stat.archived),
                                ],
                                &|| {
                                    format!(
                                        "{} profil. Diterima {} · ditolak {} · invalid {} · duplikat {}\nTemplate hilang {} · dilewati {} · buffer dibuang {} · terakhir UTC {}\nArsip ditulis {} · dipangkas {} · dilewati {} · duplikat {}\n{}\n{}",
                                        collector.config.profiles.len(),
                                        stat.accepted_datagrams,
                                        stat.wrong_source,
                                        stat.invalid,
                                        stat.duplicate,
                                        stat.missing_templates,
                                        stat.skipped,
                                        stat.evicted,
                                        display_opt(stat.last_received),
                                        stat.archived,
                                        stat.archive_pruned,
                                        stat.archive_dropped,
                                        stat.archive_duplicate,
                                        stat.archive_error.as_deref().unwrap_or(""),
                                        stat.error.as_deref().unwrap_or("")
                                    )
                                },
                            );
                            for (scope, source) in collector.source_stats() {
                                push(
                                    [
                                        scope.clone(),
                                        "Exporter / domain".into(),
                                        if source.accepted_datagrams == 0 {
                                            "Belum ada datagram diterima".into()
                                        } else {
                                            "Pernah teramati".into()
                                        },
                                        format!(
                                            "{} datagram · {} template hilang",
                                            source.accepted_datagrams, source.missing_templates
                                        ),
                                    ],
                                    &|| {
                                        format!(
                                            "{scope}\nDiterima {} · parser ditolak {} · duplikat {} · template hilang {}\nTerakhir UTC {}. Tidak ada datagram bukan bukti router putus. Drop arsip global tidak diatribusikan ke profil ini.",
                                            source.accepted_datagrams,
                                            source.invalid,
                                            source.duplicate,
                                            source.missing_templates,
                                            display_opt(source.last_received)
                                        )
                                    },
                                );
                            }
                        }
                    }
                }
                "Flow UDP hanya dari exporter terdaftar. Klik Cari untuk membaca data terbaru; Stop membersihkan buffer sesi."
            }
            11 => {
                if let Some(h) = &self.intel.history {
                    for s in &h.snapshots {
                        push(
                            [
                                s.source.clone(),
                                s.observed_at.to_string(),
                                "Snapshot tersimpan".into(),
                                format!("{} bagian", s.sections.len()),
                            ],
                            &|| {
                                format!(
                                    "{}\nUTC (Unix) {}\n{}",
                                    s.source,
                                    s.observed_at,
                                    s.sections
                                        .iter()
                                        .map(|x| format!(
                                            "{} · {} baris · {}",
                                            x.name,
                                            x.values.len(),
                                            if x.complete { "lengkap" } else { "parsial" }
                                        ))
                                        .collect::<Vec<_>>()
                                        .join("\n")
                                )
                            },
                        );
                    }
                    if h.unreadable > 0 {
                        push(
                            [
                                "Arsip lokal".into(),
                                "Histori".into(),
                                "Sebagian tidak dapat dibaca".into(),
                                h.unreadable.to_string(),
                            ],
                            &|| {
                                "File rusak, di luar batas, atau format tidak dikenal tidak dipakai.".into()
                            },
                        );
                    }
                }
                "Snapshot manual dan impor, hingga 64 snapshot atau 32 MiB. Retensi SQLite mengikuti pengaturan."
            }
            12 => {
                if let Some(h) = &self.intel.history {
                    let mut latest =
                        std::collections::BTreeMap::<&str, [Option<&history::Snapshot>; 2]>::new();
                    for s in &h.snapshots {
                        let pair = latest.entry(&s.source).or_default();
                        if pair[0].is_none() {
                            pair[0] = Some(s);
                        } else if pair[1].is_none()
                            && pair[0].is_some_and(|x| x.observed_at > s.observed_at)
                        {
                            pair[1] = Some(s);
                        }
                    }
                    for (scope, [new, old]) in latest {
                        if let (Some(new), Some(old)) = (new, old) {
                            for d in history::diff(old, new) {
                                let kind = match d.change {
                                    history::Change::Added => "Baru terlihat",
                                    history::Change::MissingInSnapshot => "Tidak terlihat lagi",
                                    history::Change::Changed => "Berubah",
                                };
                                push(
                                    [d.key.clone(), scope.into(), kind.into(), d.section.clone()],
                                    &|| {
                                        format!(
                                            "{} · {}\n{}\nSebelum (UTC {}): {}\nSesudah (UTC {}): {}\nTidak terlihat bukan bukti perangkat offline.",
                                            d.section,
                                            kind,
                                            d.key,
                                            old.observed_at,
                                            d.before.as_deref().unwrap_or("—"),
                                            new.observed_at,
                                            d.after.as_deref().unwrap_or("—")
                                        )
                                    },
                                );
                            }
                        }
                    }
                }
                "Bandingkan dua snapshot terbaru dengan waktu berbeda dari sumber sama. Data parsial tidak dipakai untuk menyimpulkan hilang."
            }
            14 | 15 => {
                for s in self.intel.routers.values() {
                    for r in if mode == 14 { &s.topology } else { &s.rules } {
                        let stamp = s
                            .coverage
                            .iter()
                            .find(|c| c.source == r.kind)
                            .map_or(s.observed_at, |c| c.observed_at);
                        push(
                            [
                                r.subject.clone(),
                                r.relation.clone(),
                                r.kind.clone(),
                                format!("{} · #{}", s.authority, r.order),
                            ],
                            &|| {
                                format!(
                                    "{} · {}\n{} → {}\nPosisi snapshot #{} · ID {}\nUTC (Unix) {}\n{}\nKonfigurasi teramati. Tidak membuktikan trafik lolos atau diblokir.",
                                    s.authority,
                                    r.kind,
                                    r.subject,
                                    r.relation,
                                    r.order,
                                    r.id,
                                    stamp,
                                    r.fields
                                        .iter()
                                        .map(|(k, v)| format!("{k}: {v}"))
                                        .collect::<Vec<_>>()
                                        .join("\n")
                                )
                            },
                        );
                    }
                }
                if mode == 14 {
                    "Bridge port, PVID, dan parent interface VLAN yang dilaporkan RouterOS."
                } else {
                    "Inventaris rule Filter/NAT IPv4. Tidak mengevaluasi keputusan untuk sebuah paket."
                }
            }
            POLL_MODE => {
                for (key, job) in &self.intel.schedule.jobs {
                    let running = self.intel.schedule.active_key() == Some(key.as_str());
                    let phase = if running {
                        "Sedang membaca"
                    } else if job.paused {
                        "Dijeda"
                    } else {
                        "Terjadwal"
                    };
                    let until = job
                        .due
                        .saturating_duration_since(std::time::Instant::now())
                        .as_secs();
                    let state = job.outcome.map_or("Belum ada hasil", Outcome::label);
                    push(
                        [
                            key.clone(),
                            phase.into(),
                            state.into(),
                            format!("{} detik", job.every.as_secs()),
                        ],
                        &|| {
                            format!(
                                "{key} · {phase}\n{state}\nInterval {} detik · perkiraan tunggu minimal {until} detik.\n{}",
                                job.every.as_secs(),
                                self.intel.poll_save_errors.get(key).map_or(
                                    "Detail per tabel di Kesehatan sumber.",
                                    String::as_str
                                )
                            )
                        },
                    );
                }
                if let Some(key) = self
                    .intel
                    .schedule
                    .active_key()
                    .filter(|k| !self.intel.schedule.jobs.contains_key(*k))
                {
                    push(
                        [
                            key.into(),
                            "Menghentikan…".into(),
                            "Menunggu I/O".into(),
                            "".into(),
                        ],
                        &|| {
                            "Permintaan berikutnya tidak dimulai sampai pekerjaan saat ini selesai."
                                .into()
                        },
                    );
                }
                "Isi host dan interval. Mulai atau hentikan target. Polling tidak aktif otomatis setelah keluar."
            }
            ALERT_MODE => {
                for event in &self.intel.alert_rows {
                    let status = event.status();
                    push(
                        [
                            event.signal.clone(),
                            event.scope.clone(),
                            status.into(),
                            format!("UTC {} · {}", event.last_seen, event.total),
                        ],
                        &|| {
                            format!(
                                "{}\nCakupan (site/VRF/profil/IP/domain): {}\nSesi {} · #{}\nDibuka UTC {} · terakhir UTC {} · total {}\nDiakui {:?} · pulih {:?}\nStatus: {}. Tidak membuktikan router putus. Tidak memicu perubahan jaringan.",
                                event.signal,
                                event.scope,
                                event.session,
                                event.serial,
                                event.opened,
                                event.last_seen,
                                event.total,
                                event.acknowledged,
                                event.recovered,
                                status
                            )
                        },
                    );
                }
                "Alert persisten tanpa popup. Cari: state=open/ack/recovered ditambah teks scope. Maksimal 1.000 terbaru. Pulih berarti observasi membaik; sesi lama tidak dinilai pulih otomatis."
            }
            TOPOLOGY_MODE | IPAM_MODE | LEASE_MODE => {
                let observations: Box<dyn Iterator<Item = &Observation>> =
                    if mode == LEASE_MODE {
                        if let Some((_, view)) = &self.intel.router_history {
                            Box::new(view.leases.events.iter().rev())
                        } else {
                            Box::new(
                                self.intel
                                    .lease_timelines
                                    .values()
                                    .flat_map(|t| t.events.iter().rev()),
                            )
                        }
                    } else {
                        Box::new(self.intel.network_views.values().flat_map(
                            |(topology, inventory)| {
                                if mode == TOPOLOGY_MODE {
                                    topology.iter()
                                } else {
                                    inventory.iter()
                                }
                            },
                        ))
                    };
                for r in observations {
                    push(
                        [
                            r.subject.clone(),
                            r.target.clone(),
                            r.basis.into(),
                            r.scope.clone(),
                        ],
                        &|| {
                            format!(
                                "{} → {}\n{}\n{} · {} · UTC {}\n\n{}",
                                r.subject,
                                r.target,
                                r.scope,
                                r.basis,
                                r.source,
                                r.observed_at,
                                r.details
                            )
                        },
                    );
                }
                if mode == IPAM_MODE
                    && let Some(local) = local
                {
                    for a in &local.addresses {
                        let scope =
                            format!("PC ini · if#{} · scope {}", a.interface_index, a.scope_id);
                        push(
                            [
                                format!("{}/{}", a.ip, a.prefix),
                                "Windows".into(),
                                "Alamat lokal".into(),
                                scope.clone(),
                            ],
                            &|| {
                                format!(
                                    "{scope}\nWindows Unicast IP · UTC {}\nTidak digabung dengan scope RouterOS.",
                                    local.observed_at
                                )
                            },
                        );
                    }
                    for a in &local.neighbors {
                        let scope =
                            format!("PC ini · if#{} · scope {}", a.interface_index, a.scope_id);
                        push(
                            [
                                a.ip.to_string(),
                                display_opt(a.mac),
                                "Cache tetangga".into(),
                                scope.clone(),
                            ],
                            &|| {
                                format!(
                                    "{scope}\nWindows ARP/ND · UTC {}\nStatus {}. Bukan bukti alamat tersedia.",
                                    local.observed_at, a.cache_state
                                )
                            },
                        );
                    }
                }
                if mode == LEASE_MODE {
                    if self.intel.router_history.is_some() {
                        "Lease dari arsip UTC. Reset untuk kembali ke sesi."
                    } else if self.intel.lease_timelines.values().any(|t| t.limited) {
                        "Histori sesi parsial. Ada batas 512 event dan 2.000 binding per router."
                    } else {
                        "Lease aktif dari snapshot sesi ini. Pengamatan hilang tidak berarti lease habis."
                    }
                } else if self.intel.network_views.is_empty() {
                    "Isi alamat, lalu tekan Baca MikroTik. IPAM juga dapat memakai Data Windows."
                } else if mode == TOPOLOGY_MODE {
                    "Relasi logis dan cache teramati. Cek Kesehatan sumber untuk tabel yang tidak tersedia."
                } else {
                    "Alamat, pool dan lease teramati. IP yang tidak terlihat belum tentu tersedia."
                }
            }
            TREND_MODE => {
                let trends: Box<dyn Iterator<Item = (&String, &Trend)>> =
                    if let Some((router, views)) = &self.intel.router_history {
                        Box::new(std::iter::once((router, &views.trend)))
                    } else {
                        Box::new(self.intel.trends.iter())
                    };
                for (router, trend) in trends {
                    for (name, points) in &trend.streams {
                        let summary = interface_trend::summarize(points);
                        let recent = points.back();
                        let latest = recent.map_or("Tidak ada sampel".into(), |p| {
                            format!(
                                "RX {} / TX {} bit/s",
                                display_opt(p.rx_bps),
                                display_opt(p.tx_bps)
                            )
                        });
                        let stats = format!(
                            "P95 RX {} / TX {} bit/s",
                            display_opt(summary.p95_rx),
                            display_opt(summary.p95_tx)
                        );
                        push(
                            [name.clone(), router.clone(), latest, stats.clone()],
                            &|| {
                                let series = points
                                    .iter()
                                    .rev()
                                    .take(20)
                                    .map(|p| {
                                        format!(
                                            "Tabel UTC {} · Terima UTC {} · Δ {} dtk · RX {} · TX {} bit/s",
                                            p.utc, p.received_utc,
                                            display_opt(p.interval_s),
                                            display_opt(p.rx_bps),
                                            display_opt(p.tx_bps)
                                        )
                                    })
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                format!(
                                    "{router} · {name}\n{stats} · puncak RX {} / TX {} bit/s\n{} sampel · {} lengkap · {} gap\n\n20 sampel terakhir\n{series}\n\nGap dapat menunjukkan counter reset/wrap, interval panjang, perubahan interface, atau data hilang.",
                                    display_opt(summary.peak_rx),
                                    display_opt(summary.peak_tx),
                                    summary.intervals,
                                    summary.valid_intervals,
                                    summary.gaps
                                )
                            },
                        );
                    }
                }
                if self.intel.router_history.is_some() {
                    "Tren dari arsip UTC. Reset untuk kembali ke sesi."
                } else if self.intel.trends.is_empty() {
                    "Tekan Baca MikroTik setidaknya dua kali untuk menghitung tren sesi."
                } else if self.intel.trends.values().any(|t| t.limited) {
                    "Tren parsial. Maksimal 512 interface dan 120 sampel per interface per router."
                } else {
                    "Tren sesi dari snapshot RouterOS. Gap bukan nol. Tidak memakai data NetFlow."
                }
            }
            STORAGE_MODE => {
                let title = if self.intel.recovery_view.is_some() {
                    "Salinan baca-saja"
                } else {
                    "Arsip utama"
                };
                if let Some(info) = &self.intel.storage {
                    let quota = info.configured_quota_mib;
                    let settings = format!(
                        "Flow {} hari · Snapshot {} hari · DB {} MiB",
                        info.flow_retention_days, info.snapshot_retention_days, quota
                    );
                    let counts = format!(
                        "{} flow · {} snapshot · {} scope",
                        info.flow_records, info.snapshots, info.source_scopes
                    );
                    let disk = format!("DB {} byte · WAL {} byte", info.main_bytes, info.wal_bytes);
                    push(
                        [
                            title.into(),
                            counts.clone(),
                            disk.clone(),
                            format!("UTC {}", info.measured_utc),
                        ],
                        &|| {
                            format!(
                                "{title}\n{counts}\n{disk}\nRentang terima flow UTC {}–{}\nDiukur UTC {}\nUkuran file dapat berubah saat writer aktif.",
                                display_opt(info.first_flow_utc),
                                display_opt(info.last_flow_utc),
                                info.measured_utc
                            )
                        },
                    );
                    push(
                        [
                            "Retensi dan kuota".into(),
                            settings.clone(),
                            "Agregat tidak disimpan".into(),
                            "WAL di luar kuota DB".into(),
                        ],
                        &|| {
                            format!(
                                "{settings}\nKuota hanya untuk DB utama. Perawatan berjalan saat collector aktif dan tidak memangkas file JSON lama."
                            )
                        },
                    );
                } else if self.intel.storage_loaded {
                    push(
                        [
                            title.into(),
                            "Arsip belum ada".into(),
                            "Default 30 / 7 / 256".into(),
                            "hari / hari / MiB".into(),
                        ],
                        &|| {
                            "Belum ada database. Gunakan Atur, Impor JSON, atau mulai collector Anda.".into()
                        },
                    );
                }
                if let Some(stats) = self.intel.collector.as_ref().map(Collector::stats) {
                    let message = format!(
                        "{} antre · {} drop ({} penuh, {} tertutup, {} SQLite) · {} dipangkas",
                        stats.archive_pending,
                        stats.archive_dropped,
                        stats.archive_queue_full,
                        stats.archive_writer_closed,
                        stats.archive_sqlite_failed,
                        stats.archive_pruned
                    );
                    push(
                        [
                            "Collector aktif".into(),
                            "Statistik arsip utama".into(),
                            message.clone(),
                            "Sejak collector mulai".into(),
                        ],
                        &|| {
                            format!(
                                "{message}\n{}",
                                stats
                                    .archive_error
                                    .as_deref()
                                    .unwrap_or("Tidak ada kegagalan arsip tercatat.")
                            )
                        },
                    );
                }
                if self.intel.recovery_view.is_some() {
                    "Salinan baca-saja. Reset kembali ke arsip utama."
                } else {
                    "Atur: hari-flow hari-snapshot kuota-MiB. Tinjau hapus: jenis UTC-awal UTC-akhir."
                }
            }
            DEVICE_MODE => {
                if let Some((view, q)) = &self.intel.device
                    && let Some(ip) = q.ip
                {
                    let now = ni::now();
                    for r in &view.scopes {
                        let partial = if view.partial { " · parsial" } else { "" };
                        push(
                            [
                                ip.to_string(),
                                r.scope.label(),
                                r.access_label(now).into(),
                                format!("{} record{partial} · UTC {}", r.count, r.last),
                            ],
                            &|| format_ip_scope(ip, r, view.partial, now),
                        );
                    }
                    // Never join Windows or imported observations to a configured site, VRF, or time filter.
                    if q.is_ip_only() {
                        let s = self.intel.local.as_ref().map_or_else(Vec::new, |local| {
                            ni::assess(local, self.intel.probe.as_ref(), now)
                        });
                        for a in s.iter().filter(|a| a.ip == ip) {
                            push(
                                [
                                    ip.to_string(),
                                    a.scope.clone(),
                                    a.access.to_string(),
                                    a.evidence.clone(),
                                ],
                                &|| {
                                    format!(
                                        "{} · {}\n{}\nUTC {}\nBukti lokal, tidak digabung ke site/VRF arsip.",
                                        a.ip, a.scope, a.evidence, a.observed_at
                                    )
                                },
                            );
                        }
                    }
                    if view.partial {
                        "Hasil parsial. Gunakan scope atau rentang waktu lebih sempit."
                    } else if view.scopes.is_empty() {
                        "Tidak ada flow tersimpan untuk filter ini. Itu bukan bukti penolakan."
                    } else {
                        "Pilih scope yang benar, lalu buka Koneksi. Observasi WAN bukan tes HTTPS."
                    }
                } else {
                    "Masukkan satu alamat IP lalu tekan Cari."
                }
            }
            ARCHIVE_MODE => {
                if let Some(page) = &self.intel.archived {
                    for r in &page.rows {
                        let f = &r.flow;
                        let src = f.source_port.map_or_else(
                            || f.source.to_string(),
                            |p| std::net::SocketAddr::new(f.source, p).to_string(),
                        );
                        let dst = f.destination_port.map_or_else(
                            || f.destination.to_string(),
                            |p| std::net::SocketAddr::new(f.destination, p).to_string(),
                        );
                        push(
                            [
                                src.clone(),
                                dst.clone(),
                                format!(
                                    "{} / {}",
                                    r.site,
                                    r.vrf.as_deref().unwrap_or("VRF tidak diketahui")
                                ),
                                format!("{} · UTC {}", r.direction.as_str(), f.received_at),
                            ],
                            &|| {
                                format!(
                                    "{src} → {dst}\nProfil {} / site {} / VRF {}\nExporter {} / domain {} / versi {}\nProtokol {} · interface {} → {}\nByte {} · paket {} · sampling tidak diketahui\nExport UTC {} · diterima UTC {}",
                                    r.profile,
                                    r.site,
                                    r.vrf.as_deref().unwrap_or("—"),
                                    f.exporter,
                                    f.domain,
                                    f.version,
                                    display_opt(f.protocol),
                                    display_opt(f.ingress),
                                    display_opt(f.egress),
                                    display_opt(f.octets),
                                    display_opt(f.packets),
                                    f.export_at,
                                    f.received_at
                                )
                            },
                        );
                    }
                }
                if self.intel.recovery_view.is_some() {
                    "Sumber histori: salinan baca-saja."
                } else if let Some(scope) = &self.intel.pivot_scope {
                    scope.as_str()
                } else if visible.is_empty() {
                    "Flow tidak ditemukan. Mulai collector, atau ubah filter."
                } else {
                    "Histori lokal. Gunakan Lanjut untuk halaman berikutnya."
                }
            }
            _ => "",
        };
        unsafe {
            ShowWindow(
                self.h(INTEL_MORE),
                if self.page == Page::Intel && mode == ARCHIVE_MODE {
                    SW_SHOW
                } else {
                    SW_HIDE
                },
            );
        }
        for (id, show) in [
            (
                INTEL_IP_JOURNEY,
                matches!(mode, 0 | 1 | DEVICE_MODE | DASHBOARD_MODE),
            ),
            (
                INTEL_BACK,
                mode == ARCHIVE_MODE && self.intel.pivot_scope.is_some()
                    || mode == DEVICE_MODE && self.intel.previous_mode.is_some(),
            ),
        ] {
            unsafe {
                ShowWindow(
                    self.h(id),
                    if show && self.page == Page::Intel {
                        SW_SHOW
                    } else {
                        SW_HIDE
                    },
                );
            }
        }
        for (id, show) in [
            (INTEL_HOST, mode != STORAGE_MODE),
            (INTEL_REFRESH, mode != STORAGE_MODE),
            (INTEL_FLOW, mode != STORAGE_MODE),
            (INTEL_HISTORY, mode != STORAGE_MODE),
            (INTEL_REDACT, mode != STORAGE_MODE),
        ] {
            unsafe {
                ShowWindow(
                    self.h(id),
                    if show && self.page == Page::Intel {
                        SW_SHOW
                    } else {
                        SW_HIDE
                    },
                );
            }
        }
        self.intel.visible_ips = visible
            .iter()
            .map(|r| r[0].split('/').next().and_then(|s| s.parse().ok()))
            .collect();
        self.table_rows(INTEL_TABLE, &visible, 4);
        self.intel.details = details;
        self.intel.dashboard_targets = dashboard_targets;
        set(
            self.h(INTEL_STATUS),
            &format!(
                "{}/{} · {description}{}{}",
                visible.len(),
                matched,
                self.intel
                    .router_history
                    .as_ref()
                    .filter(|_| matches!(mode, TREND_MODE | LEASE_MODE))
                    .map_or(String::new(), |(router, v)| format!(
                        " {router} · {} sampel.",
                        v.samples
                    )),
                if mode == ALERT_MODE {
                    self.intel
                        .collector
                        .as_ref()
                        .and_then(|c| c.stats().alert_error)
                        .map_or(String::new(), |e| format!(" · {e}"))
                } else {
                    String::new()
                }
            ),
        );
    }
}
