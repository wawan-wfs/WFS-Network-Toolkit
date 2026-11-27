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
const INTEL_CHART: i32 = 241;
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
const DHCP6_MODE: usize = 27;
const NOTES_MODE: usize = 28;
const DHCP6_HISTORY_MODE: usize = 29;
const SYSLOG_MODE: usize = 30;
const REPLAY_MODE: usize = 31;
const SECURE_MODE: usize = 32;
const IPAM_HISTORY_MODE: usize = 33;
const INTEL_MODES: [&str; 34] = [
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
    "Binding DHCPv6 / PD",
    "IPAM metadata lokal",
    "Histori DHCPv6 / PD",
    "Syslog offline",
    "Replay Flow offline",
    "Secure Transport",
    "Histori revisi IPAM",
];
const INTEL_ROW_LIMIT: usize = 1_000;

type RouterData = (Box<RouterSnapshot>, Vec<Observation>, Vec<Observation>);
type PollResult = (std::result::Result<(RouterData, Outcome, Option<String>), Outcome>, bool);
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
    PollHealth(String, Vec<ni::poll_health::Record>),
    Import(TrafficImport),
    Export(PathBuf),
    Collector(Collector),
    History(history::History),
    Stopped(Box<flow::Stats>),
    Alerts(PathBuf, Vec<AlertRecord>),
    IpamNotes(Vec<ni::ipam_notes::Note>, bool),
    Dhcp6History(String, Vec<ni::dhcp6_history::Capture>),
    Syslog(ni::syslog::Summary),
    FlowReplay(ni::flow_replay::Report),
    SecureHistory(Vec<ni::secure_monitor::Report>),
    SecureLoaded(Vec<ni::secure_monitor::Report>, Vec<ni::secure_attempt::Attempt>),
    SecureSession(Vec<ni::secure_monitor::Report>, Vec<ni::secure_attempt::Attempt>, ni::secure_bridge::SessionResult),
    IpamPivot(Vec<ni::ipam_notes::Note>, String, String),
    IpamHistory(String, String, Vec<ni::ipam_notes::Note>),
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
    storage_loading: bool,
    storage_failed: bool,
    storage_smoke: bool,
    storage_smoke_error: Option<String>,
    schedule: Schedule,
    poll_auth: std::collections::BTreeMap<String, (Authority, std::sync::Arc<nw::Credentials>)>,
    poll_rx: Option<Receiver<PollResult>>,
    poll_save_errors: std::collections::BTreeMap<String, String>,
    poll_health: Option<(String, Vec<ni::poll_health::Record>)>,
    router_history: Option<(String, Box<Views>)>,
    dashboard_targets: Vec<usize>,
    dashboard_charts: std::collections::BTreeMap<usize, ni::visual::Series>,
    visual_edges: Vec<ni::visual::Edge>,
    visual_series: Vec<ni::visual::Series>,
    ipam_notes: Vec<ni::ipam_notes::Note>,
    visible_notes: Vec<ni::ipam_notes::Note>,
    visible_subnet_keys: Vec<Option<(String, String)>>,
    ipam_pivot_draft: Option<(String, String, i64)>,
    ipam_history: Option<(String, String, Vec<ni::ipam_notes::Note>)>,
    rendered_mode: Option<usize>,
    rendered_rows: Vec<Vec<String>>,
    dhcp6_history: Option<(String, Vec<ni::dhcp6_history::Capture>)>,
    syslog_summary: Option<ni::syslog::Summary>,
    flow_replay: Option<ni::flow_replay::Report>,
    secure_history: Vec<ni::secure_monitor::Report>,
    secure_attempts: Vec<ni::secure_attempt::Attempt>,
    secure_cancel: Option<ni::secure_bridge::SessionCancel>,
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
    ask_session_credentials(h, &authority.display(), "Kredensial MikroTik — hanya sesi ini", "Masukkan akun khusus baca. Password tidak disimpan.")
}
fn ask_session_credentials(h: HWND, target: &str, caption: &str, message: &str) -> Result<Option<nw::Credentials>> {
    let caption = w::wide(caption);
    let message = w::wide(message);
    let target = w::wide(target);
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
        self.widget(
            "STATIC",
            "Bandwidth interface — pilih baris dashboard",
            INTEL_CHART,
            Some(Page::Intel),
            0,
            13, // SS_OWNERDRAW
            [228, -234, -256, 112],
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
        self.intel.storage = None;
        self.intel.storage_loaded = false;
        self.intel.storage_loading = true;
        self.intel.storage_failed = false;
        let started = self.start_intel(move || {
            let info = if path.try_exists().map_err(|e| e.to_string())? {
                Some(Box::new(Archive::reader(&path)?.health(&path)?))
            } else {
                None
            };
            Ok(IntelReply::Storage(info))
        });
        if started.is_err() {
            self.intel.storage_loading = false;
            self.intel.storage_failed = true;
        }
        self.render_intel();
        started
    }
    fn invalidate_archive_views(&mut self) {
        self.intel.archived = None;
        self.intel.archive_query = None;
        self.intel.device = None;
        self.intel.pivot_scope = None;
        self.intel.history = None;
        self.intel.router_history = None;
        self.intel.dhcp6_history = None;
        self.intel.storage_loaded = false;
        self.intel.storage_loading = false;
        self.intel.storage_failed = false;
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
            let (reply, health_saved) = match rx.try_recv() {
                Ok(reply) => reply,
                Err(TryRecvError::Empty) => return,
                Err(TryRecvError::Disconnected) => (Err(Outcome::Other), false),
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
                        self.intel.poll_save_errors.insert(key.clone(), w);
                    }
                }
                if !health_saved {
                    self.intel.poll_save_errors.entry(key).or_default()
                        .push_str(" Histori kesehatan tidak tersimpan.");
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
                        | DHCP6_MODE
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
            use ni::poll_health::ArchiveState;
            let started = std::time::Instant::now();
            let result = nw::router_snapshot_cancel(&authority, &auth, &cancel)
                .map_err(|e| Outcome::from_failure(&e))
                .map(|s| {
                    let outcome = if !s.coverage.is_empty() && s.coverage.iter().all(|c| c.state == ni::CoverageState::CompleteSnapshot) {
                        Outcome::Complete
                    } else {
                        Outcome::Partial
                    };
                    let archive = cancel.check().and_then(|_| {
                        let path = path.as_ref().map_err(Clone::clone)?;
                        let mut db = Archive::writer(path)?;
                        cancel.check()?;
                        db.save_router_sample(&Sample::capture(&s))
                    });
                    let data = prepare_router(s);
                    (data, outcome, archive.err().map(|_| "Histori tidak tersimpan. Periksa izin, kuota atau kunci SQLite.".into()))
                });
            let (outcome, archive) = match &result {
                Ok((_, outcome, warning)) => (*outcome, if warning.is_some() { ArchiveState::Failed } else { ArchiveState::Saved }),
                Err(outcome) => (*outcome, ArchiveState::NotAttempted),
            };
            let health_saved = !cancel.requested() && path.as_ref().is_ok_and(|path| {
                ni::poll_health::append(
                    &path.with_file_name("poll-health-v1.sqlite3"), &authority.display(),
                    ni::now(), started.elapsed().as_millis().min(3_600_000) as u64, outcome, archive,
                ).is_ok()
            });
            let _ = tx.send((result, health_saved));
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
    fn dhcp6_history_path(&self) -> Result<PathBuf> {
        Ok(self
            .primary_archive_path()?
            .with_file_name("dhcp6-history-v1.sqlite3"))
    }
    fn load_dhcp6_history(&mut self, save: bool) -> Result<()> {
        if save && self.intel.recovery_view.is_some() {
            return Err("Arsip pemulihan hanya-baca.".into());
        }
        let key = Authority::parse(&get(self.h(INTEL_HOST)))?.display();
        let path = self.dhcp6_history_path()?;
        let sample = if save {
            let snapshot = self
                .intel
                .routers
                .get(&key)
                .ok_or("Baca router ini terlebih dahulu.")?;
            let sample = ni::dhcp6_history::Capture::from_snapshot(snapshot)?;
            if popup(
                self.hwnd,
                "Simpan snapshot DHCPv6 dengan alamat, prefix dan scope ke database lokal terpisah? DUID dan kredensial tidak disimpan. Data tidak disamarkan.",
                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
            ) != IDYES
            {
                return Ok(());
            }
            Some(sample)
        } else {
            None
        };
        self.intel.dhcp6_history = None;
        self.start_intel(move || {
            if let Some(sample) = sample {
                ni::dhcp6_history::save(&path, &sample)?;
            }
            let rows = ni::dhcp6_history::page(&path, &key)?;
            Ok(IntelReply::Dhcp6History(key, rows))
        })?;
        self.render_intel();
        Ok(())
    }
    fn load_older_dhcp6_history(&mut self) -> Result<()> {
        let (authority, rows) = self.intel.dhcp6_history.as_ref()
            .ok_or("Muat histori DHCPv6 terlebih dahulu.")?;
        let stamp = rows.last().ok_or("Tidak ada halaman lebih lama.")?.stamp;
        let authority = authority.clone();
        let path = self.dhcp6_history_path()?;
        self.start_intel(move || {
            let rows = ni::dhcp6_history::page_before(&path, &authority, Some(stamp))?;
            Ok(IntelReply::Dhcp6History(authority, rows))
        })
    }
    fn recover_independent_metadata(&mut self, dhcp: bool) -> Result<()> {
        let active = if dhcp { self.dhcp6_history_path()? } else { self.notes_path()? };
        let filter = "SQLite (*.sqlite3)\0*.sqlite3\0";
        let Some(source) = typed_file_dialog(self.hwnd, false, "", filter, "sqlite3")? else {
            return Ok(());
        };
        if popup(self.hwnd,
            "Validasi seluruh backup dan pulihkan ke file BARU? Database aktif dan sumber tidak akan ditimpa. Salinan tidak otomatis diaktifkan.",
            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES {
            return Ok(());
        }
        let name = if dhcp { "WeNet-DHCPv6-recovered.sqlite3" } else { "WeNet-IPAM-recovered.sqlite3" };
        let Some(destination) = typed_file_dialog(self.hwnd, true, name, filter, "sqlite3")? else {
            return Ok(());
        };
        check_recovery_destination(&destination, &active)?;
        self.start_intel(move || {
            if dhcp {
                ni::dhcp6_history::recover(&source, &destination)?;
            } else {
                ni::ipam_notes::recover(&source, &destination)?;
            }
            Ok(IntelReply::Export(destination))
        })
    }
    fn notes_path(&self) -> Result<PathBuf> {
        Ok(self
            .primary_archive_path()?
            .with_file_name("ipam-notes-v1.sqlite3"))
    }
    fn load_notes(&mut self) -> Result<()> {
        let path = self.notes_path()?;
        self.intel.ipam_notes.clear();
        self.intel.visible_notes.clear();
        self.start_intel(move || {
            ni::ipam_notes::page(&path).map(|rows| IntelReply::IpamNotes(rows, false))
        })?;
        self.render_intel();
        Ok(())
    }
    fn save_notes(&mut self, undo: bool) -> Result<()> {
        if self.intel.recovery_view.is_some() {
            return Err("Kembali ke arsip utama sebelum mengedit metadata lokal.".into());
        }
        let path = self.notes_path()?;
        let selected = self
            .selected_intel_row()
            .and_then(|i| self.intel.visible_notes.get(i))
            .cloned();
        let (draft, expected) = if undo {
            let note = selected.ok_or("Pilih revisi untuk undo.")?;
            let expected = note.revision;
            (note, expected)
        } else {
            let draft = ni::ipam_notes::Note::parse(&get(self.h(INTEL_FILTER)))?;
            let expected = if let Some(note) = selected {
                if (note.scope.as_str(), note.cidr.as_str())
                    != (draft.scope.as_str(), draft.cidr.as_str())
                {
                    return Err(
                        "Key berbeda dari baris terpilih. Reset daftar sebelum membuat key baru."
                            .into(),
                    );
                }
                note.revision
            } else if let Some((scope, cidr, rev)) = &self.intel.ipam_pivot_draft {
                if scope != &draft.scope || cidr != &draft.cidr {
                    return Err("Draft scope berbeda; gunakan Reset untuk membuat metadata lain.".into());
                }
                *rev
            } else {
                0
            };
            (draft, expected)
        };
        let overlap_count = if undo {
            0
        } else {
            ni::ipam_notes::overlaps_in(&self.intel.ipam_notes, &draft)?
                .iter()
                .filter(|n| n.cidr != draft.cidr)
                .count()
        };
        if popup(
            self.hwnd,
            &format!(
                "{} metadata lokal untuk {} / {} (revisi {})?\n{} prefix lain tumpang tindih pada snapshot scope operator yang sama. Tidak membuktikan konflik assignment. Tidak ada perubahan jaringan atau reservasi router.",
                if undo { "Undo" } else { "Simpan" },
                draft.scope,
                draft.cidr,
                expected,
                overlap_count
            ),
            MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON2,
        ) == IDYES
        {
            self.start_intel(move || {
                if undo {
                    ni::ipam_notes::undo(&path, &draft, ni::now())?;
                } else {
                    ni::ipam_notes::save(&path, &draft, expected, ni::now())?;
                }
                ni::ipam_notes::page(&path).map(|rows| IntelReply::IpamNotes(rows, true))
            })?;
        }
        Ok(())
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
                TOPOLOGY_MODE => "Graf bukti",
                TREND_MODE => "Grafik",
                NOTES_MODE => "Isi editor",
                SUBNET_MODE => "Metadata IPAM",
                _ => "Detail IP",
            },
        );
        set(self.h(INTEL_MORE), if mode == DASHBOARD_MODE { "Rentang" } else { "Lanjut" });
        if mode == SYSLOG_MODE {
            set(self.h(INTEL_IMPORT), "Impor Syslog");
        }
        if mode == REPLAY_MODE {
            set(self.h(INTEL_IMPORT), "Replay JSONL");
        }
        if mode == SECURE_MODE {
            set(self.h(INTEL_ROUTER), "SNMPv3 GET");
            set(self.h(INTEL_IMPORT), "TLS Syslog");
            set(self.h(INTEL_RECORD), "Polling");
            set(self.h(INTEL_PROBE), "Stop sesi");
            set(self.h(INTEL_HISTORY), "Histori");
        }
        if mode == DHCP6_MODE || mode == DHCP6_HISTORY_MODE {
            set(self.h(INTEL_RECORD), "Simpan DHCPv6");
            set(self.h(INTEL_HISTORY), "Histori DHCPv6");
        }
        if mode == DHCP6_HISTORY_MODE {
            set(self.h(INTEL_EXPORT), "Ekspor/backup");
            set(self.h(INTEL_IMPORT), "Pulihkan…");
        }
        if mode == NOTES_MODE {
            set(self.h(INTEL_IMPORT), "Pulihkan…");
            set(self.h(INTEL_EXPORT), "Ekspor/backup");
            set(self.h(INTEL_RECORD), "Simpan metadata");
            set(self.h(INTEL_HISTORY), "Undo metadata");
            set(self.h(INTEL_PROBE), "Revisi IPAM");
        }
        if mode == IPAM_HISTORY_MODE {
            set(self.h(INTEL_SEARCH), "Cari");
            set(self.h(INTEL_MORE), "Lebih lama");
            set(self.h(INTEL_HISTORY), "Terbaru");
        }
        if mode == POLL_MODE {
            set(self.h(INTEL_ROUTER), "Mulai polling");
            set(self.h(INTEL_PROBE), "Hentikan target");
            set(self.h(INTEL_HISTORY), "Histori kesehatan");
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
                NOTES_MODE => "scope|CIDR|label/reserved|alias|tag|catatan",
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
        self.intel.secure_cancel = None;
        if self.intel.storage_loading {
            self.intel.storage_loading = false;
            self.intel.storage_failed = result.is_err();
        }
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
                        | DHCP6_MODE
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
            Ok(IntelReply::SecureSession(rows, attempts, result)) => {
                self.intel.secure_history = rows;
                self.intel.secure_attempts = attempts;
                select(self.h(INTEL_MODE), SECURE_MODE);
                self.intel.mode = SECURE_MODE;
                self.intel_mode_labels(SECURE_MODE);
                let message = format!("Sesi aman selesai: {} observasi tersimpan · {} koneksi ditolak · dihentikan {} · gagal {}.", result.saved, result.rejected, result.stopped, result.failed);
                notice = Some(if result.failed { Notice::Warning(message) } else { Notice::Information(message) });
            }
            Ok(IntelReply::SecureLoaded(rows, attempts)) => {
                self.intel.secure_history = rows;
                self.intel.secure_attempts = attempts;
                self.set_notice("Histori Secure Transport dimuat dari database lokal.");
            }
            Ok(IntelReply::SecureHistory(rows)) => {
                self.intel.secure_history = rows;
                select(self.h(INTEL_MODE), SECURE_MODE);
                self.intel.mode = SECURE_MODE;
                self.intel_mode_labels(SECURE_MODE);
            }
            Ok(IntelReply::FlowReplay(report)) => {
                self.intel.flow_replay = Some(report);
                select(self.h(INTEL_MODE), REPLAY_MODE);
                self.intel.mode = REPLAY_MODE;
                self.intel_mode_labels(REPLAY_MODE);
            }
            Ok(IntelReply::Syslog(summary)) => {
                self.intel.syslog_summary = Some(summary);
                select(self.h(INTEL_MODE), SYSLOG_MODE);
                self.intel.mode = SYSLOG_MODE;
                self.intel_mode_labels(SYSLOG_MODE);
            }
            Ok(IntelReply::PollHealth(key, rows)) => {
                self.intel.poll_health = Some((key, rows));
            }
            Ok(IntelReply::Dhcp6History(key, rows)) => {
                self.intel.dhcp6_history = Some((key, rows));
                select(self.h(INTEL_MODE), DHCP6_HISTORY_MODE);
                self.intel.mode = DHCP6_HISTORY_MODE;
                self.intel_mode_labels(DHCP6_HISTORY_MODE);
            }
            Ok(IntelReply::IpamHistory(scope,cidr,rows)) => {
                self.intel.ipam_history=Some((scope,cidr,rows));
                self.intel.filter.clear();
                select(self.h(INTEL_MODE),IPAM_HISTORY_MODE);
                self.intel.mode=IPAM_HISTORY_MODE;
                set(self.h(INTEL_FILTER),"");
                self.intel_mode_labels(IPAM_HISTORY_MODE);
            }
            Ok(IntelReply::IpamPivot(rows, scope, cidr)) => {
                let note = rows.iter().find(|n| n.scope == scope && n.cidr == cidr);
                let revision = note.map_or(0, |n| n.revision);
                let editor = note.map_or_else(|| format!("{scope}|{cidr}|label|||"), |n| n.editor());
                self.intel.ipam_pivot_draft = Some((scope, cidr, revision));
                self.intel.ipam_notes = rows;
                self.intel.filter.clear();
                select(self.h(INTEL_MODE), NOTES_MODE);
                self.intel.mode = NOTES_MODE;
                self.intel_mode_labels(NOTES_MODE);
                set(self.h(INTEL_FILTER), &editor);
                self.set_notice("Draft scope dimuat dengan revisi aktual. Tinjau sebelum menyimpan.");
            }
            Ok(IntelReply::IpamNotes(rows, saved)) => {
                self.intel.ipam_notes = rows;
                if saved {
                    self.intel.ipam_pivot_draft = None;
                    self.intel.filter.clear();
                    set(self.h(INTEL_FILTER), "");
                }
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
                    "Berkas ekspor disimpan di {}",
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
                    self.intel.ipam_pivot_draft = None;
                    self.intel.router_history = None;
                    self.intel.dhcp6_history = None;
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
                } else if mode == NOTES_MODE {
                    self.load_notes()?;
                } else {
                    self.render_intel();
                }
            }
            INTEL_SEARCH | INTEL_RESET_FILTER => {
                if id == INTEL_RESET_FILTER {
                    self.intel.ipam_pivot_draft = None;
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
                    NOTES_MODE => {
                        self.intel.filter = input;
                        self.load_notes()?;
                    }
                    DHCP6_HISTORY_MODE => {
                        self.intel.filter = input;
                        self.load_dhcp6_history(false)?;
                    }
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
            INTEL_MORE | INTEL_HISTORY if selection(self.h(INTEL_MODE)) == IPAM_HISTORY_MODE => {
                let (scope,cidr,rows)=self.intel.ipam_history.as_ref().ok_or("Pilih metadata dari modul IPAM terlebih dahulu.")?;
                let before=if id==INTEL_MORE {Some(rows.last().ok_or("Tidak ada revisi lebih lama.")?.revision)} else {None};
                let (scope,cidr)=(scope.clone(),cidr.clone());
                let path=self.notes_path()?;
                self.start_intel(move || {
                    let rows=ni::ipam_notes::history(&path,&scope,&cidr,before)?;
                    Ok(IntelReply::IpamHistory(scope,cidr,rows))
                })?;
            }
            INTEL_MORE if selection(self.h(INTEL_MODE)) == DASHBOARD_MODE => {
                let span = DASHBOARD_SPAN.with(|value| {
                    let next = match value.get() { 30 => 60, 60 => 120, _ => 30 };
                    value.set(next);
                    next
                });
                self.set_notice(&format!("Rentang chart: {span} sampel terbaru."));
                unsafe { InvalidateRect(self.h(INTEL_CHART), null(), 0); }
            }
            INTEL_MORE if selection(self.h(INTEL_MODE)) == DHCP6_HISTORY_MODE => {
                self.load_older_dhcp6_history()?;
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
                if mode == TOPOLOGY_MODE {
                    if self.intel.visual_edges.is_empty() {
                        return Err("Tidak ada relasi pada filter saat ini.".into());
                    }
                    return show_visual(
                        self.hwnd,
                        VisualData::Graph(self.intel.visual_edges.clone()),
                        self.selected_intel_row().unwrap_or(0),
                    );
                }
                let index = self
                    .selected_intel_row()
                    .ok_or("Pilih satu baris terlebih dahulu.")?;
                if mode == SUBNET_MODE {
                    let (scope, prefix) = self.intel.visible_subnet_keys.get(index)
                        .and_then(Option::as_ref).cloned()
                        .ok_or("Scope teramati belum terbukti; gunakan metadata manual secara eksplisit.")?;
                    let path = self.notes_path()?;
                    self.start_intel(move || {
                        let rows = ni::ipam_notes::page(&path)?;
                        Ok(IntelReply::IpamPivot(rows, scope, prefix))
                    })?;
                    return Ok(());
                }
                if mode == NOTES_MODE {
                    let note = self
                        .intel
                        .visible_notes
                        .get(index)
                        .ok_or("Pilih metadata.")?;
                    set(self.h(INTEL_FILTER), &note.editor());
                    return Ok(());
                }
                if mode == TREND_MODE {
                    let series = self
                        .intel
                        .visual_series
                        .get(index)
                        .cloned()
                        .ok_or("Pilih interface dengan sampel.")?;
                    return show_visual(self.hwnd, VisualData::Bandwidth(series), 0);
                }
                if mode == DASHBOARD_MODE {
                    if let Some(series) = self.intel.dashboard_charts.get(&index).cloned() {
                        return show_visual(self.hwnd, VisualData::Bandwidth(series), 0);
                    }
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
                if mode == IPAM_HISTORY_MODE {
                    select(self.h(INTEL_MODE),NOTES_MODE);
                    self.intel.mode=NOTES_MODE;
                    self.intel.filter.clear();
                    set(self.h(INTEL_FILTER),"");
                    self.intel_mode_labels(NOTES_MODE);
                    self.load_notes()?;
                    return Ok(());
                } else if mode == ARCHIVE_MODE && self.intel.pivot_scope.take().is_some() {
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
            INTEL_PROBE if selection(self.h(INTEL_MODE)) == NOTES_MODE => {
                let note=self.selected_intel_row().and_then(|i|self.intel.visible_notes.get(i))
                    .ok_or("Pilih metadata IPAM terlebih dahulu.")?;
                let (scope,cidr)=(note.scope.clone(),note.cidr.clone());
                let path=self.notes_path()?;
                self.start_intel(move || {
                    let rows=ni::ipam_notes::history(&path,&scope,&cidr,None)?;
                    Ok(IntelReply::IpamHistory(scope,cidr,rows))
                })?;
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
            INTEL_ROUTER | INTEL_RECORD if selection(self.h(INTEL_MODE)) == SECURE_MODE => {
                let polling = id == INTEL_RECORD;
                ni::secure_bridge::available()?;
                let target: std::net::SocketAddr = get(self.h(INTEL_HOST)).parse().map_err(|_| "Gunakan IP:port SNMP eksplisit.")?;
                if !ni::secure_monitor::valid_address(target) { return Err("Target SNMP tidak valid.".into()); }
                if popup(self.hwnd, &format!("{} sysUpTime.0 authPriv ke {target}? Hanya perangkat yang diizinkan. Hasil ringkas disimpan lokal. Polling maksimal 10 GET, jeda 30 detik dan berhenti saat gagal.", if polling { "Polling" } else { "GET" }), MB_YESNO | MB_DEFBUTTON2 | MB_ICONQUESTION) != IDYES { return Ok(()); }
                let Some(auth) = ask_session_credentials(self.hwnd, &target.to_string(), "SNMPv3 autentikasi", "Username dan password autentikasi SHA-256. Tidak disimpan.")? else { return Ok(()); };
                let Some(privacy) = ask_session_credentials(self.hwnd, &target.to_string(), "SNMPv3 privasi", "Username yang sama dan password privasi AES-128 yang berbeda.")? else { return Ok(()); };
                let units = |v: &[u16]| v.iter().position(|&n| n == 0).unwrap_or(v.len());
                if auth.user[..units(&auth.user)] != privacy.user[..units(&privacy.user)] { return Err("Username kedua dialog harus sama.".into()); }
                // Serialize directly from UTF-16 into short-lived buffers. Wipe
                // temporary password bytes on drop, including error paths.
                let utf8 = |v: &[u16]| -> Result<ni::secure_bridge::SecretBytes> {
                    let mut bytes = ni::secure_bridge::SecretBytes(Vec::with_capacity(2056));
                    for c in char::decode_utf16(v[..units(v)].iter().copied()) {
                        let c = c.map_err(|_| "Kredensial UTF-16 tidak valid.")?;
                        let mut buf = [0u8;4];
                        bytes.0.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                        for b in &mut buf { unsafe { std::ptr::write_volatile(b,0); } }
                    }
                    Ok(bytes)
                };
                let user = utf8(&auth.user)?;
                let ap = utf8(&auth.password)?;
                let pp = utf8(&privacy.password)?;
                if !(1..=32).contains(&user.0.len()) || !(8..=128).contains(&ap.0.len())
                    || !(8..=128).contains(&pp.0.len()) || ap.0 == pp.0 {
                    return Err("Kredensial SNMP tidak memenuhi batas atau password sama.".into());
                }
                let mut secret = ni::secure_bridge::SecretBytes(Vec::with_capacity(2048));
                use serde::Serialize;
                #[derive(Serialize)]
                struct Pipe<'a> { username: &'a str, auth_password: &'a str, privacy_password: &'a str }
                fn as_text(b: &[u8]) -> &str { std::str::from_utf8(b).unwrap_or("") }
                serde_json::to_writer(&mut secret.0, &Pipe { username: as_text(&user.0), auth_password: as_text(&ap.0), privacy_password: as_text(&pp.0) }).map_err(|_| "Serialisasi credential gagal.")?;
                let path = self.primary_archive_path()?.with_file_name("secure-observations-v1.sqlite3");
                if polling {
                    let cancel = ni::secure_bridge::SessionCancel::default();
                    let worker_cancel = cancel.clone();
                    self.start_intel(move || {
                        let result = ni::secure_bridge::poll_session(target, secret, &path, &worker_cancel)?;
                        Ok(IntelReply::SecureSession(ni::secure_monitor::page(&path)?,
                            ni::secure_monitor::attempts(&path)?, result))
                    })?;
                    self.intel.secure_cancel = Some(cancel);
                    self.set_notice("Polling SNMP berjalan; Stop sesi untuk membatalkan.");
                    self.controls();
                } else {
                    self.start_intel(move || {
                        let report = ni::secure_bridge::snmp(target, secret)?;
                        ni::secure_monitor::append(&path, &report)?;
                        Ok(IntelReply::SecureHistory(ni::secure_monitor::page(&path)?))
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
            INTEL_IMPORT if selection(self.h(INTEL_MODE)) == SECURE_MODE => {
                ni::secure_bridge::available()?;
                let Some(config) = typed_file_dialog(self.hwnd,false,"","Konfigurasi TLS JSON (*.json)\0*.json\0","json")? else { return Ok(()); };
                let expected = ni::secure_bridge::TlsConfig::read(&config)?;
                let choice = popup(self.hwnd,&format!("Mutual TLS pada {} · {} pin klien. Ya: collector 30 menit (maks 1024 koneksi, 4 bersamaan). Tidak: satu sesi. Batal: tidak membuka listener. Hanya ringkasan tersimpan. CRL: {}.",expected.bind,expected.allowed_client_sha256.len(),if expected.client_crl.is_some(){"aktif (strict)"}else{"tidak dikonfigurasi"}),MB_YESNOCANCEL | MB_DEFBUTTON3 | MB_ICONWARNING);
                if choice != IDYES && choice != IDNO { return Ok(()); }
                let path = self.primary_archive_path()?.with_file_name("secure-observations-v1.sqlite3");
                if choice == IDYES {
                    let cancel = ni::secure_bridge::SessionCancel::default();
                    let worker_cancel = cancel.clone();
                    self.start_intel(move || {
                        let result = ni::secure_bridge::collect_tls(&expected,&path,&worker_cancel)?;
                        Ok(IntelReply::SecureSession(ni::secure_monitor::page(&path)?,
                            ni::secure_monitor::attempts(&path)?, result))
                    })?;
                    self.intel.secure_cancel = Some(cancel);
                    self.set_notice("Collector TLS berjalan; Stop sesi untuk membatalkan.");
                    self.controls();
                } else {
                    self.start_intel(move || {
                        let report = ni::secure_bridge::tls(&config,&expected)?;
                        ni::secure_monitor::append(&path,&report)?;
                        Ok(IntelReply::SecureHistory(ni::secure_monitor::page(&path)?))
                    })?;
                }
            }
            INTEL_IMPORT if selection(self.h(INTEL_MODE)) == REPLAY_MODE => {
                if let Some(path) = typed_file_dialog(self.hwnd, false, "",
                    "Datagram JSONL (*.jsonl)\0*.jsonl\0", "jsonl")?
                {
                    self.intel.flow_replay = None;
                    self.start_intel(move || ni::flow_replay::read(&path).map(IntelReply::FlowReplay))?;
                    self.render_intel();
                }
            }
            INTEL_IMPORT if selection(self.h(INTEL_MODE)) == SYSLOG_MODE => {
                if let Some(path) = typed_file_dialog(
                    self.hwnd,
                    false,
                    "",
                    "Syslog (*.log;*.txt;*.bin)\0*.log;*.txt;*.bin\0",
                    "",
                )? {
                    self.intel.syslog_summary = None;
                    let framed = path.extension().and_then(|e| e.to_str())
                        .is_some_and(|e| e.eq_ignore_ascii_case("bin"));
                    self.start_intel(move || {
                        if framed { ni::syslog::read_octet_counted(&path) } else { ni::syslog::read(&path) }
                            .map(IntelReply::Syslog)
                    })?;
                    self.render_intel();
                }
            }
            INTEL_IMPORT if matches!(selection(self.h(INTEL_MODE)), NOTES_MODE | DHCP6_HISTORY_MODE) => {
                self.recover_independent_metadata(selection(self.h(INTEL_MODE)) == DHCP6_HISTORY_MODE)?;
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
            INTEL_HISTORY if selection(self.h(INTEL_MODE)) == SECURE_MODE => {
                let path = self.primary_archive_path()?.with_file_name("secure-observations-v1.sqlite3");
                self.start_intel(move || Ok(IntelReply::SecureLoaded(ni::secure_monitor::page(&path)?,
                    ni::secure_monitor::attempts(&path)?)))?;
            }
            INTEL_HISTORY if selection(self.h(INTEL_MODE)) == POLL_MODE => {
                let authority = Authority::parse(&get(self.h(INTEL_HOST)))?.display();
                let path = self.primary_archive_path()?.with_file_name("poll-health-v1.sqlite3");
                self.start_intel(move || {
                    let rows = ni::poll_health::page(&path, &authority)?;
                    Ok(IntelReply::PollHealth(authority, rows))
                })?;
            }
            INTEL_HISTORY if matches!(selection(self.h(INTEL_MODE)), TREND_MODE | LEASE_MODE) => {
                self.archived_router_views()?
            }
            INTEL_HISTORY
                if matches!(
                    selection(self.h(INTEL_MODE)),
                    DHCP6_MODE | DHCP6_HISTORY_MODE
                ) =>
            {
                self.load_dhcp6_history(false)?;
            }
            INTEL_HISTORY if selection(self.h(INTEL_MODE)) == NOTES_MODE => {
                self.save_notes(true)?;
            }
            INTEL_HISTORY => {
                let path = self.archive_path()?;
                let include_legacy = self.intel.recovery_view.is_none();
                self.start_intel(move || {
                    combined_history(ni::now(), &path, include_legacy).map(IntelReply::History)
                })?
            }
            INTEL_RECORD
                if matches!(
                    selection(self.h(INTEL_MODE)),
                    DHCP6_MODE | DHCP6_HISTORY_MODE
                ) =>
            {
                self.load_dhcp6_history(true)?;
            }
            INTEL_RECORD if selection(self.h(INTEL_MODE)) == NOTES_MODE => {
                self.save_notes(false)?;
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
                if selection(self.h(INTEL_MODE)) == DHCP6_HISTORY_MODE {
                    let authority = self.intel.dhcp6_history.as_ref()
                        .map(|(key, _)| key.clone())
                        .ok_or("Muat histori DHCPv6 terlebih dahulu.")?;
                    let source = self.dhcp6_history_path()?;
                    let redact = checked(self.h(INTEL_REDACT));
                    let (name, filter, ext) = if redact {
                        ("WeNet-DHCPv6-summary.json", "JSON (*.json)\0*.json\0", "json")
                    } else {
                        ("WeNet-DHCPv6-backup.sqlite3", "SQLite (*.sqlite3)\0*.sqlite3\0", "sqlite3")
                    };
                    if !redact && popup(self.hwnd,
                        "Backup berisi semua scope router, prefix dan histori, tanpa penyamaran. DUID tidak disimpan. Lanjutkan?",
                        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2) != IDYES {
                        return Ok(());
                    }
                    let Some(dest) = typed_file_dialog(self.hwnd, true, name, filter, ext)? else {
                        return Ok(());
                    };
                    self.start_intel(move || {
                        if redact {
                            ni::dhcp6_history::export_summary(&source, &authority, &dest)?;
                        } else {
                            ni::dhcp6_history::backup(&source, &dest)?;
                        }
                        Ok(IntelReply::Export(dest))
                    })?;
                    return Ok(());
                }
                if selection(self.h(INTEL_MODE)) == NOTES_MODE {
                    let source = self.notes_path()?;
                    let redact = checked(self.h(INTEL_REDACT));
                    let (name, filter, ext) = if redact {
                        ("WeNet-IPAM-summary.json", "JSON (*.json)\0*.json\0", "json")
                    } else {
                        (
                            "WeNet-IPAM-backup.sqlite3",
                            "SQLite (*.sqlite3)\0*.sqlite3\0",
                            "sqlite3",
                        )
                    };
                    let Some(dest) = typed_file_dialog(self.hwnd, true, name, filter, ext)? else {
                        return Ok(());
                    };
                    if !redact
                        && popup(
                            self.hwnd,
                            "Backup IPAM memuat alamat, scope dan catatan operator tanpa penyamaran. Simpan ke file baru?",
                            MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2,
                        ) != IDYES
                    {
                        return Ok(());
                    }
                    self.start_intel(move || {
                        if redact {
                            ni::ipam_notes::export_summary(&source, &dest)?;
                        } else {
                            ni::ipam_notes::backup(&source, &dest)?;
                        }
                        Ok(IntelReply::Export(dest))
                    })?;
                } else if selection(self.h(INTEL_MODE)) == ARCHIVE_MODE {
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
        let old_selection = if self.intel.rendered_mode == Some(mode) {
            self.selected_intel_row().and_then(|i|self.intel.rendered_rows.get(i)).cloned()
        } else { None };
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
            let now = ni::now();
            if stamp > now {
                "waktu ambigu"
            } else if now - stamp > ni::FRESH_SECONDS {
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
        let mut dashboard_charts = std::collections::BTreeMap::new();
        let mut visual_edges = Vec::new();
        let mut visual_series = Vec::new();
        let mut visible_notes = Vec::new();
        let mut visible_subnet_keys = Vec::new();
        let description = match mode {
            DASHBOARD_MODE => {
                let mut row = |values: [String; 4],
                               detail: String,
                               target: usize,
                               series: Option<ni::visual::Series>| {
                    if search.matches(&values.each_ref().map(String::as_str))
                        && dashboard_targets.len() < INTEL_ROW_LIMIT
                    {
                        if let Some(series) = series {
                            dashboard_charts.insert(dashboard_targets.len(), series);
                        }
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
                        None,
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
                        None,
                    );
                }
                for (key, s) in &self.intel.routers {
                    let c = overview::coverage(&s.coverage, now);
                    let poll = self.intel.schedule.jobs.get(key);
                    row(
                        [
                            "MikroTik".into(),
                            key.clone(),
                            format!(
                                "{} lengkap / {} parsial / {} gagal",
                                c.complete, c.partial, c.unavailable
                            ),
                            format!("{} observasi IP · UTC {}", s.inventory.len(), s.observed_at),
                        ],
                        format!(
                            "{} interface, {} koneksi, {} sumber historis/ambigu. Polling: {:?}. Tidak menyatakan router online dari snapshot.",
                            s.interfaces.len(),
                            s.connections.len(),
                            c.stale,
                            poll.and_then(|p| p.outcome)
                        ),
                        5,
                        None,
                    );
                    if let Some(resource) = &s.resource
                        && let Some(coverage) = s.coverage.iter().rev().find(|c| {
                            c.source == ni::router::Table::Resource.name()
                                && c.state != ni::CoverageState::Unavailable
                        })
                    {
                        let memory = resource
                            .free_memory_bytes
                            .zip(resource.total_memory_bytes)
                            .filter(|(free, total)| *total != 0 && free <= total)
                            .map(|(free, total)| {
                                (u128::from(total - free) * 100 / u128::from(total)) as u64
                            });
                        row(
                            [
                                "Resource MikroTik".into(),
                                key.clone(),
                                format!(
                                    "CPU {}% · RAM {}%",
                                    display_opt(resource.cpu_percent.filter(|v| *v <= 100)),
                                    display_opt(memory),
                                ),
                                format!(
                                    "{} · UTC {}",
                                    age(coverage.observed_at),
                                    coverage.observed_at
                                ),
                            ],
                            format!(
                                "Versi {} · uptime {:?}. CPU/RAM adalah snapshot Resource, bukan status online. Cakupan {:?}.",
                                resource.version, resource.uptime, coverage.state
                            ),
                            6,
                            None,
                        );
                    }
                    if let Some(trend) = self.intel.trends.get(key) {
                        for (name, points) in &trend.streams {
                            let summary = interface_trend::summarize(points);
                            if let Some(last) = points.back() {
                                let series = ni::visual::Series::new(
                                    format!("{key} / {name}"),
                                    points,
                                );
                                let (rx_preview, tx_preview) = series.preview(24);
                                row(
                                    [
                                        "Bandwidth interface".into(),
                                        format!("{key} / {name}"),
                                        format!(
                                            "RX {} bps · TX {} bps",
                                            display_opt(last.rx_bps),
                                            display_opt(last.tx_bps),
                                        ),
                                        format!("UTC {} · {} gap", last.utc, summary.gaps),
                                    ],
                                    format!(
                                        "P95 RX {} bps · TX {} bps. {} interval valid.\nRX {rx_preview}\nTX {tx_preview}\n24 sampel terakhir, skala bersama; ? gap, · nol. Tidak menjumlahkan interface yang mungkin membawa trafik sama.",
                                        display_opt(summary.p95_rx),
                                        display_opt(summary.p95_tx),
                                        summary.valid_intervals
                                    ),
                                    TREND_MODE,
                                    Some(series),
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
                            format!(
                                "{} drop · {} antre",
                                stats.archive_dropped, stats.archive_pending
                            ),
                            format!("{} record tersimpan", stats.archived),
                        ],
                        format!(
                            "Antrean penuh {} · writer tertutup {} · SQLite gagal {}. Sequence berulang {} · reorder {} · restart v9 {}. Error: {:?} / {:?} / {:?}. Bukan pengukuran drop kernel.",
                            stats.archive_queue_full,
                            stats.archive_writer_closed,
                            stats.archive_sqlite_failed,
                            stats.sequence_repeated,
                            stats.sequence_reordered,
                            stats.generation_restarts,
                            stats.error,
                            stats.archive_error,
                            stats.alert_error
                        ),
                        13,
                        None,
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
                            None,
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
                        None,
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
                            if self.intel.recovery_view.is_some() {
                                "baca-saja"
                            } else {
                                "utama"
                            },
                            s.main_bytes,
                            s.wal_bytes
                        ),
                        STORAGE_MODE,
                        None,
                    );
                } else {
                    row(
                        [
                            "Arsip SQLite".into(),
                            if self.intel.storage_loading {
                                "Memuat arsip"
                            } else if self.intel.storage_failed {
                                "Gagal membaca arsip"
                            } else if self.intel.storage_loaded {
                                "Arsip belum ada"
                            } else {
                                "Belum dibaca"
                            }
                            .into(),
                            "Tidak diketahui".into(),
                            "Cari untuk membaca".into(),
                        ],
                        "Tidak ada hasil pengukuran arsip saat ini. Gagal membaca tidak berarti database kosong.".into(),
                        STORAGE_MODE,
                        None,
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
                    None,
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
                    None,
                );
                row(
                    [
                        "DHCPv6 / PD".into(),
                        "Binding RouterOS".into(),
                        "Cakupan per router".into(),
                        "Buka modul".into(),
                    ],
                    "Binding terpisah dari ND/SLAAC; tidak membuktikan host online.".into(),
                    DHCP6_MODE,
                    None,
                );
                row(
                    [
                        "IPAM metadata".into(),
                        "Alias, tag, catatan".into(),
                        "Data operator".into(),
                        "Buka modul".into(),
                    ],
                    "Metadata administratif lokal terpisah dari observasi perangkat.".into(),
                    NOTES_MODE,
                    None,
                );
                row(
                    [
                        "Histori DHCPv6".into(),
                        "Snapshot persisten".into(),
                        "Scope router".into(),
                        "Buka modul".into(),
                    ],
                    "Histori tanpa DUID; tidak menyimpulkan interval assignment.".into(),
                    DHCP6_HISTORY_MODE,
                    None,
                );
                row(
                    [
                        "Syslog offline".into(),
                        "Ringkasan header".into(),
                        "Sumber tidak diautentikasi".into(),
                        "Buka modul".into(),
                    ],
                    "Impor file lokal pilihan operator; tidak ada listener atau penyimpanan pesan."
                        .into(),
                    SYSLOG_MODE,
                    None,
                );
                "Dashboard snapshot. Buka modul; baris bandwidth membuka grafik scope eksak. Tidak ada klaim jaringan sehat dari data yang tidak tersedia."
            }
            NOTES_MODE => {
                for note in &self.intel.ipam_notes {
                    let state = if !note.active {
                        "Dibatalkan"
                    } else if note.reserved {
                        "Reservasi administratif"
                    } else {
                        "Label operator"
                    };
                    let summary = format!("{} · {}", note.alias, note.tags);
                    if visible_notes.len() < INTEL_ROW_LIMIT
                        && search.matches(&[&note.cidr, &note.scope, state, &summary])
                    {
                        visible_notes.push(note.clone());
                    }
                    push(
                        [note.cidr.clone(), note.scope.clone(), state.into(), summary],
                        &|| {
                            format!(
                                "{} / {}\nAlias {} · tag {}\nCatatan: {}\nRevisi {} · UTC {}\nMetadata manual; tidak membuktikan assignment atau mengubah router. Histori tidak ditimpa.",
                                note.scope,
                                note.cidr,
                                note.alias,
                                note.tags,
                                note.note,
                                note.revision,
                                note.recorded
                            )
                        },
                    );
                }
                "Metadata lokal. Format scope|CIDR|label/reserved|alias|tag|catatan. Simpan menampilkan overlap snapshot scope yang sama. Isi editor, Undo, backup dan Pulihkan salinan baru. Reset sebelum membuat key baru."
            }
            IPAM_HISTORY_MODE => {
                if let Some((scope,cidr,rows))=&self.intel.ipam_history {
                    for n in rows {
                        push([format!("Revisi {}",n.revision),format!("{scope} / {cidr}"),
                            if !n.active {"Dibatalkan".into()} else if n.reserved {"Reservasi operator".into()} else {"Label operator".into()},
                            format!("UTC {}",n.recorded)],
                            &||format!("{}\nAlias: {}\nTag: {}\nCatatan: {}\nMetadata historis, bukan bukti assignment.",n.editor(),n.alias,n.tags,n.note));
                    }
                }
                "Histori IPAM read-only · pilih Revisi IPAM dari metadata, Terbaru atau Lebih lama. Kembali untuk mengedit metadata aktif."
            }
            SECURE_MODE => {
                for report in &self.intel.secure_history {
                    push([report.label().into(), report.scope(), report.summary(), format!("UTC {}",report.stamp())],
                        &|| format!("{}\n{}\n{}\nObservasi historis, bukan status online saat ini.",report.label(),report.scope(),report.summary()));
                }
                for attempt in &self.intel.secure_attempts {
                    push(["Polling SNMP".into(),attempt.target.to_string(),
                        if attempt.success { "Berhasil".into() } else { "Gagal / ditolak".into() },
                        format!("UTC {}",attempt.stamp)],
                        &|| format!("Durasi {} ms. Kegagalan tidak membuktikan sebab autentikasi tertentu.",attempt.elapsed_ms));
                }
                "Secure Transport · SNMP GET/polling 10 sampel; TLS satu sesi atau collector 30 menit. Stop sesi membatalkan pekerjaan. Histori lokal bukan status online. Helper harus terverifikasi."
            }
            REPLAY_MODE => {
                if let Some(report) = &self.intel.flow_replay {
                    for (name, count, explanation) in [
                        ("Datagram", report.datagrams as u64, "Frame JSONL yang diproses"),
                        ("Record", report.decoded_records as u64, "Record dengan pasangan alamat valid"),
                        ("Invalid", report.invalid as u64, "Datagram ditolak decoder"),
                        ("Duplikat", report.duplicates as u64, "Identitas datagram berulang"),
                        ("Template hilang", report.missing_templates, "Set tanpa template yang berlaku"),
                        ("Skipped", report.skipped, "Set/record tidak diinterpretasikan"),
                        ("Sequence berulang", report.repeated_sequence as u64, "Bukan estimasi loss"),
                        ("Reorder", report.reordered_sequence as u64, "Export sequence/waktu tidak maju"),
                        ("Restart", report.generation_restarts as u64, "Indikasi restart v9"),
                        ("Options record", report.options_records, "Options IPFIX yang diperiksa"),
                        ("Sampling", report.sampling_fields as u64, "Metadata terlapor, tanpa scaling"),
                        ("NAT", report.nat_fields as u64, "Field post-observation terlapor"),
                    ] {
                        push([name.into(), "Replay offline".into(), count.to_string(), explanation.into()],
                            &|| format!("{name}: {count}\n{explanation}. Tidak mengirim datagram atau mengubah arsip."));
                    }
                }
                "Pilih Replay JSONL untuk diagnostik decoder lokal. Tidak membuka socket, tidak menyimpan arsip, tidak membuktikan reachability."
            }
            SYSLOG_MODE => {
                if let Some(summary) = &self.intel.syslog_summary {
                    push(
                        [
                            "Ringkasan impor".into(),
                            format!("{} diterima", summary.accepted),
                            format!("{} ditolak", summary.rejected),
                            if summary.limited {
                                "Batas baris"
                            } else {
                                "File dibaca"
                            }
                            .into(),
                        ],
                        &|| {
                            "Header tidak diautentikasi. Isi pesan dan identitas tidak disimpan."
                                .into()
                        },
                    );
                    for ((format, facility, severity), count) in &summary.groups {
                        push(
                            [
                                format!("{format:?}"),
                                format!("Facility {facility}"),
                                format!("Severity {severity}"),
                                format!("{count} baris"),
                            ],
                            &|| {
                                format!(
                                    "Header tidak diautentikasi. {} diterima, {} ditolak; batas baris {}. Pesan, identitas host dan timestamp tidak disimpan.",
                                    summary.accepted, summary.rejected, summary.limited
                                )
                            },
                        );
                    }
                    "Ringkasan Syslog offline. Tidak membuktikan pengirim atau insiden; tidak ada listener jaringan. Detail memperlihatkan jumlah ditolak."
                } else {
                    "Impor Syslog: .log/.txt UTF-8 atau .bin octet-counted (maksimal 1 MiB / 10.000 frame). Hanya facility/severity disimpan. Tidak ada autentikasi TLS."
                }
            }
            DHCP6_HISTORY_MODE => {
                if let Some((router, rows)) = &self.intel.dhcp6_history {
                    for capture in rows {
                        push(
                            [
                                format!("UTC {}", capture.stamp),
                                router.clone(),
                                format!("{:?}", capture.coverage),
                                format!("{} / {} baris", capture.rows.len(), capture.reported),
                            ],
                            &|| {
                                let sample = capture
                                    .rows
                                    .iter()
                                    .take(100)
                                    .map(|r| {
                                        format!(
                                            "{}/{} · {} · {} · if {} · VRF {}",
                                            r.binding.prefix,
                                            r.binding.bits,
                                            r.binding.server,
                                            r.binding.state(),
                                            r.scope.interface.as_deref().unwrap_or("?"),
                                            r.scope.vrf.as_deref().unwrap_or("?")
                                        )
                                    })
                                    .collect::<Vec<_>>()
                                    .join("\n");
                                format!(
                                    "{} · UTC {} · {:?}\n{} dari {} baris disimpan; detail maks. 100. Histori snapshot, bukan interval assignment.\n{sample}",
                                    router,
                                    capture.stamp,
                                    capture.coverage,
                                    capture.rows.len(),
                                    capture.reported
                                )
                            },
                        );
                    }
                    "Histori eksak router yang dimuat; 20 snapshot per halaman. Lanjut untuk halaman lebih lama; Histori DHCPv6 untuk terbaru. Samarkan untuk ringkasan; hapus centang untuk backup semua router. Gap bukan bukti prefix bebas."
                } else {
                    "Masukkan host router lalu Histori DHCPv6. Gunakan Simpan DHCPv6 untuk menyimpan snapshot yang telah dibaca."
                }
            }
            DHCP6_MODE => {
                for (router, snapshot) in &self.intel.routers {
                    if let Some(c) = snapshot
                        .coverage
                        .iter()
                        .rev()
                        .find(|c| c.source == ni::router::Table::Dhcp6Binding.name())
                    {
                        push(
                            [
                                router.clone(),
                                "Cakupan tabel DHCPv6".into(),
                                format!("{:?}", c.state),
                                format!("{} baris · UTC {}", c.rows, c.observed_at),
                            ],
                            &|| detail_source(c),
                        );
                    }
                    let index = ni::dhcp6::ScopeIndex::new(snapshot);
                    for binding in &snapshot.dhcp6 {
                        let scope = index.scope(binding);
                        push(
                            [
                                format!("{}/{}", binding.prefix, binding.bits),
                                format!("{router} / {}", binding.server),
                                binding.state().into(),
                                binding.kind().into(),
                            ],
                            &|| {
                                format!(
                                    "{} · {}\nRouter {} · server {}\nUTC {} · status {:?} · disabled {:?}\nInterface {} · VRF {}. Pemetaan hanya tabel lengkap dan selaras ≤60 detik. Bukan bukti SLAAC, ND, online, atau alamat bebas.",
                                    binding.prefix,
                                    binding.kind(),
                                    router,
                                    binding.server,
                                    binding.observed_at,
                                    binding.status,
                                    binding.disabled,
                                    scope.interface.as_deref().unwrap_or("tidak diketahui"),
                                    scope.vrf.as_deref().unwrap_or("tidak diketahui")
                                )
                            },
                        );
                    }
                }
                "Binding DHCPv6 / PD dibaca HTTPS GET. Jika tabel tidak tersedia, status tidak diketahui; tidak menyatakan jaringan tanpa DHCPv6."
            }
            SUBNET_MODE => {
                let mut groups = Vec::new();
                if let Some(s) = local {
                    groups.push(overview::local_subnets(s));
                }
                groups.extend(self.intel.routers.values().map(|s| network_map::subnets(s)));
                let limited = groups.iter().any(|g| g.limited);
                for r in groups.iter().flat_map(|g| &g.rows) {
                    let values = [
                        r.prefix.to_string(),
                        r.scope.clone(),
                        format!("{} konfigurasi · {} IP teramati", r.configured, r.observed),
                        if r.partial { "Cakupan parsial" } else { "Snapshot sumber" }.into(),
                    ];
                    if visible_subnet_keys.len() < INTEL_ROW_LIMIT
                        && search.matches(&values.each_ref().map(String::as_str))
                    {
                        visible_subnet_keys.push(r.operator_scope.as_ref().map(|key| (key.clone(), r.prefix.to_string())));
                    }
                    push(
                        values,
                        &|| {
                            format!(
                                "Subnet {} · {}\nScope metadata: {}\n{} alamat dalam prefix (termasuk alamat khusus). {} konfigurasi interface; {} IP unik teramati pada scope. UTC {}. Tidak teramati ≠ bebas. Tidak ada pemindaian atau reservasi otomatis. Prefix bertumpang tindih tidak dijumlahkan.",
                                r.prefix,
                                r.scope,
                                r.operator_scope.as_deref().unwrap_or("tidak tersedia; scope belum terbukti"),
                                r.prefix.cardinality(),
                                r.configured,
                                r.observed,
                                r.observed_at
                            )
                        },
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
                                            "{source} → {dest}\nExporter {} · domain {}\nInterface masuk/keluar {} / {}\nByte/paket {} / {}\nExport UTC {} · diterima UTC {}\n{}\nTidak menghitung trafik yang tidak dikirim exporter.",
                                            f.exporter,
                                            f.domain,
                                            display_opt(f.ingress),
                                            display_opt(f.egress),
                                            display_opt(f.octets),
                                            display_opt(f.packets),
                                            f.export_at,
                                            f.received_at,
                                            f.provenance.as_ref().map_or_else(
                                                || "Sampling/NAT tidak diketahui.".into(),
                                                flow::Provenance::summary
                                            )
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
                if let Some((key, records)) = &self.intel.poll_health {
                    for record in records {
                        push(
                            [key.clone(), format!("UTC {}", record.stamp),
                                record.outcome.into(), format!("{} ms", record.elapsed_ms)],
                            &|| format!("Histori lokal #{} · {} · penyimpanan snapshot: {}. Bukan bukti status online saat ini.",
                                record.id, record.outcome, record.archive_state),
                        );
                    }
                }
                "Isi host dan interval. Mulai/hentikan target; Histori kesehatan menampilkan 100 hasil terakhir per router (512/router, 4096 total). Tidak aktif otomatis setelah keluar."
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
                if mode == TOPOLOGY_MODE {
                    for (authority, (topology, _)) in &self.intel.network_views {
                        for r in topology {
                            if visual_edges.len() < ni::visual::MAX_EDGES
                                && search.matches(&[&r.subject, &r.target, r.basis, &r.scope])
                            {
                                visual_edges.push(ni::visual::Edge::scoped(authority, r));
                            }
                        }
                    }
                }
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
                        if visual_series.len() < INTEL_ROW_LIMIT
                            && search.matches(&[name, router, &latest, &stats])
                        {
                            visual_series.push(ni::visual::Series::new(
                                format!("{router} / {name}"),
                                points,
                            ));
                        }
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
                } else if self.intel.storage_loading || self.intel.storage_failed {
                    let state = if self.intel.storage_loading {
                        "Memuat arsip"
                    } else {
                        "Gagal membaca arsip"
                    };
                    push(
                        [
                            title.into(),
                            state.into(),
                            "Tidak diketahui".into(),
                            "Muat ulang".into(),
                        ],
                        &|| "Tidak ada hasil pengukuran baru.".into(),
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
                                    "{src} → {dst}\nProfil {} / site {} / VRF {}\nExporter {} / domain {} / versi {}\nProtokol {} · interface {} → {}\nByte {} · paket {}\nExport UTC {} · diterima UTC {}\n{}",
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
                                    f.received_at,
                                    f.provenance.as_ref().map_or_else(
                                        || "Sampling/NAT tidak diketahui.".into(),
                                        flow::Provenance::summary
                                    )
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
                if self.page == Page::Intel && matches!(mode, ARCHIVE_MODE | DHCP6_HISTORY_MODE | DASHBOARD_MODE | IPAM_HISTORY_MODE) {
                    SW_SHOW
                } else {
                    SW_HIDE
                },
            );
        }
        for (id, show) in [
            (
                INTEL_IP_JOURNEY,
                matches!(
                    mode,
                    0 | 1 | DEVICE_MODE | DASHBOARD_MODE | TOPOLOGY_MODE | TREND_MODE | NOTES_MODE | SUBNET_MODE
                ),
            ),
            (
                INTEL_BACK,
                mode == IPAM_HISTORY_MODE || mode == ARCHIVE_MODE && self.intel.pivot_scope.is_some()
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
            (INTEL_REFRESH, mode != STORAGE_MODE && mode != SECURE_MODE),
            (INTEL_FLOW, mode != STORAGE_MODE && mode != SECURE_MODE),
            (INTEL_HISTORY, mode != STORAGE_MODE),
            (INTEL_REDACT, mode != STORAGE_MODE && mode != SECURE_MODE),
            (INTEL_PROBE, mode != IPAM_HISTORY_MODE),
            (INTEL_ROUTER, mode != IPAM_HISTORY_MODE),
            (INTEL_IMPORT, mode != IPAM_HISTORY_MODE),
            (INTEL_RECORD, mode != IPAM_HISTORY_MODE),
            (INTEL_EXPORT, mode != IPAM_HISTORY_MODE),
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
        // Mode-specific column names make the same native table usable as
        // an evidence workspace without changing existing row semantics.
        let headers = match mode {
            SECURE_MODE => ["Transport", "Target / identitas", "Hasil", "Waktu UTC"],
            IPAM_HISTORY_MODE => ["Revisi", "Scope / prefix", "Status metadata", "Waktu UTC"],
            REPLAY_MODE => ["Metrik", "Sumber", "Jumlah", "Keterangan"],
            SUBNET_MODE => ["Prefix", "Scope", "Observasi", "Cakupan"],
            DHCP6_HISTORY_MODE => ["Snapshot", "Identitas", "Bukti", "Status"],
            _ => ["Objek", "Sumber / scope", "Bukti", "Status"],
        };
        if self.intel.rendered_mode != Some(mode) {
            self.table_headers(INTEL_TABLE, &headers);
        }
        if self.intel.rendered_mode != Some(mode) || self.intel.rendered_rows != visible {
            self.table_rows(INTEL_TABLE, &visible, 4);
            if let Some(old) = old_selection {
                let mut matches = visible.iter().enumerate().filter(|(_,row)|*row==&old);
                if let Some((index,_))=matches.next() && matches.next().is_none() {
                    self.restore_table_selection(INTEL_TABLE,index);
                }
            }
            self.intel.rendered_rows=visible.clone();
            self.intel.rendered_mode=Some(mode);
        }
        self.intel.details = details;
        self.intel.dashboard_targets = dashboard_targets;
        DASHBOARD_CHART_CACHE.with(|cache| {
            *cache.borrow_mut() = dashboard_charts.clone();
        });
        self.intel.dashboard_charts = dashboard_charts;
        unsafe { InvalidateRect(self.h(INTEL_CHART),null(),0); }
        self.layout();
        self.intel.visual_edges = visual_edges;
        self.intel.visual_series = visual_series;
        self.intel.visible_notes = visible_notes;
        self.intel.visible_subnet_keys = visible_subnet_keys;
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
