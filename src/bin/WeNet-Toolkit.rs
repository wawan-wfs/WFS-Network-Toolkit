#![cfg_attr(windows, windows_subsystem = "windows")]
#[cfg(not(windows))]
fn main() {
    eprintln!("WeNet Toolkit memerlukan Windows 10/11.");
}
#[cfg(windows)]
fn main() {
    desktop::run();
}

#[cfg(windows)]
mod desktop {
    use std::{
        ffi::OsString,
        mem::size_of,
        net::Ipv4Addr,
        os::windows::ffi::{OsStrExt, OsStringExt},
        path::PathBuf,
        ptr::{null, null_mut},
        sync::mpsc::{self, Receiver, TryRecvError},
        thread,
    };
    use wfs_network_toolkit::{
        Address, Change, Ipv4, Mac, Result,
        adapter_state::MediaState,
        mac_plan, mask,
        migration::{IpDraft, RestoreScope, restore_inputs},
        optional_ipv4, parse_mask, read_backup, subnet,
        ui_layout::{COPYRIGHT_RECT, VERSION_RECT, client_scale, control_rect},
        windows as w, write_new_json,
    };
    use windows_sys::Win32::{
        Foundation::*,
        Graphics::Gdi::*,
        System::{
            Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize},
            LibraryLoader::GetModuleHandleW,
            Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject},
        },
        UI::{
            Controls::{Dialogs::*, *},
            HiDpi::{
                DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, GetDpiForSystem, GetDpiForWindow,
                SetProcessDpiAwarenessContext,
            },
            Input::KeyboardAndMouse::{EnableWindow, SetFocus},
            Shell::{
                SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
            },
            WindowsAndMessaging::*,
        },
    };
    const VERSION: &str = env!("CARGO_PKG_VERSION");
    const RESOURCE_ICON: usize = 101;

    enum Request {
        Driver,
        NetworkConnections,
        Backup {
            include_mac: bool,
        },
        Import {
            scope: RestoreScope,
            include_mac: bool,
        },
        PreviewIp(Ipv4),
        PreviewMac {
            value: String,
        },
        PreviewFactory,
        PreviewRecover,
        Confirm {
            token: u32,
        },
        Ping,
        Subnet {
            ip: Ipv4Addr,
            prefix: u8,
        },
        Export {
            redact: bool,
        },
    }
    struct Preview {
        token: u32,
        title: String,
        adapter: String,
        rows: Vec<[String; 3]>,
        note: String,
        warnings: Vec<String>,
        button: String,
    }
    enum Notice {
        Status(String),
        Information(String),
        Warning(String),
        Error(String),
    }
    impl Notice {
        fn dialog(&self) -> Option<(&'static str, u32)> {
            match self {
                Self::Status(_) => None,
                Self::Information(_) => Some(("Informasi", MB_ICONINFORMATION)),
                Self::Warning(_) => Some(("Perhatian", MB_ICONWARNING)),
                Self::Error(_) => Some(("Terjadi kesalahan", MB_ICONERROR)),
            }
        }
        fn text(&self) -> &str {
            match self {
                Self::Status(s) | Self::Information(s) | Self::Warning(s) | Self::Error(s) => s,
            }
        }
    }
    enum OperationResult {
        Changed(String),
        DialogShown,
        Ping(String),
    }
    const HELPER_SUCCESS: u32 = 0;
    const HELPER_ERROR_SHOWN: u32 = 1;
    const HELPER_DIALOG_FAILED: u32 = 2;

    #[derive(Default)]
    struct Reply {
        state: Option<Dashboard>,
        preview: Option<Preview>,
        output: Option<String>,
        notice: Option<Notice>,
    }
    struct App {
        hwnd: HWND,
        selected: Option<String>,
        work: Option<Receiver<Result<OperationResult>>>,
        preview: Option<(u32, Change)>,
        token: u32,
    }
    fn popup(h: HWND, message: &str, flags: u32) -> i32 {
        popup_titled(h, "WeNet Toolkit", message, flags)
    }
    fn popup_titled(h: HWND, title: &str, message: &str, flags: u32) -> i32 {
        // Win32 expects NUL-terminated UTF-16 for both pointers for the duration of the call.
        unsafe {
            MessageBoxW(
                h,
                w::wide(message).as_ptr(),
                w::wide(title).as_ptr(),
                flags | MB_OK,
            )
        }
    }
    fn execute_elevated(c: Change) -> Result<OperationResult> {
        if w::elevated() {
            return w::apply_checked(&c).map(OperationResult::Changed);
        }
        let payload = c.encode()?;
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let path: Vec<u16> = exe.as_os_str().encode_wide().chain([0]).collect();
        let verb = w::wide("runas");
        let args = w::wide(&format!("--apply-change {payload}"));
        let mut si = SHELLEXECUTEINFOW {
            cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
            fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
            lpVerb: verb.as_ptr(),
            lpFile: path.as_ptr(),
            lpParameters: args.as_ptr(),
            nShow: SW_SHOW,
            ..Default::default()
        };
        let com = unsafe { CoInitializeEx(null(), COINIT_APARTMENTTHREADED as u32) };
        let launched = unsafe { ShellExecuteExW(&mut si) };
        let launch_error = std::io::Error::last_os_error();
        if com >= 0 {
            unsafe {
                CoUninitialize();
            }
        }
        if launched == 0 || si.hProcess.is_null() {
            return Err(format!(
                "Izin Administrator tidak diberikan atau helper gagal dibuka: {launch_error}"
            ));
        }
        let mut code = 1;
        let wait = unsafe { WaitForSingleObject(si.hProcess, INFINITE) };
        let valid = unsafe { GetExitCodeProcess(si.hProcess, &mut code) };
        unsafe {
            CloseHandle(si.hProcess);
        }
        if wait != WAIT_OBJECT_0 || valid == 0 {
            return Err(
                "Status helper tidak diketahui. Muat ulang dan periksa snapshot pemulihan.".into(),
            );
        }
        match code {
            HELPER_SUCCESS | HELPER_ERROR_SHOWN => Ok(OperationResult::DialogShown),
            _ => Err("Hasil operasi Administrator tidak dapat ditampilkan. Muat ulang dan periksa adaptor serta snapshot pemulihan sebelum mencoba lagi.".into()),
        }
    }
    fn file_dialog(h: HWND, save: bool, report: bool) -> Result<Option<PathBuf>> {
        if report {
            typed_file_dialog(
                h,
                save,
                "WeNet-Diagnostic.txt",
                "Laporan (*.txt)\0*.txt\0",
                "txt",
            )
        } else {
            typed_file_dialog(
                h,
                save,
                "WeNet-Backup.json",
                "Profil JSON (*.json)\0*.json\0Semua berkas\0*.*\0",
                "json",
            )
        }
    }
    fn analysis_csv_dialog(h: HWND) -> Result<Option<PathBuf>> {
        typed_file_dialog(
            h,
            true,
            "WFS-Akses-Internet.csv",
            "Laporan CSV (*.csv)\0*.csv\0",
            "csv",
        )
    }
    fn typed_file_dialog(
        h: HWND,
        save: bool,
        default: &str,
        filter: &str,
        ext: &str,
    ) -> Result<Option<PathBuf>> {
        let mut buffer = vec![0u16; 32768];
        if save {
            let init = w::wide(default);
            buffer[..init.len()].copy_from_slice(&init);
        }
        let filter = w::wide(filter);
        let ext = w::wide(ext);
        let mut options = OPENFILENAMEW {
            lStructSize: size_of::<OPENFILENAMEW>() as u32,
            hwndOwner: h,
            lpstrFilter: filter.as_ptr(),
            nFilterIndex: 1,
            lpstrFile: buffer.as_mut_ptr(),
            nMaxFile: buffer.len() as u32,
            lpstrDefExt: ext.as_ptr(),
            Flags: OFN_EXPLORER
                | OFN_NOCHANGEDIR
                | OFN_DONTADDTORECENT
                | OFN_PATHMUSTEXIST
                | if save {
                    OFN_NOREADONLYRETURN
                } else {
                    OFN_FILEMUSTEXIST
                },
            ..Default::default()
        };
        let b = unsafe {
            if save {
                GetSaveFileNameW(&mut options)
            } else {
                GetOpenFileNameW(&mut options)
            }
        };
        if b == 0 {
            let e = unsafe { CommDlgExtendedError() };
            return if e == 0 {
                Ok(None)
            } else {
                Err(format!("Dialog file gagal (kode {e})"))
            };
        }
        let end = buffer.iter().position(|&c| c == 0).unwrap_or(buffer.len());
        Ok(Some(PathBuf::from(OsString::from_wide(&buffer[..end]))))
    }
    fn config_rows(c: &Ipv4) -> [String; 4] {
        [
            if c.dhcp {
                "DHCP".into()
            } else {
                "Statis".into()
            },
            c.addresses
                .iter()
                .map(|v| format!("{}/{} · {}", v.ip, v.prefix, mask(v.prefix)))
                .collect::<Vec<_>>()
                .join("\n"),
            c.gateway
                .map_or_else(|| "Otomatis / tidak disetel".into(), |v| v.to_string()),
            c.dns
                .as_ref()
                .map(|v| {
                    v.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_else(|| "Otomatis".into()),
        ]
    }
    fn label(m: Option<Mac>) -> String {
        m.map_or_else(|| "Tidak tersedia".into(), |m| m.to_string())
    }
    impl App {
        fn current(&self) -> Result<w::Adapter> {
            w::adapter(
                self.selected
                    .as_deref()
                    .ok_or("Pilih adaptor terlebih dahulu")?,
            )
        }
        fn state(&mut self) -> Result<Dashboard> {
            let (selected, dashboard) = Self::inventory(self.selected.as_deref())?;
            self.selected = selected;
            Ok(dashboard)
        }
        fn inventory(selected: Option<&str>) -> Result<(Option<String>, Dashboard)> {
            let adapters = w::adapters()?;
            let candidate = selected
                .and_then(|id| adapters.iter().find(|a| a.id == id))
                .or_else(|| adapters.first());
            let selected = candidate.map(|a| a.id.clone());
            let current = candidate.map(|a| {
                let config = w::ipv4_config(a);
                let (pending, recovery) = w::recovery_available(&a.id).unwrap_or_default();
                Current {
                    adapter: a.clone(),
                    config,
                    pending,
                    recovery,
                }
            });
            Ok((selected, Dashboard { adapters, current }))
        }
        fn preview(
            &mut self,
            title: &str,
            draft: Option<IpDraft>,
            mac: Option<Mac>,
            factory: bool,
            recover: bool,
            extra: &str,
        ) -> Result<Reply> {
            let a = self.current()?;
            let mut rows = vec![];
            let mut notes = vec![];
            let mut warnings = vec![];
            let mut before_ip = None;
            let mut ip = None;
            if !extra.is_empty() {
                notes.push(extra.to_owned());
            }
            if let Some(draft) = draft {
                let dns_only = matches!(draft, IpDraft::DnsOnly(_));
                let before = w::ipv4_config(&a)?;
                let target = draft.resolve(&before)?;
                for (i, ((field, old), new)) in ["Mode IPv4", "IP / subnet", "Gateway", "DNS"]
                    .into_iter()
                    .zip(config_rows(&before))
                    .zip(config_rows(&target))
                    .enumerate()
                {
                    if !dns_only || i == 3 {
                        rows.push([field.into(), old, new]);
                    }
                }
                if !dns_only && target.gateway_outside() {
                    warnings.push("Gateway berada di luar subnet yang dipilih. Windows dapat menolak konfigurasi ini.".into());
                }
                before_ip = Some(before);
                ip = Some(target);
            }
            if mac.is_some() || factory {
                if !a.physical_ethernet {
                    return Err("Pengubahan MAC hanya untuk adaptor Ethernet fisik.".into());
                }
                let wanted = if factory {
                    Some(a.permanent_mac.ok_or("MAC permanen tidak diketahui")?)
                } else {
                    mac
                };
                rows.push(["MAC".into(), label(a.active_mac), label(wanted)]);
                if factory || mac != a.active_mac {
                    w::check_mac_ready(&a)?;
                    if a.media == MediaState::Disconnected {
                        notes.push("Link terputus, tetapi driver berjalan. Windows dapat memeriksa MAC tanpa kabel. Sambungkan kembali untuk menguji jaringan.".into());
                    }
                }
                if factory {
                    notes.push(
                        "Override akan dihapus. MAC bawaan dibaca ulang dari Windows.".into(),
                    );
                } else if mac == a.active_mac {
                    notes.push(
                        "MAC sudah sama. Tidak ada perubahan pada driver atau restart untuk MAC."
                            .into(),
                    );
                } else {
                    warnings.push("Adaptor akan di-restart. Jika menggunakan MAC dari PC lain, pastikan PC sumber tidak terhubung ke LAN yang sama.".into());
                }
                if factory {
                    warnings
                        .push("Adaptor akan di-restart saat MAC dikembalikan ke bawaan.".into());
                }
            }
            let mut recovery_version = None;
            if recover {
                let snapshot =
                    w::recovery_preview(&a.id)?.ok_or("Tidak ada snapshot untuk adaptor ini")?;
                if let Some(target) = snapshot.ipv4 {
                    let current = if snapshot.dns_only {
                        w::ipv4_dns(&a.id).ok().map(|dns| {
                            config_rows(&Ipv4 {
                                dns,
                                ..target.clone()
                            })
                        })
                    } else {
                        w::ipv4_config(&a).ok().as_ref().map(config_rows)
                    };
                    for (i, (field, new)) in ["Mode IPv4", "IP / subnet", "Gateway", "DNS"]
                        .into_iter()
                        .zip(config_rows(&target))
                        .enumerate()
                    {
                        if snapshot.dns_only && i != 3 {
                            continue;
                        }
                        rows.push([
                            field.into(),
                            current
                                .as_ref()
                                .map(|row| row[i].clone())
                                .unwrap_or_else(|| "Tidak terbaca".into()),
                            new,
                        ]);
                    }
                }
                if let Some(target) = snapshot.mac {
                    rows.push(["MAC".into(), label(a.active_mac), target.to_string()]);
                }
                recovery_version = Some(snapshot.version);
                if snapshot.pending {
                    warnings.push("Snapshot ini berasal dari transaksi yang belum selesai. Periksa konfigurasi tujuan sebelum memulihkan.".into());
                } else {
                    notes.push("Memulihkan snapshot dari perubahan terakhir.".into());
                }
            }
            let new_ips = ip
                .as_ref()
                .zip(before_ip.as_ref())
                .map_or_else(Vec::new, |(target, before)| {
                    wfs_network_toolkit::migration::new_static_ips(target, before)
                });
            let new_mac =
                if factory { a.permanent_mac } else { mac }.filter(|m| Some(*m) != a.active_mac);
            w::ensure_no_local_conflict(&a.id, &new_ips, new_mac)?;
            let change = Change {
                id: a.id,
                expected_mac: a.active_mac,
                expected_ipv4: before_ip,
                ip,
                mac,
                factory,
                recover,
                recovery_version,
            };
            change.request()?;
            let skipped = mac_plan(a.active_mac, change.request()?)
                == wfs_network_toolkit::MacPlan::Skip
                && change.ip.is_none()
                && !recover;
            if !skipped && w::remote_session() {
                warnings.push("Sesi jarak jauh terdeteksi. Perubahan jaringan dapat memutus koneksi. Gunakan konsol lokal.".into());
            }
            if !new_ips.is_empty() {
                warnings.push("Jika alamat IP ini dipindahkan dari PC lain, putuskan PC sumber dari LAN sebelum menerapkan.".into());
            }
            if !w::elevated() && !skipped {
                notes.push(
                    "Windows akan meminta izin Administrator. Isian tidak perlu dimasukkan ulang."
                        .into(),
                );
            }
            self.token = self.token.wrapping_add(1);
            self.preview = Some((self.token, change));
            Ok(Reply {
                preview: Some(Preview {
                    token: self.token,
                    title: title.into(),
                    adapter: a.name,
                    rows,
                    note: notes.join("\n"),
                    warnings,
                    button: if recover {
                        "Pulihkan".into()
                    } else if skipped {
                        "Tutup".into()
                    } else {
                        "Terapkan".into()
                    },
                }),
                ..Default::default()
            })
        }
        fn operation(
            &mut self,
            run: impl FnOnce() -> Result<OperationResult> + Send + 'static,
        ) -> Result<Option<Reply>> {
            let (tx, rx) = mpsc::channel();
            self.work = Some(rx);
            thread::spawn(move || {
                let _ = tx.send(run());
            });
            Ok(None)
        }
        fn request(&mut self, r: Request) -> Result<Option<Reply>> {
            if self.work.is_some() {
                return Err("Tunggu operasi aktif selesai.".into());
            }
            if !matches!(r, Request::Confirm { .. }) {
                self.preview = None;
            }
            Ok(Some(match r {
                Request::Driver => {
                    notification(Notice::Information(w::driver_info(&self.current()?.id)?))
                }
                Request::NetworkConnections => {
                    w::open_network_connections()?;
                    notification(Notice::Status("Koneksi Jaringan Windows dibuka. Klik Muat ulang setelah mengubah status adaptor.".into()))
                }
                Request::Backup { include_mac } => {
                    let (profile, warning) = w::backup(&self.current()?.id, include_mac)?;
                    let Some(path) = file_dialog(self.hwnd, true, false)? else {
                        return Ok(Some(Reply::default()));
                    };
                    write_new_json(&path, &profile)?;
                    let saved = format!("Backup disimpan di {}", path.display());
                    notification(match warning {
                        Some(e) => {
                            Notice::Warning(format!("{saved}\n\nIPv4 tidak dicadangkan: {e}"))
                        }
                        None => Notice::Information(saved),
                    })
                }
                Request::Import { scope, include_mac } => {
                    let Some(path) = file_dialog(self.hwnd, false, false)? else {
                        return Ok(Some(Reply::default()));
                    };
                    let (profile, legacy) = read_backup(&path)?;
                    let title = match scope {
                        RestoreScope::Network => "Pulihkan IPv4 dan DNS",
                        RestoreScope::DnsOnly => "Pulihkan DNS saja",
                        RestoreScope::MacOnly => "Pulihkan MAC saja",
                    };
                    let extra = match scope {
                        RestoreScope::DnsOnly => {
                            "Mode IPv4, alamat, subnet, gateway, dan MAC tetap."
                        }
                        RestoreScope::MacOnly => "IPv4 dan DNS tidak diubah.",
                        RestoreScope::Network if include_mac => {
                            "IPv4/DNS diterapkan hanya setelah verifikasi MAC."
                        }
                        RestoreScope::Network if legacy => "File lama menggunakan IPv4 statis.",
                        RestoreScope::Network => "MAC tetap.",
                    };
                    let title = format!("{title} · {}", profile.source_name);
                    let (ip, mac) = restore_inputs(profile, scope, include_mac)?;
                    self.preview(&title, ip, mac, false, false, extra)?
                }
                Request::PreviewIp(c) => {
                    let old = w::ipv4_config(&self.current()?)?;
                    if old.addresses.len() > 1 || old.dns.as_ref().is_some_and(|x| x.len() > 2) {
                        return Err("Form manual tidak mencakup seluruh alamat adaptor. Gunakan profil backup.".into());
                    }
                    self.preview(
                        "Terapkan IPv4 & DNS",
                        Some(IpDraft::Full(c)),
                        None,
                        false,
                        false,
                        "MAC tidak diubah.",
                    )?
                }
                Request::PreviewMac { value } => self.preview(
                    "Ubah MAC address",
                    None,
                    Some(value.parse()?),
                    false,
                    false,
                    "IPv4 dan DNS tidak diubah.",
                )?,
                Request::PreviewFactory => self.preview(
                    "Reset MAC bawaan",
                    None,
                    None,
                    true,
                    false,
                    "IPv4 dan DNS tidak diubah.",
                )?,
                Request::PreviewRecover => {
                    self.preview("Pulihkan konfigurasi adaptor", None, None, false, true, "")?
                }
                Request::Confirm { token } => {
                    let (expected, c) = self
                        .preview
                        .take()
                        .ok_or("Pratinjau kedaluwarsa. Tinjau ulang perubahan.")?;
                    if token != expected {
                        return Err("Pratinjau sudah berubah. Tinjau ulang perubahan.".into());
                    }
                    let a = self.current()?;
                    if a.id != c.id {
                        return Err("Adaptor terpilih berubah. Tinjau ulang.".into());
                    }
                    if mac_plan(a.active_mac, c.request()?) == wfs_network_toolkit::MacPlan::Skip
                        && c.ip.is_none()
                        && !c.recover
                    {
                        notification(Notice::Information(
                            "MAC sudah cocok. Tidak ada pengubahan driver, restart adaptor, atau permintaan UAC.".into(),
                        ))
                    } else {
                        return self.operation(move || execute_elevated(c));
                    }
                }
                Request::Ping => {
                    let a = self.current()?;
                    return self
                        .operation(move || w::ping_gateway(&a.id).map(OperationResult::Ping));
                }
                Request::Subnet { ip, prefix } => {
                    let s = subnet(ip, prefix)?;
                    Reply {
                        output: Some(format!(
                            "Alamat      {ip}/{prefix}\nSubnet mask {}\nNetwork     {}\nBroadcast   {}\nRentang     {} — {}\nHost        {}",
                            s.mask,
                            s.network,
                            s.broadcast
                                .map_or_else(|| "Tidak ada".into(), |a| a.to_string()),
                            s.first,
                            s.last,
                            s.host_count
                        )),
                        ..Default::default()
                    }
                }
                Request::Export { redact } => {
                    let a = self.current()?;
                    let Some(path) = file_dialog(self.hwnd, true, true)? else {
                        return Ok(Some(Reply::default()));
                    };
                    let report = if redact {
                        format!(
                            "WeNet Toolkit {VERSION}\r\nMode: disamarkan\r\nStatus link: {}\r\nStatus antarmuka: {}\r\nEthernet fisik: {}\r\nDHCP: {}\r\nJumlah IPv4: {}\r\nJumlah gateway: {}\r\nJumlah DNS aktif: {}\r\n",
                            a.link_label(),
                            a.admin.label(),
                            a.physical_ethernet,
                            a.dhcp,
                            a.addresses.len(),
                            a.gateways.len(),
                            a.dns_active.len()
                        )
                    } else {
                        let meta = w::driver_info(&a.id)
                            .unwrap_or_else(|_| "Metadata driver tidak tersedia.".into());
                        format!("WeNet Toolkit {VERSION}\r\n{a:#?}\r\n{meta}\r\n")
                    };
                    use std::io::Write;
                    let mut f = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(&path)
                        .map_err(|e| format!("Pilih nama berkas baru: {e}"))?;
                    f.write_all(report.as_bytes())
                        .and_then(|_| f.sync_all())
                        .map_err(|e| e.to_string())?;
                    notification(Notice::Information(format!(
                        "Laporan disimpan di {}",
                        path.display()
                    )))
                }
            }))
        }
        fn finish(&mut self) -> Option<Reply> {
            let outcome = match self.work.as_ref()?.try_recv() {
                Ok(r) => r,
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => {
                    Err("Pekerjaan terhenti; periksa snapshot pemulihan.".into())
                }
            };
            self.work = None;
            Some(match outcome {
                Ok(OperationResult::Changed(s)) => Reply {
                    state: self.state().ok(),
                    notice: Some(Notice::Information(s)),
                    ..Default::default()
                },
                Ok(OperationResult::DialogShown) => Reply {
                    state: self.state().ok(),
                    notice: Some(Notice::Status("Siap.".into())),
                    ..Default::default()
                },
                Ok(OperationResult::Ping(s)) => Reply {
                    output: Some(s),
                    notice: Some(Notice::Status("Ping gateway selesai.".into())),
                    ..Default::default()
                },
                Err(e) => Reply {
                    state: self.state().ok(),
                    notice: Some(Notice::Error(e)),
                    ..Default::default()
                },
            })
        }
    }
    fn notification(notice: Notice) -> Reply {
        Reply {
            notice: Some(notice),
            ..Default::default()
        }
    }
    struct Dashboard {
        adapters: Vec<w::Adapter>,
        current: Option<Current>,
    }
    struct Current {
        adapter: w::Adapter,
        config: Result<Ipv4>,
        pending: bool,
        recovery: bool,
    }

    include!("native/toolkit_window.rs");
    include!("native/intelligence_window.rs");
}
