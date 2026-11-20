use crate::{
    Address, Backup, Change, Ipv4, Mac, MacPlan, MacRequest, Result,
    adapter_state::{
        AdminState, MacReadback, MacReadiness, MediaState, link_label, mac_readback, mac_readiness,
    },
    execute_transaction, mac_plan,
    migration::{AddressConflict, address_conflict, new_static_ips},
    usable,
};
use serde::{Deserialize, Serialize};
use std::{
    cell::Cell,
    mem::size_of,
    net::Ipv4Addr,
    os::windows::process::CommandExt,
    process::{Command, Stdio},
    ptr::{null, null_mut},
    thread,
    time::{Duration, Instant},
};
use windows_sys::{
    Win32::{
        Devices::DeviceAndDriverInstallation::*,
        Foundation::*,
        NetworkManagement::{IpHelper::*, Ndis::*},
        Networking::WinSock::*,
        Security::{GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation},
        System::{Registry::*, SystemInformation::GetSystemDirectoryW, Threading::*},
        UI::Shell::ShellExecuteW,
    },
    core::GUID,
};

const NET_CLASS: GUID = GUID::from_u128(0x4d36e972_e325_11ce_bfc1_08002be10318);
const JOURNAL_KEY: &str = r"SOFTWARE\WFS\NetworkToolkit\PendingV1";
const HIDE_CONSOLE: u32 = 0x0800_0000;
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}
pub fn from_wide(s: &[u16]) -> String {
    String::from_utf16_lossy(&s[..s.iter().position(|&v| v == 0).unwrap_or(s.len())])
}
fn guid(g: GUID) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1,
        g.data2,
        g.data3,
        g.data4[0],
        g.data4[1],
        g.data4[2],
        g.data4[3],
        g.data4[4],
        g.data4[5],
        g.data4[6],
        g.data4[7]
    )
}
fn valid_id(id: &str) -> bool {
    let b = id.as_bytes();
    b.len() == 38
        && b[0] == b'{'
        && b[37] == b'}'
        && b[1..37].iter().enumerate().all(|(i, &x)| {
            if [8, 13, 18, 23].contains(&i) {
                x == b'-'
            } else {
                x.is_ascii_hexdigit()
            }
        })
}
fn err(op: &str, code: u32) -> String {
    format!(
        "{op}: Win32 {code} ({})",
        std::io::Error::from_raw_os_error(code as i32)
    )
}
fn last(op: &str) -> String {
    err(op, unsafe { GetLastError() })
}
fn ok(code: u32, op: &str) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(err(op, code))
    }
}
fn bool_ok(value: i32, op: &str) -> Result<()> {
    if value != 0 { Ok(()) } else { Err(last(op)) }
}

#[derive(Clone, Debug, Serialize)]
pub struct Adapter {
    pub id: String,
    pub name: String,
    pub description: String,
    pub index: u32,
    pub up: bool,
    pub admin: AdminState,
    pub media: MediaState,
    pub physical_ethernet: bool,
    pub active_mac: Option<Mac>,
    pub permanent_mac: Option<Mac>,
    pub dhcp: bool,
    pub addresses: Vec<Address>,
    pub preferred: Vec<Ipv4Addr>,
    pub gateways: Vec<Ipv4Addr>,
    pub dns_active: Vec<Ipv4Addr>,
    manual_under_dhcp: bool,
}
impl Adapter {
    pub fn link_label(&self) -> &'static str {
        link_label(self.up, self.admin, self.media)
    }
}
fn mac_bytes(length: u32, bytes: &[u8]) -> Option<Mac> {
    (length == 6)
        .then(|| Mac::from_bytes(bytes[..6].try_into().unwrap()).ok())
        .flatten()
}
unsafe fn v4(sa: SOCKET_ADDRESS) -> Option<Ipv4Addr> {
    if sa.lpSockaddr.is_null() || sa.iSockaddrLength < size_of::<SOCKADDR_IN>() as i32 {
        return None;
    }
    // IP Helper owns the socket address inside the aligned output buffer.
    let a = unsafe { std::ptr::read_unaligned(sa.lpSockaddr.cast::<SOCKADDR_IN>()) };
    if a.sin_family != AF_INET {
        return None;
    }
    Some(Ipv4Addr::from(
        unsafe { a.sin_addr.S_un.S_addr }.to_ne_bytes(),
    ))
}
pub fn adapters() -> Result<Vec<Adapter>> {
    let mut count = 15_360;
    for _ in 0..4 {
        if count > 16 * 1024 * 1024 {
            return Err("Daftar adaptor terlalu besar".into());
        }
        let mut storage = vec![0u64; (count as usize).div_ceil(8)];
        let first = storage.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let code = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                GAA_FLAG_INCLUDE_GATEWAYS
                    | GAA_FLAG_INCLUDE_ALL_INTERFACES
                    | GAA_FLAG_SKIP_ANYCAST
                    | GAA_FLAG_SKIP_MULTICAST,
                null(),
                first,
                &mut count,
            )
        };
        if code == ERROR_BUFFER_OVERFLOW {
            continue;
        }
        if code == ERROR_NO_DATA {
            return Ok(Vec::new());
        }
        ok(code, "GetAdaptersAddresses")?;
        let mut out = Vec::new();
        let mut next = first;
        // Windows returns linked entries and strings within storage; no pointers escape this scope.
        while let Some(a) = unsafe { next.as_ref() } {
            next = a.Next;
            let mut row = MIB_IF_ROW2 {
                InterfaceLuid: a.Luid,
                ..Default::default()
            };
            if unsafe { GetIfEntry2(&mut row) } != 0
                || matches!(a.IfType, IF_TYPE_SOFTWARE_LOOPBACK | IF_TYPE_TUNNEL)
            {
                continue;
            }
            let index = unsafe { a.Anonymous1.Anonymous.IfIndex };
            let dhcp = (unsafe { a.Anonymous2.Flags } & IP_ADAPTER_DHCP_ENABLED) != 0;
            let mut n = a.FirstUnicastAddress;
            let (mut addresses, mut preferred) = (Vec::new(), Vec::new());
            let mut manual_under_dhcp = false;
            while let Some(x) = unsafe { n.as_ref() } {
                n = x.Next;
                if let Some(ip) = unsafe { v4(x.Address) } {
                    if !usable(ip) || ip.is_link_local() {
                        continue;
                    }
                    manual_under_dhcp |= dhcp && x.PrefixOrigin == IpPrefixOriginManual;
                    addresses.push(Address {
                        ip,
                        prefix: x.OnLinkPrefixLength,
                    });
                    if x.DadState == IpDadStatePreferred {
                        preferred.push(ip);
                    }
                }
            }
            let mut gateways = Vec::new();
            let mut n = a.FirstGatewayAddress;
            while let Some(x) = unsafe { n.as_ref() } {
                n = x.Next;
                if let Some(ip) = unsafe { v4(x.Address) }.filter(|ip| usable(*ip)) {
                    gateways.push(ip);
                }
            }
            let mut dns_active = Vec::new();
            let mut n = a.FirstDnsServerAddress;
            while let Some(x) = unsafe { n.as_ref() } {
                n = x.Next;
                if let Some(ip) = unsafe { v4(x.Address) }.filter(|ip| usable(*ip)) {
                    dns_active.push(ip);
                }
            }
            // HardwareInterface is the first bit of MIB_IF_ROW2.InterfaceAndOperStatusFlags.
            out.push(Adapter {
                id: guid(row.InterfaceGuid),
                name: from_wide(&row.Alias),
                description: from_wide(&row.Description),
                index,
                up: row.OperStatus == IfOperStatusUp,
                admin: match row.AdminStatus {
                    NET_IF_ADMIN_STATUS_UP => AdminState::Enabled,
                    NET_IF_ADMIN_STATUS_DOWN => AdminState::Disabled,
                    NET_IF_ADMIN_STATUS_TESTING => AdminState::Testing,
                    _ => AdminState::Unknown,
                },
                media: if row.MediaConnectState == MediaConnectStateConnected {
                    MediaState::Connected
                } else if row.MediaConnectState == MediaConnectStateDisconnected
                    || row.InterfaceAndOperStatusFlags._bitfield & (1 << 4) != 0
                {
                    MediaState::Disconnected
                } else {
                    MediaState::Unknown
                },
                physical_ethernet: a.IfType == IF_TYPE_ETHERNET_CSMACD
                    && row.InterfaceAndOperStatusFlags._bitfield & 1 != 0,
                active_mac: mac_bytes(row.PhysicalAddressLength, &row.PhysicalAddress),
                permanent_mac: mac_bytes(row.PhysicalAddressLength, &row.PermanentPhysicalAddress),
                dhcp,
                addresses,
                preferred,
                gateways,
                dns_active,
                manual_under_dhcp,
            });
        }
        out.sort_by_key(|a| (!a.physical_ethernet, !a.up, a.name.to_lowercase()));
        return Ok(out);
    }
    Err("Daftar adaptor berubah terlalu cepat".into())
}
pub fn adapter(id: &str) -> Result<Adapter> {
    if !valid_id(id) {
        return Err("GUID adaptor tidak valid".into());
    }
    adapters()?
        .into_iter()
        .find(|a| a.id.eq_ignore_ascii_case(id))
        .ok_or_else(|| format!("Adaptor {id} tidak tersedia"))
}
pub fn ensure_no_local_conflict(id: &str, ips: &[Ipv4Addr], mac: Option<Mac>) -> Result<()> {
    if ips.is_empty() && mac.is_none() {
        return Ok(());
    }
    for other in adapters()?
        .into_iter()
        .filter(|a| a.up && !a.id.eq_ignore_ascii_case(id))
    {
        let Some(conflict) = address_conflict(
            ips,
            mac,
            other.addresses.iter().map(|a| a.ip),
            other.active_mac,
        ) else {
            continue;
        };
        let value = match conflict {
            AddressConflict::Ipv4(ip) => format!("IPv4 {ip}"),
            AddressConflict::Mac(mac) => format!("MAC {mac}"),
        };
        return Err(format!(
            "{value} sudah dipakai adaptor aktif '{}' pada PC ini. Pilih alamat lain atau nonaktifkan adaptor tersebut bila memang tidak digunakan.",
            other.name
        ));
    }
    Ok(())
}
struct Key(HKEY);
impl Drop for Key {
    fn drop(&mut self) {
        unsafe {
            RegCloseKey(self.0);
        }
    }
}
fn open_key(path: &str, access: u32) -> Result<Option<Key>> {
    let mut h = null_mut();
    let code = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            wide(path).as_ptr(),
            0,
            access | KEY_WOW64_64KEY,
            &mut h,
        )
    };
    if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
        return Ok(None);
    }
    ok(code, "Buka konfigurasi Windows")?;
    Ok(Some(Key(h)))
}
impl Key {
    fn read(&self, name: &str) -> Result<Option<String>> {
        let mut size = 0;
        let n = wide(name);
        let code = unsafe {
            RegGetValueW(
                self.0,
                null(),
                n.as_ptr(),
                RRF_RT_REG_SZ,
                null_mut(),
                null_mut(),
                &mut size,
            )
        };
        if code == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        ok(code, name)?;
        if size > 524_288 {
            return Err(format!("{name} terlalu besar"));
        }
        let mut b = vec![0u16; (size as usize).div_ceil(2) + 1];
        size = (b.len() * 2) as u32;
        ok(
            unsafe {
                RegGetValueW(
                    self.0,
                    null(),
                    n.as_ptr(),
                    RRF_RT_REG_SZ,
                    null_mut(),
                    b.as_mut_ptr().cast(),
                    &mut size,
                )
            },
            name,
        )?;
        Ok(Some(from_wide(&b)))
    }
    fn write(&self, name: &str, value: Option<&str>) -> Result<()> {
        let n = wide(name);
        let code = match value {
            Some(v) => {
                let b = wide(v);
                unsafe {
                    RegSetValueExW(
                        self.0,
                        n.as_ptr(),
                        0,
                        REG_SZ,
                        b.as_ptr().cast(),
                        (b.len() * 2) as u32,
                    )
                }
            }
            None => unsafe { RegDeleteValueW(self.0, n.as_ptr()) },
        };
        if value.is_none() && code == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        ok(code, name)
    }
}
pub fn ipv4_config(a: &Adapter) -> Result<Ipv4> {
    if a.index == 0 {
        return Err("IPv4 tidak terikat pada adaptor ini".into());
    }
    if a.manual_under_dhcp || a.gateways.len() > 1 {
        return Err("Konfigurasi IPv4 lanjutan terdeteksi (alamat manual bersama DHCP atau beberapa gateway). Toolkit tidak akan menggantinya.".into());
    }
    let ip = Ipv4 {
        dhcp: a.dhcp,
        addresses: if a.dhcp {
            Vec::new()
        } else {
            a.addresses.clone()
        },
        gateway: if a.dhcp {
            None
        } else {
            a.gateways.first().copied()
        },
        dns: ipv4_dns(&a.id)?,
    };
    ip.validate()?;
    Ok(ip)
}
pub fn ipv4_dns(id: &str) -> Result<Option<Vec<Ipv4Addr>>> {
    if !valid_id(id) {
        return Err("GUID adaptor tidak valid".into());
    }
    let p = format!(
        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{}",
        id
    );
    let key = open_key(&p, KEY_QUERY_VALUE)?
        .ok_or("Mode DNS tidak tersedia; snapshot IPv4 yang dapat dipulihkan belum bisa dibuat.")?;
    let ns = key.read("NameServer")?.unwrap_or_default();
    let dns = ns
        .split(|c: char| c == ',' || c == ';' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse()
                .map_err(|_| format!("DNS manual non-IPv4 atau format tidak didukung: {s}"))
        })
        .collect::<Result<Vec<Ipv4Addr>>>()?;
    Ok((!dns.is_empty()).then_some(dns))
}
pub fn backup(id: &str, with_mac: bool) -> Result<(Backup, Option<String>)> {
    let a = adapter(id)?;
    let (ipv4, warning) = match ipv4_config(&a) {
        Ok(ip) => (Some(ip), None),
        Err(e) => (None, Some(e)),
    };
    if ipv4.is_none() && (!with_mac || a.active_mac.is_none()) {
        return Err(warning.unwrap_or_else(|| "Tidak ada konfigurasi untuk dicadangkan".into()));
    }
    Ok((
        Backup {
            format: 1,
            source_id: a.id,
            source_name: a.name,
            ipv4,
            mac: if with_mac { a.active_mac } else { None },
        },
        warning,
    ))
}

struct DevSet(HDEVINFO);
impl Drop for DevSet {
    fn drop(&mut self) {
        unsafe {
            SetupDiDestroyDeviceInfoList(self.0);
        }
    }
}
struct Device {
    set: DevSet,
    data: SP_DEVINFO_DATA,
}
impl Device {
    fn status(&self) -> Result<(u32, Option<u32>)> {
        let (mut status, mut problem) = (0, 0);
        let code =
            unsafe { CM_Get_DevNode_Status(&mut status, &mut problem, self.data.DevInst, 0) };
        if code != CR_SUCCESS {
            return Err(format!(
                "Windows tidak dapat membaca status perangkat Ethernet (ConfigMgr 0x{code:08X})."
            ));
        }
        Ok((status, (status & DN_HAS_PROBLEM != 0).then_some(problem)))
    }
    fn require_started(&self) -> Result<()> {
        let (status, problem) = self.status()?;
        match problem {
            Some(CM_PROB_DISABLED) => Err("Perangkat Ethernet dinonaktifkan (kode 22). Aktifkan adaptor yang dipilih di Device Manager, lalu klik Muat ulang.".into()),
            Some(CM_PROB_HARDWARE_DISABLED) => Err("Perangkat Ethernet dinonaktifkan oleh perangkat keras (kode 29). Periksa pengaturan perangkat.".into()),
            Some(code) => Err(format!("Perangkat Ethernet bermasalah (kode {code}). Periksa Device Manager.")),
            None if status & DN_STARTED == 0 => Err("Driver Ethernet belum berjalan. Periksa Device Manager atau aktifkan adaptor, lalu klik Muat ulang.".into()),
            None => Ok(()),
        }
    }
    fn key(&self, rights: u32) -> Result<Key> {
        let h = unsafe {
            SetupDiOpenDevRegKey(
                self.set.0,
                &self.data,
                DICS_FLAG_GLOBAL,
                0,
                DIREG_DRV,
                rights,
            )
        };
        if std::ptr::eq(h.cast::<core::ffi::c_void>(), INVALID_HANDLE_VALUE) {
            return Err(last("Buka software key driver dengan SetupAPI"));
        }
        Ok(Key(h))
    }
    fn find(id: &str) -> Result<Self> {
        let h = unsafe { SetupDiGetClassDevsW(&NET_CLASS, null(), null_mut(), DIGCF_PRESENT) };
        if h == INVALID_HANDLE_VALUE as isize {
            return Err(last("SetupDiGetClassDevsW"));
        }
        let set = DevSet(h);
        let mut found = None;
        let mut inaccessible = 0;
        for i in 0.. {
            let mut data = SP_DEVINFO_DATA {
                cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                ..Default::default()
            };
            if unsafe { SetupDiEnumDeviceInfo(set.0, i, &mut data) } == 0 {
                let code = unsafe { GetLastError() };
                if code == ERROR_NO_MORE_ITEMS {
                    break;
                }
                return Err(err("SetupDiEnumDeviceInfo", code));
            }
            let key = unsafe {
                SetupDiOpenDevRegKey(
                    set.0,
                    &data,
                    DICS_FLAG_GLOBAL,
                    0,
                    DIREG_DRV,
                    KEY_QUERY_VALUE,
                )
            };
            if std::ptr::eq(key.cast::<core::ffi::c_void>(), INVALID_HANDLE_VALUE) {
                inaccessible += 1;
                continue;
            }
            let key = Key(key);
            if key
                .read("NetCfgInstanceId")
                .ok()
                .flatten()
                .is_some_and(|v| v.eq_ignore_ascii_case(id))
                && found.replace(data).is_some()
            {
                return Err("GUID cocok ke lebih dari satu driver; tidak ada perubahan".into());
            }
        }
        let data = found.ok_or_else(|| format!("SetupAPI tidak menemukan software key driver untuk {id}. Key lain tidak terbaca: {inaccessible}. Tidak ada perubahan."))?;
        Ok(Self { set, data })
    }
    fn restart(&self) -> Result<()> {
        let params = SP_PROPCHANGE_PARAMS {
            ClassInstallHeader: SP_CLASSINSTALL_HEADER {
                cbSize: size_of::<SP_CLASSINSTALL_HEADER>() as u32,
                InstallFunction: DIF_PROPERTYCHANGE,
            },
            StateChange: DICS_PROPCHANGE,
            Scope: DICS_FLAG_CONFIGSPECIFIC,
            HwProfile: 0,
        };
        bool_ok(
            unsafe {
                SetupDiSetClassInstallParamsW(
                    self.set.0,
                    &self.data,
                    &params.ClassInstallHeader,
                    size_of::<SP_PROPCHANGE_PARAMS>() as u32,
                )
            },
            "Siapkan restart adaptor",
        )?;
        bool_ok(
            unsafe { SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, self.set.0, &self.data) },
            "Restart perangkat melalui SetupAPI",
        )?;
        let mut info = SP_DEVINSTALL_PARAMS_W {
            cbSize: size_of::<SP_DEVINSTALL_PARAMS_W>() as u32,
            ..Default::default()
        };
        bool_ok(
            unsafe { SetupDiGetDeviceInstallParamsW(self.set.0, &self.data, &mut info) },
            "Baca status restart adaptor",
        )?;
        if info.Flags & (DI_NEEDREBOOT | DI_NEEDRESTART) != 0 {
            return Err(
                "Windows meminta reboot untuk perubahan ini; perubahan belum terverifikasi".into(),
            );
        }
        Ok(())
    }
}
fn prepare_mac_device(a: &Adapter) -> Result<Device> {
    if !a.physical_ethernet {
        return Err("Pengubahan MAC hanya untuk adaptor Ethernet fisik.".into());
    }
    let d = Device::find(&a.id)?;
    d.require_started()
        .map_err(|e| format!("{e} Tidak ada perubahan."))?;
    match mac_readiness(a.admin, a.media, a.up, true) {
        MacReadiness::Ready => Ok(d),
        _ => Err(format!(
            "Antarmuka Ethernet belum siap (status Windows: {}; {}). Aktifkan adaptor yang dipilih dan klik Muat ulang. Tidak ada perubahan.",
            a.admin.label(),
            a.link_label()
        )),
    }
}
fn read_mac_override(id: &str) -> Result<Option<String>> {
    Device::find(id)?
        .key(KEY_QUERY_VALUE)?
        .read("NetworkAddress")
}
pub fn check_mac_ready(a: &Adapter) -> Result<()> {
    prepare_mac_device(a).map(drop)
}
pub fn driver_info(id: &str) -> Result<String> {
    let d = Device::find(id)?;
    let key = d.key(KEY_QUERY_VALUE)?;
    let (mut hardware, mut needed) = ([0u16; 2048], 0);
    let exists = unsafe {
        SetupDiGetDeviceRegistryPropertyW(
            d.set.0,
            &d.data,
            SPDRP_HARDWAREID,
            null_mut(),
            hardware.as_mut_ptr().cast(),
            (hardware.len() * 2) as u32,
            &mut needed,
        )
    } != 0;
    let adapter = adapter(id)?;
    let device_status = d.status().map_or_else(
        |e| e,
        |(flags, problem)| {
            if let Some(code) = problem {
                format!("Bermasalah (kode {code})")
            } else if flags & DN_STARTED != 0 {
                "Driver berjalan".into()
            } else {
                "Driver belum berjalan".into()
            }
        },
    );
    Ok(format!(
        "Hardware ID: {}\nVersi driver: {}\nStatus antarmuka: {}\nStatus link: {}\nStatus perangkat: {device_status}",
        if exists {
            from_wide(&hardware)
        } else {
            "Tidak tersedia".into()
        },
        key.read("DriverVersion")?
            .unwrap_or_else(|| "Tidak tersedia".into()),
        adapter.admin.label(),
        adapter.link_label()
    ))
}

pub fn elevated() -> bool {
    unsafe {
        let mut token = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut e = TOKEN_ELEVATION::default();
        let mut n = 0;
        let success = GetTokenInformation(
            token,
            TokenElevation,
            (&mut e as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut n,
        );
        CloseHandle(token);
        success != 0 && e.TokenIsElevated != 0
    }
}
pub fn remote_session() -> bool {
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::GetSystemMetrics(
            windows_sys::Win32::UI::WindowsAndMessaging::SM_REMOTESESSION,
        ) != 0
    }
}
pub fn elevate_window() -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let path: Vec<u16> = exe.as_os_str().encode_wide().chain([0]).collect();
    let code = unsafe {
        ShellExecuteW(
            null_mut(),
            wide("runas").as_ptr(),
            path.as_ptr(),
            null(),
            null(),
            1,
        )
    } as isize;
    if code <= 32 {
        return Err(format!(
            "UAC dibatalkan atau tidak tersedia ({code}); tidak ada perubahan."
        ));
    }
    Ok(())
}

pub fn open_network_connections() -> Result<()> {
    let mut path = [0u16; 32768];
    let n = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) } as usize;
    if n == 0 || n >= path.len() {
        return Err(last("Cari direktori sistem Windows"));
    }
    Command::new(std::path::PathBuf::from(from_wide(&path[..n])).join("control.exe"))
        .arg("ncpa.cpl")
        .spawn()
        .map_err(|e| format!("Tidak bisa membuka Koneksi Jaringan Windows: {e}"))?;
    Ok(())
}

struct Guard(HANDLE);
impl Guard {
    fn acquire() -> Result<Self> {
        let h = unsafe {
            CreateMutexW(
                null(),
                0,
                wide(r"Global\WFS-NetworkToolkit-v1-Mutations").as_ptr(),
            )
        };
        if h.is_null() {
            return Err(last("Kunci transaksi"));
        }
        match unsafe { WaitForSingleObject(h, 0) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(h)),
            _ => {
                unsafe {
                    CloseHandle(h);
                }
                Err("Transaksi lain sedang berjalan".into())
            }
        }
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct MacOriginal {
    active: Mac,
    value: Option<String>,
    link: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Journal {
    id: String,
    mac: Option<MacOriginal>,
    ipv4: Option<Ipv4>,
    #[serde(default)]
    dns_only: bool,
}
impl Journal {
    fn decode(json: &str, id: &str) -> Result<Self> {
        let j: Self = serde_json::from_str(json)
            .map_err(|e| format!("Snapshot pemulihan tidak valid: {e}"))?;
        if !j.id.eq_ignore_ascii_case(id) {
            return Err("GUID snapshot berbeda; tidak ada perubahan.".into());
        }
        if j.mac.is_none() && j.ipv4.is_none() {
            return Err("Snapshot pemulihan kosong; tidak ada perubahan.".into());
        }
        if j.dns_only && j.ipv4.is_none() {
            return Err("Snapshot DNS tidak memuat konfigurasi awal.".into());
        }
        if let Some(ipv4) = &j.ipv4 {
            ipv4.validate()?;
        }
        Ok(j)
    }
}
fn journal_key() -> Result<Key> {
    let mut h = null_mut();
    ok(
        unsafe {
            RegCreateKeyExW(
                HKEY_LOCAL_MACHINE,
                wide(JOURNAL_KEY).as_ptr(),
                0,
                null(),
                REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE | KEY_WOW64_64KEY,
                null(),
                &mut h,
                null_mut(),
            )
        },
        "Buat jurnal pengaman HKLM",
    )?;
    Ok(Key(h))
}
fn journal_write(key: &Key, id: &str, j: Option<&Journal>) -> Result<()> {
    let json = j
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| e.to_string())?;
    key.write(id, json.as_deref())?;
    ok(unsafe { RegFlushKey(key.0) }, "Simpan jurnal pengaman")
}
pub fn pending(id: &str) -> Result<bool> {
    if !valid_id(id) {
        return Err("GUID adaptor tidak valid".into());
    }
    Ok(match open_key(JOURNAL_KEY, KEY_QUERY_VALUE)? {
        Some(k) => k.read(id)?.is_some(),
        None => false,
    })
}
pub fn recovery_available(id: &str) -> Result<(bool, bool)> {
    if !valid_id(id) {
        return Err("GUID adaptor tidak valid".into());
    }
    let Some(k) = open_key(JOURNAL_KEY, KEY_QUERY_VALUE)? else {
        return Ok((false, false));
    };
    let p = k.read(id)?.is_some();
    Ok((p, p || k.read(&format!("last-{id}"))?.is_some()))
}
pub struct RecoveryInfo {
    pub pending: bool,
    pub ipv4: Option<Ipv4>,
    pub mac: Option<Mac>,
    pub dns_only: bool,
    pub version: String,
}
fn read_recovery(key: &Key, id: &str) -> Result<Option<(bool, String)>> {
    if let Some(v) = key.read(id)? {
        return Ok(Some((true, v)));
    }
    Ok(key.read(&format!("last-{id}"))?.map(|v| (false, v)))
}
fn journal_version(json: &str, pending: bool) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{}:{:x}",
        u8::from(pending),
        Sha256::digest(json.as_bytes())
    )
}
pub fn recovery_preview(id: &str) -> Result<Option<RecoveryInfo>> {
    if !valid_id(id) {
        return Err("GUID adaptor tidak valid".into());
    }
    let Some(k) = open_key(JOURNAL_KEY, KEY_QUERY_VALUE)? else {
        return Ok(None);
    };
    let Some((pending, json)) = read_recovery(&k, id)? else {
        return Ok(None);
    };
    let j = Journal::decode(&json, id)?;
    Ok(Some(RecoveryInfo {
        pending,
        ipv4: j.ipv4,
        mac: j.mac.map(|m| m.active),
        dns_only: j.dns_only,
        version: journal_version(&json, pending),
    }))
}
pub fn ping_gateway(id: &str) -> Result<String> {
    let a = adapter(id)?;
    let gateway = a
        .gateways
        .first()
        .copied()
        .ok_or("Gateway IPv4 tidak tersedia")?;
    let source = a
        .addresses
        .iter()
        .filter(|addr| a.preferred.contains(&addr.ip))
        .find(|addr| {
            let m = u32::from(crate::mask(addr.prefix));
            (u32::from(addr.ip) & m) == (u32::from(gateway) & m)
        })
        .or_else(|| {
            a.addresses
                .iter()
                .find(|addr| a.preferred.contains(&addr.ip))
        })
        .ok_or("Adaptor tidak memiliki IPv4 aktif untuk mengirim ping")?
        .ip;
    let handle = unsafe { IcmpCreateFile() };
    if handle == INVALID_HANDLE_VALUE {
        return Err(last("IcmpCreateFile"));
    }
    struct Icmp(HANDLE);
    impl Drop for Icmp {
        fn drop(&mut self) {
            unsafe {
                IcmpCloseHandle(self.0);
            }
        }
    }
    let h = Icmp(handle);
    let mut out = format!("Sumber {source} → gateway {gateway}\n");
    let mut replies = 0;
    let data = b"WFS Network Toolkit";
    for seq in 1..=3 {
        let mut reply = [0u64; 64];
        let count = unsafe {
            IcmpSendEcho2Ex(
                h.0,
                null_mut(),
                None,
                null(),
                u32::from_ne_bytes(source.octets()),
                u32::from_ne_bytes(gateway.octets()),
                data.as_ptr().cast(),
                data.len() as u16,
                null(),
                reply.as_mut_ptr().cast(),
                (reply.len() * 8) as u32,
                1100,
            )
        };
        if count == 0 {
            out.push_str(&format!("Paket {seq}: {}\n", last("Tidak ada balasan")));
            continue;
        }
        let echo = unsafe { &*reply.as_ptr().cast::<ICMP_ECHO_REPLY>() };
        if echo.Status == 0 {
            replies += 1;
            out.push_str(&format!(
                "Paket {seq}: balasan dari {} dalam {} ms\n",
                Ipv4Addr::from(echo.Address.to_ne_bytes()),
                echo.RoundTripTime
            ));
        } else {
            out.push_str(&format!("Paket {seq}: status ICMP {}\n", echo.Status));
        }
    }
    out.push_str(&format!(
        "Balasan {replies}/3. Gateway dapat memblokir ICMP meski jaringan aktif."
    ));
    Ok(out)
}
fn mac_wait(id: &str, expected: Mac, link: bool) -> Result<()> {
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        let (readback, detail) = match adapter(id) {
            Ok(a) => {
                let readback = mac_readback(expected, a.active_mac, link, a.up);
                if readback == MacReadback::Verified {
                    match Device::find(id).and_then(|d| d.require_started()) {
                        Ok(()) => return Ok(()),
                        Err(e) => (readback, e),
                    }
                } else {
                    (
                        readback,
                        format!(
                            "MAC aktif {}, {}, status antarmuka {}",
                            a.active_mac
                                .map_or_else(|| "tidak terbaca".into(), |m| m.to_string()),
                            a.link_label(),
                            a.admin.label()
                        ),
                    )
                }
            }
            Err(e) => (MacReadback::AddressPending, e),
        };
        if Instant::now() >= end {
            if readback == MacReadback::LinkPending {
                return Err(format!(
                    "Windows membaca MAC {expected}, tetapi link yang semula aktif belum kembali setelah 20 detik. Periksa kabel atau port switch."
                ));
            }
            if readback == MacReadback::Verified {
                return Err(format!(
                    "Windows membaca MAC {expected}, tetapi driver belum siap setelah restart. {detail}"
                ));
            }
            let suggestion = if expected.locally_administered() {
                "Driver mungkin tidak menerima override ini."
            } else {
                "Driver mungkin menolak MAC persis ini. Toolkit tidak menggantinya dengan MAC lain."
            };
            return Err(format!(
                "MAC {expected} tidak terverifikasi setelah 20 detik ({detail}). {suggestion}"
            ));
        }
        thread::sleep(Duration::from_millis(500));
    }
}
fn undo_mac(id: &str, orig: &MacOriginal) -> Result<()> {
    let d = Device::find(id)?;
    let key = d.key(KEY_QUERY_VALUE | KEY_SET_VALUE)?;
    let current = key.read("NetworkAddress")?;
    if current != orig.value || adapter(id).ok().and_then(|a| a.active_mac) != Some(orig.active) {
        key.write("NetworkAddress", orig.value.as_deref())?;
        drop(key);
        d.restart()?;
    }
    mac_wait(id, orig.active, orig.link)?;
    if read_mac_override(id)? != orig.value {
        return Err("Nilai override awal tidak cocok".into());
    }
    Ok(())
}
fn netsh(id: &str, cmd: &[String]) -> Result<()> {
    let a = adapter(id)?;
    if a.index == 0 {
        return Err("Adaptor tidak mempunyai indeks IPv4".into());
    }
    let mut path = [0u16; 32768];
    let n = unsafe { GetSystemDirectoryW(path.as_mut_ptr(), path.len() as u32) };
    if n == 0 || n as usize >= path.len() {
        return Err(last("Cari direktori sistem Windows"));
    }
    let exe = std::path::PathBuf::from(from_wide(&path)).join("netsh.exe");
    let mut args = vec![String::from("interface"), String::from("ipv4")];
    args.extend_from_slice(&cmd[..2]);
    args.push(format!("name={}", a.index));
    args.extend_from_slice(&cmd[2..]);
    let mut child = Command::new(exe)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(HIDE_CONSOLE)
        .spawn()
        .map_err(|e| e.to_string())?;
    // Read pipes concurrently, so localized output cannot block the child.
    use std::io::Read;
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let reader = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stdout.read_to_end(&mut b);
        b
    });
    let error_reader = thread::spawn(move || {
        let mut b = Vec::new();
        let _ = stderr.read_to_end(&mut b);
        b
    });
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut timed_out = false;
    loop {
        if child.try_wait().map_err(|e| e.to_string())?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            timed_out = true;
            break;
        }
        thread::sleep(Duration::from_millis(120));
    }
    let status = child.wait().map_err(|e| e.to_string())?;
    let stdout = reader.join().unwrap_or_default();
    let stderr = error_reader.join().unwrap_or_default();
    if timed_out {
        return Err(format!("netsh {} timeout", cmd.join(" ")));
    }
    if !status.success() {
        return Err(format!(
            "netsh {} gagal ({}): {} {}",
            cmd.join(" "),
            status,
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        ));
    }
    Ok(())
}
fn ipv4_write(id: &str, want: &Ipv4, previous: Option<&Ipv4>) -> Result<()> {
    for command in crate::ipv4_commands(want, previous)? {
        netsh(id, &command)?;
    }
    ipv4_wait(id, want)
}
fn undo_ipv4(id: &str, original: &Ipv4) -> Result<()> {
    let current = adapter(id).and_then(|a| ipv4_config(&a)).ok();
    ipv4_write(id, original, current.as_ref())
}
fn write_dns_only(id: &str, original: &Ipv4) -> Result<()> {
    original.validate()?;
    // Recovery must never set IP or restart DHCP if only DNS was touched.
    let want = original.dns.as_deref();
    if ipv4_dns(id)?.as_deref() == want {
        return Ok(());
    }
    for command in crate::dns_commands(want) {
        netsh(id, &command)?;
    }
    let end = Instant::now() + Duration::from_secs(12);
    while Instant::now() < end {
        if ipv4_dns(id).is_ok_and(|dns| dns.as_deref() == want) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(450));
    }
    Err("DNS belum cocok saat dibaca ulang. IP, subnet, dan gateway tidak ditulis.".into())
}
fn ipv4_wait(id: &str, want: &Ipv4) -> Result<()> {
    let end = Instant::now() + Duration::from_secs(12);
    let mut detail = String::new();
    while Instant::now() < end {
        match adapter(id).and_then(|a| {
            let c = ipv4_config(&a)?;
            Ok((a, c))
        }) {
            Ok((a, c))
                if want.matches(&c)
                    && (!a.up
                        || want.dhcp
                        || want
                            .addresses
                            .iter()
                            .all(|addr| a.preferred.contains(&addr.ip))) =>
            {
                return Ok(());
            }
            Ok((a, c)) => {
                detail = format!("IPv4 terbaca {c:?}; alamat Preferred {:?}", a.preferred)
            }
            Err(e) => detail = e,
        }
        thread::sleep(Duration::from_millis(450));
    }
    Err(format!("Pembacaan ulang IPv4/DNS tidak cocok: {detail}"))
}

pub fn apply(id: &str, request: MacRequest, ip: Option<&Ipv4>) -> Result<String> {
    apply_inner(id, request, ip, None)
}
pub fn apply_checked(change: &Change) -> Result<String> {
    let mac = change.request()?;
    if change.recover {
        return recover_inner(&change.id, change.recovery_version.as_deref());
    }
    apply_inner(&change.id, mac, change.ip.as_ref(), Some(change))
}
fn apply_inner(
    id: &str,
    request: MacRequest,
    ip: Option<&Ipv4>,
    expected: Option<&Change>,
) -> Result<String> {
    let a = adapter(id)?;
    let plan = mac_plan(a.active_mac, request);
    if plan == MacPlan::Skip && ip.is_none() {
        return Ok("MAC aktif sudah cocok. Driver dan adaptor tidak diubah.".into());
    }
    if !elevated() {
        return Err("Buka jendela Administrator untuk menerapkan perubahan".into());
    }
    let _guard = Guard::acquire()?;
    let a = adapter(id)?;
    let plan = mac_plan(a.active_mac, request);
    if let Some(snapshot) = expected
        && request != MacRequest::Keep
        && snapshot.expected_mac != a.active_mac
    {
        return Err("MAC berubah sejak pratinjau. Tinjau ulang sebelum menerapkan.".into());
    }
    if pending(&a.id)? {
        return Err(
            "Ada transaksi tertunda untuk adaptor ini. Gunakan Pulihkan transaksi dahulu.".into(),
        );
    }
    let original_ip = if let Some(want) = ip {
        want.validate()?;
        Some(ipv4_config(&a)?)
    } else {
        None
    };
    if let Some(expected) = expected.and_then(|c| c.expected_ipv4.as_ref())
        && original_ip
            .as_ref()
            .is_none_or(|actual| !expected.matches(actual))
    {
        return Err("IPv4/DNS berubah sejak pratinjau. Tinjau ulang sebelum menerapkan.".into());
    }
    let ip_needed = ip
        .zip(original_ip.as_ref())
        .is_some_and(|(want, old)| !want.matches(old));
    if ip_needed && a.admin != AdminState::Enabled {
        return Err(format!(
            "IPv4/DNS memerlukan antarmuka yang diaktifkan ({} · {}). Aktifkan adaptor dan klik Muat ulang. Jika kabel dilepas dan hanya perlu MAC, gunakan MAC Address atau restore MAC saja.",
            a.admin.label(),
            a.link_label()
        ));
    }
    let dns_only = ip_needed
        && ip
            .zip(original_ip.as_ref())
            .is_some_and(|(want, old)| want.same_addressing(old));
    let new_ips = ip
        .zip(original_ip.as_ref())
        .map_or_else(Vec::new, |(want, old)| new_static_ips(want, old));
    let new_mac = match plan {
        MacPlan::Set(m) => Some(m),
        MacPlan::Factory => a.permanent_mac.filter(|m| Some(*m) != a.active_mac),
        MacPlan::Skip => None,
    };
    ensure_no_local_conflict(&a.id, &new_ips, new_mac)?;
    let (device, original_mac, desired) = if plan == MacPlan::Skip {
        (None, None, None)
    } else {
        let d = prepare_mac_device(&a)?;
        let current = a.active_mac.ok_or("MAC aktif tidak dapat dibaca")?;
        let target = match plan {
            MacPlan::Set(m) => m,
            MacPlan::Factory => a.permanent_mac.ok_or("MAC permanen tidak diketahui")?,
            MacPlan::Skip => unreachable!(),
        };
        let key = d.key(KEY_QUERY_VALUE | KEY_SET_VALUE)?;
        let value = key.read("NetworkAddress")?;
        if plan == MacPlan::Factory && value.is_none() && current == target {
            (None, None, None)
        } else {
            (
                Some(d),
                Some(MacOriginal {
                    active: current,
                    value,
                    link: a.up,
                }),
                Some(target),
            )
        }
    };
    if device.is_none() && !ip_needed {
        return Ok("Semua nilai sudah sesuai; tidak ada perubahan.".into());
    }
    let store = journal_key()?;
    let pending = std::cell::RefCell::new(Journal {
        id: a.id.clone(),
        mac: None,
        ipv4: None,
        dns_only: false,
    });
    let wrote_mac = Cell::new(false);
    let wrote_ip = Cell::new(false);
    let r = execute_transaction(
        device.is_some(),
        ip_needed,
        || {
            let d = device.as_ref().unwrap();
            pending.borrow_mut().mac = original_mac.clone();
            journal_write(&store, &a.id, Some(&pending.borrow()))?;
            let value = match plan {
                MacPlan::Set(m) => Some(m.compact()),
                _ => None,
            };
            let key = d.key(KEY_QUERY_VALUE | KEY_SET_VALUE)?;
            wrote_mac.set(true);
            key.write("NetworkAddress", value.as_deref())?;
            drop(key);
            d.restart()?;
            mac_wait(&a.id, desired.unwrap(), a.up)?;
            if read_mac_override(&a.id)? != value {
                return Err("Driver tidak mempertahankan override yang diminta".into());
            }
            Ok(())
        },
        || {
            if adapter(&a.id)?.admin != AdminState::Enabled {
                return Err("Antarmuka tidak lagi siap menerima IPv4/DNS setelah restart. Aktifkan adaptor atau lakukan MAC saja terlebih dahulu.".into());
            }
            {
                let mut journal = pending.borrow_mut();
                journal.ipv4 = original_ip.clone();
                journal.dns_only = dns_only;
            }
            journal_write(&store, &a.id, Some(&pending.borrow()))?;
            wrote_ip.set(true);
            if dns_only {
                write_dns_only(&a.id, ip.unwrap())?;
            } else {
                ipv4_write(&a.id, ip.unwrap(), original_ip.as_ref())?;
            }
            if let Some(expected) = desired {
                mac_wait(&a.id, expected, a.up)?;
            }
            Ok(())
        },
        || {
            if wrote_mac.get() {
                undo_mac(&a.id, original_mac.as_ref().unwrap())
            } else {
                Ok(())
            }
        },
        || {
            if wrote_ip.get() {
                if dns_only {
                    write_dns_only(&a.id, original_ip.as_ref().unwrap())
                } else {
                    undo_ipv4(&a.id, original_ip.as_ref().unwrap())
                }
            } else {
                Ok(())
            }
        },
    );
    if r.is_ok()
        && let Err(e) = journal_write(&store, &format!("last-{}", a.id), Some(&pending.borrow()))
    {
        return Err(format!(
            "RECOVERY REQUIRED — snapshot pemulihan tidak dapat diselesaikan: {e}"
        ));
    }
    if !r.as_ref().is_err_and(|e| e.contains("RECOVERY REQUIRED"))
        && let Err(e) = journal_write(&store, &a.id, None)
    {
        return Err(format!(
            "RECOVERY REQUIRED — jurnal tidak dapat diselesaikan: {e}"
        ));
    }
    r?;
    let after = adapter(&a.id).ok();
    let mut message = String::from("Pengaturan diterapkan dan dibaca ulang dari Windows.");
    if let Some(m) = desired {
        message.push_str(&format!(
            "\nMAC aktif: {m}. Verifikasi frame dari perangkat kedua masih diperlukan."
        ));
    }
    if ip.is_some_and(|v| v.dhcp) && after.is_none_or(|a| a.preferred.is_empty()) {
        message.push_str("\nDHCP aktif; lease IPv4 belum terlihat.");
    }
    Ok(message)
}
pub fn recover(id: &str) -> Result<String> {
    recover_inner(id, None)
}
fn recover_inner(id: &str, expected_version: Option<&str>) -> Result<String> {
    if !elevated() {
        return Err("Jalankan pemulihan dari jendela Administrator".into());
    }
    let _guard = Guard::acquire()?;
    let a = adapter(id)?;
    let k = journal_key()?;
    let last_id = format!("last-{}", a.id);
    let (was_pending, json) =
        read_recovery(&k, &a.id)?.ok_or("Tidak ada snapshot pemulihan untuk adaptor ini")?;
    if expected_version.is_some_and(|v| v != journal_version(&json, was_pending)) {
        return Err("Snapshot berubah sejak pratinjau. Tinjau pemulihan lagi.".into());
    }
    let j = Journal::decode(&json, &a.id)?;
    if !was_pending {
        journal_write(&k, &a.id, Some(&j))?;
    }
    let m = j.mac.as_ref().map_or(Ok(()), |old| undo_mac(&a.id, old));
    let i = j.ipv4.as_ref().map_or(Ok(()), |old| {
        if j.dns_only {
            write_dns_only(&a.id, old)
        } else {
            undo_ipv4(&a.id, old)
        }
    });
    match (m, i) {
        (Ok(()), Ok(())) => {
            if !was_pending || k.read(&last_id)?.as_deref() == Some(&json) {
                journal_write(&k, &last_id, None)?;
            }
            journal_write(&k, &a.id, None)?;
            Ok("Konfigurasi awal dipulihkan dan terverifikasi.".into())
        }
        (m, i) => Err(format!(
            "RECOVERY REQUIRED — MAC: {}; IPv4/DNS: {}",
            m.err().unwrap_or_else(|| "ok".into()),
            i.err().unwrap_or_else(|| "ok".into())
        )),
    }
}

#[cfg(test)]
mod journal_tests {
    use super::*;

    #[test]
    fn accepts_legacy_journal_and_rejects_invalid_scope() {
        let id = "{00000000-0000-0000-0000-000000000001}";
        let legacy = serde_json::json!({
            "id": id,
            "ipv4": {"dhcp": true, "addresses": [], "gateway": null, "dns": null},
            "mac": null
        });
        assert!(!Journal::decode(&legacy.to_string(), id).unwrap().dns_only);
        assert!(Journal::decode(&legacy.to_string(), "{other}").is_err());
        let mut dns = legacy;
        dns["dns_only"] = true.into();
        assert!(Journal::decode(&dns.to_string(), id).unwrap().dns_only);
        dns["ipv4"]["dns"] = serde_json::json!(["0.0.0.0"]);
        assert!(Journal::decode(&dns.to_string(), id).is_err());
        dns["ipv4"] = serde_json::Value::Null;
        assert!(Journal::decode(&dns.to_string(), id).is_err());
    }
}
