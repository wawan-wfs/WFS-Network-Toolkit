use super::{
    Coverage, CoverageState, Endpoint, EndpointState, LIMIT, LocalAddress, LocalSnapshot, Neighbor,
    Probe, ProbeOutcome, Protocol, label, now,
    router::{Authority, RouterSnapshot, Table},
};
use crate::{Mac, Result, windows as w};
use std::{
    collections::HashMap,
    ffi::c_void,
    mem::{offset_of, size_of},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6},
    path::Path,
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_DATA, ERROR_NOT_FOUND, GetLastError,
    },
    NetworkManagement::IpHelper::*,
    Networking::{WinHttp::*, WinSock::*},
    System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    },
};

fn status(code: u32, source: &str) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("{source} tidak tersedia (Windows {code})."))
    }
}
fn sock(v: &SOCKADDR_INET) -> Option<SocketAddr> {
    unsafe {
        match v.si_family {
            AF_INET => Some(SocketAddr::new(
                Ipv4Addr::from(v.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).into(),
                u16::from_be(v.Ipv4.sin_port),
            )),
            AF_INET6 => Some(
                SocketAddrV6::new(
                    v.Ipv6.sin6_addr.u.Byte.into(),
                    u16::from_be(v.Ipv6.sin6_port),
                    0,
                    v.Ipv6.Anonymous.sin6_scope_id,
                )
                .into(),
            ),
            _ => None,
        }
    }
}
fn scope(v: SocketAddr) -> u32 {
    if let SocketAddr::V6(v) = v {
        v.scope_id()
    } else {
        0
    }
}
fn native_socket(raw: &SOCKADDR_STORAGE) -> Option<SocketAddr> {
    // SOCKADDR_STORAGE returned by WinHTTP is aligned and large enough for SOCKADDR_INET.
    sock(unsafe { &*(raw as *const SOCKADDR_STORAGE).cast::<SOCKADDR_INET>() })
}
struct Mib<T>(*mut T);
impl<T> Drop for Mib<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { FreeMibTable(self.0.cast()) };
        }
    }
}
fn ip_addresses() -> Result<(Vec<LocalAddress>, usize)> {
    let mut table = Mib::<MIB_UNICASTIPADDRESS_TABLE>(null_mut());
    let code = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table.0) };
    if matches!(code, ERROR_NO_DATA | ERROR_NOT_FOUND) {
        return Ok((vec![], 0));
    }
    status(code, "Alamat lokal")?;
    if table.0.is_null() {
        return Err("Tabel alamat lokal kosong tanpa status.".into());
    }
    let len = unsafe { (*table.0).NumEntries } as usize;
    let entries =
        unsafe { std::ptr::addr_of!((*table.0).Table).cast::<MIB_UNICASTIPADDRESS_ROW>() };
    let rows = (0..len.min(LIMIT))
        .filter_map(|i| {
            let row = unsafe { &*entries.add(i) };
            let a = sock(&row.Address)?;
            (!a.ip().is_unspecified() && !a.ip().is_loopback()).then_some(LocalAddress {
                ip: a.ip(),
                interface_index: row.InterfaceIndex,
                scope_id: scope(a),
                prefix: row.OnLinkPrefixLength,
            })
        })
        .collect();
    Ok((rows, len.saturating_sub(LIMIT)))
}
fn neighbors() -> Result<(Vec<Neighbor>, usize)> {
    let mut table = Mib::<MIB_IPNET_TABLE2>(null_mut());
    let code = unsafe { GetIpNetTable2(AF_UNSPEC, &mut table.0) };
    if matches!(code, ERROR_NO_DATA | ERROR_NOT_FOUND) {
        return Ok((vec![], 0));
    }
    status(code, "Tetangga ARP/ND")?;
    if table.0.is_null() {
        return Err("Tabel ARP/ND kosong tanpa status.".into());
    }
    let len = unsafe { (*table.0).NumEntries } as usize;
    let entries = unsafe { std::ptr::addr_of!((*table.0).Table).cast::<MIB_IPNET_ROW2>() };
    let rows = (0..len.min(LIMIT))
        .filter_map(|i| {
            let row = unsafe { &*entries.add(i) };
            let a = sock(&row.Address)?;
            let ip = a.ip();
            if ip.is_multicast()
                || ip.is_loopback()
                || ip.is_unspecified()
                || matches!(ip, IpAddr::V4(v) if v.is_broadcast())
            {
                return None;
            }
            let mac = (row.PhysicalAddressLength == 6)
                .then(|| {
                    Mac::from_bytes(row.PhysicalAddress[..6].try_into().expect("six bytes")).ok()
                })
                .flatten();
            let cache_state = match row.State {
                0 => "Unreachable",
                1 => "Incomplete",
                2 => "Probe",
                3 => "Delay",
                4 => "Stale",
                5 => "Reachable",
                6 => "Permanent",
                _ => "Unknown",
            }
            .into();
            Some(Neighbor {
                ip,
                interface_index: row.InterfaceIndex,
                scope_id: scope(a),
                mac,
                cache_state,
            })
        })
        .collect();
    Ok((rows, len.saturating_sub(LIMIT)))
}
fn endpoint_table<T: Copy>(
    offset: usize,
    get: impl Fn(*mut c_void, *mut u32) -> u32,
) -> Result<(Vec<T>, usize)> {
    let mut len = 0;
    let first = get(null_mut(), &mut len);
    if first == ERROR_NO_DATA {
        return Ok((vec![], 0));
    }
    if first != ERROR_INSUFFICIENT_BUFFER && first != 0 {
        status(first, "Ukuran tabel endpoint")?;
    }
    for _ in 0..4 {
        if !(4..=16 * 1024 * 1024).contains(&len) {
            return Err("Tabel endpoint berada di luar batas ukuran.".into());
        }
        let mut storage = vec![0u64; (len as usize).div_ceil(8)];
        let cap = len as usize;
        let ptr = storage.as_mut_ptr().cast::<u8>();
        let code = get(ptr.cast(), &mut len);
        if code == ERROR_INSUFFICIENT_BUFFER {
            continue;
        }
        if code == ERROR_NO_DATA {
            return Ok((vec![], 0));
        }
        status(code, "Tabel endpoint")?;
        if len as usize > cap || len < 4 {
            return Err("Panjang tabel endpoint tidak valid.".into());
        }
        let rows = unsafe { ptr.cast::<u32>().read_unaligned() } as usize;
        if rows == 0 {
            return Ok((vec![], 0));
        }
        if rows
            .checked_mul(size_of::<T>())
            .and_then(|v| v.checked_add(offset))
            .is_none_or(|v| v > len as usize)
        {
            return Err("Jumlah baris tabel endpoint tidak valid.".into());
        }
        let data = unsafe { ptr.add(offset).cast::<T>() };
        return Ok((
            (0..rows.min(LIMIT))
                .map(|i| unsafe { data.add(i).read_unaligned() })
                .collect(),
            rows.saturating_sub(LIMIT),
        ));
    }
    Err("Tabel endpoint berubah terlalu cepat. Muat ulang.".into())
}
fn tcp_state(v: u32) -> EndpointState {
    match v {
        2 => EndpointState::Listening,
        3 | 4 => EndpointState::Attempt,
        5 => EndpointState::Established,
        _ => EndpointState::Other(v),
    }
}
fn ipv4(raw: u32, port: u32) -> SocketAddr {
    SocketAddr::new(
        Ipv4Addr::from(raw.to_ne_bytes()).into(),
        u16::from_be(port as u16),
    )
}
fn ipv6(raw: [u8; 16], port: u32, scope: u32) -> SocketAddr {
    SocketAddrV6::new(Ipv6Addr::from(raw), u16::from_be(port as u16), 0, scope).into()
}
fn tcp(local: SocketAddr, remote: SocketAddr, state: u32, pid: u32) -> Endpoint {
    let state = tcp_state(state);
    Endpoint {
        protocol: Protocol::Tcp,
        local,
        remote: (state != EndpointState::Listening && !remote.ip().is_unspecified())
            .then_some(remote),
        state,
        pid,
        process: None,
    }
}
fn udp(local: SocketAddr, pid: u32) -> Endpoint {
    Endpoint {
        protocol: Protocol::Udp,
        local,
        remote: None,
        state: EndpointState::Bound,
        pid,
        process: None,
    }
}
fn process_name(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        return None;
    }
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len) };
    unsafe { CloseHandle(h) };
    if ok == 0 {
        return None;
    }
    let text = w::from_wide(&buf[..len as usize]);
    Path::new(&text).file_name()?.to_str().map(label)
}
fn collect<T>(
    result: Result<(Vec<T>, usize)>,
    source: &str,
    coverage: &mut Vec<Coverage>,
) -> Vec<T> {
    let (data, state, detail) = match result {
        Ok((v, 0)) => (v, CoverageState::CompleteSnapshot, None),
        Ok((v, n)) => (
            v,
            CoverageState::Partial,
            Some(format!("{n} baris melewati batas.")),
        ),
        Err(e) => (vec![], CoverageState::Unavailable, Some(e)),
    };
    coverage.push(Coverage {
        source: source.into(),
        observed_at: now(),
        state,
        rows: data.len(),
        detail,
    });
    data
}
fn convert<A, B>(result: Result<(Vec<A>, usize)>, f: impl Fn(A) -> B) -> Result<(Vec<B>, usize)> {
    result.map(|(r, n)| (r.into_iter().map(f).collect(), n))
}
pub fn local_snapshot() -> LocalSnapshot {
    let mut coverage = vec![];
    let addresses = collect(ip_addresses(), "Windows Unicast IP", &mut coverage);
    let neighbors = collect(neighbors(), "Windows ARP/ND cache", &mut coverage);
    let mut endpoints = vec![];
    let get_tcp = |family| {
        move |p, n| unsafe { GetExtendedTcpTable(p, n, 0, family, TCP_TABLE_OWNER_PID_ALL, 0) }
    };
    let get_udp = |family| {
        move |p, n| unsafe { GetExtendedUdpTable(p, n, 0, family, UDP_TABLE_OWNER_PID, 0) }
    };
    endpoints.extend(collect(
        convert(
            endpoint_table::<MIB_TCPROW_OWNER_PID>(
                offset_of!(MIB_TCPTABLE_OWNER_PID, table),
                get_tcp(AF_INET as u32),
            ),
            |r| {
                tcp(
                    ipv4(r.dwLocalAddr, r.dwLocalPort),
                    ipv4(r.dwRemoteAddr, r.dwRemotePort),
                    r.dwState,
                    r.dwOwningPid,
                )
            },
        ),
        "Windows TCPv4",
        &mut coverage,
    ));
    endpoints.extend(collect(
        convert(
            endpoint_table::<MIB_TCP6ROW_OWNER_PID>(
                offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
                get_tcp(AF_INET6 as u32),
            ),
            |r| {
                tcp(
                    ipv6(r.ucLocalAddr, r.dwLocalPort, r.dwLocalScopeId),
                    ipv6(r.ucRemoteAddr, r.dwRemotePort, r.dwRemoteScopeId),
                    r.dwState,
                    r.dwOwningPid,
                )
            },
        ),
        "Windows TCPv6",
        &mut coverage,
    ));
    endpoints.extend(collect(
        convert(
            endpoint_table::<MIB_UDPROW_OWNER_PID>(
                offset_of!(MIB_UDPTABLE_OWNER_PID, table),
                get_udp(AF_INET as u32),
            ),
            |r| udp(ipv4(r.dwLocalAddr, r.dwLocalPort), r.dwOwningPid),
        ),
        "Windows UDPv4",
        &mut coverage,
    ));
    endpoints.extend(collect(
        convert(
            endpoint_table::<MIB_UDP6ROW_OWNER_PID>(
                offset_of!(MIB_UDP6TABLE_OWNER_PID, table),
                get_udp(AF_INET6 as u32),
            ),
            |r| {
                udp(
                    ipv6(r.ucLocalAddr, r.dwLocalPort, r.dwLocalScopeId),
                    r.dwOwningPid,
                )
            },
        ),
        "Windows UDPv6",
        &mut coverage,
    ));
    let mut names = HashMap::new();
    for e in &mut endpoints {
        if names.len() < 2048 || names.contains_key(&e.pid) {
            e.process = names
                .entry(e.pid)
                .or_insert_with(|| process_name(e.pid))
                .clone();
        }
    }
    LocalSnapshot {
        schema: 1,
        observed_at: now(),
        addresses,
        neighbors,
        endpoints,
        coverage,
    }
}

struct Internet(*mut c_void);
impl Internet {
    fn new(raw: *mut c_void, phase: &str) -> Result<Self> {
        if raw.is_null() {
            Err(http_error(phase))
        } else {
            Ok(Self(raw))
        }
    }
    fn option(&self, id: u32, value: u32) -> Result<()> {
        http_ok(
            unsafe { WinHttpSetOption(self.0, id, (&value as *const u32).cast(), 4) },
            "atur opsi WinHTTP",
        )
    }
}
impl Drop for Internet {
    fn drop(&mut self) {
        unsafe {
            WinHttpCloseHandle(self.0);
        }
    }
}
fn http_error(phase: &str) -> String {
    let code = unsafe { GetLastError() };
    let group = match code {
        ERROR_WINHTTP_NAME_NOT_RESOLVED => "DNS tidak menemukan nama",
        ERROR_WINHTTP_CANNOT_CONNECT => "TCP tidak dapat tersambung",
        ERROR_WINHTTP_SECURE_FAILURE
        | ERROR_WINHTTP_SECURE_CERT_CN_INVALID
        | ERROR_WINHTTP_SECURE_CERT_DATE_INVALID => "validasi TLS/sertifikat gagal",
        ERROR_WINHTTP_TIMEOUT => "waktu habis",
        _ => "operasi gagal",
    };
    format!("{phase}: {group} (WinHTTP {code}).")
}
fn http_ok(ok: i32, phase: &str) -> Result<()> {
    if ok != 0 {
        Ok(())
    } else {
        Err(http_error(phase))
    }
}

pub struct Credentials {
    pub user: Vec<u16>,
    pub password: Vec<u16>,
}
impl Drop for Credentials {
    fn drop(&mut self) {
        for v in &mut self.password {
            unsafe { std::ptr::write_volatile(v, 0) };
        }
    }
}
struct HttpResponse {
    status: u32,
    bytes: Vec<u8>,
    endpoints: Option<(SocketAddr, SocketAddr)>,
}
struct HttpsClient {
    connection: Internet,
    _session: Internet,
}
impl HttpsClient {
    fn new(authority: &Authority) -> Result<Self> {
        let session = Internet::new(
            unsafe {
                WinHttpOpen(
                    w::wide("WFS Network Toolkit").as_ptr(),
                    WINHTTP_ACCESS_TYPE_NO_PROXY,
                    null(),
                    null(),
                    0,
                )
            },
            "buka sesi HTTPS",
        )?;
        http_ok(
            unsafe { WinHttpSetTimeouts(session.0, 2500, 3000, 2500, 3000) },
            "atur timeout HTTPS",
        )?;
        session.option(
            WINHTTP_OPTION_SECURE_PROTOCOLS,
            WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2,
        )?;
        let connection = Internet::new(
            unsafe {
                WinHttpConnect(
                    session.0,
                    w::wide(&authority.host).as_ptr(),
                    authority.port,
                    0,
                )
            },
            "siapkan host HTTPS",
        )?;
        Ok(Self {
            connection,
            _session: session,
        })
    }
    fn get(&self, path: &str, auth: Option<&Credentials>, max: usize) -> Result<HttpResponse> {
        self.get_until(
            path,
            auth,
            max,
            Instant::now() + Duration::from_secs(12),
            &super::polling::Cancel::default(),
        )
    }
    fn get_until(
        &self,
        path: &str,
        auth: Option<&Credentials>,
        max: usize,
        deadline: Instant,
        cancel: &super::polling::Cancel,
    ) -> Result<HttpResponse> {
        let boundary = || -> Result<()> {
            cancel.check()?;
            if Instant::now() >= deadline {
                return Err("Batas waktu pengambilan respons tercapai.".into());
            }
            Ok(())
        };
        boundary()?;
        let request = Internet::new(
            unsafe {
                WinHttpOpenRequest(
                    self.connection.0,
                    w::wide("GET").as_ptr(),
                    w::wide(path).as_ptr(),
                    null(),
                    null(),
                    null(),
                    WINHTTP_FLAG_SECURE,
                )
            },
            "siapkan GET HTTPS",
        )?;
        request.option(
            WINHTTP_OPTION_REDIRECT_POLICY,
            WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
        )?;
        request.option(
            WINHTTP_OPTION_AUTOLOGON_POLICY,
            WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH,
        )?;
        request.option(WINHTTP_OPTION_DISABLE_FEATURE, WINHTTP_DISABLE_COOKIES)?;
        request.option(WINHTTP_OPTION_MAX_RESPONSE_HEADER_SIZE, 64 * 1024)?;
        let headers = w::wide("Accept-Encoding: identity\r\n");
        let send = || -> Result<u32> {
            boundary()?;
            http_ok(
                unsafe {
                    WinHttpSendRequest(
                        request.0,
                        headers.as_ptr(),
                        (headers.len() - 1) as u32,
                        null(),
                        0,
                        0,
                        0,
                    )
                },
                "kirim HTTPS",
            )?;
            boundary()?;
            http_ok(
                unsafe { WinHttpReceiveResponse(request.0, null_mut()) },
                "terima HTTPS",
            )?;
            boundary()?;
            let mut status = 0u32;
            let mut len = size_of::<u32>() as u32;
            http_ok(
                unsafe {
                    WinHttpQueryHeaders(
                        request.0,
                        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        null(),
                        (&mut status as *mut u32).cast(),
                        &mut len,
                        null_mut(),
                    )
                },
                "baca status HTTP",
            )?;
            Ok(status)
        };
        let mut status = send()?;
        if let Some(auth) = auth.filter(|_| status == 401) {
            if auth.user.len() < 2
                || auth.password.len() < 2
                || auth.user.last() != Some(&0)
                || auth.password.last() != Some(&0)
            {
                return Err("Kredensial sesi tidak valid.".into());
            }
            let (mut schemes, mut first, mut target) = (0, 0, 0);
            let ok = unsafe {
                WinHttpQueryAuthSchemes(request.0, &mut schemes, &mut first, &mut target)
            };
            if ok != 0
                && schemes & WINHTTP_AUTH_SCHEME_BASIC != 0
                && target == WINHTTP_AUTH_TARGET_SERVER
            {
                http_ok(
                    unsafe {
                        WinHttpSetCredentials(
                            request.0,
                            WINHTTP_AUTH_TARGET_SERVER,
                            WINHTTP_AUTH_SCHEME_BASIC,
                            auth.user.as_ptr(),
                            auth.password.as_ptr(),
                            null_mut(),
                        )
                    },
                    "siapkan autentikasi HTTPS",
                )?;
                status = send()?;
            }
        }
        let endpoints = connection_info(&request);
        let mut bytes = vec![];
        if (200..300).contains(&status) {
            let mut buffer = [0u8; 8192];
            loop {
                boundary()?;
                let mut got = 0;
                http_ok(
                    unsafe {
                        WinHttpReadData(
                            request.0,
                            buffer.as_mut_ptr().cast(),
                            buffer.len() as u32,
                            &mut got,
                        )
                    },
                    "baca respons HTTPS",
                )?;
                boundary()?;
                if got == 0 {
                    break;
                }
                if bytes.len() + got as usize > max {
                    return Err("Respons melebihi batas ukuran.".into());
                }
                bytes.extend_from_slice(&buffer[..got as usize]);
            }
        }
        Ok(HttpResponse {
            status,
            bytes,
            endpoints,
        })
    }
}
fn connection_info(request: &Internet) -> Option<(SocketAddr, SocketAddr)> {
    let mut info = WINHTTP_CONNECTION_INFO {
        cbSize: size_of::<WINHTTP_CONNECTION_INFO>() as u32,
        ..Default::default()
    };
    let mut len = info.cbSize;
    let ok = unsafe {
        WinHttpQueryOption(
            request.0,
            WINHTTP_OPTION_CONNECTION_INFO,
            (&mut info as *mut WINHTTP_CONNECTION_INFO).cast(),
            &mut len,
        )
    };
    if ok == 0 {
        return None;
    }
    Some((
        native_socket(&info.LocalAddress)?,
        native_socket(&info.RemoteAddress)?,
    ))
}
pub const PROBE_TARGET: &str = "https://connectivitycheck.gstatic.com/generate_204";
pub fn probe_https() -> Probe {
    let start = Instant::now();
    let authority = Authority {
        host: "connectivitycheck.gstatic.com".into(),
        port: 443,
    };
    let response = HttpsClient::new(&authority).and_then(|c| c.get("/generate_204", None, 4096));
    let mut p = Probe {
        observed_at: now(),
        elapsed_ms: start.elapsed().as_millis() as u64,
        target: PROBE_TARGET.into(),
        source: None,
        destination: None,
        interface_index: None,
        http_status: None,
        outcome: ProbeOutcome::TransportError,
        detail: String::new(),
    };
    match response {
        Ok(r) => {
            p.http_status = Some(r.status);
            if let Some((a, b)) = r.endpoints {
                p.source = Some(a);
                p.destination = Some(b);
                if let Ok((addresses, 0)) = ip_addresses() {
                    let mut found = addresses
                        .iter()
                        .filter(|x| x.ip == a.ip() && (scope(a) == 0 || scope(a) == x.scope_id));
                    if let Some(first) = found.next().filter(|_| found.next().is_none()) {
                        p.interface_index = Some(first.interface_index);
                    }
                }
            }
            if r.status != 204 || !r.bytes.is_empty() {
                p.outcome = ProbeOutcome::UnexpectedResponse;
                p.detail = "Status, redirect, atau isi tidak cocok. Ini tidak membuktikan pemblokiran; periksa target atau captive portal.".into();
            } else if p.interface_index.is_none() {
                p.outcome = ProbeOutcome::NoAttribution;
                p.detail = "HTTPS berhasil, tetapi interface/IP sumber tidak dapat dipastikan. Tidak mengubah status IP mana pun.".into();
            } else {
                p.outcome = ProbeOutcome::Verified;
                p.detail = "HTTPS langsung tanpa proxy, sertifikat diperiksa, respons cocok. Hanya membuktikan target dan keluarga alamat yang terpakai.".into();
            }
        }
        Err(e) => {
            p.detail = format!("{e} Ini bukan bukti bahwa IP diblokir.");
        }
    }
    p
}
pub fn router_snapshot(authority: Authority, auth: Credentials) -> Result<RouterSnapshot> {
    router_snapshot_cancel(&authority, &auth, &super::polling::Cancel::default())
}
pub fn router_snapshot_cancel(
    authority: &Authority,
    auth: &Credentials,
    cancel: &super::polling::Cancel,
) -> Result<RouterSnapshot> {
    cancel.check()?;
    let deadline = Instant::now() + Duration::from_secs(24);
    let client = HttpsClient::new(authority)?;
    let mut snapshot = RouterSnapshot::new(authority, now());
    for table in Table::ALL {
        cancel.check()?;
        let result = if Instant::now() >= deadline {
            Err("Anggaran waktu snapshot habis; tabel ini tidak diminta.".into())
        } else {
            client
                .get_until(
                    table.path(),
                    Some(auth),
                    8 * 1024 * 1024,
                    deadline.min(Instant::now() + Duration::from_secs(12)),
                    cancel,
                )
                .and_then(|r| match r.status {
                    200 => Ok(r.bytes),
                    401 => Err("HTTP 401 — kredensial ditolak.".into()),
                    403 => Err("HTTP 403 — izin baca tidak tersedia.".into()),
                    404 => Err("HTTP 404 — tabel REST tidak tersedia.".into()),
                    300..=399 => Err("Redirect diblokir; periksa alamat HTTPS router.".into()),
                    n => Err(format!("Router mengembalikan HTTP {n}.")),
                })
        };
        cancel.check()?;
        if result.as_ref().is_err_and(|e| {
            e.starts_with("HTTP 401") || e.contains("validasi TLS") || e.starts_with("Redirect")
        }) {
            return Err(result.expect_err("result checked"));
        }
        snapshot.ingest(table, result, now());
    }
    if snapshot
        .coverage
        .iter()
        .all(|c| c.state == CoverageState::Unavailable)
    {
        return Err(snapshot
            .coverage
            .first()
            .and_then(|c| c.detail.clone())
            .unwrap_or_else(|| "Snapshot router tidak tersedia.".into()));
    }
    snapshot.observed_at = now();
    Ok(snapshot)
}
