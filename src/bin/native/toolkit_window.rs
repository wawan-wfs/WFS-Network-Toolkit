const DRAW_ACTION: u32 = WM_APP + 1;
const SYNC_LAYOUT: u32 = WM_APP + 2;
const ADMIN_HANDOFF: u32 = WM_APP + 3;
const PULSE: usize = 7;
const FIRST: usize = 8;
const ACTIVE: i32 = 100;
const REFRESH: i32 = 101;
const ADMIN: i32 = 102;
const LINK_STATE: i32 = 103;
const HEADING: i32 = 104;
const INTRO: i32 = 105;
const NOTICE: i32 = 106;
const BRAND_ICON: i32 = 107;
const BRAND: i32 = 108;
const COPYRIGHT: i32 = 109;
const FOOTER: i32 = 110;
const HOME_TEXT: i32 = 130;
const DRIVER: i32 = 131;
const IP_MODE: i32 = 140;
const DNS_MODE: i32 = 141;
const IP: i32 = 142;
const MASK: i32 = 143;
const GATEWAY: i32 = 144;
const DNS1: i32 = 145;
const DNS2: i32 = 146;
const IP_APPLY: i32 = 147;
const IP_UNDO: i32 = 148;
const IP_NOTE: i32 = 149;
const MAC_EDIT: i32 = 160;
const MAC_INFO: i32 = 161;
const MAC_APPLY: i32 = 162;
const MAC_RESET: i32 = 163;
const MAC_CONNECTIONS: i32 = 164;
const BACKUP_WITH_MAC: i32 = 170;
const BACKUP_SAVE: i32 = 171;
const RESTORE_WITH_MAC: i32 = 172;
const RESTORE_OPEN: i32 = 173;
const RECOVER_OPEN: i32 = 174;
const RECOVER_NOTE: i32 = 175;
const RESTORE_SCOPE: i32 = 176;
const CALC_IP: i32 = 180;
const CALC_MASK: i32 = 181;
const CALC: i32 = 182;
const PING: i32 = 183;
const REDACT: i32 = 184;
const EXPORT: i32 = 185;
const OUTPUT: i32 = 186;
const DIFF: i32 = 190;
const CONFIRM: i32 = 191;
const CANCEL: i32 = 192;
const NAV: i32 = 200;
const STATIC_START: i32 = 300;
const ADAPTER_LABEL: i32 = 111;
const BRAND_TAGLINE: i32 = 112;
const HOME_LABEL: i32 = 132;
const REVIEW_TARGET: i32 = 193;
const REVIEW_NOTE: i32 = 194;
const REVIEW_DETAILS: i32 = 195;

const SS_NOPREFIX_NATIVE: u32 = 128;
const SS_ICON_NATIVE: u32 = 3;
const STM_SETICON_NATIVE: u32 = 0x170;
const EM_SETMARGINS_NATIVE: u32 = 0xd3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Page {
    Home,
    Ip,
    Mac,
    Backup,
    Diag,
    Intel,
    Review,
}
const PAGES: [Page; 6] = [
    Page::Home,
    Page::Ip,
    Page::Mac,
    Page::Backup,
    Page::Diag,
    Page::Intel,
];
const NAV_END: i32 = NAV + PAGES.len() as i32;
impl Page {
    fn name(self) -> &'static str {
        match self {
            Self::Home => "Ringkasan",
            Self::Ip => "IPv4 dan DNS",
            Self::Mac => "MAC Address",
            Self::Backup => "Backup dan Restore",
            Self::Diag => "Diagnostik",
            Self::Intel => "Analisis Jaringan",
            Self::Review => "Tinjau perubahan",
        }
    }
    fn caption(self) -> &'static str {
        match self {
            Self::Home => "Periksa adaptor, konfigurasi IPv4, gateway, DNS, dan MAC aktif.",
            Self::Ip => "Pilih IP statis atau DHCP. Pengaturan di halaman ini tidak mengubah MAC.",
            Self::Mac => "Ubah atau pulihkan MAC pada adaptor Ethernet fisik yang didukung.",
            Self::Backup => "Cadangkan, pindahkan, atau pulihkan konfigurasi adaptor yang dipilih.",
            Self::Diag => "Uji gateway, hitung subnet, dan ekspor laporan yang dapat disamarkan.",
            Self::Intel => "Telusuri IP, layanan, trafik, histori, dan observasi MikroTik.",
            Self::Review => "Periksa adaptor serta nilai sebelum dan target sebelum melanjutkan.",
        }
    }
}
thread_local! {
    static NAV_SELECTION: std::cell::Cell<Page> = const { std::cell::Cell::new(Page::Home) };
}
struct Widget {
    handle: HWND,
    id: i32,
    page: Option<Page>,
    font: usize,
    rect: [i32; 4],
}
type InventoryResult = Result<(Option<String>, Dashboard)>;
struct Native {
    hwnd: HWND,
    widgets: Vec<Widget>,
    fonts: [HFONT; 4],
    dpi: u32,
    page: Page,
    dashboard: Option<Dashboard>,
    review: Option<(u32, Page)>,
    review_rows: Vec<[String; 3]>,
    model: App,
    inventory: Option<Receiver<InventoryResult>>,
    intel: IntelState,
}
impl Drop for Native {
    fn drop(&mut self) {
        for f in self.fonts {
            if !f.is_null() {
                unsafe {
                    DeleteObject(f);
                }
            }
        }
    }
}
fn send_native(h: HWND, m: u32, a: WPARAM, b: LPARAM) -> LRESULT {
    unsafe { SendMessageW(h, m, a, b) }
}
fn set(h: HWND, value: &str) {
    unsafe {
        SetWindowTextW(h, w::wide(value).as_ptr());
    }
}
fn get(h: HWND) -> String {
    let mut buf = vec![0; unsafe { GetWindowTextLengthW(h) }.clamp(0, 65535) as usize + 1];
    unsafe {
        GetWindowTextW(h, buf.as_mut_ptr(), buf.len() as i32);
    }
    w::from_wide(&buf)
}
fn select(h: HWND, index: usize) {
    send_native(h, CB_SETCURSEL, index, 0);
}
fn selection(h: HWND) -> usize {
    send_native(h, CB_GETCURSEL, 0, 0) as usize
}
fn checked(h: HWND) -> bool {
    send_native(h, BM_GETCHECK, 0, 0) == 1
}
fn crlf(s: &str) -> String {
    s.replace("\r\n", "\n").replace('\n', "\r\n")
}
fn join<I: IntoIterator<Item = T>, T: ToString>(values: I) -> String {
    let s = values
        .into_iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if s.is_empty() { "—".into() } else { s }
}
fn color(r: u32, g: u32, b: u32) -> u32 {
    r | (g << 8) | (b << 16)
}
fn bg() -> u32 {
    color(255, 255, 255)
}
fn rail() -> u32 {
    color(238, 245, 249)
}
fn ink() -> u32 {
    color(16, 44, 70)
}
fn accent() -> u32 {
    color(0, 103, 107)
}
fn muted() -> u32 {
    color(65, 85, 102)
}
fn line() -> u32 {
    color(207, 220, 227)
}
fn selected_nav() -> u32 {
    color(210, 239, 235)
}
fn button_border() -> u32 {
    color(115, 137, 152)
}
fn pressed_primary() -> u32 {
    color(0, 79, 84)
}
fn fill(dc: HDC, r: &RECT, c: u32) {
    let brush = unsafe { CreateSolidBrush(c) };
    if !brush.is_null() {
        unsafe {
            FillRect(dc, r, brush);
            DeleteObject(brush);
        }
    }
}

impl Native {
    fn new(hwnd: HWND, icon: HICON) -> Result<Self> {
        let mut ui = Self {
            hwnd,
            widgets: Vec::new(),
            fonts: [null_mut(); 4],
            dpi: 0,
            page: Page::Home,
            dashboard: None,
            review: None,
            review_rows: Vec::new(),
            inventory: None,
            intel: IntelState::default(),
            model: App {
                hwnd,
                selected: None,
                work: None,
                preview: None,
                token: 0,
            },
        };
        ui.widget(
            "STATIC",
            "",
            BRAND_ICON,
            None,
            0,
            SS_ICON_NATIVE,
            [20, 22, 32, 34],
        )?;
        send_native(ui.h(BRAND_ICON), STM_SETICON_NATIVE, icon as usize, 0);
        ui.text("WeNet Toolkit", BRAND, None, 1, [60, 22, 137, 27])?;
        ui.text(
            "Network intelligence",
            BRAND_TAGLINE,
            None,
            3,
            [60, 51, 137, 19],
        )?;
        for (i, page) in PAGES.into_iter().enumerate() {
            ui.button(
                page.name(),
                NAV + i as i32,
                None,
                [12, 96 + i as i32 * 44, 176, 38],
            )?;
        }
        ui.text(&format!("Versi {VERSION}"), FOOTER, None, 3, VERSION_RECT)?;
        ui.text("by WFS Project", COPYRIGHT, None, 3, COPYRIGHT_RECT)?;
        ui.text(Page::Home.name(), HEADING, None, 2, [228, 20, -256, 39])?;
        ui.text(Page::Home.caption(), INTRO, None, 0, [228, 63, -256, 29])?;
        ui.text(
            "Adaptor jaringan",
            ADAPTER_LABEL,
            None,
            0,
            [228, 89, 200, 20],
        )?;
        ui.widget(
            "COMBOBOX",
            "",
            ACTIVE,
            None,
            0,
            WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST as u32,
            [228, 111, -540, 180],
        )?;
        ui.button("Muat ulang", REFRESH, None, [-296, 106, 112, 36])?;
        ui.button("Mode admin", ADMIN, None, [-172, 106, 144, 36])?;
        ui.text(
            "Membaca adaptor Windows…",
            LINK_STATE,
            None,
            0,
            [228, 151, -256, 23],
        )?;
        ui.widget(
            "EDIT",
            "Membaca daftar adaptor…",
            NOTICE,
            None,
            0,
            WS_TABSTOP | WS_VSCROLL | ES_MULTILINE as u32 | ES_READONLY as u32,
            [228, -49, -256, 34],
        )?;
        send_native(ui.h(NOTICE), EM_SETMARGINS_NATIVE, 3, 7 | (7 << 16));

        ui.text(
            "Rincian adaptor",
            HOME_LABEL,
            Some(Page::Home),
            1,
            [228, 189, 230, 26],
        )?;
        ui.table(
            HOME_TEXT,
            Page::Home,
            [228, 223, -256, -336],
            &["Pengaturan", "Nilai"],
        )?;
        ui.table_rows(
            HOME_TEXT,
            &[vec!["Adaptor".into(), "Membaca daftar adaptor…".into()]],
            2,
        );
        ui.button(
            "Detail driver",
            DRIVER,
            Some(Page::Home),
            [228, -96, 135, 36],
        )?;

        ui.caption("Mode alamat IPv4", 0, Page::Ip, [228, 188, 205, 23])?;
        ui.caption("Mode DNS", 1, Page::Ip, [462, 188, 205, 23])?;
        ui.widget(
            "COMBOBOX",
            "",
            IP_MODE,
            Some(Page::Ip),
            0,
            WS_TABSTOP | CBS_DROPDOWNLIST as u32,
            [228, 214, 210, 125],
        )?;
        ui.widget(
            "COMBOBOX",
            "",
            DNS_MODE,
            Some(Page::Ip),
            0,
            WS_TABSTOP | CBS_DROPDOWNLIST as u32,
            [462, 214, 210, 125],
        )?;
        ui.options(IP_MODE, &["IP statis", "Otomatis (DHCP)"]);
        ui.options(DNS_MODE, &["DNS otomatis", "DNS manual"]);
        for (i, (id, label, x, y)) in [
            (IP, "Alamat IPv4", 228, 258),
            (MASK, "Subnet mask / prefix", 462, 258),
            (GATEWAY, "Gateway", 228, 323),
            (DNS1, "DNS 1", 462, 323),
            (DNS2, "DNS 2", 228, 388),
        ]
        .into_iter()
        .enumerate()
        {
            ui.caption(label, 2 + i as i32, Page::Ip, [x, y, 210, 23])?;
            ui.edit(id, Page::Ip, [x, y + 24, 210, 31], 15)?;
        }
        ui.button(
            "Tinjau perubahan",
            IP_APPLY,
            Some(Page::Ip),
            [228, 457, 164, 36],
        )?;
        ui.button(
            "Kembalikan isian",
            IP_UNDO,
            Some(Page::Ip),
            [404, 457, 153, 36],
        )?;
        ui.text("", IP_NOTE, Some(Page::Ip), 0, [462, 390, -490, 54])?;

        ui.multiline("", MAC_INFO, Page::Mac, [228, 189, -256, 91])?;
        ui.caption("MAC target", 8, Page::Mac, [228, 290, 220, 23])?;
        ui.edit(MAC_EDIT, Page::Mac, [228, 316, 220, 31], 17)?;
        ui.button(
            "Tinjau MAC",
            MAC_APPLY,
            Some(Page::Mac),
            [228, 367, 135, 36],
        )?;
        ui.button(
            "Reset ke bawaan",
            MAC_RESET,
            Some(Page::Mac),
            [375, 367, 157, 36],
        )?;
        ui.button(
            "Koneksi Jaringan",
            MAC_CONNECTIONS,
            Some(Page::Mac),
            [544, 367, 155, 36],
        )?;
        ui.caption(
            "Jika driver menolak perubahan, aplikasi mencoba mengembalikan MAC awal.",
            9,
            Page::Mac,
            [228, 419, -256, 43],
        )?;

        ui.text(
            "Simpan backup",
            STATIC_START + 10,
            Some(Page::Backup),
            1,
            [228, 189, 235, 26],
        )?;
        ui.caption(
            "Simpan konfigurasi adaptor ke file JSON.",
            17,
            Page::Backup,
            [228, 220, 245, 46],
        )?;
        ui.checkbox(
            "Sertakan MAC aktif",
            BACKUP_WITH_MAC,
            Page::Backup,
            [228, 266, 235, 28],
        )?;
        ui.button(
            "Simpan file JSON",
            BACKUP_SAVE,
            Some(Page::Backup),
            [228, 303, 166, 36],
        )?;
        ui.text(
            "Pulihkan backup",
            STATIC_START + 11,
            Some(Page::Backup),
            1,
            [512, 189, 235, 26],
        )?;
        ui.caption(
            "Pengaturan yang dipulihkan",
            18,
            Page::Backup,
            [512, 219, 245, 22],
        )?;
        ui.widget(
            "COMBOBOX",
            "",
            RESTORE_SCOPE,
            Some(Page::Backup),
            0,
            WS_TABSTOP | CBS_DROPDOWNLIST as u32,
            [512, 242, 245, 115],
        )?;
        ui.options(RESTORE_SCOPE, &["IPv4 dan DNS", "DNS saja", "MAC saja"]);
        ui.checkbox(
            "Sertakan MAC dari backup",
            RESTORE_WITH_MAC,
            Page::Backup,
            [512, 266, 260, 28],
        )?;
        ui.button(
            "Buka file backup",
            RESTORE_OPEN,
            Some(Page::Backup),
            [512, 303, 166, 36],
        )?;
        ui.text(
            "Batalkan perubahan terakhir",
            STATIC_START + 12,
            Some(Page::Backup),
            1,
            [228, 368, 350, 26],
        )?;
        ui.text(
            "",
            RECOVER_NOTE,
            Some(Page::Backup),
            0,
            [228, 399, -256, 42],
        )?;
        ui.button(
            "Tinjau pemulihan",
            RECOVER_OPEN,
            Some(Page::Backup),
            [228, 449, 173, 36],
        )?;

        ui.caption("Alamat IPv4", 13, Page::Diag, [228, 188, 141, 22])?;
        ui.caption("Mask / prefix", 14, Page::Diag, [390, 188, 116, 22])?;
        ui.edit(CALC_IP, Page::Diag, [228, 214, 147, 31], 15)?;
        ui.edit(CALC_MASK, Page::Diag, [390, 214, 108, 31], 15)?;
        ui.button("Hitung subnet", CALC, Some(Page::Diag), [513, 212, 125, 36])?;
        ui.button("Ping gateway", PING, Some(Page::Diag), [650, 212, 129, 36])?;
        ui.multiline(
            "Belum ada hasil diagnostik.",
            OUTPUT,
            Page::Diag,
            [228, 270, -256, -383],
        )?;
        ui.checkbox(
            "Samarkan alamat dan identitas",
            REDACT,
            Page::Diag,
            [228, -88, 249, 30],
        )?;
        send_native(ui.h(REDACT), BM_SETCHECK, 1, 0);
        ui.button(
            "Ekspor laporan",
            EXPORT,
            Some(Page::Diag),
            [495, -94, 151, 36],
        )?;

        ui.text(
            "",
            REVIEW_TARGET,
            Some(Page::Review),
            1,
            [228, 189, -256, 28],
        )?;
        ui.table(
            DIFF,
            Page::Review,
            [228, 226, -256, -410],
            &["Pengaturan", "Sebelum", "Target"],
        )?;
        ui.multiline("", REVIEW_NOTE, Page::Review, [228, -170, -256, 68])?;
        ui.button(
            "Lihat nilai lengkap",
            REVIEW_DETAILS,
            Some(Page::Review),
            [228, -94, 177, 36],
        )?;
        ui.button("Batal", CANCEL, Some(Page::Review), [-296, -94, 112, 36])?;
        ui.button(
            "Terapkan",
            CONFIRM,
            Some(Page::Review),
            [-172, -94, 144, 36],
        )?;
        ui.create_intel()?;
        ui.layout();
        ui.show_page(Page::Home);
        Ok(ui)
    }
    fn h(&self, id: i32) -> HWND {
        self.widgets
            .iter()
            .find(|a| a.id == id)
            .map_or(null_mut(), |a| a.handle)
    }
    fn options(&self, id: i32, items: &[&str]) {
        let h = self.h(id);
        send_native(h, CB_RESETCONTENT, 0, 0);
        for item in items {
            send_native(h, CB_ADDSTRING, 0, w::wide(item).as_ptr() as isize);
        }
        select(h, 0);
    }
    #[allow(clippy::too_many_arguments)]
    fn widget(
        &mut self,
        class: &str,
        text: &str,
        id: i32,
        page: Option<Page>,
        font: usize,
        styles: u32,
        rect: [i32; 4],
    ) -> Result<()> {
        let ex = if class == "EDIT" { WS_EX_CLIENTEDGE } else { 0 };
        let h = unsafe {
            CreateWindowExW(
                ex,
                w::wide(class).as_ptr(),
                w::wide(text).as_ptr(),
                WS_CHILD | styles,
                0,
                0,
                0,
                0,
                self.hwnd,
                id as usize as HMENU,
                GetModuleHandleW(null()),
                null(),
            )
        };
        if h.is_null() {
            return Err(format!(
                "Kontrol {id} gagal dibuat: {}",
                std::io::Error::last_os_error()
            ));
        }
        self.widgets.push(Widget {
            handle: h,
            id,
            page,
            font,
            rect,
        });
        Ok(())
    }
    fn text(
        &mut self,
        value: &str,
        id: i32,
        page: Option<Page>,
        font: usize,
        r: [i32; 4],
    ) -> Result<()> {
        self.widget("STATIC", value, id, page, font, SS_NOPREFIX_NATIVE, r)
    }
    fn table(&mut self, id: i32, page: Page, r: [i32; 4], columns: &[&str]) -> Result<()> {
        self.widget(
            "SysListView32",
            "",
            id,
            Some(page),
            0,
            WS_TABSTOP
                | WS_BORDER
                | LVS_REPORT
                | LVS_SINGLESEL
                | LVS_SHOWSELALWAYS
                | LVS_NOSORTHEADER,
            r,
        )?;
        let h = self.h(id);
        send_native(
            h,
            LVM_SETEXTENDEDLISTVIEWSTYLE,
            0,
            (LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER) as isize,
        );
        for (i, name) in columns.iter().enumerate() {
            let mut name = w::wide(name);
            let c = LVCOLUMNW {
                mask: LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM,
                cx: 100,
                pszText: name.as_mut_ptr(),
                iSubItem: i as i32,
                ..Default::default()
            };
            if send_native(h, LVM_INSERTCOLUMNW, i, (&c as *const LVCOLUMNW) as isize) < 0 {
                return Err(format!("Kolom tabel {id} tidak dapat dibuat."));
            }
        }
        Ok(())
    }
    fn table_rows(&self, id: i32, rows: &[Vec<String>], column_count: usize) {
        let h = self.h(id);
        let redraw = unsafe { IsWindowVisible(h) } != 0;
        if redraw {
            send_native(h, WM_SETREDRAW, 0, 0);
        }
        send_native(h, LVM_DELETEALLITEMS, 0, 0);
        for (i, row) in rows.iter().enumerate() {
            for (j, value) in row.iter().take(column_count).enumerate() {
                let mut value = w::wide(value);
                let item = LVITEMW {
                    mask: LVIF_TEXT,
                    iItem: i as i32,
                    iSubItem: j as i32,
                    pszText: value.as_mut_ptr(),
                    ..Default::default()
                };
                let ptr = (&item as *const LVITEMW) as isize;
                if j == 0 {
                    send_native(h, LVM_INSERTITEMW, 0, ptr);
                } else {
                    send_native(h, LVM_SETITEMTEXTW, i, ptr);
                }
            }
        }
        if redraw {
            send_native(h, WM_SETREDRAW, 1, 0);
            unsafe {
                RedrawWindow(
                    h,
                    null(),
                    null_mut(),
                    RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_ERASE,
                );
            }
        }
    }
    fn caption(&mut self, label: &str, offset: i32, page: Page, r: [i32; 4]) -> Result<()> {
        self.widget(
            "STATIC",
            label,
            STATIC_START + offset,
            Some(page),
            0,
            SS_NOPREFIX_NATIVE,
            r,
        )
    }
    fn button(&mut self, label: &str, id: i32, page: Option<Page>, r: [i32; 4]) -> Result<()> {
        self.widget(
            "BUTTON",
            label,
            id,
            page,
            0,
            WS_TABSTOP | BS_OWNERDRAW as u32,
            r,
        )
    }
    fn checkbox(&mut self, label: &str, id: i32, page: Page, r: [i32; 4]) -> Result<()> {
        self.widget(
            "BUTTON",
            label,
            id,
            Some(page),
            0,
            WS_TABSTOP | BS_AUTOCHECKBOX as u32,
            r,
        )
    }
    fn edit(&mut self, id: i32, page: Page, r: [i32; 4], length: usize) -> Result<()> {
        self.widget(
            "EDIT",
            "",
            id,
            Some(page),
            0,
            WS_TABSTOP | ES_AUTOHSCROLL as u32,
            r,
        )?;
        send_native(self.h(id), EM_LIMITTEXT, length, 0);
        send_native(self.h(id), EM_SETMARGINS_NATIVE, 3, 6 | (6 << 16));
        Ok(())
    }
    fn multiline(&mut self, label: &str, id: i32, page: Page, r: [i32; 4]) -> Result<()> {
        self.widget(
            "EDIT",
            label,
            id,
            Some(page),
            0,
            WS_TABSTOP
                | WS_VSCROLL
                | ES_MULTILINE as u32
                | ES_READONLY as u32
                | ES_AUTOVSCROLL as u32,
            r,
        )?;
        send_native(self.h(id), EM_SETMARGINS_NATIVE, 3, 9 | (9 << 16));
        Ok(())
    }
    fn layout(&mut self) {
        let mut rect = RECT::default();
        unsafe {
            GetClientRect(self.hwnd, &mut rect);
        }
        if rect.right <= 0 || rect.bottom <= 0 {
            return;
        }
        let dpi = client_scale(
            rect.right,
            rect.bottom,
            unsafe { GetDpiForWindow(self.hwnd) } as i32,
        ) as u32;
        let scale = |v: i32| (v * dpi as i32 + 48) / 96;
        if self.dpi != dpi {
            self.dpi = dpi;
            let old = self.fonts;
            for (i, (height, weight)) in [(15, 400), (17, 650), (30, 700), (12, 400)]
                .into_iter()
                .enumerate()
            {
                self.fonts[i] = unsafe {
                    CreateFontW(
                        -scale(height),
                        0,
                        0,
                        0,
                        weight,
                        0,
                        0,
                        0,
                        DEFAULT_CHARSET as u32,
                        0,
                        0,
                        CLEARTYPE_QUALITY as u32,
                        0,
                        w::wide("Segoe UI").as_ptr(),
                    )
                };
            }
            for item in &self.widgets {
                let f = self.fonts[item.font];
                if !f.is_null() {
                    send_native(item.handle, WM_SETFONT, f as usize, 1);
                }
            }
            for f in old {
                if !f.is_null() {
                    unsafe {
                        DeleteObject(f);
                    }
                }
            }
        }
        for item in &self.widgets {
            let [x, y, width, height] =
                control_rect(item.rect, rect.right, rect.bottom, dpi as i32);
            unsafe {
                MoveWindow(item.handle, x, y, width, height, 0);
            }
            if item.id == INTEL_TABLE {
                let available = (width - scale(21)).max(80);
                for (column, share) in [25, 24, 25, 26].into_iter().enumerate() {
                    send_native(
                        item.handle,
                        LVM_SETCOLUMNWIDTH,
                        column,
                        (available * share / 100) as isize,
                    );
                }
            }
            if matches!(item.id, HOME_TEXT | DIFF) {
                // Reserve space for the vertical scrollbar so long restore lists never force horizontal scroll.
                let available = (width - scale(21)).max(60);
                let first = if item.id == HOME_TEXT {
                    scale(194)
                } else {
                    scale(142)
                };
                let rest = (available - first).max(40);
                send_native(item.handle, LVM_SETCOLUMNWIDTH, 0, first as isize);
                send_native(
                    item.handle,
                    LVM_SETCOLUMNWIDTH,
                    1,
                    if item.id == HOME_TEXT { rest } else { rest / 2 } as isize,
                );
                if item.id == DIFF {
                    send_native(
                        item.handle,
                        LVM_SETCOLUMNWIDTH,
                        2,
                        (rest - rest / 2) as isize,
                    );
                }
            }
        }
        unsafe {
            RedrawWindow(
                self.hwnd,
                null(),
                null_mut(),
                RDW_INVALIDATE | RDW_ERASE | RDW_ALLCHILDREN,
            );
        }
    }
    fn show_page(&mut self, page: Page) {
        self.page = page;
        if page != Page::Review {
            NAV_SELECTION.with(|s| s.set(page));
        }
        for item in &self.widgets {
            unsafe {
                ShowWindow(
                    item.handle,
                    if item.page.is_none_or(|x| x == page) {
                        SW_SHOW
                    } else {
                        SW_HIDE
                    },
                );
            }
            if (NAV..NAV_END).contains(&item.id) {
                unsafe {
                    InvalidateRect(item.handle, null(), 1);
                }
            }
        }
        set(self.h(HEADING), page.name());
        set(self.h(INTRO), page.caption());
        if page == Page::Intel {
            self.render_intel();
        }
        self.controls();
    }
    fn set_notice(&self, value: &str) {
        set(self.h(NOTICE), &crlf(value));
    }
    fn present_notice_with(&self, notice: Notice, show: impl FnOnce(HWND, &str, &str, u32)) {
        if let Some((title, icon)) = notice.dialog() {
            self.set_notice("Siap.");
            show(self.hwnd, title, notice.text(), icon);
        } else {
            self.set_notice(notice.text());
        }
    }
    fn present_notice(&self, notice: Notice) {
        self.present_notice_with(notice, |hwnd, title, message, icon| {
            popup_titled(
                hwnd,
                &format!("{title} — WeNet Toolkit"),
                &crlf(message),
                icon,
            );
        });
    }
    fn show_error(&self, error: impl Into<String>) {
        self.present_notice(Notice::Error(error.into()));
    }
    fn controls(&self) {
        let busy = self.is_busy();
        let current = self.dashboard.as_ref().and_then(|s| s.current.as_ref());
        let normal = self.page != Page::Review;
        let exists = current.is_some();
        let supported = current.is_some_and(|a| a.adapter.physical_ethernet);
        let has_config = current
            .and_then(|a| a.config.as_ref().ok())
            .is_some_and(|c| c.addresses.len() <= 1 && c.dns.as_ref().is_none_or(|d| d.len() <= 2));
        for id in [
            ACTIVE,
            REFRESH,
            ADMIN,
            DRIVER,
            IP_MODE,
            DNS_MODE,
            IP,
            MASK,
            GATEWAY,
            DNS1,
            DNS2,
            IP_APPLY,
            IP_UNDO,
            MAC_EDIT,
            MAC_APPLY,
            MAC_RESET,
            MAC_CONNECTIONS,
            BACKUP_WITH_MAC,
            BACKUP_SAVE,
            RESTORE_SCOPE,
            RESTORE_WITH_MAC,
            RESTORE_OPEN,
            RECOVER_OPEN,
            CALC_IP,
            CALC_MASK,
            CALC,
            PING,
            REDACT,
            EXPORT,
            CONFIRM,
            CANCEL,
            REVIEW_DETAILS,
            INTEL_MODE,
            INTEL_FILTER,
            INTEL_SEARCH,
            INTEL_RESET_FILTER,
            INTEL_REFRESH,
            INTEL_HOST,
            INTEL_ROUTER,
            INTEL_PROBE,
            INTEL_IMPORT,
            INTEL_DETAILS,
            INTEL_REDACT,
            INTEL_EXPORT,
            INTEL_FLOW,
            INTEL_STOP,
            INTEL_RECORD,
            INTEL_HISTORY,
            INTEL_MORE,
            INTEL_IP_JOURNEY,
            INTEL_BACK,
        ] {
            let allow = match id {
                CANCEL | CONFIRM => !normal,
                REVIEW_DETAILS => !normal && !self.review_rows.is_empty(),
                REFRESH | REDACT | CALC_IP | CALC_MASK | CALC | MAC_CONNECTIONS => normal,
                INTEL_FLOW => normal && self.intel.collector.is_none(),
                INTEL_STOP => normal && self.intel.collector.is_some(),
                INTEL_RECORD | INTEL_IMPORT if selection(self.h(INTEL_MODE)) == STORAGE_MODE => {
                    normal && self.intel.recovery_view.is_none()
                }
                INTEL_PROBE if selection(self.h(INTEL_MODE)) == STORAGE_MODE => {
                    normal && self.intel.recovery_view.is_none() && self.intel.collector.is_none()
                }
                INTEL_RECORD if selection(self.h(INTEL_MODE)) == ALERT_MODE => {
                    normal
                        && self.intel.recovery_view.is_none()
                        && !self.intel.alert_rows.is_empty()
                }
                INTEL_RECORD
                    if matches!(selection(self.h(INTEL_MODE)), TREND_MODE | LEASE_MODE) =>
                {
                    normal && self.intel.recovery_view.is_none()
                }
                INTEL_RECORD | INTEL_HISTORY if selection(self.h(INTEL_MODE)) == SYSLOG_MODE => false,
                INTEL_RECORD
                    if matches!(selection(self.h(INTEL_MODE)), DHCP6_MODE | DHCP6_HISTORY_MODE) =>
                {
                    normal && self.intel.recovery_view.is_none()
                }
                INTEL_RECORD | INTEL_HISTORY if selection(self.h(INTEL_MODE)) == NOTES_MODE => {
                    normal && self.intel.recovery_view.is_none()
                }
                INTEL_RECORD | INTEL_HISTORY => normal,
                INTEL_EXPORT => {
                    normal
                        && (matches!(selection(self.h(INTEL_MODE)), 0 | STORAGE_MODE | NOTES_MODE)
                            || selection(self.h(INTEL_MODE)) == ARCHIVE_MODE
                                && self.intel.archive_query.is_some())
                }
                INTEL_IP_JOURNEY => {
                    normal
                        && match selection(self.h(INTEL_MODE)) {
                            0 | 1 => self.intel.visible_ips.iter().any(Option::is_some),
                            DASHBOARD_MODE => !self.intel.dashboard_targets.is_empty(),
                            TOPOLOGY_MODE => !self.intel.visual_edges.is_empty(),
                            TREND_MODE => !self.intel.visual_series.is_empty(),
                            NOTES_MODE => !self.intel.visible_notes.is_empty(),
                            DEVICE_MODE => self
                                .intel
                                .device
                                .as_ref()
                                .is_some_and(|(v, _)| !v.scopes.is_empty()),
                            _ => false,
                        }
                }
                INTEL_BACK => normal,
                INTEL_MORE => {
                    normal
                        && selection(self.h(INTEL_MODE)) == ARCHIVE_MODE
                        && self
                            .intel
                            .archived
                            .as_ref()
                            .is_some_and(|p| p.next.is_some())
                }
                INTEL_DETAILS => normal && !self.intel.details.is_empty(),
                INTEL_MODE | INTEL_FILTER | INTEL_SEARCH | INTEL_RESET_FILTER | INTEL_REFRESH
                | INTEL_HOST | INTEL_ROUTER | INTEL_PROBE | INTEL_IMPORT | INTEL_REDACT => normal,
                ADMIN => normal && !w::elevated(),
                IP | MASK | GATEWAY => normal && exists && selection(self.h(IP_MODE)) == 0,
                DNS1 | DNS2 => normal && exists && selection(self.h(DNS_MODE)) == 1,
                IP_APPLY => normal && has_config,
                MAC_APPLY | MAC_EDIT => normal && supported,
                RESTORE_WITH_MAC => {
                    normal && supported && self.restore_scope() == RestoreScope::Network
                }
                RESTORE_OPEN => {
                    normal && exists && (supported || self.restore_scope() != RestoreScope::MacOnly)
                }
                MAC_RESET => {
                    normal
                        && supported
                        && current.is_some_and(|a| a.adapter.permanent_mac.is_some())
                }
                RECOVER_OPEN => normal && current.is_some_and(|a| a.recovery),
                PING => normal && current.is_some_and(|a| !a.adapter.gateways.is_empty()),
                _ => normal && exists,
            };
            unsafe {
                EnableWindow(self.h(id), i32::from(allow && !busy));
            }
        }
        for i in 0..(NAV_END - NAV) {
            unsafe {
                EnableWindow(self.h(NAV + i), i32::from(!busy && normal));
            }
        }
    }
    fn populate_fields(&self) {
        let current = self.dashboard.as_ref().and_then(|s| s.current.as_ref());
        let config = current.and_then(|a| a.config.as_ref().ok());
        let a = current.map(|a| &a.adapter);
        select(
            self.h(IP_MODE),
            usize::from(config.map_or_else(|| a.is_some_and(|a| a.dhcp), |c| c.dhcp)),
        );
        select(
            self.h(DNS_MODE),
            usize::from(config.is_some_and(|c| c.dns.is_some())),
        );
        let address = config
            .and_then(|c| c.addresses.first())
            .or_else(|| a.and_then(|a| a.addresses.first()));
        set(
            self.h(IP),
            &address.map(|x| x.ip.to_string()).unwrap_or_default(),
        );
        set(
            self.h(MASK),
            &address.map(|x| x.prefix.to_string()).unwrap_or_default(),
        );
        set(
            self.h(GATEWAY),
            &a.and_then(|a| a.gateways.first())
                .map(ToString::to_string)
                .unwrap_or_default(),
        );
        let dns = config.and_then(|c| c.dns.as_deref()).unwrap_or_default();
        for (i, id) in [DNS1, DNS2].into_iter().enumerate() {
            set(
                self.h(id),
                &dns.get(i).map(ToString::to_string).unwrap_or_default(),
            );
        }
        set(
            self.h(MAC_EDIT),
            &a.and_then(|a| a.active_mac)
                .map(|m| m.to_string())
                .unwrap_or_default(),
        );
        let message = match current.map(|c| &c.config) {
            Some(Ok(c)) if c.addresses.len() > 1 || c.dns.as_ref().is_some_and(|v| v.len() > 2) => {
                "Gunakan Backup dan Restore untuk profil dengan beberapa alamat atau DNS.".into()
            }
            Some(Ok(_)) => "Pengaturan lama disimpan sebelum perubahan diterapkan.".into(),
            Some(Err(e)) => format!("Konfigurasi tidak bisa dicadangkan: {e}"),
            None => "Pilih adaptor yang tersedia terlebih dahulu.".into(),
        };
        set(self.h(IP_NOTE), &message);
        self.controls();
    }
    fn render(&mut self, dashboard: Dashboard) {
        let h = self.h(ACTIVE);
        send_native(h, CB_RESETCONTENT, 0, 0);
        let mut index = 0;
        for (i, a) in dashboard.adapters.iter().enumerate() {
            let status = a.link_label();
            send_native(
                h,
                CB_ADDSTRING,
                0,
                w::wide(&format!("{}  /  {status}", a.name)).as_ptr() as isize,
            );
            if dashboard
                .current
                .as_ref()
                .is_some_and(|c| c.adapter.id == a.id)
            {
                index = i;
            }
        }
        if dashboard.adapters.is_empty() {
            send_native(
                h,
                CB_ADDSTRING,
                0,
                w::wide("Tidak ada adaptor").as_ptr() as isize,
            );
        }
        select(h, index);
        if let Some(ref c) = dashboard.current {
            let a = &c.adapter;
            let network = a.link_label();
            let mode = if a.dhcp { "DHCP" } else { "IP statis" };
            let role = if w::elevated() {
                "Administrator"
            } else {
                "Mode baca"
            };
            set(
                self.h(LINK_STATE),
                &format!(
                    "{network}   ·   Antarmuka {}   ·   {mode}   ·   {role}",
                    a.admin.label().to_lowercase()
                ),
            );
            self.table_rows(
                HOME_TEXT,
                &[
                    vec!["Adaptor".into(), a.name.clone()],
                    vec!["Perangkat".into(), a.description.clone()],
                    vec!["Status antarmuka".into(), a.admin.label().into()],
                    vec!["Status link".into(), a.link_label().into()],
                    vec![
                        "Alamat IPv4".into(),
                        join(a.addresses.iter().map(|v| format!("{}/{}", v.ip, v.prefix))),
                    ],
                    vec!["Gateway".into(), join(&a.gateways)],
                    vec!["DNS aktif".into(), join(&a.dns_active)],
                    vec!["MAC aktif".into(), label(a.active_mac)],
                    vec!["MAC bawaan".into(), label(a.permanent_mac)],
                    vec!["ID adaptor".into(), a.id.clone()],
                ],
                2,
            );
            set(
                self.h(MAC_INFO),
                &crlf(&format!(
                    "MAC aktif  {}\nMAC permanen  {}\n{} · Antarmuka {}\n{}",
                    label(a.active_mac),
                    label(a.permanent_mac),
                    a.link_label(),
                    a.admin.label().to_lowercase(),
                    if a.physical_ethernet {
                        "Ethernet fisik · kemampuan pengubahan bergantung pada driver."
                    } else {
                        "Pengubahan tidak tersedia pada jenis adaptor ini."
                    }
                )),
            );
            set(
                self.h(RECOVER_NOTE),
                if c.pending {
                    "Transaksi tertunda. Tinjau pemulihan sebelum melakukan perubahan baru."
                } else if c.recovery {
                    "Pengaturan sebelum perubahan terakhir tersedia."
                } else {
                    "Belum ada snapshot untuk adaptor yang dipilih."
                },
            );
        } else {
            set(
                self.h(LINK_STATE),
                "Tidak ada adaptor yang dapat ditampilkan",
            );
            self.table_rows(
                HOME_TEXT,
                &[vec![
                    "Adaptor".into(),
                    "Tidak ditemukan. Klik Muat ulang.".into(),
                ]],
                2,
            );
            set(self.h(MAC_INFO), "Tidak ada adaptor terpilih.");
            set(self.h(RECOVER_NOTE), "Tidak ada adaptor terpilih.");
        }
        self.dashboard = Some(dashboard);
        self.populate_fields();
    }
    fn reply(&mut self, r: Reply) {
        let mut warnings = vec![];
        if let Some(s) = r.state {
            self.render(s);
        }
        if let Some(output) = r.output {
            set(self.h(OUTPUT), &crlf(&output));
        }
        if let Some(p) = r.preview {
            warnings = p.warnings;
            let rows = p
                .rows
                .iter()
                .map(|row| row.iter().map(|v| v.replace('\n', " / ")).collect())
                .collect::<Vec<Vec<String>>>();
            self.table_rows(DIFF, &rows, 3);
            self.review_rows = p.rows;
            set(
                self.h(REVIEW_TARGET),
                &format!("{}  ·  {}", p.title, p.adapter),
            );
            set(self.h(REVIEW_NOTE), &crlf(&p.note));
            set(self.h(CONFIRM), &p.button);
            self.review = Some((p.token, self.page));
            self.show_page(Page::Review);
            unsafe {
                SetFocus(self.h(CANCEL));
            }
        }
        self.controls();
        if let Some(notice) = r.notice {
            self.present_notice(notice);
        }
        if !warnings.is_empty() {
            self.present_notice(Notice::Warning(warnings.join("\n\n")));
        }
    }
    fn is_busy(&self) -> bool {
        self.model.work.is_some() || self.inventory.is_some() || self.intel.work.is_some()
    }
    fn refresh(&mut self, selected: Option<String>) {
        if self.is_busy() {
            return;
        }
        let (tx, rx) = mpsc::channel();
        match thread::Builder::new()
            .name("wfs-inventory".into())
            .spawn(move || {
                let _ = tx.send(App::inventory(selected.as_deref()));
            }) {
            Ok(_) => {
                self.inventory = Some(rx);
                self.set_notice("Membaca adaptor Windows…");
                self.controls();
            }
            Err(e) => self.show_error(format!("Tidak dapat memulai inventaris: {e}")),
        }
    }
    fn finish_refresh(&mut self) {
        let Some(r) = self.inventory.as_ref() else {
            return;
        };
        let result = match r.try_recv() {
            Ok(v) => v,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                Err("Inventaris terhenti. Klik Muat ulang untuk mencoba lagi.".into())
            }
        };
        self.inventory = None;
        match result {
            Ok((selected, dashboard)) => {
                self.model.selected = selected;
                self.render(dashboard);
                self.set_notice("Inventaris adaptor diperbarui.");
            }
            Err(e) => self.show_error(format!("Inventaris gagal: {e}")),
        }
        self.controls();
    }
    fn dispatch(&mut self, request: Request) {
        match self.model.request(request) {
            Ok(Some(r)) => self.reply(r),
            Ok(None) => {
                self.set_notice("Operasi sedang berjalan. Tunggu sampai hasil diterima.");
                self.controls();
            }
            Err(e) => self.show_error(e),
        }
    }
    fn ip_request(&self) -> Result<Ipv4> {
        let dhcp = selection(self.h(IP_MODE)) == 1;
        let dns = if selection(self.h(DNS_MODE)) == 1 {
            let first =
                optional_ipv4(&get(self.h(DNS1)))?.ok_or("Isi DNS 1 atau pilih DNS otomatis")?;
            let mut values = vec![first];
            if let Some(second) = optional_ipv4(&get(self.h(DNS2)))? {
                values.push(second);
            }
            Some(values)
        } else {
            None
        };
        let (addresses, gateway) = if dhcp {
            (vec![], None)
        } else {
            let ip = optional_ipv4(&get(self.h(IP)))?.ok_or("Isi alamat IPv4")?;
            let prefix = parse_mask(get(self.h(MASK)).trim())?;
            (
                vec![Address { ip, prefix }],
                optional_ipv4(&get(self.h(GATEWAY)))?,
            )
        };
        let result = Ipv4 {
            dhcp,
            addresses,
            gateway,
            dns,
        };
        result.validate()?;
        Ok(result)
    }
    fn restore_scope(&self) -> RestoreScope {
        match selection(self.h(RESTORE_SCOPE)) {
            1 => RestoreScope::DnsOnly,
            2 => RestoreScope::MacOnly,
            _ => RestoreScope::Network,
        }
    }
    fn action(&mut self, id: i32, notification: u16) -> Result<()> {
        if self.is_busy() {
            return Ok(());
        }
        if (NAV..NAV_END).contains(&id) {
            if self.page != Page::Review {
                self.show_page(PAGES[(id - NAV) as usize]);
                if self.page == Page::Intel && self.intel.local.is_none() {
                    self.intel_action(INTEL_REFRESH)?;
                }
            }
            return Ok(());
        }
        if self.page == Page::Review && !matches!(id, CONFIRM | CANCEL | REVIEW_DETAILS) {
            return Ok(());
        }
        if matches!(
            id,
            INTEL_MODE
                | INTEL_SEARCH
                | INTEL_RESET_FILTER
                | INTEL_REFRESH
                | INTEL_ROUTER
                | INTEL_PROBE
                | INTEL_IMPORT
                | INTEL_DETAILS
                | INTEL_EXPORT
                | INTEL_FLOW
                | INTEL_STOP
                | INTEL_RECORD
                | INTEL_HISTORY
                | INTEL_MORE
                | INTEL_IP_JOURNEY
                | INTEL_BACK
        ) {
            self.intel_action(id)?;
            self.controls();
            return Ok(());
        }
        let command = match id {
            ACTIVE if notification == CBN_SELCHANGE as u16 => {
                let i = selection(self.h(ACTIVE));
                let Some(a) = self.dashboard.as_ref().and_then(|s| s.adapters.get(i)) else {
                    return Ok(());
                };
                self.refresh(Some(a.id.clone()));
                return Ok(());
            }
            ACTIVE => return Ok(()),
            REFRESH => {
                self.refresh(self.model.selected.clone());
                return Ok(());
            }
            ADMIN => {
                if w::elevated() {
                    return Ok(());
                }
                if self.intel.collector.is_some()
                    || !self.intel.schedule.jobs.is_empty()
                    || self.intel.poll_rx.is_some()
                {
                    return Err("Hentikan collector Flow dan polling MikroTik sebelum membuka Mode Admin agar arsip tidak terputus.".into());
                }
                // Only close the existing window after UAC has succeeded.
                // The child waits for this process to exit before showing the GUI.
                w::elevate_window()?;
                // No background task can be active here; quit the message loop directly
                // instead of a WM_CLOSE that may be suppressed by GWLP_USERDATA.
                if unsafe { PostMessageW(self.hwnd, ADMIN_HANDOFF, 0, 0) } == 0 {
                    return Err(
                        "Gagal menutup jendela lama; periksa aplikasi yang sudah berjalan.".into(),
                    );
                }
                return Ok(());
            }
            DRIVER => Request::Driver,
            RESTORE_SCOPE => {
                if self.restore_scope() != RestoreScope::Network {
                    send_native(self.h(RESTORE_WITH_MAC), BM_SETCHECK, 0, 0);
                }
                self.controls();
                return Ok(());
            }
            IP_MODE | DNS_MODE => {
                self.controls();
                return Ok(());
            }
            IP_UNDO => {
                self.populate_fields();
                return Ok(());
            }
            IP_APPLY => Request::PreviewIp(self.ip_request()?),
            MAC_APPLY => Request::PreviewMac {
                value: get(self.h(MAC_EDIT)).trim().into(),
            },
            MAC_RESET => Request::PreviewFactory,
            MAC_CONNECTIONS => Request::NetworkConnections,
            BACKUP_SAVE => Request::Backup {
                include_mac: checked(self.h(BACKUP_WITH_MAC)),
            },
            RESTORE_OPEN => Request::Import {
                scope: self.restore_scope(),
                include_mac: self
                    .dashboard
                    .as_ref()
                    .and_then(|d| d.current.as_ref())
                    .is_some_and(|a| a.adapter.physical_ethernet)
                    && checked(self.h(RESTORE_WITH_MAC)),
            },
            RECOVER_OPEN => Request::PreviewRecover,
            REVIEW_DETAILS => {
                let row = send_native(
                    self.h(DIFF),
                    LVM_GETNEXTITEM,
                    usize::MAX,
                    LVNI_SELECTED as isize,
                );
                if let Some([field, before, target]) = self.review_rows.get(row as usize) {
                    popup(
                        self.hwnd,
                        &format!("{field}\n\nSebelum\n{before}\n\nTarget\n{target}"),
                        MB_OK | MB_ICONINFORMATION,
                    );
                } else {
                    self.present_notice(Notice::Information(
                        "Pilih satu baris pada tabel, lalu klik Lihat nilai lengkap.".into(),
                    ));
                    unsafe {
                        SetFocus(self.h(DIFF));
                    }
                }
                return Ok(());
            }
            CONFIRM => {
                let Some((token, prior)) = self.review.take() else {
                    return Ok(());
                };
                self.show_page(prior);
                Request::Confirm { token }
            }
            CANCEL => {
                if let Some((_, prior)) = self.review.take() {
                    self.model.preview = None;
                    self.show_page(prior);
                    self.set_notice("Dibatalkan. Tidak ada pengaturan yang diubah.");
                }
                return Ok(());
            }
            CALC => Request::Subnet {
                ip: optional_ipv4(&get(self.h(CALC_IP)))?
                    .ok_or("Isi alamat IPv4 untuk menghitung subnet")?,
                prefix: parse_mask(get(self.h(CALC_MASK)).trim())?,
            },
            PING => Request::Ping,
            EXPORT => Request::Export {
                redact: checked(self.h(REDACT)),
            },
            _ => return Ok(()),
        };
        self.dispatch(command);
        Ok(())
    }
}

fn draw_button(item: &DRAWITEMSTRUCT) {
    let id = item.CtlID as i32;
    let disabled = item.itemState & ODS_DISABLED != 0;
    let selected = item.itemState & ODS_SELECTED != 0;
    let nav = (NAV..NAV_END).contains(&id);
    let active = nav && NAV_SELECTION.with(|s| s.get() == PAGES[(id - NAV) as usize]);
    let primary = matches!(id, IP_APPLY | MAC_APPLY | BACKUP_SAVE | CONFIRM | CALC);
    let body = if nav {
        if active {
            selected_nav()
        } else if selected {
            line()
        } else {
            rail()
        }
    } else if disabled {
        rail()
    } else if primary {
        if selected {
            pressed_primary()
        } else {
            accent()
        }
    } else if selected {
        selected_nav()
    } else {
        bg()
    };
    let fg = if disabled {
        muted()
    } else if primary {
        bg()
    } else if active {
        accent()
    } else {
        ink()
    };
    if nav {
        fill(item.hDC, &item.rcItem, rail());
    }
    let r = item.rcItem;
    let h = r.bottom - r.top;
    let radius = (h / 3).max(3);
    let border = if nav || primary || disabled {
        body
    } else {
        button_border()
    };
    unsafe {
        let brush = CreateSolidBrush(body);
        let pen = CreatePen(PS_SOLID, 1, border);
        if !brush.is_null() && !pen.is_null() {
            let before_brush = SelectObject(item.hDC, brush);
            let before_pen = SelectObject(item.hDC, pen);
            RoundRect(item.hDC, r.left, r.top, r.right, r.bottom, radius, radius);
            SelectObject(item.hDC, before_pen);
            SelectObject(item.hDC, before_brush);
        } else {
            fill(item.hDC, &r, body);
        }
        if !pen.is_null() {
            DeleteObject(pen);
        }
        if !brush.is_null() {
            DeleteObject(brush);
        }
    }
    if active && !disabled {
        let indicator = RECT {
            left: r.left + 3,
            top: r.top + h / 5,
            right: r.left + 6,
            bottom: r.bottom - h / 5,
        };
        fill(item.hDC, &indicator, accent());
    }
    let s = w::wide(&get(item.hwndItem));
    let mut r = item.rcItem;
    if nav {
        r.left += 12;
    }
    unsafe {
        SetBkMode(item.hDC, TRANSPARENT as i32);
        SetTextColor(item.hDC, fg);
        let font = send_native(item.hwndItem, WM_GETFONT, 0, 0) as HFONT;
        let old = if font.is_null() {
            null_mut()
        } else {
            SelectObject(item.hDC, font)
        };
        DrawTextW(
            item.hDC,
            s.as_ptr(),
            -1,
            &mut r,
            DT_VCENTER
                | DT_SINGLELINE
                | DT_END_ELLIPSIS
                | DT_NOPREFIX
                | if nav { DT_LEFT } else { DT_CENTER },
        );
        if !old.is_null() {
            SelectObject(item.hDC, old);
        }
        if item.itemState & ODS_FOCUS != 0 {
            let mut border = item.rcItem;
            border.left += 3;
            border.right -= 3;
            border.top += 3;
            border.bottom -= 3;
            DrawFocusRect(item.hDC, &border);
        }
    }
}
fn paint_background(h: HWND, dc: HDC) {
    let mut client = RECT::default();
    unsafe {
        GetClientRect(h, &mut client);
    }
    let dpi = client_scale(client.right, client.bottom, unsafe { GetDpiForWindow(h) }
        as i32);
    let split = wfs_network_toolkit::ui_layout::NAV_WIDTH * dpi / 96;
    fill(dc, &client, bg());
    fill(
        dc,
        &RECT {
            right: split,
            ..client
        },
        rail(),
    );
    fill(
        dc,
        &RECT {
            left: split,
            right: split + (dpi / 96).max(1),
            ..client
        },
        line(),
    );
    let x = 228 * dpi / 96;
    let right = client.right - 28 * dpi / 96;
    let y = 178 * dpi / 96;
    fill(
        dc,
        &RECT {
            left: x,
            top: y,
            right,
            bottom: y + (dpi / 96).max(1),
        },
        line(),
    );
}
unsafe extern "system" fn wnd(h: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    match msg {
        WM_COMMAND => {
            if lparam != 0 {
                let id = (wparam & 0xffff) as i32;
                let note = (wparam >> 16) as u16;
                let supported = (NAV..NAV_END).contains(&id)
                    || matches!(
                        id,
                        REFRESH
                            | ADMIN
                            | DRIVER
                            | IP_APPLY
                            | IP_UNDO
                            | MAC_APPLY
                            | MAC_RESET
                            | MAC_CONNECTIONS
                            | BACKUP_SAVE
                            | RESTORE_OPEN
                            | RECOVER_OPEN
                            | REVIEW_DETAILS
                            | CONFIRM
                            | CANCEL
                            | CALC
                            | PING
                            | EXPORT
                            | INTEL_SEARCH
                            | INTEL_RESET_FILTER
                            | INTEL_REFRESH
                            | INTEL_ROUTER
                            | INTEL_PROBE
                            | INTEL_IMPORT
                            | INTEL_DETAILS
                            | INTEL_EXPORT
                            | INTEL_FLOW
                            | INTEL_STOP
                            | INTEL_RECORD
                            | INTEL_HISTORY
                            | INTEL_MORE
                            | INTEL_IP_JOURNEY
                            | INTEL_BACK
                    );
                if supported && note == BN_CLICKED as u16
                    || matches!(id, ACTIVE | IP_MODE | DNS_MODE | RESTORE_SCOPE | INTEL_MODE)
                        && note == CBN_SELCHANGE as u16
                {
                    unsafe {
                        PostMessageW(h, DRAW_ACTION, wparam, 0);
                    }
                }
            }
            0
        }
        WM_SIZE => {
            unsafe {
                PostMessageW(h, SYNC_LAYOUT, 0, 0);
            }
            0
        }
        WM_DPICHANGED => {
            let r = unsafe { &*(lparam as *const RECT) };
            unsafe {
                SetWindowPos(
                    h,
                    null_mut(),
                    r.left,
                    r.top,
                    r.right - r.left,
                    r.bottom - r.top,
                    SWP_NOZORDER | SWP_NOACTIVATE,
                );
                PostMessageW(h, SYNC_LAYOUT, 0, 0);
            }
            0
        }
        WM_GETMINMAXINFO => {
            let dpi = unsafe { GetDpiForWindow(h) }.max(96) as i32;
            let info = unsafe { &mut *(lparam as *mut MINMAXINFO) };
            info.ptMinTrackSize.x = (805 * dpi / 96)
                .min(unsafe { GetSystemMetrics(SM_CXSCREEN) })
                .max(620);
            info.ptMinTrackSize.y = (560 * dpi / 96)
                .min(unsafe { GetSystemMetrics(SM_CYSCREEN) })
                .max(440);
            0
        }
        WM_DRAWITEM if lparam != 0 => {
            draw_button(unsafe { &*(lparam as *const DRAWITEMSTRUCT) });
            1
        }
        WM_CTLCOLORSTATIC | WM_CTLCOLOREDIT | WM_CTLCOLORLISTBOX | WM_CTLCOLORBTN => {
            let dc = wparam as HDC;
            let id = unsafe { GetDlgCtrlID(lparam as HWND) };
            let tint = if matches!(
                id,
                BRAND_ICON | BRAND | BRAND_TAGLINE | COPYRIGHT | FOOTER | NOTICE | REVIEW_NOTE
            ) {
                rail()
            } else {
                bg()
            };
            let fg = if matches!(
                id,
                INTRO
                    | BRAND_TAGLINE
                    | COPYRIGHT
                    | FOOTER
                    | IP_NOTE
                    | RECOVER_NOTE
                    | NOTICE
                    | REVIEW_NOTE
            ) {
                muted()
            } else if id == LINK_STATE {
                accent()
            } else {
                ink()
            };
            unsafe {
                SetTextColor(dc, fg);
                SetBkColor(dc, tint);
                SetDCBrushColor(dc, tint);
                GetStockObject(DC_BRUSH) as LRESULT
            }
        }
        WM_ERASEBKGND => {
            paint_background(h, wparam as HDC);
            1
        }
        WM_PAINT => {
            let mut p = PAINTSTRUCT::default();
            let dc = unsafe { BeginPaint(h, &mut p) };
            if !dc.is_null() {
                paint_background(h, dc);
            }
            unsafe {
                EndPaint(h, &p);
            }
            0
        }
        WM_CLOSE if unsafe { GetWindowLongPtrW(h, GWLP_USERDATA) } != 0 => 0,
        WM_DESTROY => {
            unsafe {
                PostQuitMessage(0);
            }
            0
        }
        _ => unsafe { DefWindowProcW(h, msg, wparam, lparam) },
    }
}
// CI uses a dedicated log because the GUI executable has no console.
fn smoke_trace(message: &str) {
    use std::io::Write;
    if let Some(path) = std::env::var_os("WENET_SMOKE_LOG")
        && let Ok(mut log) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    {
        let _ = writeln!(log, "{message}");
    }
}
fn show_launch_error(error: &str, smoke: bool) {
    if smoke {
        smoke_trace(&format!("FAIL: {error}"));
    } else {
        popup(null_mut(), error, MB_OK | MB_ICONERROR);
    }
}
fn start_ui(smoke: bool) -> Result<()> {
    unsafe {
        SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    }
    let common = INITCOMMONCONTROLSEX {
        dwSize: size_of::<INITCOMMONCONTROLSEX>() as u32,
        dwICC: ICC_LISTVIEW_CLASSES,
    };
    if unsafe { InitCommonControlsEx(&common) } == 0 {
        return Err("Kontrol tabel Windows tidak dapat dibuka.".into());
    }
    let class = w::wide("WfsNetworkToolkit");
    let instance = unsafe { GetModuleHandleW(null()) };
    let icon = unsafe { LoadIconW(instance, RESOURCE_ICON as *const u16) };
    if icon.is_null() {
        return Err("Resource ikon aplikasi tidak dapat dimuat.".into());
    }
    let wc = WNDCLASSW {
        hInstance: instance,
        lpszClassName: class.as_ptr(),
        lpfnWndProc: Some(wnd),
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        hIcon: icon,
        ..Default::default()
    };
    if unsafe { RegisterClassW(&wc) } == 0 {
        return Err(format!(
            "Jendela Windows tidak dapat didaftarkan: {}",
            std::io::Error::last_os_error()
        ));
    }
    let dpi = unsafe { GetDpiForSystem() }.max(96) as i32;
    let logical = |x: i32| x * dpi / 96;
    let mut work = RECT::default();
    unsafe {
        SystemParametersInfoW(SPI_GETWORKAREA, 0, (&mut work as *mut RECT).cast(), 0);
    }
    let (available_w, available_h) = if work.right > work.left && work.bottom > work.top {
        (work.right - work.left, work.bottom - work.top)
    } else {
        (unsafe { GetSystemMetrics(SM_CXSCREEN) }, unsafe {
            GetSystemMetrics(SM_CYSCREEN)
        })
    };
    let width = logical(1060).min(available_w).max(500);
    let height = logical(740).min(available_h).max(450);
    let title = w::wide("WeNet Toolkit");
    let h = unsafe {
        CreateWindowExW(
            WS_EX_CONTROLPARENT,
            class.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            width,
            height,
            null_mut(),
            null_mut(),
            instance,
            null(),
        )
    };
    if h.is_null() {
        return Err(format!(
            "Jendela Windows tidak dapat dibuka: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut ui = match Native::new(h, icon) {
        Ok(ui) => ui,
        Err(error) => {
            unsafe {
                DestroyWindow(h);
            }
            return Err(error);
        }
    };
    unsafe {
        ShowWindow(h, if smoke { SW_SHOWNOACTIVATE } else { SW_SHOW });
        UpdateWindow(h);
    }
    if smoke {
        let status = smoke_ui(&mut ui);
        unsafe {
            DestroyWindow(h);
        }
        return status;
    }
    if unsafe { SetTimer(h, PULSE, 110, None) } == 0 {
        unsafe {
            DestroyWindow(h);
        }
        return Err("Timer aplikasi tidak dapat dibuat.".into());
    }
    if unsafe { SetTimer(h, FIRST, 75, None) } == 0 {
        unsafe {
            PostMessageW(h, DRAW_ACTION, REFRESH as usize, 0);
        }
    }
    let mut m = MSG::default();
    loop {
        let result = unsafe { GetMessageW(&mut m, null_mut(), 0, 0) };
        if result == -1 {
            return Err(format!(
                "Loop pesan Windows: {}",
                std::io::Error::last_os_error()
            ));
        }
        if result == 0 {
            break;
        }
        match (m.hwnd == h, m.message, m.wParam) {
            (true, ADMIN_HANDOFF, _) => {
                unsafe {
                    DestroyWindow(h);
                }
                break;
            }
            (true, SYNC_LAYOUT, _) => ui.layout(),
            (true, DRAW_ACTION, p) => {
                if let Err(e) = ui.action((p & 0xffff) as i32, (p >> 16) as u16) {
                    ui.show_error(e);
                }
                unsafe {
                    SetWindowLongPtrW(
                        h,
                        GWLP_USERDATA,
                        isize::from(ui.model.work.is_some() || ui.intel.work.is_some()),
                    );
                }
            }
            (true, WM_TIMER, FIRST) => {
                unsafe {
                    KillTimer(h, FIRST);
                }
                ui.refresh(ui.model.selected.clone());
            }
            (true, WM_TIMER, PULSE) => {
                ui.finish_refresh();
                ui.finish_intel();
                ui.poll_router_step();
                if let Some(r) = ui.model.finish() {
                    ui.reply(r);
                }
                unsafe {
                    SetWindowLongPtrW(
                        h,
                        GWLP_USERDATA,
                        isize::from(ui.model.work.is_some() || ui.intel.work.is_some()),
                    );
                }
            }
            (_, WM_KEYDOWN, p) if p == 0x1b && ui.page == Page::Review => {
                if let Err(e) = ui.action(CANCEL, 0) {
                    ui.show_error(e);
                }
            }
            _ => {
                if unsafe { IsDialogMessageW(h, &m) } == 0 {
                    unsafe {
                        TranslateMessage(&m);
                        DispatchMessageW(&m);
                    }
                }
            }
        }
    }
    Ok(())
}
fn smoke_ui(ui: &mut Native) -> Result<()> {
    smoke_trace("Initial window and branding");
    if get(ui.h(HEADING)) != "Ringkasan"
        || send_native(ui.h(HOME_TEXT), LVM_GETITEMCOUNT, 0, 0) != 1
    {
        return Err("Tampilan awal tidak berisi kontrol Windows".into());
    }
    if get(ui.h(BRAND)) != "WeNet Toolkit"
        || get(ui.h(BRAND_TAGLINE)) != "Network intelligence"
        || get(ui.h(COPYRIGHT)) != "by WFS Project"
        || ui.restore_scope() != RestoreScope::Network
    {
        return Err("Header, footer, atau pilihan restore awal tidak sesuai".into());
    }
    smoke_trace("Notifications");
    ui.present_notice_with(Notice::Status("Membaca adaptor…".into()), |_, _, _, _| {
        panic!("Status rutin tidak boleh membuka dialog");
    });
    if get(ui.h(NOTICE)) != "Membaca adaptor…" {
        return Err("Status rutin tidak tampil di bilah bawah.".into());
    }
    for (notice, expected_icon) in [
        (
            Notice::Information("Detail operasi".into()),
            MB_ICONINFORMATION,
        ),
        (Notice::Warning("Peringatan uji".into()), MB_ICONWARNING),
        (Notice::Error("Kesalahan uji".into()), MB_ICONERROR),
    ] {
        let mut called = false;
        ui.present_notice_with(notice, |owner, _, message, icon| {
            called = owner == ui.hwnd && icon == expected_icon && !message.is_empty();
        });
        if !called || get(ui.h(NOTICE)) != "Siap." {
            return Err(
                "Notifikasi penting tidak diteruskan ke dialog, atau bocor ke status.".into(),
            );
        }
    }
    for (i, page) in PAGES.into_iter().enumerate() {
        smoke_trace(&format!("Navigation: {page:?}"));
        if page == Page::Intel {
            // Smoke test is strictly read-only and does not open a network connection.
            ui.intel.local = Some(Box::new(nw::local_snapshot()));
        }
        ui.action(NAV + i as i32, 0)?;
        if get(ui.h(HEADING)) != page.name() {
            return Err(format!("Navigasi gagal: {page:?}"));
        }
        let page_widget = match page {
            Page::Home => HOME_TEXT,
            Page::Ip => IP_MODE,
            Page::Mac => MAC_INFO,
            Page::Backup => BACKUP_SAVE,
            Page::Diag => OUTPUT,
            Page::Intel => INTEL_TABLE,
            Page::Review => unreachable!(),
        };
        if unsafe { IsWindowVisible(ui.h(page_widget)) } == 0 {
            return Err(format!("Kontrol halaman {page:?} tersembunyi"));
        }
        if page == Page::Mac && unsafe { IsWindowVisible(ui.h(MAC_CONNECTIONS)) } == 0 {
            return Err("Pintasan Koneksi Jaringan tidak tampil.".into());
        }
        if page == Page::Backup {
            send_native(ui.h(RESTORE_WITH_MAC), BM_SETCHECK, 1, 0);
            send_native(ui.h(RESTORE_SCOPE), CB_SETCURSEL, 1, 0);
            let param = RESTORE_SCOPE as usize | ((CBN_SELCHANGE as usize) << 16);
            send_native(ui.hwnd, WM_COMMAND, param, ui.h(RESTORE_SCOPE) as isize);
            let mut event = MSG::default();
            if unsafe { PeekMessageW(&mut event, ui.hwnd, DRAW_ACTION, DRAW_ACTION, PM_REMOVE) }
                == 0
                || event.wParam != param
            {
                return Err("Notifikasi pilihan restore tidak diteruskan oleh jendela.".into());
            }
            ui.action((event.wParam & 0xffff) as i32, (event.wParam >> 16) as u16)?;
            if ui.restore_scope() != RestoreScope::DnsOnly || checked(ui.h(RESTORE_WITH_MAC)) {
                return Err("Scope DNS tidak mematikan pilihan MAC".into());
            }
            send_native(ui.h(RESTORE_SCOPE), CB_SETCURSEL, 0, 0);
            ui.action(RESTORE_SCOPE, CBN_SELCHANGE as u16)?;
        }
        unsafe {
            UpdateWindow(ui.hwnd);
        }
    }
    ui.intel_action(INTEL_MODE)?;
    if !get(ui.h(INTEL_STATUS)).contains("Tidak terlihat bukan diblokir") {
        return Err("Halaman analisis tidak menampilkan batas cakupan.".into());
    }
    select(ui.h(INTEL_MODE), ARCHIVE_MODE);
    ui.intel.archived = Some(store::Page {
        rows: vec![],
        next: None,
    });
    ui.render_intel();
    ui.controls();
    if unsafe { IsWindowVisible(ui.h(INTEL_MORE)) } == 0
        || unsafe {
            windows_sys::Win32::UI::Input::KeyboardAndMouse::IsWindowEnabled(ui.h(INTEL_MORE))
        } != 0
        || !get(ui.h(INTEL_STATUS)).contains("Flow tidak ditemukan")
    {
        return Err("Arsip kosong atau kontrol paginasi tidak tampil dengan benar.".into());
    }
    smoke_trace("SQLite fixture and Detail IP");
    let dir = std::env::temp_dir().join(format!(
        "wfs-gui-smoke-{}-{}",
        std::process::id(),
        ni::now()
    ));
    let mut cleanup = false;
    ui.intel.storage_smoke = true;
    let journey = (|| -> Result<()> {
        std::fs::create_dir(&dir).map_err(|e| e.to_string())?;
        cleanup = true;
        let path = dir.join("test.sqlite3");
        let ip = std::net::Ipv4Addr::new(192, 0, 2, 21).into();
        let stamp = ni::now();
        let row = store::ArchiveRow {
            profile: "uji".into(),
            site: "Lab".into(),
            vrf: None,
            direction: flow::Direction::Unknown,
            flow: flow::Flow {
                exporter: "192.0.2.1:40001".parse().unwrap(),
                domain: 1,
                version: 10,
                export_at: stamp,
                received_at: stamp,
                source: ip,
                destination: "203.0.113.9".parse().unwrap(),
                source_port: Some(55000),
                destination_port: Some(443),
                protocol: Some(6),
                ingress: None,
                egress: None,
                octets: None,
                packets: None,
                datagram_hash: [7; 32],
                ordinal: 0,
            },
        };
        let mut db = Archive::writer(&path)?;
        let mut overlapping = row.clone();
        overlapping.vrf = Some("scope-yang-lain".into());
        db.insert(&[row, overlapping])?;
        drop(db);
        ui.intel.archive_override = Some(path);
        select(ui.h(INTEL_MODE), DEVICE_MODE);
        ui.intel.mode = DEVICE_MODE;
        ui.intel.previous_mode = Some((1, "filter pengguna".into()));
        ui.intel_mode_labels(DEVICE_MODE);
        set(
            ui.h(INTEL_FILTER),
            &format!("ip={ip} vrf-unknown=true port=443"),
        );
        let finish = |ui: &mut Native| -> Result<()> {
            let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
            while ui.intel.work.is_some() {
                if std::time::Instant::now() > until {
                    return Err("Worker basis data smoke GUI tidak selesai.".into());
                }
                ui.finish_intel();
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            ui.intel.storage_smoke_error.take().map_or(Ok(()), Err)
        };
        ui.action(INTEL_SEARCH, 0)?;
        finish(ui)?;
        if send_native(ui.h(INTEL_TABLE), LVM_GETITEMCOUNT, 0, 0) != 1
            || get(ui.h(INTEL_IP_JOURNEY)) != "Koneksi"
            || unsafe { IsWindowVisible(ui.h(INTEL_BACK)) } == 0
            || !get(ui.h(INTEL_STATUS)).contains("Observasi WAN bukan tes HTTPS")
        {
            return Err(
                "Detail IP tidak menampilkan scope dan kontrol koneksi dengan benar.".into(),
            );
        }
        let item = LVITEMW {
            state: LVIS_SELECTED,
            stateMask: LVIS_SELECTED,
            ..Default::default()
        };
        send_native(
            ui.h(INTEL_TABLE),
            LVM_SETITEMSTATE,
            0,
            &item as *const _ as isize,
        );
        ui.action(INTEL_IP_JOURNEY, 0)?;
        finish(ui)?;
        if selection(ui.h(INTEL_MODE)) != ARCHIVE_MODE
            || send_native(ui.h(INTEL_TABLE), LVM_GETITEMCOUNT, 0, 0) != 1
            || !ui
                .intel
                .archive_query
                .as_ref()
                .is_some_and(|q| q.without_vrf && q.port == Some(443))
        {
            return Err("Pivot dari Detail IP tidak memelihara cakupan eksak.".into());
        }
        ui.action(INTEL_BACK, 0)?;
        if selection(ui.h(INTEL_MODE)) != DEVICE_MODE {
            return Err("Kembali dari Koneksi tidak membuka Detail IP.".into());
        }
        ui.action(INTEL_BACK, 0)?;
        if selection(ui.h(INTEL_MODE)) != 1 || get(ui.h(INTEL_FILTER)) != "filter pengguna" {
            return Err("Kembali dari Detail IP tidak memulihkan pencarian inventaris.".into());
        }
        select(ui.h(INTEL_MODE), STORAGE_MODE);
        ui.action(INTEL_MODE, CBN_SELCHANGE as u16)?;
        finish(ui)?;
        if get(ui.h(INTEL_EXPORT)) != "Backup SQLite…"
            || get(ui.h(INTEL_ROUTER)) != "Pulihkan salinan…"
            || !ui
                .intel
                .storage
                .as_ref()
                .is_some_and(|s| s.flow_records == 2 && s.source_scopes == 2)
        {
            return Err("Panel penyimpanan tidak menampilkan ukuran atau cakupan fixture.".into());
        }
        smoke_trace("Backup and read-only recovery");
        let current = ui.primary_archive_path()?;
        let source = dir.join("copy.sqlite3");
        let target = dir.join("restored.sqlite3");
        Archive::reader(&current)?.backup_to(&source)?;
        RecoveryPlan::inspect(&source)?.recover(&source, &target)?;
        ui.intel.recovery_view = Some(target);
        ui.load_storage()?;
        finish(ui)?;
        if !get(ui.h(INTEL_STATUS)).contains("baca-saja")
            || unsafe {
                windows_sys::Win32::UI::Input::KeyboardAndMouse::IsWindowEnabled(ui.h(INTEL_PROBE))
            } != 0
        {
            return Err("Salinan arsip tidak ditampilkan sebagai baca-saja.".into());
        }
        ui.action(INTEL_RESET_FILTER, 0)?;
        finish(ui)?;
        if ui.intel.recovery_view.is_some() || ui.archive_path()? != current {
            return Err("Reset tidak kembali ke arsip utama.".into());
        }

        // Alert mode loads asynchronously. Wait for its real worker, using only
        // the temporary database; never inspect or acknowledge a user's alerts.
        smoke_trace("Alert ledger load, acknowledge and filter");
        let mut db = Archive::writer(&current)?;
        let stamp = ni::now() as i64;
        db.save_alerts(&[AlertRecord {
            id: 0,
            session: "smoke-session".into(),
            serial: 1,
            scope: "Lab / VRF biru".into(),
            signal: "Template hilang".into(),
            opened: stamp,
            last_seen: stamp,
            total: 1,
            acknowledged: None,
            recovered: None,
        }])?;
        drop(db);
        select(ui.h(INTEL_MODE), ALERT_MODE);
        ui.action(INTEL_MODE, CBN_SELCHANGE as u16)?;
        finish(ui)?;
        if get(ui.h(INTEL_RECORD)) != "Akui"
            || !get(ui.h(INTEL_STATUS)).contains("tanpa popup")
            || send_native(ui.h(INTEL_TABLE), LVM_GETITEMCOUNT, 0, 0) != 1
            || ui.intel.alert_rows.len() != 1
        {
            return Err("Panel alert gagal memuat fixture.".into());
        }
        send_native(
            ui.h(INTEL_TABLE),
            LVM_SETITEMSTATE,
            0,
            &item as *const _ as isize,
        );
        ui.action(INTEL_RECORD, 0)?;
        finish(ui)?;
        let saved = Archive::reader(&current)?.alert_page("state=ack")?;
        if saved.len() != 1 || saved[0].acknowledged.is_none() {
            return Err("Pengakuan alert tidak tersimpan.".into());
        }
        set(ui.h(INTEL_FILTER), "state=open");
        ui.action(INTEL_SEARCH, 0)?;
        finish(ui)?;
        if send_native(ui.h(INTEL_TABLE), LVM_GETITEMCOUNT, 0, 0) != 0 {
            return Err("Filter alert terbuka masih menampilkan alert yang diakui.".into());
        }
        smoke_trace("IPAM metadata fixture, editor and undo");
        let notes_path = ui.notes_path()?;
        let draft =
            ni::ipam_notes::Note::parse("lab/blue|192.0.2.0/24|reserved|Fixture|tag|offline")?;
        ni::ipam_notes::save(&notes_path, &draft, 0, ni::now())?;
        select(ui.h(INTEL_MODE), NOTES_MODE);
        ui.action(INTEL_MODE, CBN_SELCHANGE as u16)?;
        finish(ui)?;
        if ui.intel.visible_notes.len() != 1
            || send_native(ui.h(INTEL_TABLE), LVM_GETITEMCOUNT, 0, 0) != 1
        {
            return Err("Panel metadata tidak memuat fixture.".into());
        }
        send_native(
            ui.h(INTEL_TABLE),
            LVM_SETITEMSTATE,
            0,
            &item as *const _ as isize,
        );
        ui.action(INTEL_IP_JOURNEY, 0)?;
        if get(ui.h(INTEL_FILTER)) != draft.editor() {
            return Err("Editor metadata tidak memelihara key.".into());
        }
        let saved = ui.intel.visible_notes[0].clone();
        ni::ipam_notes::undo(&notes_path, &saved, ni::now())?;
        ui.action(INTEL_RESET_FILTER, 0)?;
        finish(ui)?;
        if ui
            .intel
            .visible_notes
            .first()
            .is_none_or(|note| note.active || note.revision != 2)
        {
            return Err("Undo metadata tidak tampil sebagai revisi nonaktif.".into());
        }
        smoke_trace("DHCPv6 scoped history fixture and IPAM backup");
        let mut router = RouterSnapshot::new(&Authority::parse("dhcp6-fixture.test")?, 100);
        use ni::router::Table as RouterTable;
        router.ingest(
            RouterTable::Vrf,
            Ok(br#"[{"name":"blue","interfaces":"ether1"}]"#.to_vec()),
            100,
        );
        router.ingest(
            RouterTable::Dhcp6Server,
            Ok(br#"[{"name":"dhcp","interface":"ether1","disabled":false}]"#.to_vec()),
            100,
        );
        router.ingest(
            RouterTable::Dhcp6Binding,
            Ok(br#"[{"address":"2001:db8::/64","server":"dhcp","status":"bound","disabled":false}]"#.to_vec()),
            101,
        );
        let captured = ni::dhcp6_history::Capture::from_snapshot(&router)?;
        let dhcp_path = ui.dhcp6_history_path()?;
        ni::dhcp6_history::save(&dhcp_path, &captured)?;
        set(ui.h(INTEL_HOST), &router.authority);
        select(ui.h(INTEL_MODE), DHCP6_HISTORY_MODE);
        ui.action(INTEL_MODE, CBN_SELCHANGE as u16)?;
        ui.action(INTEL_HISTORY, 0)?;
        finish(ui)?;
        if send_native(ui.h(INTEL_TABLE), LVM_GETITEMCOUNT, 0, 0) != 1
            || !ui.intel.details.iter().any(|d| d.contains("VRF blue"))
        {
            return Err("Histori DHCPv6 fixture gagal menjaga scope.".into());
        }
        let backup = notes_path.with_file_name("notes-smoke-backup.sqlite3");
        ni::ipam_notes::backup(&notes_path, &backup)?;
        if ni::ipam_notes::page(&backup)? != ni::ipam_notes::page(&notes_path)? {
            return Err("Backup IPAM fixture tidak cocok.".into());
        }
        let summary = notes_path.with_file_name("notes-smoke-summary.json");
        ni::ipam_notes::export_summary(&notes_path, &summary)?;
        if std::fs::read_to_string(&summary).map_err(|e| e.to_string())?.contains("192.0.2") {
            return Err("Ringkasan IPAM memuat alamat.".into());
        }
        smoke_trace("Offline syslog summary fixture");
        ui.intel.syslog_summary = Some(ni::syslog::summarize(b"<13>fixture")?);
        select(ui.h(INTEL_MODE), SYSLOG_MODE);
        ui.action(INTEL_MODE, CBN_SELCHANGE as u16)?;
        if send_native(ui.h(INTEL_TABLE), LVM_GETITEMCOUNT, 0, 0) != 2
            || get(ui.h(INTEL_IMPORT)) != "Impor Syslog"
        {
            return Err("Ringkasan syslog fixture gagal.".into());
        }
        Ok(())
    })();
    ui.intel.archive_override = None;
    ui.intel.storage_smoke = false;
    if cleanup {
        let _ = std::fs::remove_dir_all(dir);
    }
    journey?;
    smoke_trace("Dashboard and subnet fixtures");
    select(ui.h(INTEL_MODE), SUBNET_MODE);
    ui.action(INTEL_MODE, CBN_SELCHANGE as u16)?;
    if !get(ui.h(INTEL_STATUS)).contains("alamat bebas") {
        return Err("Ringkasan subnet tidak menampilkan batas bukti.".into());
    }
    // Render without launching a real archive read outside the fixture.
    select(ui.h(INTEL_MODE), DASHBOARD_MODE);
    ui.intel_mode_labels(DASHBOARD_MODE);
    ui.render_intel();
    if ui.intel.dashboard_targets.is_empty() || get(ui.h(INTEL_IP_JOURNEY)) != "Buka modul" {
        return Err("Dashboard jaringan tidak menampilkan modul.".into());
    }
    smoke_trace("RouterOS topology and IPAM fixtures");
    let auth = Authority::parse("fixture.example.test")?;
    let mut fixture = RouterSnapshot::new(&auth, 100);
    use ni::router::Table;
    fixture.ingest(
        Table::Vrf,
        Ok(br#"[{"name":"blue","interfaces":"vlan20"}]"#.to_vec()),
        100,
    );
    fixture.ingest(
        Table::Address4,
        Ok(br#"[{"address":"192.0.2.1/24","interface":"vlan20"}]"#.to_vec()),
        100,
    );
    fixture.ingest(Table::BridgeHost, Ok(br#"[{"mac-address":"02:11:22:33:44:55","bridge":"br","on-interface":"ether1","vid":"20"}]"#.to_vec()), 100);
    ui.intel.network_views.insert(
        fixture.authority.clone(),
        (
            network_map::topology(&fixture),
            network_map::inventory(&fixture),
        ),
    );
    select(ui.h(INTEL_MODE), TOPOLOGY_MODE);
    ui.action(INTEL_MODE, CBN_SELCHANGE as u16)?;
    if send_native(ui.h(INTEL_TABLE), LVM_GETITEMCOUNT, 0, 0) != 2
        || !ui
            .intel
            .details
            .iter()
            .any(|s| s.contains("RouterOS Bridge FDB"))
    {
        return Err("Topologi fixture gagal menampilkan sumber dan relasi.".into());
    }
    smoke_trace("Native graph and bandwidth viewer");
    if ui.intel.visual_edges.len() != 2 {
        return Err("Graf tidak cocok dengan relasi fixture.".into());
    }
    show_visual_inner(
        ui.hwnd,
        VisualData::Graph(ui.intel.visual_edges.clone()),
        0,
        true,
    )?;
    let samples = std::collections::VecDeque::from([
        ni::interface_trend::Point {
            utc: 100,
            received_utc: 101,
            interval_s: Some(10),
            rx_bps: Some(0),
            tx_bps: Some(100),
        },
        ni::interface_trend::Point {
            utc: 110,
            received_utc: 111,
            interval_s: Some(10),
            rx_bps: None,
            tx_bps: Some(200),
        },
    ]);
    show_visual_inner(
        ui.hwnd,
        VisualData::Bandwidth(ni::visual::Series::new("fixture".into(), &samples)),
        0,
        true,
    )?;
    select(ui.h(INTEL_MODE), IPAM_MODE);
    ui.action(INTEL_MODE, CBN_SELCHANGE as u16)?;
    set(ui.h(INTEL_FILTER), "192.0.2.1/24");
    ui.action(INTEL_SEARCH, 0)?;
    if !ui
        .intel
        .details
        .iter()
        .any(|s| s.contains("VRF tercantum blue") && s.contains("RouterOS IPv4 Addresses"))
    {
        return Err("IPAM fixture gagal mempertahankan scope dan provenance.".into());
    }
    select(ui.h(INTEL_MODE), POLL_MODE);
    ui.action(INTEL_MODE, CBN_SELCHANGE as u16)?;
    if get(ui.h(INTEL_ROUTER)) != "Mulai polling" || get(ui.h(INTEL_PROBE)) != "Hentikan target" {
        return Err("Kontrol polling tidak tampil.".into());
    }
    set(ui.h(INTEL_HOST), "fixture.example.test");
    ui.intel
        .schedule
        .configure(auth.display(), 120, std::time::Instant::now())?;
    ui.render_intel();
    if send_native(ui.h(INTEL_TABLE), LVM_GETITEMCOUNT, 0, 0) != 1 {
        return Err("Jadwal polling fixture tidak tampil.".into());
    }
    ui.action(INTEL_PROBE, 0)?;
    if !ui.intel.schedule.jobs.is_empty() {
        return Err("Jadwal polling fixture tidak berhenti.".into());
    }
    select(ui.h(INTEL_MODE), TREND_MODE);
    ui.action(INTEL_MODE, CBN_SELCHANGE as u16)?;
    if get(ui.h(INTEL_HISTORY)) != "Arsip UTC" || get(ui.h(INTEL_RECORD)) != "Sampel" {
        return Err("Kontrol histori tren tidak tampil.".into());
    }
    smoke_trace("Calculator, review and local inventory");
    ui.show_page(Page::Diag);
    set(ui.h(CALC_IP), "172.20.95.190");
    set(ui.h(CALC_MASK), "16");
    ui.action(CALC, 0)?;
    if !get(ui.h(OUTPUT)).contains("172.20.0.0") {
        return Err("Kalkulator tidak menampilkan hasil".into());
    }
    ui.reply(Reply {
        preview: Some(Preview {
            token: 1,
            title: "Uji tampilan".into(),
            adapter: "Adaptor uji".into(),
            rows: vec![["DNS".into(), "Otomatis".into(), "Manual".into()]],
            note: "Simulasi tanpa perubahan.".into(),
            warnings: vec![],
            button: "Terapkan".into(),
        }),
        ..Default::default()
    });
    if send_native(ui.h(DIFF), LVM_GETITEMCOUNT, 0, 0) != 1
        || !get(ui.h(REVIEW_NOTE)).contains("Simulasi")
    {
        return Err("Perbandingan sebelum/target tidak tampil".into());
    }
    ui.action(CANCEL, 0)?;
    if ui.page != Page::Diag {
        return Err("Batal tidak kembali ke halaman sebelumnya".into());
    }
    let (selected, dashboard) = App::inventory(None)?;
    ui.model.selected = selected;
    ui.render(dashboard);
    if ui.dashboard.is_none() {
        return Err("Inventaris adaptor Windows gagal".into());
    }
    Ok(())
}
pub fn run() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if let [flag, payload] = args.as_slice()
        && flag == "--apply-change"
    {
        let outcome = if !w::elevated() {
            Err("Helper harus dijalankan dengan izin Administrator.".into())
        } else {
            Change::decode(payload).and_then(|c| w::apply_checked(&c))
        };
        let (notice, code) = match outcome {
            Ok(s) => (Notice::Information(s), HELPER_SUCCESS),
            Err(e) => (Notice::Error(e), HELPER_ERROR_SHOWN),
        };
        let (title, icon) = notice.dialog().expect("helper result is a dialog");
        let shown = popup_titled(
            null_mut(),
            &format!("{title} — WeNet Toolkit"),
            &crlf(notice.text()),
            icon | MB_SETFOREGROUND,
        );
        std::process::exit(if shown == 0 {
            HELPER_DIALOG_FAILED
        } else {
            code
        } as i32);
    }
    if let [flag, parent] = args.as_slice()
        && flag == "--wait-for-parent"
    {
        if !w::elevated() {
            show_launch_error(
                "Mode Admin harus dijalankan dengan izin Administrator.",
                false,
            );
            std::process::exit(1);
        }
        if let Err(e) = w::wait_for_parent(parent) {
            show_launch_error(&e, false);
            std::process::exit(1);
        }
    }
    let smoke = args.as_slice() == ["--smoke-ui"];
    if smoke {
        smoke_trace("Starting native GUI smoke");
    }
    if let Err(e) = start_ui(smoke) {
        show_launch_error(&e, smoke);
        std::process::exit(1);
    }
    if smoke {
        smoke_trace("PASS: native GUI smoke");
    }
}
