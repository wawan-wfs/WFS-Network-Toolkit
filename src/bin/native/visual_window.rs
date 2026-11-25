// Native GDI evidence viewer; immutable copy of the filtered view, no network writes.
enum VisualData {
    Graph(Vec<ni::visual::Edge>),
    Bandwidth(ni::visual::Series),
}

struct VisualState {
    data: VisualData,
    selected: usize,
    span: usize,
}
impl VisualState {
    fn len(&self) -> usize {
        match &self.data {
            VisualData::Graph(edges) => edges.len(),
            VisualData::Bandwidth(series) => series.points.len(),
        }
    }

    fn step(&mut self, delta: isize) {
        self.selected = self
            .selected
            .saturating_add_signed(delta)
            .min(self.len().saturating_sub(1));
    }

    fn zoom(&mut self, more: bool) {
        self.span = match &self.data {
            VisualData::Graph(_) => {
                if more { self.span.saturating_sub(1).max(2) } else { (self.span + 1).min(8) }
            }
            VisualData::Bandwidth(_) => {
                if more { (self.span / 2).max(15) } else { (self.span * 2).min(120) }
            }
        };
    }
}
thread_local! {
    static VISUAL_STATE: std::cell::RefCell<Option<VisualState>> = const { std::cell::RefCell::new(None) };
}

fn vis_text(dc: HDC, rect: RECT, text: &str, tint: u32, wrap: bool) {
    let mut rect = rect;
    let text = w::wide(text);
    unsafe {
        SetTextColor(dc, tint);
        SetBkMode(dc, TRANSPARENT as i32);
        DrawTextW(
            dc,
            text.as_ptr(),
            -1,
            &mut rect,
            DT_NOPREFIX | if wrap { DT_WORDBREAK | DT_END_ELLIPSIS } else {
                DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS
            },
        );
    }
}

fn vis_rect(x: i32, y: i32, width: i32, height: i32) -> RECT {
    RECT {
        left: x,
        top: y,
        right: x + width.max(0),
        bottom: y + height.max(0),
    }
}
fn vis_line(dc: HDC, a: (i32, i32), b: (i32, i32), tint: u32) {
    let pen = unsafe { CreatePen(PS_SOLID, 2, tint) };
    if !pen.is_null() {
        unsafe {
            let old = SelectObject(dc, pen);
            MoveToEx(dc, a.0, a.1, null_mut());
            LineTo(dc, b.0, b.1);
            SelectObject(dc, old);
            DeleteObject(pen);
        }
    }
}

fn visual_paint(h: HWND, dc: HDC, state: &VisualState) {
    let mut client = RECT::default();
    unsafe {
        GetClientRect(h, &mut client);
        SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
    }
    let width = client.right;
    let height = client.bottom;
    fill(dc, &client, color(248, 250, 252));
    if width < 320 || height < 260 {
        return;
    }
    let navy = color(20, 43, 66);
    let teal = color(0, 122, 125);
    let blue = color(50, 95, 175);
    let ink = color(24, 39, 55);
    fill(dc, &vis_rect(0, 0, width, 52), navy);
    let title = match &state.data {
        VisualData::Graph(_) => "Topologi — graf bukti logis",
        VisualData::Bandwidth(_) => "Bandwidth — histori interface",
    };
    vis_text(dc, vis_rect(18, 4, width - 36, 26), title, color(255, 255, 255), false);
    vis_text(
        dc,
        vis_rect(18, 30, width - 36, 18),
        "← → / ↑ ↓ / roda mouse: navigasi   + / −: zoom   Esc: tutup",
        color(210, 228, 230),
        false,
    );
    match &state.data {
        VisualData::Graph(edges) => {
            let span = state.span.max(1);
            let start = state.selected / span * span;
            let rows = &edges[start.min(edges.len())..(start + span).min(edges.len())];
            let row_h = ((height - 192) / span as i32).max(1);
            let box_w = (width - 96) / 2;
            for (i, edge) in rows.iter().enumerate() {
                let y = 70 + i as i32 * row_h;
                let chosen = start + i == state.selected;
                let tint = if chosen { color(213, 240, 237) } else { color(232, 239, 245) };
                let left = vis_rect(20, y, box_w, row_h - 8);
                let right = vis_rect(width - 20 - box_w, y, box_w, row_h - 8);
                fill(dc, &left, tint);
                fill(dc, &right, tint);
                let mid = y + (row_h - 8).max(0) / 2;
                vis_line(dc, (left.right, mid), (right.left, mid), if chosen { teal } else { blue });
                vis_text(dc, vis_rect(left.left + 7, y, box_w - 14, 18), edge.left_kind, teal, false);
                vis_text(dc, vis_rect(left.left + 7, y + 18, box_w - 14, row_h - 26), &edge.left, ink, false);
                vis_text(dc, vis_rect(right.left + 7, y, box_w - 14, 18), edge.right_kind, teal, false);
                vis_text(dc, vis_rect(right.left + 7, y + 18, box_w - 14, row_h - 26), &edge.right, ink, false);
            }
            if let Some(edge) = edges.get(state.selected) {
                let y = height - 115;
                let detail = format!(
                    "{} / {} · {}/{}\n{} · UTC {}\n{}\nBukan bukti kabel fisik.",
                    edge.scope, edge.source, state.selected + 1, edges.len(), edge.left_kind, edge.utc, edge.details
                );
                vis_text(dc, vis_rect(20, y, width - 40, 100), &detail, ink, true);
            }
        }
        VisualData::Bandwidth(series) => {
            vis_text(dc, vis_rect(20, 58, width - 40, 22), &series.label, ink, false);
            let end = (state.selected + 1).max(state.span).min(series.points.len());
            let points = series.range(end, state.span);
            let max = ni::visual::Series::max_value(points);
            let left = 75;
            let right = width - 24;
            let top = 112;
            let bottom = height - 115;
            vis_text(dc, vis_rect(20, 85, width - 40, 20), &format!("RX teal · TX biru · skala maksimum {max} bit/s"), ink, false);
            vis_line(dc, (left, top), (left, bottom), ink);
            vis_line(dc, (left, bottom), (right, bottom), ink);
            let t0 = points.first().map_or(0, |p| p.utc);
            let dt = points.last().map_or(0, |p| p.utc).saturating_sub(t0).max(1);
            let x = |utc: u64| left + ni::visual::Series::axis(utc.saturating_sub(t0), dt, right - left);
            for (rx, tint) in [(true, teal), (false, blue)] {
                let mut prior = None;
                for p in points {
                    let value = if rx { p.rx_bps } else { p.tx_bps };
                    if let Some(value) = value {
                        let at = (x(p.utc), bottom - ni::visual::Series::axis(value, max, bottom - top));
                        if let Some(prev) = prior {
                            vis_line(dc, prev, at, tint);
                        }
                        fill(dc, &vis_rect(at.0 - 2, at.1 - 2, 5, 5), tint);
                        prior = Some(at);
                    } else {
                        prior = None;
                    }
                }
            }
            if let Some(point) = series.points.get(state.selected) {
                let cursor = x(point.utc);
                vis_line(dc, (cursor, top), (cursor, bottom), color(160, 173, 184));
                let detail = format!(
                    "Sampel {}/{} · UTC {} · interval {} detik\nRX {} bit/s · TX {} bit/s\nRentang {}–{} UTC. Data hilang/reset = gap, bukan nol.",
                    state.selected + 1, series.points.len(), point.utc, display_opt(point.interval_s),
                    display_opt(point.rx_bps), display_opt(point.tx_bps),
                    points.first().map_or(0, |p| p.utc), points.last().map_or(0, |p| p.utc)
                );
                vis_text(dc, vis_rect(20, height - 96, width - 40, 80), &detail, ink, true);
            }
            if points.is_empty() {
                vis_text(dc, vis_rect(20, 112, width - 40, 32), "Tidak ada sampel.", ink, false);
            }
        }
    }
}

unsafe extern "system" fn visual_wnd(h: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    match msg {
        WM_PAINT => {
            let mut paint = PAINTSTRUCT::default();
            let dc = unsafe { BeginPaint(h, &mut paint) };
            if !dc.is_null() {
                VISUAL_STATE.with(|slot| {
                    if let Some(state) = slot.borrow().as_ref() {
                        visual_paint(h, dc, state);
                    }
                });
            }
            unsafe { EndPaint(h, &paint); }
            0
        }
        WM_ERASEBKGND => 1,
        WM_CLOSE => {
            unsafe { DestroyWindow(h); }
            0
        }
        WM_KEYDOWN | WM_MOUSEWHEEL => {
            if msg == WM_KEYDOWN && wp == 0x1b {
                unsafe { DestroyWindow(h); }
                return 0;
            }
            VISUAL_STATE.with(|slot| {
                if let Some(state) = slot.borrow_mut().as_mut() {
                    match (msg, wp) {
                        (WM_KEYDOWN, 0x25 | 0x26) => state.step(-1),
                        (WM_KEYDOWN, 0x27 | 0x28) => state.step(1),
                        (WM_KEYDOWN, 0x21) => state.step(-(state.span as isize)),
                        (WM_KEYDOWN, 0x22) => state.step(state.span as isize),
                        (WM_KEYDOWN, 0x24) => state.selected = 0,
                        (WM_KEYDOWN, 0x23) => state.selected = state.len().saturating_sub(1),
                        (WM_KEYDOWN, 0x6b | 0xbb) => state.zoom(true),
                        (WM_KEYDOWN, 0x6d | 0xbd) => state.zoom(false),
                        (WM_MOUSEWHEEL, _) => {
                            let delta = ((wp >> 16) as u16) as i16;
                            state.step(if delta > 0 { -1 } else { 1 });
                        }
                        _ => {}
                    }
                }
            });
            unsafe { InvalidateRect(h, null(), 0); }
            0
        }
        WM_SIZE => {
            unsafe { InvalidateRect(h, null(), 0); }
            0
        }
        WM_LBUTTONDOWN => {
            let x = (lp as u16) as i16 as i32;
            let y = ((lp >> 16) as u16) as i16 as i32;
            let mut client = RECT::default();
            unsafe { GetClientRect(h, &mut client); }
            VISUAL_STATE.with(|slot| {
                if let Some(state) = slot.borrow_mut().as_mut() {
                    match &state.data {
                        VisualData::Graph(_) if y >= 70 && y < client.bottom - 115 => {
                            let row_h = ((client.bottom - 192) / state.span as i32).max(1);
                            let row = ((y - 70) / row_h) as usize;
                            if row < state.span {
                                state.selected = (state.selected / state.span * state.span + row)
                                    .min(state.len().saturating_sub(1));
                            }
                        }
                        VisualData::Bandwidth(series) if y >= 112 && y < client.bottom - 115 => {
                            let end = (state.selected + 1).max(state.span).min(series.points.len());
                            let points = series.range(end, state.span);
                            let t0 = points.first().map_or(0, |p| p.utc);
                            let dt = points.last().map_or(0, |p| p.utc).saturating_sub(t0).max(1);
                            let width = (client.right - 99).max(1);
                            if let Some((index, _)) = points.iter().enumerate().min_by_key(|(_, p)| {
                                let px = 75 + ni::visual::Series::axis(
                                    p.utc.saturating_sub(t0), dt, width
                                );
                                px.abs_diff(x)
                            }) {
                                state.selected = end - points.len() + index;
                            }
                        }
                        _ => {}
                    }
                }
            });
            unsafe { InvalidateRect(h, null(), 0); }
            0
        }
        _ => unsafe { DefWindowProcW(h, msg, wp, lp) },
    }
}

fn show_visual(owner: HWND, data: VisualData, selected: usize) -> Result<()> {
    show_visual_inner(owner, data, selected, false)
}

fn show_visual_inner(owner: HWND, data: VisualData, selected: usize, smoke: bool) -> Result<()> {
    let instance = unsafe { GetModuleHandleW(null()) };
    let class = w::wide("WeNetEvidenceViewer");
    let wc = WNDCLASSW {
        hInstance: instance,
        lpszClassName: class.as_ptr(),
        lpfnWndProc: Some(visual_wnd),
        hCursor: unsafe { LoadCursorW(null_mut(), IDC_ARROW) },
        ..Default::default()
    };
    if unsafe { RegisterClassW(&wc) } == 0 {
        return Err("Tidak dapat mendaftarkan penampil bukti.".into());
    }
    let mut state = VisualState {
        span: if matches!(&data, VisualData::Graph(_)) { 4 } else { 60 },
        data,
        selected,
    };
    if matches!(&state.data, VisualData::Bandwidth(_)) {
        state.selected = state.len().saturating_sub(1);
    }
    state.selected = state.selected.min(state.len().saturating_sub(1));
    VISUAL_STATE.with(|slot| *slot.borrow_mut() = Some(state));
    let h = unsafe {
        CreateWindowExW(
            WS_EX_TOOLWINDOW,
            class.as_ptr(),
            w::wide("WeNet Toolkit | Visual Intelligence").as_ptr(),
            WS_OVERLAPPEDWINDOW,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            980,
            680,
            owner,
            null_mut(),
            instance,
            null(),
        )
    };
    let result = if h.is_null() {
        Err("Penampil bukti tidak dapat dibuka.".into())
    } else {
        unsafe {
            EnableWindow(owner, 0);
            ShowWindow(h, if smoke { SW_SHOWNOACTIVATE } else { SW_SHOW });
            if !smoke {
                SetFocus(h);
            }
            UpdateWindow(h);
        }
        let mut smoke_error = false;
        if smoke {
            let before = VISUAL_STATE.with(|slot| slot.borrow().as_ref().map(|s| s.span));
            unsafe {
                SendMessageW(h, WM_KEYDOWN, 0x6b, 0);
                SendMessageW(h, WM_KEYDOWN, 0x25, 0);
                UpdateWindow(h);
            }
            let after = VISUAL_STATE.with(|slot| slot.borrow().as_ref().map(|s| s.span));
            smoke_error = before == after || after.is_none();
            unsafe {
                PostMessageW(h, WM_CLOSE, 0, 0);
            }
        }
        let mut message = MSG::default();
        let mut result = if smoke_error {
            Err("Smoke viewer gagal mengubah rentang.".into())
        } else {
            Ok(())
        };
        while unsafe { IsWindow(h) } != 0 {
            let status = unsafe { GetMessageW(&mut message, null_mut(), 0, 0) };
            if status <= 0 {
                if status == 0 {
                    unsafe { PostQuitMessage(message.wParam as i32); }
                } else {
                    result = Err("Loop pesan penampil gagal.".into());
                }
                break;
            }
            // Main UI has its own dispatch loop. Defer its model work until
            // returning; the viewer displays only an immutable snapshot.
            if message.hwnd != owner {
                unsafe {
                    TranslateMessage(&message);
                    DispatchMessageW(&message);
                }
            }
        }
        unsafe {
            if IsWindow(h) != 0 {
                DestroyWindow(h);
            }
            EnableWindow(owner, 1);
            SetFocus(owner);
            PostMessageW(owner, SYNC_LAYOUT, 0, 0);
        }
        result
    };
    VISUAL_STATE.with(|slot| *slot.borrow_mut() = None);
    unsafe { UnregisterClassW(class.as_ptr(), instance); }
    result
}
