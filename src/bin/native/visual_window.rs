// Native GDI evidence viewer; immutable copy of the filtered view, no network writes.
enum VisualData {
    Graph(Vec<ni::visual::Edge>),
    Bandwidth(ni::visual::Series),
}

struct VisualState {
    data: VisualData,
    selected: usize,
    span: usize,
    graph: Option<ni::graph::Graph>,
    viewport: ni::graph::Viewport,
    drag: Option<(i32, i32)>,
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
        if matches!(&self.data, VisualData::Graph(_)) {
            let factor = if more { 20 } else { -20 };
            self.viewport.zoom(self.viewport.scale + factor);
        }
        self.span = match &self.data {
            VisualData::Graph(_) => {
                if more {
                    self.span.saturating_sub(1).max(2)
                } else {
                    (self.span + 1).min(8)
                }
            }
            VisualData::Bandwidth(_) => {
                if more {
                    (self.span / 2).max(15)
                } else {
                    (self.span * 2).min(120)
                }
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
            DT_NOPREFIX
                | if wrap {
                    DT_WORDBREAK | DT_END_ELLIPSIS
                } else {
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
    vis_text(
        dc,
        vis_rect(18, 4, width - 36, 26),
        title,
        color(255, 255, 255),
        false,
    );
    vis_text(
        dc,
        vis_rect(18, 30, width - 36, 18),
        "← → / roda mouse: bukti   W A S D / drag kanan: pan   + / −: zoom   Esc: tutup",
        color(210, 228, 230),
        false,
    );
    match &state.data {
        VisualData::Graph(edges) => {
            if let Some(graph) = &state.graph {
                let viewport = state.viewport;
                let point = |x, y| {
                    let (x, y) = viewport.project(x, y);
                    (x + 20, y + 88)
                };
                let (nw, nh) = (
                    ni::graph::NODE_WIDTH * viewport.scale / 100,
                    ni::graph::NODE_HEIGHT * viewport.scale / 100,
                );
                vis_text(
                    dc,
                    vis_rect(20, 56, width - 40, 25),
                    &format!(
                        "{} node · {} relasi · zoom {}% · ruang {} × {} · {}",
                        graph.nodes.len(),
                        graph.links.len(),
                        viewport.scale,
                        graph.width(),
                        graph.height,
                        if graph.limited || edges.len() == ni::visual::MAX_EDGES {
                            "batas tampilan"
                        } else {
                            "snapshot terfilter"
                        }
                    ),
                    ink,
                    false,
                );
                let saved = unsafe { SaveDC(dc) };
                if saved != 0 {
                    unsafe {
                        IntersectClipRect(dc, 8, 83, width - 8, height - 118);
                    }
                    for link in &graph.links {
                        let a = &graph.nodes[link.from];
                        let b = &graph.nodes[link.to];
                        let p = point(
                            a.x + ni::graph::NODE_WIDTH / 2,
                            a.y + ni::graph::NODE_HEIGHT / 2,
                        );
                        let q = point(
                            b.x + ni::graph::NODE_WIDTH / 2,
                            b.y + ni::graph::NODE_HEIGHT / 2,
                        );
                        vis_line(
                            dc,
                            p,
                            q,
                            if link.evidence == state.selected {
                                teal
                            } else {
                                color(156, 177, 195)
                            },
                        );
                    }
                    for node in &graph.nodes {
                        let (x, y) = point(node.x, node.y);
                        if x + nw < 8 || x > width || y + nh < 83 || y > height - 118 {
                            continue;
                        }
                        let chosen = node.incident.contains(&state.selected);
                        fill(
                            dc,
                            &vis_rect(x, y, nw, nh),
                            if chosen {
                                color(213, 240, 237)
                            } else {
                                color(232, 239, 245)
                            },
                        );
                        vis_text(dc, vis_rect(x + 5, y, nw - 10, 17), node.kind, teal, false);
                        vis_text(
                            dc,
                            vis_rect(x + 5, y + 17, nw - 10, 19),
                            &node.name,
                            ink,
                            false,
                        );
                        if nh >= 52 {
                            vis_text(
                                dc,
                                vis_rect(x + 5, y + 36, nw - 10, 15),
                                &node.authority,
                                ink,
                                false,
                            );
                        }
                    }
                    unsafe {
                        RestoreDC(dc, saved);
                    }
                }
                if let Some(edge) = edges.get(state.selected) {
                    let detail = format!(
                        "{} → {} · {}/{}\n{} · {} · UTC {}\n{}\nRelasi logis; tidak membuktikan kabel fisik.",
                        edge.left,
                        edge.right,
                        state.selected + 1,
                        edges.len(),
                        edge.scope,
                        edge.source,
                        edge.utc,
                        edge.details
                    );
                    vis_text(
                        dc,
                        vis_rect(20, height - 112, width - 40, 104),
                        &detail,
                        ink,
                        true,
                    );
                }
            }
        }
        VisualData::Bandwidth(series) => {
            vis_text(
                dc,
                vis_rect(20, 58, width - 40, 22),
                &series.label,
                ink,
                false,
            );
            let end = (state.selected + 1)
                .max(state.span)
                .min(series.points.len());
            let points = series.range(end, state.span);
            let max = ni::visual::Series::max_value(points);
            let summary = interface_trend::summarize(
                &points
                    .iter()
                    .cloned()
                    .collect::<std::collections::VecDeque<_>>(),
            );
            let left = 75;
            let right = width - 24;
            let top = 112;
            let bottom = height - 115;
            vis_text(
                dc,
                vis_rect(20, 85, width - 40, 20),
                &format!(
                    "RX teal · TX biru · max {max} · P95 RX {} / TX {} bps · {} gap",
                    display_opt(summary.p95_rx),
                    display_opt(summary.p95_tx),
                    summary.gaps
                ),
                ink,
                false,
            );
            vis_line(dc, (left, top), (left, bottom), ink);
            vis_line(dc, (left, bottom), (right, bottom), ink);
            let t0 = points.first().map_or(0, |p| p.utc);
            let dt = points.last().map_or(0, |p| p.utc).saturating_sub(t0).max(1);
            let x = |utc: u64| {
                left + ni::visual::Series::axis(utc.saturating_sub(t0), dt, right - left)
            };
            for (rx, tint) in [(true, teal), (false, blue)] {
                let mut prior = None;
                for p in points {
                    let value = if rx { p.rx_bps } else { p.tx_bps };
                    if let Some(value) = value {
                        let at = (
                            x(p.utc),
                            bottom - ni::visual::Series::axis(value, max, bottom - top),
                        );
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
                    state.selected + 1,
                    series.points.len(),
                    point.utc,
                    display_opt(point.interval_s),
                    display_opt(point.rx_bps),
                    display_opt(point.tx_bps),
                    points.first().map_or(0, |p| p.utc),
                    points.last().map_or(0, |p| p.utc)
                );
                vis_text(
                    dc,
                    vis_rect(20, height - 96, width - 40, 80),
                    &detail,
                    ink,
                    true,
                );
            }
            if points.is_empty() {
                vis_text(
                    dc,
                    vis_rect(20, 112, width - 40, 32),
                    "Tidak ada sampel.",
                    ink,
                    false,
                );
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
            unsafe {
                EndPaint(h, &paint);
            }
            0
        }
        WM_ERASEBKGND => 1,
        WM_CLOSE => {
            unsafe {
                DestroyWindow(h);
            }
            0
        }
        WM_KEYDOWN | WM_MOUSEWHEEL => {
            if msg == WM_KEYDOWN && wp == 0x1b {
                unsafe {
                    DestroyWindow(h);
                }
                return 0;
            }
            VISUAL_STATE.with(|slot| {
                if let Some(state) = slot.borrow_mut().as_mut() {
                    match (msg, wp) {
                        (WM_KEYDOWN, 0x25 | 0x26) => state.step(-1),
                        (WM_KEYDOWN, 0x27 | 0x28) => state.step(1),
                        (WM_KEYDOWN, 0x21) => state.step(-(state.span as isize)),
                        (WM_KEYDOWN, 0x22) => state.step(state.span as isize),
                        (WM_KEYDOWN, 0x24) => {
                            state.selected = 0;
                            state.viewport = ni::graph::Viewport::default();
                        }
                        (WM_KEYDOWN, 0x23) => state.selected = state.len().saturating_sub(1),
                        (WM_KEYDOWN, 0x57) => state.viewport.pan(0, 100),
                        (WM_KEYDOWN, 0x53) => state.viewport.pan(0, -100),
                        (WM_KEYDOWN, 0x41) => state.viewport.pan(100, 0),
                        (WM_KEYDOWN, 0x44) => state.viewport.pan(-100, 0),
                        (WM_KEYDOWN, 0x52) => state.viewport = ni::graph::Viewport::default(),
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
            unsafe {
                InvalidateRect(h, null(), 0);
            }
            0
        }
        WM_SIZE => {
            unsafe {
                InvalidateRect(h, null(), 0);
            }
            0
        }
        WM_RBUTTONDOWN | WM_RBUTTONUP | WM_MOUSEMOVE | WM_CAPTURECHANGED => {
            let x = (lp as u16) as i16 as i32;
            let y = ((lp >> 16) as u16) as i16 as i32;
            let mut repaint = false;
            VISUAL_STATE.with(|slot| {
                if let Some(state) = slot.borrow_mut().as_mut()
                    && matches!(&state.data, VisualData::Graph(_))
                {
                    match msg {
                        WM_RBUTTONDOWN => state.drag = Some((x, y)),
                        WM_MOUSEMOVE => {
                            if let Some((px, py)) = state.drag {
                                state.viewport.pan(x - px, y - py);
                                state.drag = Some((x, y));
                                repaint = true;
                            }
                        }
                        _ => state.drag = None,
                    }
                }
            });
            unsafe {
                if msg == WM_RBUTTONDOWN {
                    windows_sys::Win32::UI::Input::KeyboardAndMouse::SetCapture(h);
                } else if msg == WM_RBUTTONUP {
                    windows_sys::Win32::UI::Input::KeyboardAndMouse::ReleaseCapture();
                }
                if repaint {
                    InvalidateRect(h, null(), 0);
                }
            }
            0
        }
        WM_LBUTTONDOWN => {
            let x = (lp as u16) as i16 as i32;
            let y = ((lp >> 16) as u16) as i16 as i32;
            let mut client = RECT::default();
            unsafe {
                GetClientRect(h, &mut client);
            }
            VISUAL_STATE.with(|slot| {
                if let Some(state) = slot.borrow_mut().as_mut() {
                    match &state.data {
                        VisualData::Graph(_) if y >= 83 && y < client.bottom - 118 => {
                            if let Some(graph) = &state.graph
                                && let Some(id) = state.viewport.hit(graph, x - 20, y - 88)
                            {
                                let incident = &graph.nodes[id].incident;
                                if let Some(edge) = incident
                                    .iter()
                                    .find(|&&i| i > state.selected)
                                    .or_else(|| incident.first())
                                {
                                    state.selected = *edge;
                                }
                            }
                        }
                        VisualData::Bandwidth(series) if y >= 112 && y < client.bottom - 115 => {
                            let end = (state.selected + 1)
                                .max(state.span)
                                .min(series.points.len());
                            let points = series.range(end, state.span);
                            let t0 = points.first().map_or(0, |p| p.utc);
                            let dt = points.last().map_or(0, |p| p.utc).saturating_sub(t0).max(1);
                            let width = (client.right - 99).max(1);
                            if let Some((index, _)) =
                                points.iter().enumerate().min_by_key(|(_, p)| {
                                    let px = 75
                                        + ni::visual::Series::axis(
                                            p.utc.saturating_sub(t0),
                                            dt,
                                            width,
                                        );
                                    px.abs_diff(x)
                                })
                            {
                                state.selected = end - points.len() + index;
                            }
                        }
                        _ => {}
                    }
                }
            });
            unsafe {
                InvalidateRect(h, null(), 0);
            }
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
    let graph = match &data {
        VisualData::Graph(edges) => Some(ni::graph::Graph::build(edges)),
        VisualData::Bandwidth(_) => None,
    };
    let mut state = VisualState {
        graph,
        viewport: ni::graph::Viewport::default(),
        drag: None,
        span: if matches!(&data, VisualData::Graph(_)) {
            4
        } else {
            60
        },
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
            let before = VISUAL_STATE.with(|slot| {
                slot.borrow()
                    .as_ref()
                    .map(|s| (s.span, s.viewport.scale, s.viewport.pan_x))
            });
            unsafe {
                SendMessageW(h, WM_KEYDOWN, 0x6b, 0);
                SendMessageW(h, WM_KEYDOWN, 0x25, 0);
                SendMessageW(h, WM_KEYDOWN, 0x44, 0);
                UpdateWindow(h);
            }
            let after = VISUAL_STATE.with(|slot| {
                slot.borrow()
                    .as_ref()
                    .map(|s| (s.span, s.viewport.scale, s.viewport.pan_x))
            });
            smoke_error = match (before, after) {
                (Some((span, scale, pan)), Some((new_span, new_scale, new_pan))) => {
                    span == new_span || (scale != new_scale && pan == new_pan)
                }
                _ => true,
            };
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
                    unsafe {
                        PostQuitMessage(message.wParam as i32);
                    }
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
    unsafe {
        UnregisterClassW(class.as_ptr(), instance);
    }
    result
}
