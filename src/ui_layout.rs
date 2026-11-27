pub const NAV_WIDTH: i32 = 200;
pub const MIN_CONTENT_WIDTH: i32 = 840;
pub const MIN_CONTENT_HEIGHT: i32 = 562;
pub const VERSION_RECT: [i32; 4] = [20, -56, 162, 20];
pub const COPYRIGHT_RECT: [i32; 4] = [20, -34, 162, 20];

pub fn client_scale(width: i32, height: i32, dpi: i32) -> i32 {
    let fit = (width * 96 / MIN_CONTENT_WIDTH).min(height * 96 / MIN_CONTENT_HEIGHT);
    dpi.max(96).min(fit.max(1))
}

pub fn control_rect([x, y, w, h]: [i32; 4], width: i32, height: i32, scale: i32) -> [i32; 4] {
    let logical_w = width * 96 / scale;
    let logical_h = height * 96 / scale;
    let x = if x < 0 { logical_w + x } else { x };
    let y = if y < 0 { logical_h + y } else { y };
    let w = if w < 0 { logical_w + w } else { w };
    let h = if h < 0 { logical_h + h } else { h };
    [x, y, w, h].map(|v| (v * scale + 48) / 96)
}

/// Each native workspace has its own section layout. Rectangles use logical
/// coordinates and stay inside the content area; no WebView or extra window.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum Workspace { Home, Ip, Mac, Backup, Diag, Intel, Review }
pub fn adaptive_workspace_rect(page:Workspace,mut rect:[i32;4],width:i32)->[i32;4] {
    if width<1000 {return rect;}
    let col=((width-256-24)/2).clamp(210,440);
    match page {
        Workspace::Ip => {
            if rect[0]==462 {
                rect[0]=228+col+24;
                if rect[2]==210 || rect[2]==205 || rect[2]==-490 {rect[2]=col;}
            } else if rect[0]==228 && matches!(rect[2],210|205) {
                rect[2]=col;
            }
        }
        Workspace::Backup => {
            if rect[0]==512 {
                rect[0]=228+col+24;
                if matches!(rect[2],235|245|260) {rect[2]=col;}
            } else if rect[0]==228 && matches!(rect[2],235|245) {
                rect[2]=col;
            }
        }
        Workspace::Diag => {
            let extra=((width-840)/3).clamp(0,120);
            match rect[0] {
                228 if matches!(rect[2],141|147) => rect[2]+=extra,
                390 => {rect[0]+=extra;rect[2]+=extra;}
                513|650 => rect[0]+=2*extra,
                _=>{}
            }
        }
        _=>{}
    }
    rect
}
pub fn workspace_sections(page:Workspace,width:i32,height:i32)->Vec<[i32;4]> {
    let right=width-18;
    let left=218;
    let bottom=height-105;
    let col=((width-256-24)/2).clamp(210,440);
    let divider=if width>=1000 {228+col+12} else {500};
    let mut out=Vec::new();
    let mut section=|x,y,r,b| {
        if x>=left && y>=181 && r<=right && b<=height-54 && r>x && b>y {
            out.push([x,y,r-x,b-y]);
        }
    };
    match page {
        Workspace::Home => section(left,182,right,bottom),
        Workspace::Ip => {
            section(left,182,right,444);
            section(left,450,right,501);
        }
        Workspace::Mac => {
            section(left,182,right,284);
            section(left,286,right,412);
            section(left,414,right,468);
        }
        Workspace::Backup => {
            section(left,182,divider-4,351);
            section(divider+4,182,right,351);
            section(left,359,right,495);
        }
        Workspace::Diag => {
            section(left,182,right,255);
            section(left,262,right,bottom);
        }
        Workspace::Intel => {
            section(left,182,right,268);
            section(left,270,right,height-128);
        }
        Workspace::Review => {
            section(left,182,right,height-176);
            section(left,height-175,right,height-98);
        }
    }
    out
}

/// Reserve a native chart strip only when the logical client can retain
/// a useful table. Compact windows keep the existing full-screen drilldown.
pub fn dashboard_chart_rect(height: i32, scale: i32) -> Option<[i32; 4]> {
    (height * 96 / scale.max(1) >= 650).then_some([228, -234, -256, 112])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn adaptive_workspaces_keep_sections_and_columns_inside_client() {
        for width in [840,1000,1280,1920,2560] {
            for height in [562,720,1080] {
                for page in [Workspace::Home,Workspace::Ip,Workspace::Mac,Workspace::Backup,
                    Workspace::Diag,Workspace::Intel,Workspace::Review] {
                    let panels=workspace_sections(page,width,height);
                    assert!(!panels.is_empty());
                    for [x,y,w,h] in panels {assert!(x>=218 && y>=181 && w>0 && h>0 && x+w<=width-18 && y+h<=height-54);}
                }
                let [x,_,w,_]=adaptive_workspace_rect(Workspace::Ip,[228,214,210,31],width);
                let [rx,_,rw,_]=adaptive_workspace_rect(Workspace::Ip,[462,214,210,31],width);
                assert!(x+w<rx && rx+rw<=width-28);
                let [x,_,w,_]=adaptive_workspace_rect(Workspace::Backup,[228,220,245,46],width);
                let [rx,_,rw,_]=adaptive_workspace_rect(Workspace::Backup,[512,242,245,31],width);
                assert!(x+w<rx && rx+rw<=width-28);
                let [x,_,w,_]=adaptive_workspace_rect(Workspace::Diag,[228,214,147,31],width);
                let [rx,_,rw,_]=adaptive_workspace_rect(Workspace::Diag,[390,214,108,31],width);
                let [bx,_,bw,_]=adaptive_workspace_rect(Workspace::Diag,[513,212,125,36],width);
                let [px,_,pw,_]=adaptive_workspace_rect(Workspace::Diag,[650,212,129,36],width);
                assert!(x+w<rx && rx+rw<bx && bx+bw<px && px+pw<=width-28);
            }
        }
    }
    #[test]
    fn actions_do_not_overlap_adapter_picker_at_supported_sizes() {
        for (w, h, dpi) in [
            (640, 450, 96),
            (840, 562, 96),
            (1060, 708, 96),
            (1280, 660, 144),
            (1600, 900, 192),
            (2560, 1400, 192),
        ] {
            let scale = client_scale(w, h, dpi);
            let [x, _, width, _] = control_rect([228, 111, -540, 180], w, h, scale);
            let [refresh, _, refresh_width, _] = control_rect([-296, 106, 112, 36], w, h, scale);
            let [admin, _, admin_width, _] = control_rect([-172, 106, 144, 36], w, h, scale);
            assert!(
                x + width < refresh && refresh + refresh_width < admin && admin + admin_width <= w
            );
            let [_, table_y, _, table_height] = control_rect([228, 226, -256, -410], w, h, scale);
            let [_, note_y, _, _] = control_rect([228, -170, -256, 68], w, h, scale);
            assert!(table_height > 0 && table_y + table_height < note_y);
            let [_, version_y, _, version_h] = control_rect(VERSION_RECT, w, h, scale);
            let [copyright_x, copyright_y, copyright_w, copyright_h] =
                control_rect(COPYRIGHT_RECT, w, h, scale);
            let [_, nav_y, _, nav_h] = control_rect([12, 316, 176, 38], w, h, scale);
            let [rail_end, _, _, _] = control_rect([NAV_WIDTH, 0, 0, 0], w, h, scale);
            assert!(nav_y + nav_h < version_y && version_y + version_h <= copyright_y);
            assert!(copyright_y + copyright_h < h && copyright_x + copyright_w <= rail_end);
        }
    }
    #[test]
    fn embedded_dashboard_keeps_table_and_status_separate() {
        assert!(dashboard_chart_rect(562, 96).is_none());
        for (w, h, dpi) in [(1366, 720, 96), (1920, 1080, 144), (2560, 1440, 192)] {
            let scale = client_scale(w, h, dpi);
            let chart = dashboard_chart_rect(h, scale).unwrap();
            let [_, table_y, _, table_h] = control_rect([228, 273, -256, -513], w, h, scale);
            let [_, chart_y, _, chart_h] = control_rect(chart, w, h, scale);
            let [_, status_y, _, _] = control_rect([228, -113, -554, 30], w, h, scale);
            assert!(table_h > 0 && table_y + table_h < chart_y);
            assert!(chart_y + chart_h < status_y);
        }
    }

    #[test]
    fn intelligence_filters_and_router_buttons_do_not_overlap() {
        for (w, h, dpi) in [
            (640, 450, 96),
            (840, 562, 96),
            (1366, 720, 96),
            (1600, 900, 144),
            (2560, 1440, 192),
        ] {
            let scale = client_scale(w, h, dpi);
            let groups: [&[[i32; 4]]; 3] = [
                &[
                    [228, -113, -554, 30],
                    [-319, -121, 94, 25],
                    [-217, -121, 90, 25],
                    [-119, -121, 91, 25],
                ],
                &[
                    [228, 188, 180, 194],
                    [417, 187, -760, 29],
                    [-332, 184, 60, 34],
                    [-265, 184, 65, 34],
                    [-192, 184, 164, 34],
                ],
                &[
                    [228, 230, -746, 30],
                    [-510, 226, 124, 36],
                    [-378, 226, 147, 36],
                    [-223, 226, 100, 36],
                    [-115, 226, 87, 36],
                ],
            ];
            for rects in groups {
                let mut edge = 0;
                for r in rects {
                    let [x, _, width, _] = control_rect(*r, w, h, scale);
                    assert!(x >= edge && width > 0 && x + width <= w);
                    edge = x + width;
                }
            }
        }
    }
}
