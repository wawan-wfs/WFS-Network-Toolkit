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

#[cfg(test)]
mod tests {
    use super::*;
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
