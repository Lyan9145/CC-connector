//! The Activity tab: usage analytics per connection, drawn with the egui
//! painter (no plotting dependency).
//!
//! Colour roles (validated: adjacent pairs clear CVD ΔE 24+, normal ΔE 28+):
//! volume = blue accent, failed = critical red, refused = warning amber;
//! availability is magnitude, so it uses one blue ramp (no red/green pair).

use crate::i18n::{self, tf, tr};
use crate::stats::{Counts, Range, Stats, View};
use ccc_proto::Tool;
use eframe::egui::{self, pos2, vec2, Align2, Color32, CornerRadius, FontId, Pos2, Rect, Sense, Stroke, StrokeKind};
use std::collections::HashMap;

/// Theme-dependent colours (chart roles + text tokens).
#[derive(Clone, Copy)]
pub struct Pal {
    pub accent: Color32,
    pub warn: Color32,
    pub crit: Color32,
    pub grid: Color32,
    pub muted: Color32,
    pub ink: Color32,
    pub ink2: Color32,
    pub tile: Color32,
    pub border: Color32,
    pub wash: Color32,
    pub seq_lo: Color32,
    pub seq_hi: Color32,
    pub good_text: Color32,
    pub bad_text: Color32,
    pub spark: Color32,
}

const fn hex(v: u32) -> Color32 {
    Color32::from_rgb((v >> 16) as u8, (v >> 8) as u8, v as u8)
}

impl Pal {
    pub fn of(ui: &egui::Ui) -> Pal {
        if ui.visuals().dark_mode {
            Pal {
                accent: hex(0x3987e5),
                warn: hex(0xfab219),
                crit: hex(0xd03b3b),
                grid: hex(0x2f2f2d),
                muted: hex(0x9a988f),
                ink: hex(0xf0efec),
                ink2: hex(0xc3c2b7),
                tile: Color32::from_gray(34),
                border: Color32::from_white_alpha(22),
                wash: Color32::from_white_alpha(14),
                seq_lo: hex(0x184f95),
                seq_hi: hex(0x9ec5f4),
                good_text: hex(0x2fbf4a),
                bad_text: hex(0xf07070),
                spark: hex(0x6b6a64),
            }
        } else {
            Pal {
                accent: hex(0x2a78d6),
                warn: hex(0xfab219),
                crit: hex(0xd03b3b),
                grid: hex(0xe1e0d9),
                muted: hex(0x6f6d68),
                ink: hex(0x0b0b0b),
                ink2: hex(0x52514e),
                tile: Color32::WHITE,
                border: Color32::from_black_alpha(26),
                wash: Color32::from_black_alpha(12),
                seq_lo: hex(0xcde2fb),
                seq_hi: hex(0x1c5cab),
                good_text: hex(0x006300),
                bad_text: hex(0xb42323),
                spark: hex(0xb5b3ab),
            }
        }
    }
}

fn lerp(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let f = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgb(f(a.r(), b.r()), f(a.g(), b.g()), f(a.b(), b.b()))
}

// ------------------------------------------------------------- formatting

pub fn fmt_n(n: u64) -> String {
    if n >= 10_000_000 {
        return format!("{:.1}M", n as f64 / 1e6);
    }
    if n >= 10_000 {
        return format!("{:.1}K", n as f64 / 1e3);
    }
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub fn fmt_bytes(n: u64) -> String {
    let f = n as f64;
    if f >= 1e9 {
        format!("{:.1} GB", f / 1e9)
    } else if f >= 1e6 {
        format!("{:.1} MB", f / 1e6)
    } else if f >= 1e3 {
        format!("{:.0} KB", f / 1e3)
    } else {
        format!("{n} B")
    }
}

fn fmt_ms(ms: u64) -> String {
    if ms >= 60_000 {
        "> 30 s".into()
    } else if ms >= 1000 {
        format!("{:.1} s", ms as f64 / 1000.0)
    } else {
        format!("{ms} ms")
    }
}

fn ago(secs: i64) -> String {
    match secs {
        s if s < 90 => tr("just now").into(),
        s if s < 3600 => tf!("{n} min ago", n = s / 60),
        s if s < 86_400 => tf!("{n} h ago", n = s / 3600),
        s => tf!("{n} d ago", n = s / 86_400),
    }
}

fn local(hour: i64) -> chrono::DateTime<chrono::Local> {
    chrono::DateTime::from_timestamp(hour * 3600, 0).unwrap_or_default().with_timezone(&chrono::Local)
}

fn bucket_label(v: &View, i: usize) -> String {
    let a = local(v.start_hour + i as i64 * v.bucket_hours);
    let b = local(v.start_hour + (i as i64 + 1) * v.bucket_hours);
    match v.bucket_hours {
        // date formats are translated too (month and day names would be English)
        1 => format!("{}  {}–{}", a.format(tr("%a %b %-d")), a.format("%H:00"), b.format("%H:00")),
        24 => a.format(tr("%a %b %-d")).to_string(),
        _ => format!("{}  {}–{}", a.format(tr("%a %b %-d")), a.format("%H:00"), b.format("%H:00")),
    }
}

// ------------------------------------------------------------- page state

pub struct PageState {
    pub range: Range,
    /// show only this machine
    pub focus: Option<String>,
    pub search: String,
    confirm_clear: Option<std::time::Instant>,
}

impl Default for PageState {
    fn default() -> Self {
        Self { range: Range::Day, focus: None, search: String::new(), confirm_clear: None }
    }
}

pub enum Action {
    ClearStats,
}

/// Everything the page needs besides the statistics.
pub struct Inputs<'a> {
    /// machine -> status text ("online", "error: ...")
    pub status: &'a HashMap<String, String>,
    pub log: &'a [String],
    pub now: i64,
    /// machines with a tool call running right now
    pub busy: &'a std::collections::HashSet<String>,
}

// ------------------------------------------------------------- the page

pub fn page(ui: &mut egui::Ui, st: &mut PageState, stats: &Stats, inp: &Inputs) -> Option<Action> {
    let pal = Pal::of(ui);
    let mut action = None;
    if st.focus.as_ref().is_some_and(|f| !stats.lifetime.contains_key(f) && !inp.status.contains_key(f)) {
        st.focus = None;
    }
    let view = stats.view(st.range, st.focus.as_deref(), inp.now);

    // filter row
    ui.horizontal(|ui| {
        for r in [Range::Day, Range::Week, Range::Month] {
            if ui.selectable_label(st.range == r, egui::RichText::new(range_title(r)).size(13.5)).clicked() {
                st.range = r;
            }
        }
        ui.add_space(12.0);
        let mut names: Vec<String> = stats.lifetime.keys().cloned().collect();
        for k in inp.status.keys() {
            if !names.contains(k) {
                names.push(k.clone());
            }
        }
        names.sort();
        egui::ComboBox::from_id_salt("focus")
            .selected_text(st.focus.clone().unwrap_or_else(|| tr("All machines").into()))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut st.focus, None, tr("All machines"));
                for n in names {
                    ui.selectable_value(&mut st.focus, Some(n.clone()), n);
                }
            });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let armed = st.confirm_clear.is_some_and(|t| t.elapsed().as_secs() < 4);
            let label = if armed { tr("Click again to clear all statistics") } else { tr("Clear statistics") };
            if ui.small_button(label).clicked() {
                if armed {
                    action = Some(Action::ClearStats);
                    st.confirm_clear = None;
                } else {
                    st.confirm_clear = Some(std::time::Instant::now());
                }
            }
        });
    });
    ui.add_space(6.0);

    kpi_row(ui, &pal, &view, st.range);
    ui.add_space(12.0);

    card(ui, &pal, |ui| {
        let per = match view.bucket_hours {
            1 => tr("per hour"),
            24 => tr("per day"),
            _ => tr("per 6 hours"),
        };
        chart_header(ui, &pal, tr("Requests"), per, &[(tr("Succeeded"), pal.accent), (tr("Failed"), pal.crit), (tr("Refused"), pal.warn)]);
        requests_chart(ui, &pal, &view);
    });
    ui.add_space(12.0);

    ui.columns(2, |cols| {
        card(&mut cols[0], &pal, |ui| {
            chart_header(ui, &pal, tr("Machines"), tr("click one to focus the page on it"), &[]);
            if let Some(clicked) = machines_list(ui, &pal, &view, stats, inp, st.focus.as_deref()) {
                st.focus = if st.focus.as_deref() == Some(&clicked) { None } else { Some(clicked) };
            }
        });
        card(&mut cols[1], &pal, |ui| {
            chart_header(ui, &pal, tr("Tools"), tr("calls by tool"), &[]);
            tools_list(ui, &pal, &view.total);
        });
    });
    ui.add_space(12.0);

    card(ui, &pal, |ui| {
        chart_header(ui, &pal, tr("Availability"), tr("share of time each machine was reachable"), &[]);
        availability(ui, &pal, &view);
    });
    ui.add_space(12.0);

    card(ui, &pal, |ui| {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(tr("Recent activity")).strong().size(15.0).color(pal.ink));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add(egui::TextEdit::singleline(&mut st.search).hint_text(tr("filter")).desired_width(160.0));
            });
        });
        log_list(ui, &pal, inp.log, st.focus.as_deref(), &st.search);
    });
    action
}

fn card(ui: &mut egui::Ui, pal: &Pal, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(pal.tile)
        .stroke(Stroke::new(1.0_f32, pal.border))
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::same(12))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        });
}

fn chart_header(ui: &mut egui::Ui, pal: &Pal, title: &str, sub: &str, legend: &[(&str, Color32)]) {
    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(title).strong().size(15.0).color(pal.ink));
        ui.label(egui::RichText::new(sub).size(12.0).color(pal.muted));
        if !legend.is_empty() {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                for (name, col) in legend.iter().rev() {
                    ui.label(egui::RichText::new(*name).size(12.0).color(pal.ink2));
                    swatch(ui, *col);
                    ui.add_space(6.0);
                }
            });
        }
    });
    ui.add_space(4.0);
}

fn swatch(ui: &mut egui::Ui, c: Color32) {
    let (r, _) = ui.allocate_exact_size(vec2(10.0, 10.0), Sense::hover());
    ui.painter().rect_filled(r, CornerRadius::same(2), c);
}

// ------------------------------------------------------------- KPI tiles

enum Tone {
    Neutral,
    Good,
    Bad,
}

/// "Last 24 hours" etc. (whole phrases: some languages inflect "last")
fn range_title(r: Range) -> &'static str {
    match r {
        Range::Day => tr("Last 24 hours"),
        Range::Week => tr("Last 7 days"),
        Range::Month => tr("Last 30 days"),
    }
}

fn kpi_row(ui: &mut egui::Ui, pal: &Pal, v: &View, range: Range) {
    let t = &v.total;
    let p = &v.prev;
    let range = tr(range.label());
    // (text, tone, arrow up / down / none)
    let delta = |cur: f64, prev: f64, up_good: Option<bool>| -> Option<(String, Tone, Option<bool>)> {
        if prev <= 0.0 {
            return None;
        }
        let d = (cur - prev) / prev * 100.0;
        if d.abs() < 0.5 {
            return Some((tf!("no change vs previous {range}", range = range), Tone::Neutral, None));
        }
        let tone = match up_good {
            None => Tone::Neutral,
            Some(g) if (d > 0.0) == g => Tone::Good,
            _ => Tone::Bad,
        };
        Some((tf!("{pct}% vs previous {range}", pct = format!("{:.0}", d.abs()), range = range), tone, Some(d > 0.0)))
    };
    // sparklines: at most 12 points (merge neighbouring buckets)
    let groups: Vec<Counts> = {
        let k = v.buckets.len().div_ceil(12).max(1);
        v.buckets
            .chunks(k)
            .map(|c| {
                let mut t = Counts::default();
                for b in c {
                    t.add(b);
                }
                t
            })
            .collect()
    };
    let spark_calls: Vec<f64> = groups.iter().map(|b| b.calls as f64).collect();
    let spark_rate: Vec<f64> = groups.iter().map(|b| b.success_rate().unwrap_or(1.0)).collect();
    let spark_bytes: Vec<f64> = groups.iter().map(|b| (b.up + b.down) as f64).collect();

    let rate = t.success_rate();
    let rate_prev = p.success_rate();
    type TileSpec = (String, String, Option<(String, Tone, Option<bool>)>, String, Option<Vec<f64>>);
    let tiles: Vec<TileSpec> = vec![
        (
            tr("Requests").into(),
            fmt_n(t.calls as u64),
            delta(t.calls as f64, p.calls as f64, None),
            tf!("{n} tool calls by the agent", n = fmt_n(t.calls as u64)),
            Some(spark_calls),
        ),
        (
            tr("Success rate").into(),
            rate.map(|r| format!("{:.1}%", r * 100.0)).unwrap_or_else(|| "–".into()),
            match (rate, rate_prev) {
                (Some(a), Some(b)) if (a - b).abs() >= 0.001 => Some((
                    tf!("{pts} pts vs previous {range}", pts = format!("{:.1}", ((a - b) * 100.0).abs()), range = range),
                    if a > b { Tone::Good } else { Tone::Bad },
                    Some(a > b),
                )),
                _ => None,
            },
            tf!("{n} failed", n = fmt_n(t.failed as u64)),
            Some(spark_rate),
        ),
        (
            tr("Needed you").into(),
            fmt_n(t.asked as u64),
            None,
            tf!("{a} approved · {r} refused", a = fmt_n(t.approved as u64), r = fmt_n(t.refused as u64)),
            None,
        ),
        (
            tr("Data moved").into(),
            fmt_bytes(t.up + t.down),
            delta((t.up + t.down) as f64, (p.up + p.down) as f64, None),
            tf!("{up} up · {down} down", up = fmt_bytes(t.up), down = fmt_bytes(t.down)),
            Some(spark_bytes),
        ),
        (
            tr("Typical duration").into(),
            t.quantile_ms(0.5).map(fmt_ms).unwrap_or_else(|| "–".into()),
            None,
            t.quantile_ms(0.95).map(|x| tf!("95% finish within {time}", time = fmt_ms(x))).unwrap_or_default(),
            None,
        ),
    ];
    let gap = 10.0;
    let n = tiles.len() as f32;
    let w = ((ui.available_width() - gap * (n - 1.0)) / n).floor();
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = gap;
        for (label, value, d, sub, spark) in tiles {
            tile(ui, pal, w, &label, &value, d, &sub, spark.as_deref());
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn tile(ui: &mut egui::Ui, pal: &Pal, w: f32, label: &str, value: &str, delta: Option<(String, Tone, Option<bool>)>, sub: &str, spark: Option<&[f64]>) {
    let (rect, _) = ui.allocate_exact_size(vec2(w, 104.0), Sense::hover());
    let p = ui.painter_at(rect.expand(2.0));
    p.rect_filled(rect, CornerRadius::same(8), pal.tile);
    p.rect_stroke(rect, CornerRadius::same(8), Stroke::new(1.0_f32, pal.border), StrokeKind::Inside);
    let x = rect.left() + 12.0;
    p.text(pos2(x, rect.top() + 10.0), Align2::LEFT_TOP, label, FontId::proportional(12.5), pal.muted);
    p.text(pos2(x, rect.top() + 28.0), Align2::LEFT_TOP, value, FontId::proportional(24.0), pal.ink);
    if let Some(s) = spark {
        sparkline(&p, pal, Rect::from_min_size(pos2(rect.right() - 14.0 - 52.0, rect.top() + 14.0), vec2(52.0, 22.0)), s);
    }
    let mut y = rect.top() + 64.0;
    if let Some((text, tone, up)) = delta {
        let col = match tone {
            Tone::Neutral => pal.ink2,
            Tone::Good => pal.good_text,
            Tone::Bad => pal.bad_text,
        };
        let c = pos2(x + 4.0, y + 7.0);
        let tri = if up == Some(true) {
            vec![pos2(c.x - 4.0, c.y + 3.0), pos2(c.x + 4.0, c.y + 3.0), pos2(c.x, c.y - 4.0)]
        } else {
            vec![pos2(c.x - 4.0, c.y - 3.0), pos2(c.x + 4.0, c.y - 3.0), pos2(c.x, c.y + 4.0)]
        };
        if up.is_some() {
            p.add(egui::Shape::convex_polygon(tri, col, Stroke::NONE));
        }
        let tx = if up.is_none() { x } else { x + 12.0 };
        p.text(pos2(tx, y), Align2::LEFT_TOP, text, FontId::proportional(11.5), col);
        y += 17.0;
    }
    p.text(pos2(x, y), Align2::LEFT_TOP, sub, FontId::proportional(11.5), pal.ink2);
}

fn sparkline(p: &egui::Painter, pal: &Pal, r: Rect, v: &[f64]) {
    if v.len() < 2 {
        return;
    }
    let max = v.iter().cloned().fold(f64::MIN, f64::max);
    let min = v.iter().cloned().fold(f64::MAX, f64::min).min(max * 0.5);
    let span = (max - min).max(1e-9);
    let pts: Vec<Pos2> = v
        .iter()
        .enumerate()
        .map(|(i, y)| pos2(r.left() + r.width() * i as f32 / (v.len() - 1) as f32, r.bottom() - r.height() * ((*y - min) / span) as f32))
        .collect();
    p.add(egui::Shape::line(pts.clone(), Stroke::new(1.5_f32, pal.spark)));
    let last = *pts.last().unwrap();
    p.circle_filled(last, 4.5, pal.tile);
    p.circle_filled(last, 3.0, pal.accent);
}

// ------------------------------------------------------------- column chart

fn nice_step(max: f64) -> f64 {
    let raw = (max / 4.0).max(1.0);
    let mag = 10f64.powf(raw.log10().floor());
    for m in [1.0, 2.0, 5.0, 10.0] {
        if raw <= m * mag {
            return m * mag;
        }
    }
    10.0 * mag
}

fn requests_chart(ui: &mut egui::Ui, pal: &Pal, v: &View) {
    let h = 180.0;
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), h), Sense::hover());
    let p = ui.painter_at(rect);
    let plot = Rect::from_min_max(pos2(rect.left() + 40.0, rect.top() + 6.0), pos2(rect.right() - 4.0, rect.bottom() - 20.0));
    let max = v.buckets.iter().map(|b| b.calls).max().unwrap_or(0) as f64;
    let step = nice_step(max);
    let top = (max / step).ceil().max(1.0) * step;
    let y_of = |val: f64| plot.bottom() - plot.height() * (val / top) as f32;
    // gridlines + y ticks
    let mut t = 0.0;
    while t <= top + 1e-9 {
        let y = y_of(t).round() + 0.5;
        p.line_segment([pos2(plot.left(), y), pos2(plot.right(), y)], Stroke::new(1.0_f32, pal.grid));
        p.text(pos2(plot.left() - 8.0, y), Align2::RIGHT_CENTER, fmt_n(t as u64), FontId::proportional(11.0), pal.muted);
        t += step;
    }
    let n = v.buckets.len().max(1);
    let band = plot.width() / n as f32;
    let bw = (band * 0.68).clamp(2.0, 24.0);
    let hovered = resp.hover_pos().filter(|p| plot.x_range().contains(p.x)).map(|p| (((p.x - plot.left()) / band) as usize).min(n - 1));
    if let Some(i) = hovered {
        let x0 = plot.left() + band * i as f32;
        p.rect_filled(Rect::from_min_max(pos2(x0, plot.top()), pos2(x0 + band, plot.bottom())), CornerRadius::same(3), pal.wash);
    }
    for (i, b) in v.buckets.iter().enumerate() {
        let cx = plot.left() + band * (i as f32 + 0.5);
        let mut y = plot.bottom();
        let segs = [(b.ok, pal.accent), (b.failed, pal.crit), (b.refused, pal.warn)];
        let last = segs.iter().rposition(|(c, _)| *c > 0);
        for (k, (c, col)) in segs.iter().enumerate() {
            if *c == 0 {
                continue;
            }
            let hgt = plot.height() * (*c as f64 / top) as f32;
            let r = Rect::from_min_max(pos2(cx - bw / 2.0, y - hgt), pos2(cx + bw / 2.0, y));
            let rad = if Some(k) == last { (4.0f32).min(hgt / 2.0).min(bw / 2.0) as u8 } else { 0 };
            p.rect_filled(r, CornerRadius { nw: rad, ne: rad, sw: 0, se: 0 }, *col);
            y -= hgt;
            if Some(k) != last {
                // 2px surface gap between stacked segments
                y -= 2.0;
            }
        }
    }
    // baseline
    p.line_segment([pos2(plot.left(), plot.bottom() + 0.5), pos2(plot.right(), plot.bottom() + 0.5)], Stroke::new(1.0_f32, pal.muted.gamma_multiply(0.6)));
    // x labels
    let every = match v.bucket_hours {
        1 => 6,
        6 => 4,
        _ => 5,
    };
    for i in (0..n).step_by(every) {
        let t = local(v.start_hour + i as i64 * v.bucket_hours);
        let s = match v.bucket_hours {
            1 => t.format("%H:00").to_string(),
            6 => t.format(tr("%a %-d")).to_string(),
            _ => t.format(tr("%b %-d")).to_string(),
        };
        p.text(pos2(plot.left() + band * i as f32, plot.bottom() + 5.0), Align2::LEFT_TOP, s, FontId::proportional(11.0), pal.muted);
    }
    if let Some(i) = hovered {
        let b = &v.buckets[i];
        let label = bucket_label(v, i);
        resp.on_hover_ui_at_pointer(|ui| {
            ui.label(egui::RichText::new(label).strong());
            for (name, val, col) in [(tr("Succeeded"), b.ok, pal.accent), (tr("Failed"), b.failed, pal.crit), (tr("Refused"), b.refused, pal.warn)] {
                ui.horizontal(|ui| {
                    swatch(ui, col);
                    ui.label(format!("{name}  {}", fmt_n(val as u64)));
                });
            }
            ui.label(if b.calls == 1 { tr("1 request").to_string() } else { tf!("{n} requests", n = fmt_n(b.calls as u64)) });
        });
    }
}

// ------------------------------------------------------------- machine list

fn status_col(pal: &Pal, s: Option<&String>) -> (Color32, &'static str) {
    match s {
        Some(s) if s.starts_with("online") => (hex(0x0ca30c), tr("online")),
        Some(s) if s.starts_with("connecting") => (pal.warn, tr("connecting")),
        Some(s) if s == "disabled" || s == "paused" => (pal.muted, tr("hidden")),
        Some(_) => (pal.crit, tr("error")),
        None => (pal.muted, tr("removed")),
    }
}

fn machines_list(ui: &mut egui::Ui, pal: &Pal, v: &View, stats: &Stats, inp: &Inputs, focus: Option<&str>) -> Option<String> {
    let mut rows: Vec<(&String, &Counts)> = v.per_machine.iter().map(|(m, t, _)| (m, t)).collect();
    rows.sort_by(|a, b| b.1.calls.cmp(&a.1.calls).then(a.0.cmp(b.0)));
    if rows.is_empty() {
        ui.label(egui::RichText::new(tr("No activity in this period.")).color(pal.muted));
        return None;
    }
    let max = rows.iter().map(|r| r.1.calls).max().unwrap_or(1).max(1) as f32;
    let mut clicked = None;
    for (m, c) in rows {
        let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 40.0), Sense::click());
        let p = ui.painter_at(rect);
        let sel = focus == Some(m.as_str());
        if resp.hovered() || sel {
            p.rect_filled(rect, CornerRadius::same(6), pal.wash);
        }
        if sel {
            p.rect_filled(Rect::from_min_size(rect.min + vec2(0.0, 6.0), vec2(3.0, rect.height() - 12.0)), CornerRadius::same(2), pal.accent);
        }
        let (dc, sname) = status_col(pal, inp.status.get(m));
        let y1 = rect.top() + 13.0;
        let busy = inp.busy.contains(m.as_str());
        if busy {
            let t = ui.input(|i| i.time);
            for k in 0..2 {
                let ph = ((t * 0.8 + k as f64 * 0.5) % 1.0) as f32;
                p.circle_stroke(pos2(rect.left() + 14.0, y1), 4.5 + 6.0 * ph, Stroke::new(1.5_f32, pal.accent.gamma_multiply(0.8 * (1.0 - ph))));
            }
            ui.ctx().request_repaint();
        }
        p.circle_filled(pos2(rect.left() + 14.0, y1), 4.5, if busy { pal.accent } else { dc });
        p.text(pos2(rect.left() + 26.0, y1), Align2::LEFT_CENTER, m, FontId::proportional(13.5), pal.ink);
        let fig = fmt_n(c.calls as u64);
        p.text(pos2(rect.right() - 8.0, y1), Align2::RIGHT_CENTER, &fig, FontId::proportional(13.0), pal.ink);
        // bar
        let bx0 = rect.left() + 26.0;
        let bx1 = rect.right() - 8.0;
        let by = rect.top() + 26.0;
        let full = Rect::from_min_max(pos2(bx0, by), pos2(bx1, by + 6.0));
        p.rect_filled(full, CornerRadius::same(3), pal.wash);
        let fw = (full.width() * c.calls as f32 / max).max(if c.calls > 0 { 3.0 } else { 0.0 });
        p.rect_filled(Rect::from_min_size(full.min, vec2(fw, 6.0)), CornerRadius::same(3), pal.accent);
        let avail = c.availability().map(|a| tf!("{pct}% online", pct = format!("{:.1}", a * 100.0))).unwrap_or_else(|| tr("no availability data").into());
        let last = stats.last_active.get(m).map(|t| tf!("active {ago}", ago = ago(inp.now - t))).unwrap_or_default();
        let name_w = ui.painter().layout_no_wrap(m.to_string(), FontId::proportional(13.5), pal.ink).size().x;
        let info = if busy { tr("running now").to_string() } else { format!("{avail}   {last}") };
        p.text(
            pos2(rect.left() + 26.0 + (name_w + 14.0).max(110.0), y1),
            Align2::LEFT_CENTER,
            info,
            FontId::proportional(11.5),
            if busy { pal.accent } else { pal.muted },
        );
        let life = stats.lifetime.get(m).cloned().unwrap_or_default();
        let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
        let resp = resp.on_hover_ui(|ui| {
            ui.label(egui::RichText::new(m).strong());
            let full = inp.status.get(m).map(|s| i18n::status(s)).unwrap_or_else(|| sname.to_string());
            ui.label(tf!("status: {status}", status = full));
            ui.label(tf!(
                "this period: {n} requests, {failed} failed, {refused} refused",
                n = fmt_n(c.calls as u64),
                failed = fmt_n(c.failed as u64),
                refused = fmt_n(c.refused as u64)
            ));
            ui.label(tf!("all time: {n} requests, {bytes} moved", n = fmt_n(life.calls as u64), bytes = fmt_bytes(life.up + life.down)));
            ui.label(
                egui::RichText::new(if focus == Some(m.as_str()) { tr("click to show all machines") } else { tr("click to focus on this machine") }).weak(),
            );
        });
        if resp.clicked() {
            clicked = Some(m.clone());
        }
    }
    clicked
}

// ------------------------------------------------------------- tools

fn tools_list(ui: &mut egui::Ui, pal: &Pal, t: &Counts) {
    let mut rows: Vec<(Tool, u32)> = Tool::ALL.iter().map(|tl| (*tl, t.tools[crate::stats::tool_index(*tl)])).collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.1));
    let max = rows.first().map(|r| r.1).unwrap_or(0).max(1) as f32;
    let total: u32 = rows.iter().map(|r| r.1).sum();
    for (tool, n) in rows {
        let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 23.0), Sense::hover());
        let p = ui.painter_at(rect);
        let cy = rect.center().y;
        p.text(pos2(rect.left() + 2.0, cy), Align2::LEFT_CENTER, tool.name(), FontId::monospace(12.5), pal.ink);
        let x0 = rect.left() + 56.0;
        let x1 = rect.right() - 58.0;
        let w = ((x1 - x0) * n as f32 / max).max(if n > 0 { 3.0 } else { 0.0 });
        p.rect_filled(Rect::from_min_size(pos2(x0, cy - 5.0), vec2(w, 10.0)), CornerRadius { nw: 0, sw: 0, ne: 4, se: 4 }, pal.accent);
        p.text(pos2(rect.right() - 2.0, cy), Align2::RIGHT_CENTER, fmt_n(n as u64), FontId::proportional(12.5), pal.ink2);
        if total > 0 {
            resp.on_hover_text(tf!(
                "{n} {tool}: {pct}% of calls",
                n = fmt_n(n as u64),
                tool = tool.name(),
                pct = format!("{:.0}", n as f32 / total as f32 * 100.0)
            ));
        }
    }
}

// ------------------------------------------------------------- availability

fn availability(ui: &mut egui::Ui, pal: &Pal, v: &View) {
    if v.per_machine.is_empty() {
        ui.label(egui::RichText::new(tr("No data in this period.")).color(pal.muted));
        return;
    }
    let n = v.buckets.len();
    for (m, tot, buckets) in &v.per_machine {
        let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 22.0), Sense::hover());
        let p = ui.painter_at(rect);
        p.text(pos2(rect.left() + 2.0, rect.center().y), Align2::LEFT_CENTER, m, FontId::proportional(12.5), pal.ink);
        let pct = tot.availability().map(|a| format!("{:.1}%", a * 100.0)).unwrap_or_else(|| "–".into());
        p.text(pos2(rect.right() - 2.0, rect.center().y), Align2::RIGHT_CENTER, &pct, FontId::proportional(12.0), pal.ink2);
        let x0 = rect.left() + 100.0;
        let x1 = rect.right() - 56.0;
        let cw = (x1 - x0) / n as f32;
        let mut hovered = None;
        for (i, b) in buckets.iter().enumerate() {
            let r = Rect::from_min_size(pos2(x0 + cw * i as f32, rect.top() + 3.0), vec2((cw - 2.0).max(1.0), 16.0));
            match b.availability() {
                Some(a) => p.rect_filled(r, CornerRadius::same(2), lerp(pal.seq_lo, pal.seq_hi, a as f32)),
                None => p.rect_stroke(r, CornerRadius::same(2), Stroke::new(1.0_f32, pal.grid), StrokeKind::Inside),
            };
            if resp.hover_pos().is_some_and(|hp| r.expand2(vec2(1.0, 3.0)).contains(hp)) {
                hovered = Some(i);
                p.rect_stroke(r.expand(1.0), CornerRadius::same(3), Stroke::new(1.5_f32, pal.ink), StrokeKind::Outside);
            }
        }
        if let Some(i) = hovered {
            let b = &buckets[i];
            let label = bucket_label(v, i);
            resp.on_hover_ui_at_pointer(|ui| {
                ui.label(egui::RichText::new(format!("{m} · {label}")).strong());
                match b.availability() {
                    Some(a) => ui.label(tf!("online {pct}% ({n} of {total} min sampled)", pct = format!("{:.0}", a * 100.0), n = b.online, total = b.samples)),
                    None => ui.label(tr("no data (connector was not running)")),
                };
            });
        }
    }
    // legend
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.add_space(96.0);
        ui.label(egui::RichText::new(tr("0% online")).size(11.5).color(pal.muted));
        for k in 0..6 {
            let (r, _) = ui.allocate_exact_size(vec2(14.0, 10.0), Sense::hover());
            ui.painter().rect_filled(r, CornerRadius::same(2), lerp(pal.seq_lo, pal.seq_hi, k as f32 / 5.0));
        }
        ui.label(egui::RichText::new("100%").size(11.5).color(pal.muted));
        ui.add_space(12.0);
        let (r, _) = ui.allocate_exact_size(vec2(14.0, 10.0), Sense::hover());
        ui.painter().rect_stroke(r, CornerRadius::same(2), Stroke::new(1.0_f32, pal.grid), StrokeKind::Inside);
        ui.label(egui::RichText::new(tr("no data")).size(11.5).color(pal.muted));
    });
    let _ = n;
}

// ------------------------------------------------------------- log

fn log_list(ui: &mut egui::Ui, pal: &Pal, log: &[String], focus: Option<&str>, search: &str) {
    let q = search.to_lowercase();
    let lines: Vec<&String> = log
        .iter()
        .rev()
        .filter(|l| focus.is_none_or(|f| l.get(9..).is_some_and(|r| r.starts_with(&format!("{f}:")))))
        .filter(|l| q.is_empty() || l.to_lowercase().contains(&q))
        .take(300)
        .collect();
    egui::ScrollArea::vertical().max_height(220.0).auto_shrink([false, true]).show(ui, |ui| {
        if lines.is_empty() {
            ui.label(egui::RichText::new(tr("Nothing yet.")).color(pal.muted));
        }
        for l in lines {
            let col = if l.contains("refused") || l.contains("denied") || l.contains("not approved") {
                Some(pal.warn)
            } else if l.contains("error") {
                Some(pal.crit)
            } else if l.contains("waiting for your approval") || l.contains("you approved") || l.contains("you allowed") {
                Some(pal.accent)
            } else {
                None
            };
            ui.horizontal(|ui| {
                let (r, _) = ui.allocate_exact_size(vec2(8.0, 14.0), Sense::hover());
                if let Some(c) = col {
                    ui.painter().circle_filled(r.center(), 3.0, c);
                }
                ui.label(egui::RichText::new(l).monospace().size(12.0).color(pal.ink2));
            });
        }
    });
}
