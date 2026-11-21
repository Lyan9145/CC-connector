//! Desktop GUI (egui). The connector runs while the window is open.
//!
//! Anything that touches disk, the keyring or the network runs on the tokio
//! runtime and reports back through `events`, so the UI never blocks.

use crate::runtime::{self, Decision, Runtime};
use crate::store::{self, Access, Auth, Connection, Kind, Perm};
use anyhow::{bail, Result};
use eframe::egui::{self, Color32, RichText, Stroke};
use std::sync::{Arc, Mutex};

#[derive(PartialEq, Clone, Copy)]
enum Tab {
    Connections,
    Hub,
    Activity,
}

#[derive(Default, Clone)]
struct Form {
    conn: Connection,
    /// name before editing ("" for a new connection)
    orig: String,
    password: String,
    passphrase: String,
    has_pw: bool,
    has_pp: bool,
    clear_pw: bool,
}

struct HubForm {
    pair: String,
    name: String,
    url: String,
    token: String,
    has_token: bool,
}

enum Event {
    Msg(String, bool),
    Saved { name: String, then_test: bool },
    Deleted(String),
    Secrets { name: String, has_pw: bool, has_pp: bool },
    HubSaved,
    Paired { url: String, pinned: bool },
    Test(String),
}

struct App {
    rt: Arc<Runtime>,
    tokio: tokio::runtime::Runtime,
    tab: Tab,
    form: Option<Form>,
    hub: HubForm,
    msg: (String, bool),
    test: Option<String>,
    busy: bool,
    events: Arc<Mutex<Vec<Event>>>,
    /// highest approval id we already asked the OS to flash the window for
    seen_approval: u64,
}

const GREEN: Color32 = Color32::from_rgb(46, 160, 67);
const AMBER: Color32 = Color32::from_rgb(214, 153, 34);
const RED: Color32 = Color32::from_rgb(218, 54, 51);
const GREY: Color32 = Color32::from_rgb(130, 130, 130);

pub fn run() -> Result<()> {
    #[cfg(windows)]
    detach_console();
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tokio = tokio::runtime::Runtime::new()?;
    let rt = {
        let _g = tokio.enter();
        let rt = Runtime::new(false);
        rt.start();
        rt
    };
    let cfg = rt.cfg.read().unwrap().clone();
    let hub = HubForm {
        pair: String::new(),
        name: cfg.name.clone(),
        url: cfg.hub_url.clone(),
        token: String::new(),
        has_token: store::get_secret(store::HUB_TOKEN).ok().flatten().is_some(),
    };
    let tab = if cfg.hub_url.is_empty() { Tab::Hub } else { Tab::Connections };
    let app = App {
        rt,
        tokio,
        tab,
        form: None,
        hub,
        msg: (String::new(), false),
        test: None,
        busy: false,
        events: Default::default(),
        seen_approval: 0,
    };
    let mut viewport = egui::ViewportBuilder::default().with_inner_size([880.0, 620.0]).with_title("CC-connector");
    if let Ok(icon) = eframe::icon_data::from_png_bytes(include_bytes!("../assets/icon.png")) {
        viewport = viewport.with_icon(Arc::new(icon));
    }
    let opts = eframe::NativeOptions { viewport, ..Default::default() };
    eframe::run_native(
        "CC-connector",
        opts,
        Box::new(|cc| {
            setup_style(&cc.egui_ctx);
            let ctx = cc.egui_ctx.clone();
            *app.rt.notify.lock().unwrap() = Some(Box::new(move || ctx.request_repaint()));
            app.rt.interactive.store(true, std::sync::atomic::Ordering::Relaxed);
            Ok(Box::new(app))
        }),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Higher-contrast text than egui's defaults, in both themes.
fn setup_style(ctx: &egui::Context) {
    ctx.style_mut_of(egui::Theme::Dark, |s| {
        let w = &mut s.visuals.widgets;
        w.noninteractive.fg_stroke.color = Color32::from_gray(226);
        w.inactive.fg_stroke.color = Color32::from_gray(236);
        w.hovered.fg_stroke.color = Color32::WHITE;
        w.active.fg_stroke.color = Color32::WHITE;
        w.open.fg_stroke.color = Color32::WHITE;
        s.visuals.hyperlink_color = Color32::from_rgb(110, 170, 255);
    });
    ctx.style_mut_of(egui::Theme::Light, |s| {
        let w = &mut s.visuals.widgets;
        w.noninteractive.fg_stroke.color = Color32::from_gray(25);
        w.inactive.fg_stroke.color = Color32::from_gray(15);
        w.hovered.fg_stroke.color = Color32::BLACK;
        w.active.fg_stroke.color = Color32::BLACK;
        w.open.fg_stroke.color = Color32::BLACK;
    });
    ctx.all_styles_mut(|s| {
        s.spacing.button_padding = egui::vec2(10.0, 4.0);
        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
    });
}

/// When started by double-click on Windows, hide the console window.
#[cfg(windows)]
fn detach_console() {
    use windows_sys::Win32::System::Console::{FreeConsole, GetConsoleProcessList};
    let mut ids = [0u32; 4];
    let n = unsafe { GetConsoleProcessList(ids.as_mut_ptr(), ids.len() as u32) };
    if n <= 1 {
        unsafe { FreeConsole() };
    }
}

fn status_color(s: &str) -> Color32 {
    if s.starts_with("online") || s.starts_with("connected") {
        GREEN
    } else if s.starts_with("connecting") || s.starts_with("starting") {
        AMBER
    } else if s == "disabled" || s == "paused" {
        GREY
    } else {
        RED
    }
}

/// A small filled circle (drawn, so it doesn't depend on font glyphs).
fn dot(ui: &mut egui::Ui, c: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(12.0, 12.0), egui::Sense::hover());
    ui.painter().circle_filled(rect.center(), 5.0, c);
}

/// A rounded, coloured status pill with white text.
fn badge(ui: &mut egui::Ui, text: &str, fill: Color32) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(text.to_string(), egui::FontId::proportional(12.5), Color32::WHITE);
    let size = galley.size() + egui::vec2(22.0, 8.0);
    let (rect, resp) = ui.allocate_exact_size(size, egui::Sense::hover());
    let p = ui.painter();
    p.rect_filled(rect, egui::CornerRadius::same((size.y / 2.0) as u8), fill);
    p.circle_filled(egui::pos2(rect.left() + 9.0, rect.center().y), 3.0, Color32::WHITE);
    p.galley(egui::pos2(rect.left() + 15.0, rect.center().y - galley.size().y / 2.0), galley, Color32::WHITE);
    resp
}

fn access_color(a: Access) -> Color32 {
    match a {
        Access::Allow => GREEN,
        Access::Ask => AMBER,
        Access::Deny => RED,
    }
}

/// Preset picker plus an Allow / Ask / Deny row per tool.
fn perms_editor(ui: &mut egui::Ui, p: &mut store::Perms, windows_local: bool) {
    ui.vertical(|ui| {
        ui.horizontal(|ui| {
            ui.label("Preset");
            let cur = p.preset().and_then(|k| store::PRESETS.iter().find(|x| x.0 == k)).map(|x| x.1).unwrap_or("Custom");
            egui::ComboBox::from_id_salt("preset").selected_text(cur).show_ui(ui, |ui| {
                for (_, label, preset) in store::PRESETS {
                    if ui.selectable_label(*p == preset, label).clicked() {
                        *p = preset;
                    }
                }
            });
        });
        egui::Grid::new("perms").num_columns(4).spacing([12.0, 3.0]).striped(true).show(ui, |ui| {
            ui.label("");
            for a in ["Allow", "Ask", "Deny"] {
                ui.label(RichText::new(a).strong());
            }
            ui.end_row();
            for perm in Perm::ALL {
                let na = perm == Perm::Sudo && windows_local;
                let cur = p.get(perm);
                ui.horizontal(|ui| {
                    dot(ui, if na { GREY } else { access_color(cur) });
                    ui.label(perm.label()).on_hover_text(format!("agent tool `{}`", perm.name()));
                });
                for a in [Access::Allow, Access::Ask, Access::Deny] {
                    let mut v = cur;
                    if ui.add_enabled(!na, egui::RadioButton::new(v == a, "")).clicked() {
                        v = a;
                        p.set(perm, v);
                    }
                }
                if na {
                    ui.label(RichText::new("n/a on Windows").weak());
                }
                ui.end_row();
            }
        });
        ui.label(
            RichText::new("Ask: you approve each use in a pop-up here (refused if this window is closed or headless).")
                .weak()
                .size(12.0),
        );
    });
}

fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(4.0);
    ui.label(RichText::new(title).strong().size(15.0));
}

impl App {
    fn push(events: &Arc<Mutex<Vec<Event>>>, e: Event) {
        events.lock().unwrap().push(e);
    }

    /// Run blocking work (disk, keyring, reload) off the UI thread.
    fn bg<F>(&mut self, ctx: &egui::Context, f: F)
    where
        F: FnOnce(&Arc<Runtime>) -> Event + Send + 'static,
    {
        self.busy = true;
        let rt = self.rt.clone();
        let ev = self.events.clone();
        let ctx = ctx.clone();
        self.tokio.spawn_blocking(move || {
            let e = f(&rt);
            Self::push(&ev, e);
            ctx.request_repaint();
        });
    }

    fn drain_events(&mut self, ctx: &egui::Context) {
        let evs: Vec<Event> = std::mem::take(&mut *self.events.lock().unwrap());
        for e in evs {
            match e {
                Event::Msg(m, err) => {
                    self.busy = false;
                    self.msg = (m, err);
                }
                Event::Saved { name, then_test } => {
                    self.busy = false;
                    if let Some(f) = self.form.as_mut() {
                        f.orig = name.clone();
                        f.has_pw = (f.has_pw && !f.clear_pw) || !f.password.is_empty();
                        f.has_pp = f.has_pp || !f.passphrase.is_empty();
                        f.password.clear();
                        f.passphrase.clear();
                        f.clear_pw = false;
                    }
                    self.msg = (format!("saved '{name}'"), false);
                    if then_test {
                        self.start_test(ctx, name);
                    }
                }
                Event::Deleted(name) => {
                    self.busy = false;
                    self.form = None;
                    self.msg = (format!("deleted '{name}'"), false);
                }
                Event::Secrets { name, has_pw, has_pp } => {
                    if let Some(f) = self.form.as_mut().filter(|f| f.orig == name) {
                        f.has_pw = has_pw;
                        f.has_pp = has_pp;
                    }
                }
                Event::HubSaved => {
                    self.busy = false;
                    self.hub.has_token = self.hub.has_token || !self.hub.token.trim().is_empty();
                    self.hub.token.clear();
                    self.msg = ("hub settings saved".into(), false);
                }
                Event::Paired { url, pinned } => {
                    self.busy = false;
                    self.hub.url = url.clone();
                    self.hub.pair.clear();
                    self.hub.has_token = true;
                    self.msg = (format!("paired with {url}{}", if pinned { " (certificate pinned)" } else { "" }), false);
                }
                Event::Test(r) => {
                    self.busy = false;
                    self.test = Some(r);
                }
            }
        }
    }

    fn open_form(&mut self, name: Option<&str>) {
        let conn = name.and_then(|n| self.rt.cfg.read().unwrap().get(n).cloned()).unwrap_or_default();
        let orig = name.unwrap_or("").to_string();
        self.form = Some(Form { conn, orig: orig.clone(), ..Default::default() });
        self.test = None;
        self.msg = (String::new(), false);
        if !orig.is_empty() {
            // keyring lookups can be slow (Secret Service), do them off-thread
            let ev = self.events.clone();
            self.tokio.spawn_blocking(move || {
                let has_pw = store::get_secret(&store::pw_key(&orig)).ok().flatten().is_some();
                let has_pp = store::get_secret(&store::pp_key(&orig)).ok().flatten().is_some();
                Self::push(&ev, Event::Secrets { name: orig, has_pw, has_pp });
            });
        }
    }

    fn validate(&self, f: &Form) -> Result<Connection> {
        let mut c = f.conn.clone();
        c.name = c.name.trim().to_string();
        c.host = c.host.trim().to_string();
        c.user = c.user.trim().to_string();
        c.key_path = c.key_path.trim().to_string();
        store::validate_name(&c.name)?;
        if c.kind == Kind::Ssh && (c.host.is_empty() || c.user.is_empty()) {
            bail!("host and user are required for SSH");
        }
        if c.kind == Kind::Ssh && c.auth == Auth::Key && c.key_path.is_empty() {
            bail!("key file is required for key authentication");
        }
        if c.name != f.orig && self.rt.cfg.read().unwrap().get(&c.name).is_some() {
            bail!("a connection named '{}' already exists", c.name);
        }
        Ok(c)
    }

    fn save(&mut self, ctx: &egui::Context, then_test: bool) {
        let Some(f) = self.form.clone() else { return };
        let c = match self.validate(&f) {
            Ok(c) => c,
            Err(e) => {
                self.msg = (format!("{e:#}"), true);
                return;
            }
        };
        if then_test {
            self.test = Some("saving…".into());
        }
        self.bg(ctx, move |rt| {
            let r = (|| -> Result<String> {
                let mut c = c;
                let mut cfg = store::load()?;
                if f.orig.is_empty() {
                    cfg.connections.push(c.clone());
                } else {
                    let Some(slot) = cfg.get_mut(&f.orig) else { bail!("connection was removed") };
                    if slot.host != c.host || slot.port != c.port {
                        c.host_key.clear();
                    }
                    *slot = c.clone();
                    if c.name != f.orig {
                        store::rename_secrets(&f.orig, &c.name)?;
                    }
                }
                if f.clear_pw {
                    store::del_secret(&store::pw_key(&c.name))?;
                }
                if !f.password.is_empty() {
                    store::set_secret(&store::pw_key(&c.name), &f.password)?;
                }
                if !f.passphrase.is_empty() {
                    store::set_secret(&store::pp_key(&c.name), &f.passphrase)?;
                }
                store::save(&cfg)?;
                let _ = rt.reload();
                Ok(c.name)
            })();
            match r {
                Ok(name) => Event::Saved { name, then_test },
                Err(e) => Event::Msg(format!("{e:#}"), true),
            }
        });
    }

    fn start_test(&mut self, ctx: &egui::Context, name: String) {
        self.test = Some(format!("testing '{name}'…"));
        self.busy = true;
        let ev = self.events.clone();
        let rt = self.rt.clone();
        let ctx = ctx.clone();
        self.tokio.spawn(async move {
            let r = match runtime::test_connection(&name).await {
                Ok(s) => s,
                Err(e) => format!("FAILED: {e:#}"),
            };
            // pick up a newly trusted host key and re-probe
            let _ = tokio::task::spawn_blocking(move || rt.reload()).await;
            Self::push(&ev, Event::Test(r));
            ctx.request_repaint();
        });
    }

    fn top(&mut self, ui: &mut egui::Ui) {
        let hs = self.rt.hub_status.lock().unwrap().clone();
        let paused_now = self.rt.cfg.read().unwrap().paused;
        ui.horizontal(|ui| {
            let (label, col) = if paused_now {
                ("PAUSED", GREY)
            } else if hs.starts_with("connected") {
                ("CONNECTED", GREEN)
            } else if hs.starts_with("starting") {
                ("STARTING", AMBER)
            } else {
                ("OFFLINE", RED)
            };
            badge(ui, label, col).on_hover_text(format!("hub: {hs}"));
            let name = self.rt.cfg.read().unwrap().name.clone();
            ui.label(RichText::new(name).strong().size(15.0));
            let detail = hs.strip_prefix("disconnected: ").unwrap_or(&hs);
            if hs.contains("TLS") {
                ui.label(RichText::new("encrypted").color(GREEN)).on_hover_text(hs.clone());
            } else if hs.contains("unencrypted") {
                ui.label(RichText::new("unencrypted ws://").color(AMBER)).on_hover_text("Use a wss:// URL to encrypt traffic");
            } else if !hs.starts_with("connected") {
                ui.label(RichText::new(detail).weak());
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let mut paused = paused_now;
                if ui
                    .checkbox(&mut paused, "Pause agent access")
                    .on_hover_text("While paused the agent sees no machines and all requests are refused")
                    .changed()
                {
                    let ctx = ui.ctx().clone();
                    self.bg(&ctx, move |rt| {
                        let r = store::load().and_then(|mut c| {
                            c.paused = paused;
                            store::save(&c)
                        });
                        let _ = rt.reload();
                        match r {
                            Ok(()) => Event::Msg(if paused { "agent access paused".into() } else { "agent access resumed".into() }, false),
                            Err(e) => Event::Msg(format!("{e:#}"), true),
                        }
                    });
                }
                if self.busy {
                    ui.spinner();
                }
            });
        });
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            for (t, name) in [(Tab::Connections, "Connections"), (Tab::Hub, "Hub"), (Tab::Activity, "Activity")] {
                if ui.selectable_label(self.tab == t, RichText::new(name).size(14.5)).clicked() {
                    self.tab = t;
                }
            }
        });
    }

    fn connections(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("list").resizable(true).default_width(240.0).show(ctx, |ui| {
            ui.add_space(6.0);
            if ui.button("+ Add connection").clicked() {
                self.open_form(None);
            }
            ui.separator();
            let cfg = self.rt.cfg.read().unwrap().clone();
            let st = self.rt.status.lock().unwrap().clone();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for c in &cfg.connections {
                    ui.horizontal(|ui| {
                        let s = if !c.enabled {
                            "disabled".to_string()
                        } else if cfg.paused {
                            "paused".to_string()
                        } else {
                            st.get(&c.name).map(|m| m.status.clone()).unwrap_or_else(|| "connecting".into())
                        };
                        dot(ui, status_color(&s));
                        let sel = self.form.as_ref().is_some_and(|f| f.orig == c.name);
                        let kind = if c.kind == Kind::Local { "  (this computer)" } else { "" };
                        let text = RichText::new(format!("{}{kind}", c.name)).size(14.0);
                        let tip = format!("{s}\naccess: {}", c.perms.summary());
                        if ui.selectable_label(sel, text).on_hover_text(tip).clicked() {
                            let n = c.name.clone();
                            self.open_form(Some(&n));
                        }
                    });
                }
                if cfg.connections.is_empty() {
                    ui.label(RichText::new("No connections yet.").weak());
                }
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.form.is_none() {
                ui.heading("Connections");
                ui.label(
                    "Select a connection or add one. The agent only sees each connection's name, OS and \
                     description, never hosts, users or passwords.",
                );
                self.msg_line(ui);
                return;
            }
            let mut action = None;
            let busy = self.busy;
            egui::ScrollArea::vertical().show(ui, |ui| {
                let f = self.form.as_mut().unwrap();
                ui.heading(if f.orig.is_empty() { "New connection".to_string() } else { format!("Edit '{}'", f.orig) });
                ui.add_space(6.0);
                egui::Grid::new("form").num_columns(2).spacing([14.0, 9.0]).show(ui, |ui| {
                    ui.label("Name");
                    ui.text_edit_singleline(&mut f.conn.name).on_hover_text("What the agent calls this machine, e.g. robot");
                    ui.end_row();
                    ui.label("Type");
                    ui.horizontal(|ui| {
                        ui.radio_value(&mut f.conn.kind, Kind::Ssh, "SSH host");
                        ui.radio_value(&mut f.conn.kind, Kind::Local, "This computer");
                    });
                    ui.end_row();
                    if f.conn.kind == Kind::Ssh {
                        ui.label("Host");
                        ui.text_edit_singleline(&mut f.conn.host);
                        ui.end_row();
                        ui.label("Port");
                        let mut port = f.conn.port.to_string();
                        if ui.add(egui::TextEdit::singleline(&mut port).desired_width(70.0)).changed() {
                            f.conn.port = port.trim().parse().unwrap_or(f.conn.port);
                        }
                        ui.end_row();
                        ui.label("User");
                        ui.text_edit_singleline(&mut f.conn.user);
                        ui.end_row();
                        ui.label("Login");
                        ui.horizontal(|ui| {
                            ui.radio_value(&mut f.conn.auth, Auth::Password, "Password");
                            ui.radio_value(&mut f.conn.auth, Auth::Key, "Private key");
                        });
                        ui.end_row();
                        if f.conn.auth == Auth::Key {
                            ui.label("Key file");
                            ui.text_edit_singleline(&mut f.conn.key_path).on_hover_text("e.g. ~/.ssh/id_ed25519");
                            ui.end_row();
                            ui.label("Key passphrase");
                            ui.add(
                                egui::TextEdit::singleline(&mut f.passphrase)
                                    .password(true)
                                    .hint_text(if f.has_pp { "saved (leave empty to keep)" } else { "none" }),
                            );
                            ui.end_row();
                        }
                    }
                    let pw_label = match (f.conn.kind, f.conn.auth) {
                        (Kind::Ssh, Auth::Password) => "Password",
                        _ => "sudo password",
                    };
                    ui.label(pw_label);
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut f.password)
                                .password(true)
                                .hint_text(if f.has_pw { "saved (leave empty to keep)" } else { "not set" }),
                        );
                        if f.has_pw {
                            ui.checkbox(&mut f.clear_pw, "remove saved");
                        }
                    });
                    ui.end_row();
                    ui.label("Notes for agent").on_hover_text(
                        "Shown to the agent with the machine list, like a system prompt for this machine",
                    );
                    ui.add(
                        egui::TextEdit::multiline(&mut f.conn.description)
                            .desired_rows(5)
                            .desired_width(f32::INFINITY)
                            .hint_text(
                                "What this machine is and how to work on it, e.g.\n\
                                 UR5 arm controller, ROS 2 Humble in ~/ws.\n\
                                 Never move the arm without asking me first.",
                            ),
                    );
                    ui.end_row();
                    ui.label("Default directory");
                    ui.text_edit_singleline(&mut f.conn.cwd).on_hover_text("Where commands start; empty = home");
                    ui.end_row();
                    ui.label("Init commands");
                    ui.add(egui::TextEdit::multiline(&mut f.conn.init).desired_rows(2).hint_text("e.g. source /opt/ros/humble/setup.bash"));
                    ui.end_row();
                    ui.label("Agent access");
                    ui.checkbox(&mut f.conn.enabled, "Visible to the agent")
                        .on_hover_text("When off, the agent can't see or use this machine at all");
                    ui.end_row();
                    if f.conn.enabled {
                        ui.label("");
                        perms_editor(ui, &mut f.conn.perms, f.conn.kind == Kind::Local && cfg!(windows));
                        ui.end_row();
                    }
                    if f.conn.kind == Kind::Ssh {
                        ui.label("Host key");
                        ui.horizontal(|ui| {
                            if f.conn.host_key.is_empty() {
                                ui.label(RichText::new("not trusted yet (trusted on first connect)").weak());
                            } else {
                                ui.label(RichText::new(&f.conn.host_key).monospace());
                                if ui.small_button("Forget").clicked() {
                                    f.conn.host_key.clear();
                                }
                            }
                        });
                        ui.end_row();
                    }
                });
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(!busy, |ui| {
                        if ui.button(RichText::new("Save").strong()).clicked() {
                            action = Some("save");
                        }
                        if ui.button("Save and test").clicked() {
                            action = Some("test");
                        }
                        if !f.orig.is_empty() && ui.button(RichText::new("Delete").color(RED)).clicked() {
                            action = Some("delete");
                        }
                    });
                    if ui.button("Close").clicked() {
                        action = Some("close");
                    }
                });
            });
            if let Some(t) = &self.test {
                ui.add_space(8.0);
                let col = if t.starts_with("FAILED") { RED } else if t.starts_with("ok") || t.starts_with("local") { GREEN } else { AMBER };
                egui::Frame::group(ui.style()).stroke(Stroke::new(1.0_f32, col)).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.label(RichText::new(t).monospace());
                });
            }
            match action {
                Some("save") => self.save(ctx, false),
                Some("test") => self.save(ctx, true),
                Some("delete") => {
                    let name = self.form.as_ref().unwrap().orig.clone();
                    self.bg(ctx, move |rt| {
                        let r = (|| -> Result<()> {
                            let mut c = store::load()?;
                            c.connections.retain(|x| x.name != name);
                            store::delete_conn_secrets(&name)?;
                            store::save(&c)
                        })();
                        let _ = rt.reload();
                        match r {
                            Ok(()) => Event::Deleted(name),
                            Err(e) => Event::Msg(format!("{e:#}"), true),
                        }
                    });
                }
                Some("close") => {
                    self.form = None;
                    self.test = None;
                }
                _ => {}
            }
            self.msg_line(ui);
        });
    }

    fn msg_line(&self, ui: &mut egui::Ui) {
        if !self.msg.0.is_empty() {
            ui.add_space(6.0);
            ui.label(RichText::new(&self.msg.0).color(if self.msg.1 { RED } else { GREEN }));
        }
    }

    fn hub_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Hub");
        ui.label("The hub runs on the Claude Code server. Get a pairing code there with `ccc-hub token new <name>`.");
        section(ui, "Quick setup");
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.hub.pair)
                    .password(true)
                    .desired_width(460.0)
                    .hint_text("paste pairing code (ccc1:…)"),
            );
            let can = !self.busy && !self.hub.pair.trim().is_empty();
            if ui.add_enabled(can, egui::Button::new(RichText::new("Pair").strong())).clicked() {
                let code = self.hub.pair.trim().to_string();
                let ctx = ui.ctx().clone();
                self.bg(&ctx, move |rt| {
                    let r = store::apply_pairing(&code);
                    let _ = rt.reload();
                    match r {
                        Ok(p) => Event::Paired { url: p.url, pinned: p.cert.is_some() },
                        Err(e) => Event::Msg(format!("{e:#}"), true),
                    }
                });
            }
        });
        section(ui, "Manual settings");
        egui::Grid::new("hub").num_columns(2).spacing([14.0, 9.0]).show(ui, |ui| {
            ui.label("Connector name");
            ui.text_edit_singleline(&mut self.hub.name);
            ui.end_row();
            ui.label("Hub URL");
            ui.add(egui::TextEdit::singleline(&mut self.hub.url).desired_width(400.0).hint_text("wss://your-server.example.com/ccc"));
            ui.end_row();
            ui.label("Token");
            ui.add(
                egui::TextEdit::singleline(&mut self.hub.token)
                    .password(true)
                    .desired_width(400.0)
                    .hint_text(if self.hub.has_token { "saved (leave empty to keep)" } else { "paste token" }),
            );
            ui.end_row();
        });
        ui.add_space(10.0);
        let clicked = ui.add_enabled(!self.busy, egui::Button::new(RichText::new("Save and connect").strong())).clicked();
        if clicked {
            let url = self.hub.url.trim().to_string();
            let name = self.hub.name.trim().to_string();
            let token = self.hub.token.trim().to_string();
            let check = (|| -> Result<()> {
                if !url.is_empty() && !(url.starts_with("wss://") || url.starts_with("ws://")) {
                    bail!("URL must start with wss:// (or ws:// for testing)");
                }
                store::validate_name(&name)
            })();
            match check {
                Err(e) => self.msg = (format!("{e:#}"), true),
                Ok(()) => {
                    let ctx = ui.ctx().clone();
                    self.bg(&ctx, move |rt| {
                        let r = (|| -> Result<()> {
                            let mut c = store::load()?;
                            if c.hub_url != url {
                                c.hub_cert.clear();
                            }
                            c.hub_url = url;
                            c.name = name;
                            if !token.is_empty() {
                                store::set_secret(store::HUB_TOKEN, &token)?;
                            }
                            store::save(&c)
                        })();
                        let _ = rt.reload();
                        match r {
                            Ok(()) => Event::HubSaved,
                            Err(e) => Event::Msg(format!("{e:#}"), true),
                        }
                    });
                }
            }
        }
        if self.hub.url.trim().starts_with("ws://") {
            ui.add_space(4.0);
            ui.label(
                RichText::new("ws:// is unencrypted: the token and all traffic can be read on the network. Prefer wss://.")
                    .color(AMBER),
            );
        }
        section(ui, "Status");
        ui.label(self.rt.hub_status.lock().unwrap().clone());
        let pin = self.rt.cfg.read().unwrap().hub_cert.clone();
        if !pin.is_empty() {
            ui.label(RichText::new(format!("pinned certificate {pin}")).monospace().weak());
        }
        self.msg_line(ui);
    }

    /// Pop-up for requests waiting on the owner's approval.
    fn approvals(&mut self, ctx: &egui::Context) {
        let pending: Vec<_> = self.rt.approvals.lock().unwrap().clone();
        let Some(a) = pending.first().cloned() else { return };
        if a.id > self.seen_approval {
            self.seen_approval = pending.iter().map(|a| a.id).max().unwrap_or(a.id);
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(egui::UserAttentionType::Critical));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        let left = a.deadline.saturating_duration_since(std::time::Instant::now()).as_secs();
        let what = format!("{}{}", a.tool.name(), if a.sudo { " as root (sudo)" } else { "" });
        let mut decision = None;
        egui::Window::new(RichText::new("Approval needed").strong())
            .collapsible(false)
            .resizable(true)
            .default_width(560.0)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label("The agent wants to use");
                    ui.label(RichText::new(&what).strong().color(if a.sudo { RED } else { AMBER }));
                    ui.label("on");
                    ui.label(RichText::new(&a.machine).strong());
                });
                ui.add_space(4.0);
                egui::Frame::group(ui.style()).show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    egui::ScrollArea::vertical().max_height(280.0).show(ui, |ui| {
                        ui.label(RichText::new(&a.detail).monospace());
                    });
                });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    if ui.button(RichText::new("Allow").strong().color(GREEN)).clicked() {
                        decision = Some(Decision::Once);
                    }
                    if ui
                        .button(format!("Allow {} for 15 min", a.tool.name()))
                        .on_hover_text(format!("Don't ask again for `{what}` on {} for 15 minutes", a.machine))
                        .clicked()
                    {
                        decision = Some(Decision::For(std::time::Duration::from_secs(15 * 60)));
                    }
                    if ui.button(RichText::new("Deny").strong().color(RED)).clicked() {
                        decision = Some(Decision::Deny);
                    }
                });
                let more = if pending.len() > 1 { format!("  ·  {} more waiting", pending.len() - 1) } else { String::new() };
                ui.label(RichText::new(format!("refused automatically in {left}s{more}")).weak());
            });
        if let Some(d) = decision {
            self.rt.decide(a.id, d);
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(250));
    }

    fn activity(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Activity");
            if ui.small_button("Clear").clicked() {
                self.rt.log.lock().unwrap().clear();
            }
        });
        ui.label("Every request the agent makes is listed here.");
        let grants = self.rt.active_grants();
        if !grants.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Temporarily allowed:").color(AMBER));
                for (m, t, sudo, left) in &grants {
                    ui.label(format!("{} on {m} ({} min)", if *sudo { format!("{} as root", t.name()) } else { t.name().to_string() }, left.as_secs() / 60 + 1));
                }
                if ui.small_button("Revoke").clicked() {
                    self.rt.revoke_grants();
                }
            });
        }
        ui.separator();
        let lines: Vec<String> = self.rt.log.lock().unwrap().iter().cloned().collect();
        egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
            for l in lines {
                ui.label(RichText::new(l).monospace());
            }
        });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_events(ctx);
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(6.0);
            self.top(ui);
            ui.add_space(4.0);
        });
        self.approvals(ctx);
        match self.tab {
            Tab::Connections => self.connections(ctx),
            Tab::Hub => {
                egui::CentralPanel::default().show(ctx, |ui| self.hub_tab(ui));
            }
            Tab::Activity => {
                egui::CentralPanel::default().show(ctx, |ui| self.activity(ui));
            }
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(500));
    }
}
