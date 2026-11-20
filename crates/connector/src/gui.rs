//! Desktop GUI (egui). The connector runs while the window is open.

use crate::runtime::{self, Runtime};
use crate::store::{self, Auth, Connection, Kind};
use anyhow::{bail, Result};
use eframe::egui::{self, Color32, RichText};
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
    name: String,
    url: String,
    token: String,
    has_token: bool,
}

struct App {
    rt: Arc<Runtime>,
    tokio: tokio::runtime::Runtime,
    tab: Tab,
    form: Option<Form>,
    hub: HubForm,
    msg: (String, bool),
    test: Arc<Mutex<Option<String>>>,
}

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
        name: cfg.name.clone(),
        url: cfg.hub_url.clone(),
        token: String::new(),
        has_token: store::get_secret(store::HUB_TOKEN).ok().flatten().is_some(),
    };
    let tab = if cfg.hub_url.is_empty() { Tab::Hub } else { Tab::Connections };
    let app = App { rt, tokio, tab, form: None, hub, msg: (String::new(), false), test: Default::default() };
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([860.0, 600.0]).with_title("CC-connector"),
        ..Default::default()
    };
    eframe::run_native("CC-connector", opts, Box::new(|_cc| Ok(Box::new(app)))).map_err(|e| anyhow::anyhow!("{e}"))
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
        Color32::from_rgb(60, 170, 80)
    } else if s.starts_with("connecting") || s.starts_with("starting") {
        Color32::from_rgb(210, 160, 30)
    } else {
        Color32::from_rgb(200, 60, 60)
    }
}

fn dot(ui: &mut egui::Ui, c: Color32) {
    ui.label(RichText::new("●").color(c));
}

impl App {
    fn reload(&mut self) {
        let _g = self.tokio.enter();
        if let Err(e) = self.rt.reload() {
            self.msg = (format!("{e:#}"), true);
        }
    }

    fn open_form(&mut self, name: Option<&str>) {
        let cfg = store::load().unwrap_or_default();
        let conn = name.and_then(|n| cfg.get(n).cloned()).unwrap_or_default();
        let orig = name.unwrap_or("").to_string();
        let (has_pw, has_pp) = if orig.is_empty() {
            (false, false)
        } else {
            (
                store::get_secret(&store::pw_key(&orig)).ok().flatten().is_some(),
                store::get_secret(&store::pp_key(&orig)).ok().flatten().is_some(),
            )
        };
        self.form = Some(Form { conn, orig, has_pw, has_pp, ..Default::default() });
        *self.test.lock().unwrap() = None;
    }

    fn save_form(&mut self) -> Result<String> {
        let Some(f) = self.form.clone() else { bail!("nothing to save") };
        let mut c = f.conn.clone();
        c.name = c.name.trim().to_string();
        c.host = c.host.trim().to_string();
        c.user = c.user.trim().to_string();
        store::validate_name(&c.name)?;
        if c.kind == Kind::Ssh && (c.host.is_empty() || c.user.is_empty()) {
            bail!("host and user are required for SSH");
        }
        if c.kind == Kind::Ssh && c.auth == Auth::Key && c.key_path.trim().is_empty() {
            bail!("key file is required for key authentication");
        }
        let mut cfg = store::load()?;
        if c.name != f.orig && cfg.get(&c.name).is_some() {
            bail!("a connection named '{}' already exists", c.name);
        }
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
        self.reload();
        let name = c.name.clone();
        self.open_form(Some(&name));
        Ok(format!("saved '{name}'"))
    }

    fn top(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let hs = self.rt.hub_status.lock().unwrap().clone();
            dot(ui, status_color(&hs));
            let name = self.rt.cfg.read().unwrap().name.clone();
            ui.label(RichText::new(name).strong());
            ui.label(format!("hub: {hs}"));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let mut paused = self.rt.cfg.read().unwrap().paused;
                if ui
                    .checkbox(&mut paused, "Pause agent access")
                    .on_hover_text("While paused the agent sees no machines and all requests are refused")
                    .changed()
                {
                    if let Ok(mut c) = store::load() {
                        c.paused = paused;
                        if let Err(e) = store::save(&c) {
                            self.msg = (format!("{e:#}"), true);
                        }
                        self.reload();
                    }
                }
            });
        });
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.tab, Tab::Connections, "Connections");
            ui.selectable_value(&mut self.tab, Tab::Hub, "Hub");
            ui.selectable_value(&mut self.tab, Tab::Activity, "Activity");
        });
    }

    fn connections(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("list").resizable(true).default_width(230.0).show(ctx, |ui| {
            ui.add_space(4.0);
            if ui.button("➕ Add connection").clicked() {
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
                        } else {
                            st.get(&c.name).map(|m| m.status.clone()).unwrap_or_else(|| "connecting".into())
                        };
                        let col = if c.enabled { status_color(&s) } else { Color32::GRAY };
                        dot(ui, col);
                        let sel = self.form.as_ref().is_some_and(|f| f.orig == c.name);
                        let kind = if c.kind == Kind::Local { " (local)" } else { "" };
                        if ui.selectable_label(sel, format!("{}{kind}", c.name)).on_hover_text(s).clicked() {
                            let n = c.name.clone();
                            self.open_form(Some(&n));
                        }
                    });
                }
                if cfg.connections.is_empty() {
                    ui.label("No connections yet.");
                }
            });
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.form.is_none() {
                ui.heading("Connections");
                ui.label("Select a connection or add one. The agent only sees each connection's name, OS and description — never hosts, users or passwords.");
                self.msg_line(ui);
                return;
            }
            let mut action = None;
            egui::ScrollArea::vertical().show(ui, |ui| {
                let f = self.form.as_mut().unwrap();
                ui.heading(if f.orig.is_empty() { "New connection".to_string() } else { format!("Edit '{}'", f.orig) });
                ui.add_space(6.0);
                egui::Grid::new("form").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
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
                        if ui.add(egui::TextEdit::singleline(&mut port).desired_width(60.0)).changed() {
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
                            ui.add(egui::TextEdit::singleline(&mut f.passphrase).password(true).hint_text(if f.has_pp { "(saved — leave empty to keep)" } else { "(none)" }));
                            ui.end_row();
                        }
                    }
                    let pw_label = match (f.conn.kind, f.conn.auth) {
                        (Kind::Ssh, Auth::Password) => "Password",
                        _ => "sudo password",
                    };
                    ui.label(pw_label);
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut f.password).password(true).hint_text(if f.has_pw { "(saved — leave empty to keep)" } else { "(not set)" }));
                        if f.has_pw {
                            ui.checkbox(&mut f.clear_pw, "remove saved");
                        }
                    });
                    ui.end_row();
                    ui.label("Description");
                    ui.text_edit_singleline(&mut f.conn.description).on_hover_text("Shown to the agent, e.g. 'UR5 arm controller, ROS 2 Humble'");
                    ui.end_row();
                    ui.label("Default directory");
                    ui.text_edit_singleline(&mut f.conn.cwd).on_hover_text("Where commands start; empty = home");
                    ui.end_row();
                    ui.label("Init commands");
                    ui.add(egui::TextEdit::multiline(&mut f.conn.init).desired_rows(2).hint_text("e.g. source /opt/ros/humble/setup.bash"));
                    ui.end_row();
                    ui.label("Options");
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut f.conn.enabled, "Visible to agent");
                        ui.checkbox(&mut f.conn.allow_sudo, "Allow sudo").on_hover_text("The agent may run commands as root; the saved password is fed to sudo without being shown to it");
                    });
                    ui.end_row();
                    if f.conn.kind == Kind::Ssh {
                        ui.label("Host key");
                        ui.horizontal(|ui| {
                            ui.label(if f.conn.host_key.is_empty() { "not trusted yet (trusted on first connect)".to_string() } else { f.conn.host_key.clone() });
                            if !f.conn.host_key.is_empty() && ui.small_button("Forget").clicked() {
                                f.conn.host_key.clear();
                            }
                        });
                        ui.end_row();
                    }
                });
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button("💾 Save").clicked() {
                        action = Some("save");
                    }
                    if !f.orig.is_empty() {
                        if ui.button("🔌 Test").clicked() {
                            action = Some("test");
                        }
                        if ui.button("🗑 Delete").clicked() {
                            action = Some("delete");
                        }
                    }
                    if ui.button("Close").clicked() {
                        action = Some("close");
                    }
                });
                if let Some(t) = self.test.lock().unwrap().clone() {
                    ui.add_space(6.0);
                    ui.group(|ui| {
                        ui.label(RichText::new(t).monospace());
                    });
                }
            });
            match action {
                Some("save") => {
                    self.msg = match self.save_form() {
                        Ok(m) => (m, false),
                        Err(e) => (format!("{e:#}"), true),
                    }
                }
                Some("test") => {
                    // save first so the test uses what's on screen
                    match self.save_form() {
                        Ok(_) => {
                            let name = self.form.as_ref().unwrap().orig.clone();
                            let out = self.test.clone();
                            *out.lock().unwrap() = Some("testing…".into());
                            let ctx2 = ui.ctx().clone();
                            let rt = self.rt.clone();
                            self.tokio.spawn(async move {
                                let r = match runtime::test_connection(&name).await {
                                    Ok(s) => s,
                                    Err(e) => format!("FAILED: {e:#}"),
                                };
                                *out.lock().unwrap() = Some(r);
                                // pick up a newly trusted host key, re-probe
                                let _ = rt.reload();
                                ctx2.request_repaint();
                            });
                        }
                        Err(e) => self.msg = (format!("{e:#}"), true),
                    }
                }
                Some("delete") => {
                    let name = self.form.as_ref().unwrap().orig.clone();
                    let r = (|| -> Result<()> {
                        let mut c = store::load()?;
                        c.connections.retain(|x| x.name != name);
                        store::delete_conn_secrets(&name)?;
                        store::save(&c)
                    })();
                    self.msg = match r {
                        Ok(()) => (format!("deleted '{name}'"), false),
                        Err(e) => (format!("{e:#}"), true),
                    };
                    self.form = None;
                    self.reload();
                }
                Some("close") => self.form = None,
                _ => {}
            }
            self.msg_line(ui);
        });
    }

    fn msg_line(&self, ui: &mut egui::Ui) {
        if !self.msg.0.is_empty() {
            ui.add_space(6.0);
            let col = if self.msg.1 { Color32::from_rgb(200, 60, 60) } else { Color32::from_rgb(60, 170, 80) };
            ui.label(RichText::new(&self.msg.0).color(col));
        }
    }

    fn hub_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Hub");
        ui.label("The hub runs on the Claude Code server. Create a token there with `ccc-hub token new <name>`.");
        ui.add_space(6.0);
        egui::Grid::new("hub").num_columns(2).spacing([12.0, 8.0]).show(ui, |ui| {
            ui.label("Connector name");
            ui.text_edit_singleline(&mut self.hub.name);
            ui.end_row();
            ui.label("Hub URL");
            ui.add(egui::TextEdit::singleline(&mut self.hub.url).desired_width(380.0).hint_text("wss://your-server.example.com/ccc"));
            ui.end_row();
            ui.label("Token");
            ui.add(egui::TextEdit::singleline(&mut self.hub.token).password(true).desired_width(380.0).hint_text(if self.hub.has_token { "(saved — leave empty to keep)" } else { "paste token" }));
            ui.end_row();
        });
        ui.add_space(8.0);
        if ui.button("💾 Save and connect").clicked() {
            let r = (|| -> Result<()> {
                let url = self.hub.url.trim().to_string();
                if !url.is_empty() && !(url.starts_with("wss://") || url.starts_with("ws://")) {
                    bail!("URL must start with wss:// (or ws:// for testing)");
                }
                store::validate_name(self.hub.name.trim())?;
                let mut c = store::load()?;
                c.hub_url = url;
                c.name = self.hub.name.trim().to_string();
                if !self.hub.token.trim().is_empty() {
                    store::set_secret(store::HUB_TOKEN, self.hub.token.trim())?;
                    self.hub.token.clear();
                    self.hub.has_token = true;
                }
                store::save(&c)
            })();
            self.msg = match r {
                Ok(()) => ("hub settings saved".into(), false),
                Err(e) => (format!("{e:#}"), true),
            };
            self.reload();
        }
        if self.hub.url.trim().starts_with("ws://") {
            ui.label(RichText::new("Warning: ws:// is unencrypted; the token and all traffic can be read on the network. Use wss://.").color(Color32::from_rgb(210, 160, 30)));
        }
        self.msg_line(ui);
    }

    fn activity(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.heading("Activity");
            if ui.small_button("Clear").clicked() {
                self.rt.log.lock().unwrap().clear();
            }
        });
        ui.label("Every request the agent makes is listed here.");
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
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.add_space(4.0);
            self.top(ui);
            ui.add_space(2.0);
        });
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
