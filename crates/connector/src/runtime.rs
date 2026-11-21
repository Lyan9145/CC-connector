//! The running connector: config/secrets state, SSH targets, status probing
//! and the WebSocket link to the hub.

use crate::exec::{local, ssh::{KeyCallback, SshTarget}};
use crate::ops::{self, Ctx, Target};
use crate::redact::Redactor;
use crate::stats::{Outcome, Stats};
use crate::store::{self, Access, Config, Connection, Kind, Perm, Secrets, Tool};
use anyhow::{Context, Result};
use ccc_proto::{self as proto, Down, JobOp, MachineInfo, Op, Up};
use futures_util::{SinkExt, StreamExt};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{mpsc, oneshot, watch};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Default)]
pub struct MachState {
    pub status: String,
    pub os: String,
}

/// How long the owner has to answer an approval request.
pub const APPROVAL_WAIT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Decision {
    Once,
    /// Allow this tool on this machine (with the same sudo-ness) for a while.
    For(Duration),
    Deny,
}

/// A request waiting for the owner's decision (shown by the GUI).
pub struct Approval {
    pub id: u64,
    pub machine: String,
    pub tool: Tool,
    pub sudo: bool,
    /// Full description of what the agent wants to do.
    pub detail: String,
    pub deadline: Instant,
    tx: Mutex<Option<oneshot::Sender<Decision>>>,
}

pub struct Runtime {
    pub cfg: RwLock<Config>,
    secrets: RwLock<HashMap<String, Secrets>>,
    hub_token: RwLock<Option<String>>,
    targets: RwLock<HashMap<String, Target>>,
    pub status: Mutex<HashMap<String, MachState>>,
    pub hub_status: Mutex<String>,
    pub log: Mutex<VecDeque<String>>,
    redactor: RwLock<Redactor>,
    /// bumped when the machine list sent to the hub may have changed
    changed: watch::Sender<u64>,
    /// bumped on config reload (reconnect hub if URL/token changed, re-probe)
    reloaded: watch::Sender<u64>,
    cfg_mtime: Mutex<Option<SystemTime>>,
    /// true when the user forced the log to be printed to stderr (headless)
    pub echo_log: bool,
    /// true while someone can answer approval requests (the GUI is open)
    pub interactive: AtomicBool,
    /// called when approvals change (the GUI repaints / asks for attention)
    pub notify: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
    pub approvals: Mutex<Vec<Arc<Approval>>>,
    next_approval: AtomicU64,
    /// (machine, tool, sudo) -> allowed until
    grants: Mutex<HashMap<(String, Tool, bool), Instant>>,
    /// agent tool call id -> (allowed, decided at); later ops of the same
    /// call (push/pull chunks) reuse the decision
    calls: Mutex<HashMap<u64, (bool, Instant)>>,
    /// usage statistics (persisted to stats.json)
    pub stats: Mutex<Stats>,
    /// wakes the hub link to reconnect immediately
    kick: tokio::sync::Notify,
}

fn mtime() -> Option<SystemTime> {
    std::fs::metadata(store::config_path()).and_then(|m| m.modified()).ok()
}

impl Runtime {
    pub fn new(echo_log: bool) -> Arc<Self> {
        let rt = Arc::new(Self {
            cfg: RwLock::new(Config::default()),
            secrets: Default::default(),
            hub_token: Default::default(),
            targets: Default::default(),
            status: Default::default(),
            hub_status: Mutex::new("starting".into()),
            log: Default::default(),
            redactor: Default::default(),
            changed: watch::channel(0).0,
            reloaded: watch::channel(0).0,
            cfg_mtime: Mutex::new(None),
            echo_log,
            interactive: AtomicBool::new(false),
            notify: Mutex::new(None),
            approvals: Default::default(),
            next_approval: AtomicU64::new(1),
            grants: Default::default(),
            calls: Default::default(),
            stats: Mutex::new(Stats::load()),
            kick: tokio::sync::Notify::new(),
        });
        if let Err(e) = rt.reload() {
            rt.push_log(format!("config error: {e:#}"));
        }
        rt
    }

    pub fn push_log(&self, s: String) {
        let line = format!("{} {s}", chrono::Local::now().format("%H:%M:%S"));
        if self.echo_log {
            eprintln!("{line}");
        }
        let mut l = self.log.lock().unwrap();
        l.push_back(line);
        while l.len() > 1000 {
            l.pop_front();
        }
    }

    /// Re-read config and secrets from disk, rebuild targets.
    pub fn reload(self: &Arc<Self>) -> Result<()> {
        *self.cfg_mtime.lock().unwrap() = mtime();
        let cfg = store::load()?;
        let mut secrets = HashMap::new();
        let mut errs = vec![];
        for c in &cfg.connections {
            match store::conn_secrets(&c.name) {
                Ok(s) => {
                    secrets.insert(c.name.clone(), s);
                }
                Err(e) => errs.push(format!("{e:#}")),
            }
        }
        let token = store::get_secret(store::HUB_TOKEN).unwrap_or_else(|e| {
            errs.push(format!("{e:#}"));
            None
        });

        // redaction patterns
        let mut pats = vec![];
        for c in &cfg.connections {
            if c.kind == Kind::Ssh {
                Redactor::add_host(&mut pats, &c.name, &c.host);
            }
            if let Some(s) = secrets.get(&c.name) {
                for v in [&s.password, &s.passphrase].into_iter().flatten() {
                    Redactor::add_secret(&mut pats, v);
                }
            }
        }
        if let Some(t) = &token {
            Redactor::add_secret(&mut pats, t);
        }

        // targets: keep pooled SSH sessions whose endpoint/secrets are unchanged
        let old = self.targets.read().unwrap().clone();
        let mut targets = HashMap::new();
        for c in cfg.connections.iter().filter(|c| c.enabled) {
            let sec = secrets.get(&c.name).cloned().unwrap_or_default();
            let t = match c.kind {
                Kind::Local => Target::Local,
                Kind::Ssh => match old.get(&c.name) {
                    Some(Target::Ssh(t)) if t.conn.same_endpoint(c) && t.secrets == sec => Target::Ssh(t.clone()),
                    _ => Target::Ssh(Arc::new(SshTarget::new(c.clone(), sec, self.tofu_saver()))),
                },
            };
            targets.insert(c.name.clone(), t);
        }
        // close dropped/changed sessions
        for (name, t) in &old {
            if let Target::Ssh(o) = t {
                let still = matches!(targets.get(name), Some(Target::Ssh(n)) if Arc::ptr_eq(n, o));
                if !still {
                    let o = o.clone();
                    tokio::spawn(async move { o.disconnect().await });
                }
            }
        }
        {
            let mut st = self.status.lock().unwrap();
            st.retain(|k, _| targets.contains_key(k));
            for c in cfg.connections.iter().filter(|c| c.enabled && c.kind == Kind::Local) {
                st.insert(c.name.clone(), MachState { status: "online".into(), os: local::os_label() });
            }
            for c in cfg.connections.iter().filter(|c| c.enabled && c.kind == Kind::Ssh) {
                st.entry(c.name.clone()).or_insert(MachState { status: "connecting".into(), os: String::new() });
            }
        }
        *self.redactor.write().unwrap() = Redactor::new(pats);
        *self.targets.write().unwrap() = targets;
        *self.secrets.write().unwrap() = secrets;
        *self.hub_token.write().unwrap() = token;
        *self.cfg.write().unwrap() = cfg;
        self.reloaded.send_modify(|v| *v += 1);
        self.changed.send_modify(|v| *v += 1);
        if !errs.is_empty() {
            errs.dedup();
            anyhow::bail!(errs.join("; "));
        }
        Ok(())
    }

    fn tofu_saver(self: &Arc<Self>) -> KeyCallback {
        let me = Arc::downgrade(self);
        Box::new(move |name: &str, fp: &str| {
            let r = (|| -> Result<()> {
                let mut c = store::load()?;
                if let Some(conn) = c.get_mut(name) {
                    if conn.host_key.is_empty() {
                        conn.host_key = fp.to_string();
                        store::save(&c)?;
                    }
                }
                Ok(())
            })();
            if let Some(me) = me.upgrade() {
                match r {
                    Ok(()) => {
                        me.push_log(format!("{name}: trusted host key {fp}"));
                        if let Some(conn) = me.cfg.write().unwrap().get_mut(name) {
                            conn.host_key = fp.to_string();
                        }
                        // don't reload here (would drop the pooled session); just
                        // record the mtime so the watcher doesn't either
                        *me.cfg_mtime.lock().unwrap() = mtime();
                    }
                    Err(e) => me.push_log(format!("{name}: failed to save host key: {e:#}")),
                }
            }
        })
    }

    pub fn machines(&self) -> Vec<MachineInfo> {
        let cfg = self.cfg.read().unwrap();
        if cfg.paused {
            return vec![];
        }
        let st = self.status.lock().unwrap();
        let red = self.redactor.read().unwrap();
        cfg.connections
            .iter()
            .filter(|c| c.enabled)
            .map(|c| {
                let s = st.get(&c.name).cloned().unwrap_or_default();
                let mut perms = c.perms;
                if c.kind == Kind::Local && cfg!(windows) {
                    perms.sudo = Access::Deny;
                }
                MachineInfo {
                    alias: c.name.clone(),
                    os: if s.os.is_empty() { "?".into() } else { s.os },
                    description: red.text(&c.description),
                    status: red.text(&s.status),
                    ask: perms.names_with(Access::Ask),
                    denied: perms.names_with(Access::Deny),
                }
            })
            .collect()
    }

    fn set_status(&self, name: &str, status: String, os: Option<String>) {
        let mut st = self.status.lock().unwrap();
        let e = st.entry(name.to_string()).or_default();
        let changed = e.status != status || os.as_ref().is_some_and(|o| *o != e.os);
        e.status = status;
        if let Some(o) = os {
            e.os = o;
        }
        drop(st);
        if changed {
            self.changed.send_modify(|v| *v += 1);
        }
    }

    pub fn target(&self, name: &str) -> Option<Target> {
        self.targets.read().unwrap().get(name).cloned()
    }

    /// Probe one SSH target, updating status. Returns status text.
    pub async fn probe(&self, name: &str) -> String {
        let Some(Target::Ssh(t)) = self.target(name) else { return "online".into() };
        let red = self.redactor.read().unwrap().clone();
        match t.probe().await {
            Ok(os) => {
                self.set_status(name, "online".into(), Some(os.clone()));
                format!("online, {os}")
            }
            Err(e) => {
                let s = format!("error: {}", red.text(&format!("{e:#}")));
                self.set_status(name, s.clone(), None);
                s
            }
        }
    }

    pub fn start(self: &Arc<Self>) {
        // config file watcher (CLI edits while GUI/headless runs)
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                let m = mtime();
                if m != *me.cfg_mtime.lock().unwrap() {
                    match me.reload() {
                        Ok(()) => me.push_log("config reloaded".into()),
                        Err(e) => me.push_log(format!("config reload: {e:#}")),
                    }
                }
            }
        });
        // SSH status prober
        let me = self.clone();
        tokio::spawn(async move {
            let mut rx = me.reloaded.subscribe();
            loop {
                let names: Vec<String> = me
                    .targets
                    .read()
                    .unwrap()
                    .iter()
                    .filter(|(_, t)| matches!(t, Target::Ssh(_)))
                    .map(|(n, _)| n.clone())
                    .collect();
                for n in names {
                    let Some(Target::Ssh(t)) = me.target(&n) else { continue };
                    let online = me.status.lock().unwrap().get(&n).is_some_and(|s| s.status == "online");
                    if online && t.is_connected().await {
                        continue;
                    }
                    let me2 = me.clone();
                    tokio::spawn(async move {
                        me2.probe(&n).await;
                    });
                }
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {}
                    _ = rx.changed() => {}
                }
            }
        });
        // availability samples (once a minute) and periodic statistics save
        let me = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            tick.tick().await;
            loop {
                tick.tick().await;
                let names: Vec<String> = me.cfg.read().unwrap().connections.iter().filter(|c| c.enabled).map(|c| c.name.clone()).collect();
                let st = me.status.lock().unwrap().clone();
                {
                    let mut stats = me.stats.lock().unwrap();
                    for n in names {
                        stats.sample(&n, st.get(&n).is_some_and(|s| s.status.starts_with("online")));
                    }
                }
                let me2 = me.clone();
                let _ = tokio::task::spawn_blocking(move || me2.save_stats()).await;
            }
        });
        // hub link
        let me = self.clone();
        tokio::spawn(async move { me.link_loop().await });
    }

    async fn link_loop(self: Arc<Self>) {
        let mut reload_rx = self.reloaded.subscribe();
        let mut backoff = 1u64;
        loop {
            let url = self.cfg.read().unwrap().hub_url.clone();
            let token = self.hub_token.read().unwrap().clone();
            let res = if url.is_empty() {
                Err(anyhow::anyhow!("no hub URL configured"))
            } else if token.is_none() {
                Err(anyhow::anyhow!("no hub token configured"))
            } else {
                self.session(&url, token.as_deref().unwrap(), &mut reload_rx).await
            };
            match res {
                Ok(()) => backoff = 1,
                Err(e) => {
                    let msg = self.redactor.read().unwrap().text(&format!("{e:#}"));
                    let prev = std::mem::replace(&mut *self.hub_status.lock().unwrap(), format!("disconnected: {msg}"));
                    if !prev.ends_with(&msg) {
                        self.push_log(format!("hub: {msg}"));
                    }
                }
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(backoff)) => backoff = (backoff * 2).min(30),
                _ = reload_rx.changed() => {}
                _ = self.kick.notified() => {
                    backoff = 1;
                    *self.hub_status.lock().unwrap() = "connecting".into();
                }
            }
        }
    }

    /// One connected session with the hub. Returns Ok on clean
    /// reconnect-worthy events (config change), Err on failures.
    async fn session(self: &Arc<Self>, url: &str, token: &str, reload_rx: &mut watch::Receiver<u64>) -> Result<()> {
        let mut req = url.into_client_request().context("invalid hub URL")?;
        req.headers_mut().insert("authorization", format!("Bearer {token}").parse()?);
        let pin = self.cfg.read().unwrap().hub_cert.clone();
        let connector = (url.starts_with("wss://") && !pin.is_empty())
            .then(|| tokio_tungstenite::Connector::Rustls(crate::pin::client_config(&pin)));
        let (ws, _) = tokio::time::timeout(
            Duration::from_secs(20),
            tokio_tungstenite::connect_async_tls_with_config(req, None, true, connector),
        )
            .await
            .map_err(|_| anyhow::anyhow!("connect timed out"))?
            .map_err(|e| match e {
                tokio_tungstenite::tungstenite::Error::Http(r) if r.status() == 401 => anyhow::anyhow!("hub rejected token (401)"),
                e => anyhow::anyhow!("{e}"),
            })?;
        let (mut sink, mut stream) = ws.split();
        let name = self.cfg.read().unwrap().name.clone();
        sink.send(Message::Binary(proto::encode(&Up::Hello { name, version: proto::VERSION.into() }).into())).await?;
        sink.send(Message::Binary(proto::encode(&Up::Machines(self.machines())).into())).await?;
        let plain = url.starts_with("ws://");
        let pinned = !plain && !pin.is_empty();
        let how = if plain { " (unencrypted ws://)" } else if pinned { " (TLS, pinned certificate)" } else { " (TLS)" };
        *self.hub_status.lock().unwrap() = format!("connected{how}");
        self.push_log(format!("hub: connected{how}"));

        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Up>();
        let mut changed_rx = self.changed.subscribe();
        reload_rx.borrow_and_update();
        let mut ping = tokio::time::interval(Duration::from_secs(20));
        let idle = Duration::from_secs(90);
        let mut last_rx = tokio::time::Instant::now();
        let start_url = url.to_string();
        let start_token = token.to_string();
        let start_pin = pin.clone();
        loop {
            tokio::select! {
                m = stream.next() => {
                    last_rx = tokio::time::Instant::now();
                    match m {
                        Some(Ok(Message::Binary(b))) => match proto::decode::<Down>(&b) {
                            Ok(Down::Req { id, machine, op, tool, call }) => {
                                let me = self.clone();
                                let tx = out_tx.clone();
                                tokio::spawn(async move {
                                    let result = me.handle(&machine, op, tool, call).await;
                                    let _ = tx.send(Up::Resp { id, result });
                                });
                            }
                            Ok(Down::Welcome { .. }) => {}
                            Err(e) => self.push_log(format!("bad message from hub: {e}")),
                        },
                        Some(Ok(Message::Close(Some(f)))) if !f.reason.is_empty() => anyhow::bail!("hub closed the connection: {}", f.reason),
                        Some(Ok(Message::Close(_))) | None => anyhow::bail!("hub closed the connection"),
                        Some(Err(e)) => anyhow::bail!("{e}"),
                        Some(Ok(_)) => {}
                    }
                }
                Some(up) = out_rx.recv() => {
                    sink.send(Message::Binary(proto::encode(&up).into())).await?;
                }
                Ok(()) = changed_rx.changed() => {
                    sink.send(Message::Binary(proto::encode(&Up::Machines(self.machines())).into())).await?;
                }
                Ok(()) = reload_rx.changed() => {
                    let url_now = self.cfg.read().unwrap().hub_url.clone();
                    let tok_now = self.hub_token.read().unwrap().clone();
                    let pin_now = self.cfg.read().unwrap().hub_cert.clone();
                    if url_now != start_url || tok_now.as_deref() != Some(start_token.as_str()) || pin_now != start_pin {
                        let _ = sink.close().await;
                        self.push_log("hub: settings changed, reconnecting".into());
                        return Ok(());
                    }
                }
                _ = ping.tick() => {
                    if last_rx.elapsed() > idle {
                        anyhow::bail!("hub not responding");
                    }
                    sink.send(Message::Ping(Vec::new().into())).await?;
                }
            }
        }
    }

    fn summarize(op: &Op) -> Option<String> {
        fn cut(s: &str) -> String {
            let one = s.replace('\n', "; ");
            if one.chars().count() > 100 { format!("{}…", one.chars().take(100).collect::<String>()) } else { one }
        }
        Some(match op {
            Op::Exec { cmd, sudo, .. } => format!("exec{} {}", if *sudo { " [sudo]" } else { "" }, cut(cmd)),
            Op::Read { path, .. } => format!("read {path}"),
            Op::Edit { path, .. } => format!("edit {path}"),
            Op::List { path } => format!("list {path}"),
            Op::Mkdir { path } => format!("mkdir {path}"),
            Op::ReadChunk { path, offset, .. } if *offset == 0 => format!("download {path}"),
            Op::WriteChunk { path, offset, .. } if *offset == 0 => format!("write {path}"),
            Op::ReadChunk { .. } | Op::WriteChunk { .. } => return None,
            Op::Job(j) => match j {
                ccc_proto::JobOp::Start { cmd, sudo, .. } => format!("job start{} {}", if *sudo { " [sudo]" } else { "" }, cut(cmd)),
                ccc_proto::JobOp::Status { id } => format!("job status {id}"),
                ccc_proto::JobOp::Tail { id, .. } => format!("job tail {id}"),
                ccc_proto::JobOp::Kill { id } => format!("job kill {id}"),
                ccc_proto::JobOp::List => "job list".into(),
            },
        })
    }

    /// Full description of an op for the approval dialog.
    fn detail(op: &Op) -> String {
        fn cap(s: &str, n: usize) -> String {
            if s.chars().count() > n { format!("{}\n… ({} chars total)", s.chars().take(n).collect::<String>(), s.chars().count()) } else { s.to_string() }
        }
        match op {
            Op::Exec { cmd, cwd, timeout, .. } => {
                let mut d = cap(cmd, 4000);
                if let Some(c) = cwd {
                    d.push_str(&format!("\n\nin {c}"));
                }
                d.push_str(&format!("\ntimeout {timeout}s"));
                d
            }
            Op::Read { path, .. } => format!("read {path}"),
            Op::Edit { path, old, new, all } => format!(
                "edit {path}{}\n\n--- replace\n{}\n\n+++ with\n{}",
                if *all { " (all occurrences)" } else { "" },
                cap(old, 1500),
                cap(new, 1500)
            ),
            Op::List { path } => format!("download {path} to the server"),
            Op::ReadChunk { path, .. } => format!("download {path} to the server"),
            Op::Mkdir { path } => format!("upload into {path}"),
            Op::WriteChunk { path, data, offset, .. } => {
                let mut d = format!("write {path} ({} bytes{})", data.len(), if *offset > 0 { ", continued" } else { "" });
                match std::str::from_utf8(data) {
                    Ok(t) if !t.is_empty() => d.push_str(&format!("\n\n{}", cap(t, 2000))),
                    Ok(_) => {}
                    Err(_) => d.push_str(" binary"),
                }
                d
            }
            Op::Job(j) => match j {
                JobOp::Start { cmd, cwd, .. } => {
                    format!("start background job:\n{}{}", cap(cmd, 4000), cwd.as_ref().map(|c| format!("\n\nin {c}")).unwrap_or_default())
                }
                JobOp::Kill { id } => format!("kill job {id}"),
                JobOp::Status { id } | JobOp::Tail { id, .. } => format!("look at job {id}"),
                JobOp::List => "list jobs".into(),
            },
        }
    }

    /// Check the connection's permissions for one request; may wait for the
    /// owner's approval.
    async fn authorize(&self, conn: &Connection, tool: Tool, call: u64, op: &Op) -> Result<(), String> {
        let m = &conn.name;
        if !tool.permits(op) {
            return Err(format!("`{}` cannot send this operation", tool.name()));
        }
        let sudo = matches!(op, Op::Exec { sudo: true, .. } | Op::Job(JobOp::Start { sudo: true, .. }));
        let tool_level = conn.perms.get(Perm::Tool(tool));
        let mut level = tool_level;
        // looking at jobs is harmless; only start/kill need approval
        if level == Access::Ask && matches!(op, Op::Job(JobOp::Status { .. } | JobOp::Tail { .. } | JobOp::List)) {
            level = Access::Allow;
        }
        if sudo {
            // sudo can't work on the Windows machine itself: refuse without asking
            let sudo_level = if conn.kind == Kind::Local && cfg!(windows) { Access::Deny } else { conn.perms.sudo };
            level = level.max(sudo_level);
        }
        let refuse = |what: String| {
            self.push_log(format!("{m}: refused `{what}` (not allowed)"));
            Err(format!("the owner of '{m}' does not allow `{what}` on it"))
        };
        match level {
            Access::Allow => Ok(()),
            Access::Deny if tool_level == Access::Deny => refuse(tool.name().into()),
            Access::Deny if conn.kind == Kind::Local && cfg!(windows) => {
                self.push_log(format!("{m}: refused `sudo` (not available on Windows)"));
                Err("sudo is not available on Windows; run the connector as Administrator instead".into())
            }
            Access::Deny => refuse("sudo".into()),
            Access::Ask => self.ask(m, tool, sudo, call, op).await,
        }
    }

    async fn ask(&self, m: &str, tool: Tool, sudo: bool, call: u64, op: &Op) -> Result<(), String> {
        let what = format!("`{}`{}", tool.name(), if sudo { " with sudo" } else { "" });
        {
            let mut calls = self.calls.lock().unwrap();
            calls.retain(|_, (_, t)| t.elapsed() < Duration::from_secs(3600));
            if let Some((ok, _)) = calls.get(&call) {
                return if *ok { Ok(()) } else { Err(format!("the owner refused {what} on '{m}'")) };
            }
        }
        {
            let mut g = self.grants.lock().unwrap();
            let now = Instant::now();
            g.retain(|_, until| *until > now);
            let key = |s: bool| (m.to_string(), tool, s);
            if g.contains_key(&key(sudo)) || (!sudo && g.contains_key(&key(true))) {
                return Ok(());
            }
        }
        if !self.interactive.load(Ordering::Relaxed) {
            self.push_log(format!("{m}: refused {what}: needs approval, but no window is open"));
            return Err(format!(
                "{what} on '{m}' needs the owner's approval, but the connector is running without its window; \
                 ask the owner to allow it or open the connector"
            ));
        }
        let (tx, rx) = oneshot::channel();
        let a = Arc::new(Approval {
            id: self.next_approval.fetch_add(1, Ordering::Relaxed),
            machine: m.to_string(),
            tool,
            sudo,
            detail: Self::detail(op),
            deadline: Instant::now() + APPROVAL_WAIT,
            tx: Mutex::new(Some(tx)),
        });
        self.approvals.lock().unwrap().push(a.clone());
        self.push_log(format!("{m}: waiting for your approval ({what})"));
        self.notify();
        let r = tokio::time::timeout(APPROVAL_WAIT, rx).await;
        self.approvals.lock().unwrap().retain(|x| x.id != a.id);
        self.notify();
        let d = match r {
            Ok(Ok(d)) => Some(d),
            _ => None,
        };
        let ok = matches!(d, Some(Decision::Once | Decision::For(_)));
        self.calls.lock().unwrap().insert(call, (ok, Instant::now()));
        self.stats.lock().unwrap().asked(m, ok);
        match d {
            Some(Decision::Once) => {
                self.push_log(format!("{m}: you approved {what}"));
                Ok(())
            }
            Some(Decision::For(dur)) => {
                self.grants.lock().unwrap().insert((m.to_string(), tool, sudo), Instant::now() + dur);
                self.push_log(format!("{m}: you allowed {what} for {} min", dur.as_secs() / 60));
                Ok(())
            }
            Some(Decision::Deny) => {
                self.push_log(format!("{m}: you denied {what}"));
                Err(format!("the owner refused {what} on '{m}'"))
            }
            None => {
                self.push_log(format!("{m}: {what} not approved in time"));
                Err(format!("the owner did not approve {what} on '{m}' within {}s", APPROVAL_WAIT.as_secs()))
            }
        }
    }

    /// Answer a pending approval (from the GUI).
    pub fn decide(&self, id: u64, d: Decision) {
        let a = self.approvals.lock().unwrap().iter().find(|a| a.id == id).cloned();
        if let Some(tx) = a.and_then(|a| a.tx.lock().unwrap().take()) {
            let _ = tx.send(d);
        }
    }

    /// Withdraw all temporary "allow for N minutes" grants.
    pub fn revoke_grants(&self) {
        self.grants.lock().unwrap().clear();
    }

    pub fn active_grants(&self) -> Vec<(String, Tool, bool, Duration)> {
        let now = Instant::now();
        let mut v: Vec<_> = self
            .grants
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, u)| **u > now)
            .map(|((m, t, s), u)| (m.clone(), *t, *s, *u - now))
            .collect();
        v.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.name().cmp(b.1.name())));
        v
    }

    fn notify(&self) {
        if let Some(f) = self.notify.lock().unwrap().as_ref() {
            f();
        }
    }

    pub async fn handle(&self, machine: &str, op: Op, tool: Tool, call: u64) -> ccc_proto::OpResult {
        let up = match &op {
            Op::WriteChunk { data, .. } => data.len() as u64,
            _ => 0,
        };
        let started = Instant::now();
        let (res, ran) = self.handle_inner(machine, op, tool, call).await;
        let outcome = match (&res, ran) {
            // a command that exits non-zero or times out counts as failed
            (Ok(ccc_proto::OpOk::Exec { code, timed_out, .. }), _) if *timed_out || *code != Some(0) => Outcome::Failed,
            (Ok(_), _) => Outcome::Ok,
            (Err(_), true) => Outcome::Failed,
            (Err(_), false) => Outcome::Refused,
        };
        let down = match &res {
            Ok(ccc_proto::OpOk::Bytes(b)) => b.len() as u64,
            _ => 0,
        };
        let ms = ran.then(|| started.elapsed().as_millis() as u64);
        let known = self.cfg.read().unwrap().get(machine).is_some();
        if known {
            self.stats.lock().unwrap().record(machine, tool, call, outcome, ms, up, down);
        }
        res
    }

    /// Returns the result and whether the op actually ran (false = refused
    /// by permissions, pause or an unknown machine).
    async fn handle_inner(&self, machine: &str, op: Op, tool: Tool, call: u64) -> (ccc_proto::OpResult, bool) {
        if let Some(s) = Self::summarize(&op) {
            self.push_log(format!("{machine}: {s}"));
        }
        let (conn, paused) = {
            let cfg = self.cfg.read().unwrap();
            (cfg.get(machine).filter(|c| c.enabled).cloned(), cfg.paused)
        };
        if paused {
            return (Err("connector is paused by its user".into()), false);
        }
        let (Some(conn), Some(target)) = (conn, self.target(machine)) else {
            return (Err(format!("machine '{machine}' is not available")), false);
        };
        if let Err(e) = self.authorize(&conn, tool, call, &op).await {
            return (Err(e), false);
        }
        // the owner may have paused or changed permissions while we waited
        if self.cfg.read().unwrap().paused {
            return (Err("connector is paused by its user".into()), false);
        }
        let secrets = self.secrets.read().unwrap().get(machine).cloned().unwrap_or_default();
        let ctx = Ctx { target: &target, conn: &conn, secrets: &secrets };
        let res = ops::handle(&ctx, op).await;
        if let Err(e) = &res {
            self.push_log(format!("{machine}: error: {}", self.redactor.read().unwrap().text(e)));
        }
        // refresh status if an SSH op failed due to connectivity
        if let (Err(_), Target::Ssh(t)) = (&res, &target) {
            if !t.is_connected().await {
                self.set_status(machine, "error: connection lost".into(), None);
            }
        } else if res.is_ok() && matches!(target, Target::Ssh(_)) {
            let online = self.status.lock().unwrap().get(machine).is_some_and(|s| s.status == "online");
            if !online {
                self.set_status(machine, "online".into(), None);
            }
        }
        (self.redactor.read().unwrap().result(res), true)
    }

    /// Retry a connection now (GUI: click on a failed dot).
    pub async fn retry(&self, name: &str) -> String {
        self.set_status(name, "connecting".into(), None);
        self.push_log(format!("{name}: retrying connection"));
        let r = self.probe(name).await;
        self.push_log(format!("{name}: {r}"));
        r
    }

    /// Reconnect to the hub now instead of waiting for the retry backoff.
    pub fn reconnect_hub(&self) {
        self.kick.notify_one();
    }

    pub fn save_stats(&self) {
        let mut st = self.stats.lock().unwrap();
        if st.dirty {
            if let Err(e) = st.save() {
                drop(st);
                self.push_log(format!("could not save statistics: {e:#}"));
            }
        }
    }
}

/// One-off connection test (CLI `test`, GUI "Test"). Trusts and saves the
/// host key on first use. Returns a human-readable result.
pub async fn test_connection(name: &str) -> Result<String> {
    let cfg = store::load()?;
    let conn = cfg.get(name).cloned().with_context(|| format!("no connection '{name}'"))?;
    if conn.kind == Kind::Local {
        let o = local::run(crate::exec::Run {
            script: if cfg!(windows) { "Write-Output ok" } else { "echo ok" },
            stdin: None,
            timeout: Duration::from_secs(20),
            display: true,
        })
        .await?;
        return Ok(format!("local shell ok (exit {:?}), {}", o.code, local::os_label()));
    }
    let secrets = store::conn_secrets(name)?;
    let saved = Arc::new(Mutex::new(None::<String>));
    let s2 = saved.clone();
    let t = SshTarget::new(
        conn.clone(),
        secrets,
        Box::new(move |name: &str, fp: &str| {
            if let Ok(mut c) = store::load() {
                if let Some(conn) = c.get_mut(name) {
                    conn.host_key = fp.to_string();
                    let _ = store::save(&c);
                }
            }
            *s2.lock().unwrap() = Some(fp.to_string());
        }),
    );
    let os = t.probe().await?;
    let mut s = format!("ok: {os}");
    if conn.perms.sudo != Access::Deny {
        let sudo = t
            .run(crate::exec::Run {
                script: "sudo -k -S -p '' true 2>&1 && echo SUDO_OK",
                stdin: t.secrets.password.as_ref().map(|p| format!("{p}\n").into_bytes()),
                timeout: Duration::from_secs(15),
                display: true,
            })
            .await?;
        let out = String::from_utf8_lossy(&sudo.stdout);
        s.push_str(if out.contains("SUDO_OK") { "; sudo works" } else { "; sudo FAILED (wrong/missing password or user not in sudoers)" });
    }
    match saved.lock().unwrap().clone() {
        Some(fp) => s.push_str(&format!("\nnew host key trusted: {fp}")),
        None => s.push_str(&format!("\nhost key: {}", conn.host_key)),
    }
    t.disconnect().await;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Perms;

    fn op_exec(sudo: bool) -> Op {
        Op::Exec { cmd: "ls".into(), cwd: None, timeout: 5, sudo }
    }

    /// Answer every approval request with `d` from a background task.
    fn auto_answer(rt: &Arc<Runtime>, d: Decision) -> tokio::task::JoinHandle<()> {
        let rt = rt.clone();
        tokio::spawn(async move {
            loop {
                let ids: Vec<u64> = rt.approvals.lock().unwrap().iter().map(|a| a.id).collect();
                for id in ids {
                    rt.decide(id, d);
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    }

    #[tokio::test]
    async fn permissions_and_approvals() {
        let dir = std::env::temp_dir().join(format!("ccc-test-{}", std::process::id()));
        std::env::set_var("CCC_DIR", &dir);
        std::env::set_var("CCC_SECRETS", "file");
        let rt = Runtime::new(false);
        let mut conn = Connection { name: "m".into(), kind: Kind::Local, ..Default::default() };
        conn.perms = Perms::read_only(Access::Ask);
        conn.perms.push = Access::Deny;
        conn.perms.sudo = Access::Deny;

        // allowed / denied without asking
        assert!(rt.authorize(&conn, Tool::Read, 1, &Op::Read { path: "x".into(), offset: 1, limit: 1 }).await.is_ok());
        let e = rt.authorize(&conn, Tool::Push, 2, &Op::Mkdir { path: "x".into() }).await.unwrap_err();
        assert!(e.contains("does not allow `push`"), "{e}");
        // a tool can't carry another tool's op
        assert!(rt.authorize(&conn, Tool::Read, 3, &op_exec(false)).await.is_err());
        // job status is free even when job is "ask"
        assert!(rt.authorize(&conn, Tool::Job, 4, &Op::Job(JobOp::List)).await.is_ok());

        // headless: ask is refused
        let e = rt.authorize(&conn, Tool::Exec, 5, &op_exec(false)).await.unwrap_err();
        assert!(e.contains("without its window"), "{e}");

        rt.interactive.store(true, Ordering::Relaxed);
        // sudo denied even though exec would be asked
        let e = rt.authorize(&conn, Tool::Exec, 6, &op_exec(true)).await.unwrap_err();
        assert!(e.contains("sudo"), "{e}");

        // deny
        let h = auto_answer(&rt, Decision::Deny);
        let e = rt.authorize(&conn, Tool::Exec, 7, &op_exec(false)).await.unwrap_err();
        assert!(e.contains("refused"), "{e}");
        h.abort();
        // the same call stays refused without asking again
        assert!(rt.authorize(&conn, Tool::Exec, 7, &op_exec(false)).await.is_err());

        // once: only this call
        let h = auto_answer(&rt, Decision::Once);
        assert!(rt.authorize(&conn, Tool::Write, 8, &Op::Mkdir { path: "x".into() }).await.is_err()); // wrong op
        let w = |n| Op::WriteChunk { path: "f".into(), offset: n, data: vec![1], mode: None };
        assert!(rt.authorize(&conn, Tool::Write, 9, &w(0)).await.is_ok());
        h.abort();
        assert!(rt.authorize(&conn, Tool::Write, 9, &w(1)).await.is_ok()); // same call, no prompt
        assert!(rt.approvals.lock().unwrap().is_empty());

        // for 15 min: later calls pass without a prompt
        let h = auto_answer(&rt, Decision::For(Duration::from_secs(900)));
        assert!(rt.authorize(&conn, Tool::Edit, 10, &Op::Edit { path: "f".into(), old: "a".into(), new: "b".into(), all: false }).await.is_ok());
        h.abort();
        assert!(rt.authorize(&conn, Tool::Edit, 11, &Op::Edit { path: "g".into(), old: "a".into(), new: "b".into(), all: false }).await.is_ok());
        assert_eq!(rt.active_grants().len(), 1);
        rt.revoke_grants();
        // after revoking, a new call asks again (nobody answers -> times out; check it's pending)
        let rt2 = rt.clone();
        let c2 = conn.clone();
        let t = tokio::spawn(async move { rt2.authorize(&c2, Tool::Edit, 12, &Op::Edit { path: "g".into(), old: "a".into(), new: "b".into(), all: false }).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let pending: Vec<_> = rt.approvals.lock().unwrap().iter().map(|a| (a.machine.clone(), a.tool, a.detail.clone())).collect();
        assert_eq!(pending.len(), 1);
        assert!(pending[0].2.contains("--- replace"), "{}", pending[0].2);
        let id = rt.approvals.lock().unwrap()[0].id;
        rt.decide(id, Decision::Deny);
        assert!(t.await.unwrap().is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
