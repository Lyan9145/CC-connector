//! The running connector: config/secrets state, SSH targets, status probing
//! and the WebSocket link to the hub.

use crate::exec::{local, ssh::{KeyCallback, SshTarget}};
use crate::ops::{self, Ctx, Target};
use crate::redact::Redactor;
use crate::store::{self, Config, Kind, Secrets};
use anyhow::{Context, Result};
use ccc_proto::{self as proto, Down, MachineInfo, Op, Up};
use futures_util::{SinkExt, StreamExt};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};
use tokio::sync::{mpsc, watch};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

#[derive(Clone, Default)]
pub struct MachState {
    pub status: String,
    pub os: String,
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
                let windows = c.kind == Kind::Local && cfg!(windows);
                MachineInfo {
                    alias: c.name.clone(),
                    os: if s.os.is_empty() { "?".into() } else { s.os },
                    description: red.text(&c.description),
                    status: red.text(&s.status),
                    sudo: c.allow_sudo && !windows,
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
                _ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
                _ = reload_rx.changed() => {}
            }
            backoff = (backoff * 2).min(30);
        }
    }

    /// One connected session with the hub. Returns Ok on clean
    /// reconnect-worthy events (config change), Err on failures.
    async fn session(self: &Arc<Self>, url: &str, token: &str, reload_rx: &mut watch::Receiver<u64>) -> Result<()> {
        let mut req = url.into_client_request().context("invalid hub URL")?;
        req.headers_mut().insert("authorization", format!("Bearer {token}").parse()?);
        let (ws, _) = tokio::time::timeout(Duration::from_secs(20), tokio_tungstenite::connect_async(req))
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
        *self.hub_status.lock().unwrap() = if plain { "connected (unencrypted ws://)".into() } else { "connected".into() };
        self.push_log(format!("hub: connected{}", if plain { " (unencrypted ws://)" } else { "" }));

        let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Up>();
        let mut changed_rx = self.changed.subscribe();
        reload_rx.borrow_and_update();
        let mut ping = tokio::time::interval(Duration::from_secs(20));
        let idle = Duration::from_secs(90);
        let mut last_rx = tokio::time::Instant::now();
        let start_url = url.to_string();
        let start_token = token.to_string();
        loop {
            tokio::select! {
                m = stream.next() => {
                    last_rx = tokio::time::Instant::now();
                    match m {
                        Some(Ok(Message::Binary(b))) => match proto::decode::<Down>(&b) {
                            Ok(Down::Req { id, machine, op }) => {
                                let me = self.clone();
                                let tx = out_tx.clone();
                                tokio::spawn(async move {
                                    let result = me.handle(&machine, op).await;
                                    let _ = tx.send(Up::Resp { id, result });
                                });
                            }
                            Ok(Down::Welcome { .. }) => {}
                            Err(e) => self.push_log(format!("bad message from hub: {e}")),
                        },
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
                    if url_now != start_url || tok_now.as_deref() != Some(start_token.as_str()) {
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

    pub async fn handle(&self, machine: &str, op: Op) -> ccc_proto::OpResult {
        if let Some(s) = Self::summarize(&op) {
            self.push_log(format!("{machine}: {s}"));
        }
        let (conn, paused) = {
            let cfg = self.cfg.read().unwrap();
            (cfg.get(machine).filter(|c| c.enabled).cloned(), cfg.paused)
        };
        if paused {
            return Err("connector is paused by its user".into());
        }
        let (Some(conn), Some(target)) = (conn, self.target(machine)) else {
            return Err(format!("machine '{machine}' is not available"));
        };
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
        self.redactor.read().unwrap().result(res)
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
    if conn.allow_sudo {
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
