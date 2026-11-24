//! Hub daemon: accepts connector WebSockets and serves local IPC requests
//! from the MCP shim, routing them to the right connector.

use crate::config::{self, HubConfig, Token};
use crate::tokens;
use crate::users::{self, Caller};
use anyhow::{Context, Result};
use ccc_proto::{self as proto, Down, IpcReq, IpcResp, Listed, MachineInfo, McpOp, Op, OpResult, Session, TokenReq, TokenResp, Tool, Up};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{mpsc, oneshot};
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message;

struct Conn {
    name: String,
    /// the token this connector authenticated with
    token: Token,
    tx: mpsc::UnboundedSender<Down>,
    machines: Vec<MachineInfo>,
}

/// Settings that apply while running (reloaded with hub.toml).
#[derive(Debug, Clone, Default, PartialEq)]
struct Settings {
    multi_user: bool,
    root_all_access: bool,
}

impl Settings {
    fn of(c: &HubConfig) -> Self {
        Settings { multi_user: c.multi_user, root_all_access: c.root_all_access }
    }
}

/// Connector identity that survives reconnects: (token name, connector name).
type ConnKey = (String, String);

#[derive(Default)]
struct Hub {
    /// accepted tokens; reloaded from hub.toml while running
    tokens: std::sync::RwLock<Vec<Token>>,
    settings: std::sync::RwLock<Settings>,
    conns: Mutex<HashMap<u64, Conn>>,
    pending: Mutex<HashMap<u64, (u64, oneshot::Sender<OpResult>)>>,
    /// connectors each (scoped) agent session has used, so its end is told
    /// only to them
    sessions: Mutex<HashMap<u64, (Instant, HashSet<ConnKey>)>>,
    /// serializes token changes made through the socket
    cfg_lock: Mutex<()>,
    next: AtomicU64,
}

/// The session id the connectors see: derived from the caller's uid, so one
/// user can neither reuse nor end another user's session (and its grants).
/// On a multi-user hub the label starts with the user name.
fn scope_session(who: &Caller, s: Session, multi_user: bool) -> Session {
    let mut h = Sha256::new();
    h.update(who.uid.to_le_bytes());
    h.update(s.id.to_le_bytes());
    let id = u64::from_le_bytes(h.finalize()[..8].try_into().unwrap()) | 1;
    let label = if multi_user { format!("{}: {}", who.name, s.label) } else { s.label };
    Session { id, label }
}

impl Hub {
    fn id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// The machines `who` may use. Names are made unique within that view
    /// only, so they don't reveal other users' connectors.
    fn listed(&self, who: &Caller) -> Vec<(Listed, u64)> {
        let root_all = self.settings.read().unwrap().root_all_access;
        let tokens = self.tokens.read().unwrap();
        let conns = self.conns.lock().unwrap();
        let visible: Vec<(u64, &Conn)> = conns
            .iter()
            .filter(|(_, c)| tokens.iter().find(|t| t.name == c.token.name).is_some_and(|t| config::can_use(t, who, root_all)))
            .map(|(id, c)| (*id, c))
            .collect();
        let mut count: HashMap<&str, usize> = HashMap::new();
        let mut conn_names: HashMap<&str, usize> = HashMap::new();
        for (_, c) in &visible {
            *conn_names.entry(c.name.as_str()).or_default() += 1;
            for m in &c.machines {
                *count.entry(m.alias.as_str()).or_default() += 1;
            }
        }
        let mut out = vec![];
        for (cid, c) in visible {
            // two visible connectors with one name (different tokens): tell them apart by token
            let via = if conn_names[c.name.as_str()] > 1 { c.token.name.clone() } else { c.name.clone() };
            for m in &c.machines {
                let name = if count[m.alias.as_str()] > 1 { format!("{via}/{}", m.alias) } else { m.alias.clone() };
                out.push((Listed { name, via: via.clone(), info: m.clone() }, cid));
            }
        }
        out.sort_by(|a, b| a.0.name.cmp(&b.0.name));
        out
    }

    async fn request(&self, who: &Caller, machine: &str, op: Op, tool: Tool, call: u64, session: Session) -> OpResult {
        let listed = self.listed(who);
        let Some((listed, cid)) = listed.iter().find(|(l, _)| l.name == machine).cloned() else {
            let names: Vec<String> = listed.into_iter().map(|(l, _)| l.name).collect();
            return Err(format!("unknown machine '{machine}'. available: {}", if names.is_empty() { "(none)".into() } else { names.join(", ") }));
        };
        let session = scope_session(who, session, self.settings.read().unwrap().multi_user);
        if let Some(c) = self.conns.lock().unwrap().get(&cid) {
            let key = (c.token.name.clone(), c.name.clone());
            let mut ss = self.sessions.lock().unwrap();
            ss.retain(|_, (t, _)| t.elapsed() < Duration::from_secs(24 * 3600));
            let e = ss.entry(session.id).or_insert_with(|| (Instant::now(), HashSet::new()));
            e.0 = Instant::now();
            e.1.insert(key);
        }
        // leave room for the owner to approve "ask" requests (up to 2 min)
        let timeout = match &op {
            Op::Exec { timeout, .. } => Duration::from_secs(timeout + 180),
            // 0 = the server's own default, which the hub doesn't know (at most 3600)
            Op::Mcp(McpOp::Call { timeout, .. }) => Duration::from_secs(if *timeout == 0 { 3600 } else { *timeout } + 180),
            _ => Duration::from_secs(600),
        };
        let id = self.id();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, (cid, tx));
        let sent = {
            let conns = self.conns.lock().unwrap();
            conns.get(&cid).map(|c| c.tx.send(Down::Req { id, machine: listed.info.alias.clone(), op, tool, call, session }).is_ok())
        };
        if sent != Some(true) {
            self.pending.lock().unwrap().remove(&id);
            return Err("machine went offline".into());
        }
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err("connector disconnected during request".into()),
            Err(_) => {
                self.pending.lock().unwrap().remove(&id);
                Err(format!("no response from connector after {}s", timeout.as_secs()))
            }
        }
    }

    /// Tell the connectors a session used that it ended.
    fn end_session(&self, who: &Caller, id: u64) {
        let id = scope_session(who, Session { id, label: String::new() }, false).id;
        let Some((_, used)) = self.sessions.lock().unwrap().remove(&id) else { return };
        for c in self.conns.lock().unwrap().values() {
            if used.contains(&(c.token.name.clone(), c.name.clone())) {
                let _ = c.tx.send(Down::EndSession { id });
            }
        }
    }

    /// `ccc-hub token ...` from a local user: apply it to hub.toml as them.
    fn token_op(&self, who: &Caller, req: TokenReq) -> Result<TokenResp> {
        let _g = self.cfg_lock.lock().unwrap();
        let mut cfg = HubConfig::load()?;
        let (mut resp, changed) = tokens::apply(&mut cfg, who, req, &users::owner_exists)?;
        if changed {
            cfg.save()?;
            eprintln!("tokens changed by '{}'", who.name);
            self.set_tokens(cfg.tokens.clone());
        }
        match &mut resp {
            TokenResp::Created { token, pairing, .. } => *pairing = config::pairing_for(&cfg, token),
            TokenResp::List(list) => {
                let conns = self.conns.lock().unwrap();
                for t in list {
                    t.online = Some(conns.values().any(|c| c.token.name == t.name));
                }
            }
            TokenResp::Done(_) => {}
        }
        Ok(resp)
    }

    /// Apply a changed token list: new tokens work at once, connectors whose
    /// token was revoked or replaced are disconnected. Changed owners apply
    /// to the next request (looked up by token name).
    fn set_tokens(&self, tokens: Vec<Token>) {
        let gone: Vec<(u64, String, String)> = self
            .conns
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, c)| !tokens.iter().any(|t| t.name == c.token.name && t.sha256 == c.token.sha256))
            .map(|(id, c)| (*id, c.name.clone(), c.token.name.clone()))
            .collect();
        eprintln!("tokens reloaded ({} configured)", tokens.len());
        *self.tokens.write().unwrap() = tokens;
        for (cid, name, tok) in gone {
            eprintln!("disconnecting '{name}': token '{tok}' was revoked or replaced");
            self.drop_conn(cid);
        }
    }

    /// An answer from connector `cid`; only the connector a request went to
    /// may answer it.
    fn resolve(&self, cid: u64, id: u64, result: OpResult) {
        let mut p = self.pending.lock().unwrap();
        if p.get(&id).is_some_and(|(c, _)| *c == cid) {
            if let Some((_, tx)) = p.remove(&id) {
                let _ = tx.send(result);
            }
        }
    }

    fn drop_conn(&self, cid: u64) {
        if let Some(c) = self.conns.lock().unwrap().remove(&cid) {
            eprintln!("connector '{}' disconnected", c.name);
        }
        let mut p = self.pending.lock().unwrap();
        let ids: Vec<u64> = p.iter().filter(|(_, (c, _))| *c == cid).map(|(i, _)| *i).collect();
        for i in ids {
            if let Some((_, tx)) = p.remove(&i) {
                let _ = tx.send(Err("connector disconnected".into()));
            }
        }
    }
}

pub async fn serve(cfg: HubConfig) -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let hub = Arc::new(Hub::default());
    *hub.tokens.write().unwrap() = cfg.tokens.clone();
    *hub.settings.write().unwrap() = Settings::of(&cfg);
    let cfg = Arc::new(cfg);

    // Reload tokens when hub.toml changes (`ccc-hub token new/pair/revoke`).
    let h = hub.clone();
    tokio::spawn(async move {
        let mtime = || std::fs::metadata(config::path()).and_then(|m| m.modified()).ok();
        let mut last = mtime();
        loop {
            tokio::time::sleep(Duration::from_secs(2)).await;
            let now = mtime();
            if now == last {
                continue;
            }
            last = now;
            match HubConfig::load() {
                Ok(c) => {
                    let st = Settings::of(&c);
                    let old = std::mem::replace(&mut *h.settings.write().unwrap(), st.clone());
                    if old.multi_user != st.multi_user {
                        eprintln!("multi_user changed; restart the hub to move the socket");
                    }
                    if old.root_all_access != st.root_all_access {
                        eprintln!("root_all_access is now {}", if st.root_all_access { "on" } else { "off" });
                    }
                    if *h.tokens.read().unwrap() != c.tokens {
                        h.set_tokens(c.tokens);
                    }
                }
                Err(e) => eprintln!("hub.toml changed but could not be read: {e:#}"),
            }
        }
    });

    // Local IPC for the MCP shim.
    let sock = cfg.socket_path();
    if let Some(d) = sock.parent() {
        let fresh = !d.exists();
        std::fs::create_dir_all(d).with_context(|| {
            format!("create {} (a multi-user hub not running as root needs `socket = \"...\"` in hub.toml)", d.display())
        })?;
        if fresh && cfg.multi_user {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755))?;
        }
    }
    let _ = std::fs::remove_file(&sock);
    let ipc = UnixListener::bind(&sock).with_context(|| format!("bind {}", sock.display()))?;
    {
        // multi-user: every local user may connect; each sees only their machines
        use std::os::unix::fs::PermissionsExt;
        let mode = if cfg.multi_user { 0o666 } else { 0o600 };
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(mode))?;
    }
    eprintln!("ipc socket: {}{}", sock.display(), if cfg.multi_user { " (multi-user)" } else { "" });
    let h = hub.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = ipc.accept().await else { continue };
            let h = h.clone();
            tokio::spawn(async move {
                // the kernel tells who is calling; that decides what they see
                let Ok(cred) = s.peer_cred() else { return };
                let uid = cred.uid();
                let Ok(who) = tokio::task::spawn_blocking(move || Caller::from_uid(uid)).await else { return };
                let Ok(req) = proto::read_frame::<_, IpcReq>(&mut s).await else { return };
                let resp = match req {
                    IpcReq::Machines => IpcResp::Machines(h.listed(&who).into_iter().map(|(l, _)| l).collect()),
                    IpcReq::Op { machine, op, tool, call, session } => IpcResp::Result(h.request(&who, &machine, op, tool, call, session).await),
                    IpcReq::EndSession { id } => {
                        h.end_session(&who, id);
                        IpcResp::Result(Ok(proto::OpOk::Done { n: 0 }))
                    }
                    IpcReq::Token(req) => {
                        let h = h.clone();
                        let who = who.clone();
                        let r = tokio::task::spawn_blocking(move || h.token_op(&who, req)).await;
                        IpcResp::Token(match r {
                            Ok(r) => r.map_err(|e| format!("{e:#}")),
                            Err(e) => Err(e.to_string()),
                        })
                    }
                };
                let _ = proto::write_frame(&mut s, &resp).await;
            });
        }
    });

    // TLS (optional).
    let tls = if !cfg.tls_cert.is_empty() {
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(load_tls(&cfg.tls_cert, &cfg.tls_key)?)))
    } else {
        None
    };
    if hub.tokens.read().unwrap().is_empty() {
        eprintln!("warning: no tokens configured; create one with `ccc-hub token new <name>`");
    }
    let listener = TcpListener::bind(&cfg.listen).await.with_context(|| format!("bind {}", cfg.listen))?;
    eprintln!("listening on {} ({})", cfg.listen, if tls.is_some() { "wss" } else { "ws; put TLS in front of it" });
    if let Ok(fp) = crate::config::cert_fingerprint(&cfg.tls_cert) {
        eprintln!("certificate {fp}");
    }
    loop {
        let (tcp, _) = listener.accept().await?;
        let _ = tcp.set_nodelay(true);
        let hub = hub.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let r = match tls {
                Some(acc) => match acc.accept(tcp).await {
                    Ok(s) => handle(hub, s).await,
                    Err(e) => Err(e.into()),
                },
                None => handle(hub, tcp).await,
            };
            if let Err(e) = r {
                eprintln!("connection ended: {e:#}");
            }
        });
    }
}

fn load_tls(cert: &str, key: &str) -> Result<rustls::ServerConfig> {
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(cert).context("open tls_cert")?))
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(key).context("open tls_key")?))?
        .context("no private key in tls_key")?;
    Ok(rustls::ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?)
}

#[allow(clippy::result_large_err)]
async fn handle<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(hub: Arc<Hub>, stream: S) -> Result<()> {
    let mut token_name = None;
    let ws = tokio_tungstenite::accept_hdr_async(stream, |req: &Request, resp: Response| {
        let tok = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        match config::check_token(&hub.tokens.read().unwrap(), tok) {
            Some(t) => {
                token_name = Some(t);
                Ok(resp)
            }
            None => {
                let mut e = ErrorResponse::new(Some("bad token".into()));
                *e.status_mut() = StatusCode::UNAUTHORIZED;
                Err(e)
            }
        }
    })
    .await
    .context("handshake")?;
    let Some(token) = token_name else { return Ok(()) };
    let token_name = token.name.clone();
    let (mut sink, mut stream) = ws.split();

    // First message must be Hello.
    let name = loop {
        match stream.next().await {
            Some(Ok(Message::Binary(b))) => match proto::decode::<Up>(&b)? {
                Up::Hello { name, version } => {
                    if !proto::compatible(&version, proto::VERSION) {
                        let why = format!("connector v{version} does not match hub v{}; update the connector", proto::VERSION);
                        eprintln!("connector '{name}' rejected: {why}");
                        let frame = tokio_tungstenite::tungstenite::protocol::CloseFrame {
                            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Policy,
                            reason: why.into(),
                        };
                        let _ = sink.send(Message::Close(Some(frame))).await;
                        return Ok(());
                    }
                    eprintln!("connector '{name}' connected (token '{token_name}', v{version})");
                    break name;
                }
                _ => anyhow::bail!("expected hello"),
            },
            Some(Ok(_)) => continue,
            _ => return Ok(()),
        }
    };
    let (tx, mut rx) = mpsc::unbounded_channel::<Down>();
    let cid = hub.id();
    {
        let mut conns = hub.conns.lock().unwrap();
        // A reconnect replaces the stale session of the same connector (same
        // token: a connector can't push out another token's connector).
        conns.retain(|_, c| !(c.name == name && c.token.name == token.name));
        conns.insert(cid, Conn { name: name.clone(), token, tx: tx.clone(), machines: vec![] });
    }
    let _ = tx.send(Down::Welcome { version: proto::VERSION.into() });
    drop(tx); // the registry holds the only sender; removing it closes the writer

    let writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(Duration::from_secs(25));
        loop {
            tokio::select! {
                m = rx.recv() => match m {
                    Some(m) => if sink.send(Message::Binary(proto::encode(&m).into())).await.is_err() { break },
                    None => break,
                },
                _ = ping.tick() => if sink.send(Message::Ping(Vec::new().into())).await.is_err() { break },
            }
        }
        let _ = sink.close().await;
    });

    let idle = Duration::from_secs(90);
    loop {
        let msg = match tokio::time::timeout(idle, stream.next()).await {
            Ok(Some(Ok(m))) => m,
            _ => break,
        };
        let Message::Binary(b) = msg else {
            if matches!(msg, Message::Close(_)) {
                break;
            }
            continue;
        };
        match proto::decode::<Up>(&b) {
            Ok(Up::Machines(list)) => {
                if let Some(c) = hub.conns.lock().unwrap().get_mut(&cid) {
                    c.machines = list;
                }
            }
            Ok(Up::Resp { id, result }) => hub.resolve(cid, id, result),
            Ok(Up::Hello { .. }) => {}
            Err(e) => eprintln!("bad message from '{name}': {e}"),
        }
        if !hub.conns.lock().unwrap().contains_key(&cid) {
            break; // replaced by a newer session
        }
    }
    hub.drop_conn(cid);
    writer.abort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(uid: u32, name: &str, groups: &[&str]) -> Caller {
        Caller { uid, name: name.into(), groups: groups.iter().map(|s| s.to_string()).collect(), admin: false }
    }
    fn root() -> Caller {
        Caller { uid: 0, name: "root".into(), groups: vec![], admin: true }
    }
    fn tok(name: &str, owners: &[&str]) -> Token {
        Token { name: name.into(), sha256: format!("h-{name}"), owners: owners.iter().map(|s| s.to_string()).collect(), created_by: String::new() }
    }
    fn machine(alias: &str) -> MachineInfo {
        MachineInfo {
            alias: alias.into(),
            os: String::new(),
            description: String::new(),
            status: "online".into(),
            ask: vec![],
            denied: vec![],
            folders: String::new(),
            mcp: vec![],
        }
    }

    /// A hub with connectors (conn name, token, machine aliases); returns
    /// each connector's receiving end.
    fn hub(tokens: Vec<Token>, conns: &[(&str, &str, &[&str])]) -> (Hub, Vec<mpsc::UnboundedReceiver<Down>>) {
        let h = Hub { settings: std::sync::RwLock::new(Settings { multi_user: true, root_all_access: true }), ..Default::default() };
        let mut rxs = vec![];
        for (name, token, aliases) in conns {
            let (tx, rx) = mpsc::unbounded_channel();
            let token = tokens.iter().find(|t| t.name == *token).unwrap().clone();
            let id = h.id();
            h.conns.lock().unwrap().insert(id, Conn { name: name.to_string(), token, tx, machines: aliases.iter().map(|a| machine(a)).collect() });
            rxs.push(rx);
        }
        *h.tokens.write().unwrap() = tokens;
        (h, rxs)
    }
    fn names(h: &Hub, who: &Caller) -> Vec<String> {
        h.listed(who).into_iter().map(|(l, _)| l.name).collect()
    }

    #[test]
    fn listing_is_per_owner() {
        let (h, _rx) = hub(
            vec![tok("a", &["alice"]), tok("b", &["bob"]), tok("r", &["alice", "@lab"]), tok("adm", &[])],
            &[("alice-pc", "a", &["laptop"]), ("bob-pc", "b", &["laptop"]), ("robot", "r", &["robot"]), ("box", "adm", &["box"])],
        );
        assert_eq!(names(&h, &user(1, "alice", &[])), vec!["laptop", "robot"]);
        assert_eq!(names(&h, &user(2, "bob", &[])), vec!["laptop"]);
        assert_eq!(names(&h, &user(3, "carol", &["lab"])), vec!["robot"]);
        assert!(names(&h, &user(4, "dave", &[])).is_empty());
        assert_eq!(names(&h, &root()), vec!["alice-pc/laptop", "bob-pc/laptop", "box", "robot"]);
        h.settings.write().unwrap().root_all_access = false;
        assert_eq!(names(&h, &root()), vec!["box"]);
    }

    #[test]
    fn same_connector_name_on_two_tokens() {
        let (h, _rx) = hub(vec![tok("a", &["x"]), tok("b", &["x"])], &[("pc", "a", &["m"]), ("pc", "b", &["m"])]);
        assert_eq!(names(&h, &user(1, "x", &[])), vec!["a/m", "b/m"]);
    }

    #[test]
    fn sessions_are_scoped_per_user() {
        let s = Session { id: 777, label: "/home/x (agent)".into() };
        let a = scope_session(&user(1001, "alice", &[]), s.clone(), true);
        let b = scope_session(&user(1002, "bob", &[]), s.clone(), true);
        assert_ne!(a.id, b.id);
        assert_eq!(a, scope_session(&user(1001, "alice", &[]), s.clone(), true));
        assert_eq!(a.label, "alice: /home/x (agent)");
        assert_eq!(scope_session(&user(1001, "alice", &[]), s, false).label, "/home/x (agent)");
    }

    #[tokio::test]
    async fn requests_and_session_end_reach_only_the_right_connector() {
        let (h, mut rx) = hub(vec![tok("a", &["alice", "bob"]), tok("b", &["bob"])], &[("alice-pc", "a", &["laptop"]), ("bob-pc", "b", &["desk"])]);
        let h = Arc::new(h);
        let alice = user(1001, "alice", &[]);
        let bob = user(1002, "bob", &[]);
        // bob can't reach a machine that isn't his
        let e = h.request(&user(1003, "eve", &[]), "laptop", Op::Exec { cmd: "id".into(), cwd: None, timeout: 5, sudo: false }, Tool::Exec, 1, Session { id: 5, label: "l".into() }).await;
        assert!(e.unwrap_err().contains("unknown machine"));
        // alice's request goes to alice-pc with her scoped session
        let h2 = h.clone();
        let a2 = alice.clone();
        let task = tokio::spawn(async move {
            h2.request(&a2, "laptop", Op::Exec { cmd: "id".into(), cwd: None, timeout: 5, sudo: false }, Tool::Exec, 1, Session { id: 5, label: "l".into() }).await
        });
        let Some(Down::Req { id, session, .. }) = rx[0].recv().await else { panic!() };
        assert_eq!(session.id, scope_session(&alice, Session { id: 5, label: String::new() }, false).id);
        assert_eq!(session.label, "alice: l");
        let cid_of = |n: &str| *h.conns.lock().unwrap().iter().find(|(_, c)| c.name == n).unwrap().0;
        // bob-pc (another connector) can't answer alice's request ...
        h.resolve(cid_of("bob-pc"), id, Ok(proto::OpOk::Text("forged".into())));
        assert!(!task.is_finished());
        // ... alice-pc can
        h.resolve(cid_of("alice-pc"), id, Ok(proto::OpOk::Text("real".into())));
        assert!(matches!(task.await.unwrap(), Ok(proto::OpOk::Text(t)) if t == "real"));
        // bob ending "his" session 5 doesn't end alice's session 5
        h.end_session(&bob, 5);
        assert!(rx[0].try_recv().is_err());
        h.end_session(&alice, 5);
        assert!(matches!(rx[0].try_recv(), Ok(Down::EndSession { .. })));
        assert!(rx[1].try_recv().is_err(), "bob-pc was never used by that session");
    }
}
