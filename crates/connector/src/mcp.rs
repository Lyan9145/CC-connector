//! MCP servers on the connector's own machine, used by the agent's `mcp`
//! tool. The connector is the MCP client: it starts a program and talks
//! JSON-RPC over its stdin/stdout, or connects to a URL (Streamable HTTP).
//! Each server is kept running (restarted with backoff when it dies) and its
//! tool list is kept current (`notifications/tools/list_changed`).

use crate::exec::local;
use crate::store::{split_command, McpServer, McpTransport};
use anyhow::{anyhow, bail, Context, Result};
use futures_util::StreamExt;
use serde_json::{json, Value};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{ChildStdin, Command};
use tokio::sync::{mpsc, oneshot, watch};

/// MCP protocol version we ask for.
pub const PROTOCOL: &str = "2025-06-18";
/// The first start of e.g. `uvx …` may download packages.
const INIT_TIMEOUT: Duration = Duration::from_secs(120);
const LIST_TIMEOUT: Duration = Duration::from_secs(30);
/// Tool list refresh for HTTP servers that offer no notification stream.
const POLL: Duration = Duration::from_secs(60);
const STDERR_KEEP: usize = 30;
const MAX_BACKOFF: u64 = 60;

#[derive(Debug, Clone, PartialEq)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub schema: Value,
}

/// What a server is doing, for the agent and the window.
#[derive(Debug, Clone, Default)]
pub struct State {
    /// "starting", "running", "stopped" or "error: …"
    pub status: String,
    pub tools: Vec<ToolDef>,
    /// the server's own name and version, e.g. "BlenderMCP 1.2"
    pub server: String,
    /// its last stderr lines (stdio)
    pub stderr: VecDeque<String>,
}

type Hook = Arc<dyn Fn() + Send + Sync>;
type LogHook = Arc<dyn Fn(String) + Send + Sync>;

/// One configured MCP server and its running connection.
pub struct Client {
    /// "<connection>/<server>", for the log
    pub label: String,
    pub cfg: McpServer,
    /// working folder (stdio)
    pub cwd: std::path::PathBuf,
    /// environment variables (stdio) or HTTP headers, from the keyring
    secret: Vec<(String, String)>,
    state: Mutex<State>,
    peer: Mutex<Option<Arc<Peer>>>,
    stop: watch::Sender<bool>,
    on_change: Hook,
    log: LogHook,
}

impl Client {
    pub fn new(label: String, cfg: McpServer, cwd: std::path::PathBuf, secret: Vec<(String, String)>, on_change: Hook, log: LogHook) -> Arc<Self> {
        Arc::new(Client {
            label,
            cfg,
            cwd,
            secret,
            state: Mutex::new(State { status: "starting".into(), ..Default::default() }),
            peer: Mutex::new(None),
            stop: watch::channel(false).0,
            on_change,
            log,
        })
    }

    /// Whether this client starts the server the same way (no restart
    /// needed). Access and timeout are read from the config at each call.
    pub fn same(&self, cfg: &McpServer, cwd: &std::path::Path, secret: &[(String, String)]) -> bool {
        let launch = |m: &McpServer| (m.transport, m.command.clone(), m.url.clone(), m.cwd.clone());
        launch(&self.cfg) == launch(cfg) && self.cwd == cwd && self.secret == secret
    }

    pub fn start(self: &Arc<Self>) {
        tokio::spawn(self.clone().supervise());
    }

    /// Stop the server for good (the supervisor kills it and exits).
    pub fn stop(&self) {
        self.stop.send_replace(true);
    }

    pub fn state(&self) -> State {
        self.state.lock().unwrap().clone()
    }

    fn set(&self, f: impl FnOnce(&mut State)) {
        f(&mut self.state.lock().unwrap());
        (self.on_change)();
    }

    /// Call one tool. Returns the MCP content items (JSON array text) and
    /// whether the server flagged the result as an error.
    pub async fn call(&self, tool: &str, args: Value, timeout: Duration) -> Result<(String, bool)> {
        let peer = self.peer.lock().unwrap().clone();
        let st = self.state();
        let Some(peer) = peer.filter(|_| st.status == "running") else {
            bail!("MCP server '{}' is not running ({})", self.cfg.name, st.status);
        };
        if !st.tools.iter().any(|t| t.name == tool) {
            let names: Vec<&str> = st.tools.iter().map(|t| t.name.as_str()).collect();
            bail!("MCP server '{}' has no tool '{tool}'. Its tools: {}", self.cfg.name, if names.is_empty() { "(none)".into() } else { names.join(", ") });
        }
        let r = peer.request("tools/call", json!({"name": tool, "arguments": args}), timeout).await?;
        Ok(call_result(&r))
    }

    async fn supervise(self: Arc<Self>) {
        let mut stop = self.stop.subscribe();
        let mut backoff = 1u64;
        // a server that keeps failing the same way is logged once
        let mut last_logged = String::new();
        loop {
            if *stop.borrow() {
                break;
            }
            self.set(|s| s.status = "starting".into());
            let started = Instant::now();
            let err = tokio::select! {
                e = self.clone().session() => e,
                _ = stop.wait_for(|v| *v) => break,
            };
            if self.state().status == "running" {
                last_logged.clear(); // it worked in between: say so again
            }
            self.shutdown().await;
            let mut why = format!("{err:#}");
            if let Some(last) = self.state().stderr.back() {
                why.push_str(&format!(" (last output: {last})"));
            }
            if why != last_logged {
                (self.log)(format!("MCP {}: {why}", self.label));
                last_logged = why.clone();
            }
            self.set(|s| {
                s.status = format!("error: {why}");
                s.tools.clear();
            });
            if started.elapsed() > Duration::from_secs(60) {
                backoff = 1;
            }
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(backoff)) => {}
                _ = stop.wait_for(|v| *v) => break,
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
        self.shutdown().await;
        self.set(|s| {
            s.status = "stopped".into();
            s.tools.clear();
        });
    }

    /// Kill the process (stdio) or end the HTTP session.
    async fn shutdown(&self) {
        let Some(peer) = self.peer.lock().unwrap().take() else { return };
        peer.fail_all("the MCP server stopped");
        match &peer.io {
            Io::Stdio { pid, .. } => local::kill_tree(*pid).await,
            Io::Http(h) => {
                let sid = h.session.lock().unwrap().clone();
                if let Some(sid) = sid {
                    let mut req = h.client.delete(&h.url).header("mcp-session-id", sid);
                    for (k, v) in &h.headers {
                        req = req.header(k, v);
                    }
                    let _ = tokio::time::timeout(Duration::from_secs(3), req.send()).await;
                }
            }
        }
    }

    /// One connection: start, initialize, list tools, then follow changes
    /// until it fails. Only returns with the reason it ended.
    async fn session(self: Arc<Self>) -> anyhow::Error {
        match self.session_inner().await {
            Ok(never) => match never {},
            Err(e) => e,
        }
    }

    async fn session_inner(self: &Arc<Self>) -> Result<std::convert::Infallible> {
        self.state.lock().unwrap().stderr.clear();
        let (events_tx, mut events) = mpsc::unbounded_channel();
        let peer = match self.cfg.transport {
            McpTransport::Stdio => self.spawn_stdio(events_tx)?,
            McpTransport::Http => self.open_http(events_tx)?,
        };
        *self.peer.lock().unwrap() = Some(peer.clone());
        let init = peer
            .request(
                "initialize",
                json!({"protocolVersion": PROTOCOL, "capabilities": {}, "clientInfo": {"name": "ccc", "version": ccc_proto::VERSION}}),
                INIT_TIMEOUT,
            )
            .await
            .context("initialize")?;
        if let Some(v) = init.get("protocolVersion").and_then(Value::as_str) {
            *peer.version.lock().unwrap() = Some(v.to_string());
        }
        let info = init.get("serverInfo");
        let sname = [info.and_then(|i| i.get("name")), info.and_then(|i| i.get("version"))]
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(" ");
        peer.notify("notifications/initialized").await?;
        if let Io::Http(_) = peer.io {
            peer.clone().listen_http();
        }
        let tools = list_tools(&peer).await?;
        (self.log)(format!("MCP {}: running, {} tool{}", self.label, tools.len(), if tools.len() == 1 { "" } else { "s" }));
        self.set(|s| {
            s.status = "running".into();
            s.server = sname;
            s.tools = tools;
        });
        let mut poll: Option<tokio::time::Interval> = None;
        loop {
            let refresh = tokio::select! {
                ev = events.recv() => match ev {
                    Some(Event::ToolsChanged) => true,
                    Some(Event::NoStream) => {
                        let mut i = tokio::time::interval(POLL);
                        i.tick().await;
                        poll = Some(i);
                        false
                    }
                    Some(Event::Closed(why)) => bail!(why),
                    None => bail!("connection closed"),
                },
                _ = async { poll.as_mut().unwrap().tick().await }, if poll.is_some() => true,
            };
            if refresh {
                let tools = list_tools(&peer).await.context("refresh tools")?;
                if tools != self.state().tools {
                    (self.log)(format!("MCP {}: tools changed ({})", self.label, tools.len()));
                    self.set(|s| s.tools = tools);
                }
            }
        }
    }

    fn spawn_stdio(self: &Arc<Self>, events: mpsc::UnboundedSender<Event>) -> Result<Arc<Peer>> {
        let parts = split_command(&self.cfg.command);
        let Some((prog, args)) = parts.split_first() else { bail!("the command is empty") };
        let setup = |c: &mut Command| {
            c.stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true)
                .current_dir(&self.cwd)
                .envs(self.secret.iter().map(|(k, v)| (k, v)));
            #[cfg(windows)]
            c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
            #[cfg(unix)]
            c.process_group(0);
        };
        let mut c = Command::new(prog);
        c.args(args);
        setup(&mut c);
        let spawned = match c.spawn() {
            // `npx`, `uvx` … are often .cmd/.bat shims, which only cmd.exe runs
            #[cfg(windows)]
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut c = Command::new("cmd");
                c.arg("/D").arg("/S").arg("/C").raw_arg(format!("\"{}\"", self.cfg.command));
                setup(&mut c);
                c.spawn()
            }
            r => r,
        };
        let mut child = spawned.map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => anyhow!(not_found(prog)),
            _ => anyhow!("cannot start '{prog}': {e}"),
        })?;
        let pid = child.id();
        let stdin = child.stdin.take().context("no stdin")?;
        let stdout = child.stdout.take().context("no stdout")?;
        let stderr = child.stderr.take().context("no stderr")?;
        let peer = Arc::new(Peer::new(Io::Stdio { stdin: tokio::sync::Mutex::new(stdin), pid }, events));
        // stderr: keep the last lines (they explain crashes)
        let me = self.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                me.keep_output(l);
            }
        });
        // stdout: JSON-RPC messages, one per line
        let p = peer.clone();
        let me = self.clone();
        let prog = prog.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                let t = l.trim();
                if t.is_empty() {
                    continue;
                }
                match serde_json::from_str::<Value>(t) {
                    Ok(v) => p.incoming(v),
                    Err(_) => me.keep_output(format!("[stdout] {l}")),
                }
            }
            let status = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
            let why = match status {
                // 9009: cmd.exe (the fallback for .cmd shims) didn't find the program
                Ok(Ok(s)) if cfg!(windows) && s.code() == Some(9009) => not_found(&prog),
                Ok(Ok(s)) => format!("the server exited ({})", s.code().map(|c| format!("exit code {c}")).unwrap_or_else(|| "killed".into())),
                _ => "the server exited (closed its output)".into(),
            };
            p.fail_all("the MCP server exited");
            let _ = p.events.send(Event::Closed(why));
        });
        Ok(peer)
    }

    fn keep_output(&self, line: String) {
        let line: String = line.chars().take(500).collect();
        let mut s = self.state.lock().unwrap();
        s.stderr.push_back(line);
        while s.stderr.len() > STDERR_KEEP {
            s.stderr.pop_front();
        }
    }

    fn open_http(self: &Arc<Self>, events: mpsc::UnboundedSender<Event>) -> Result<Arc<Peer>> {
        let client = reqwest::Client::builder()
            // the proxy settings are for the hub, not for local servers
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .build()
            .context("HTTP client")?;
        let http = Http { client, url: self.cfg.url.clone(), headers: self.secret.clone(), session: Mutex::new(None) };
        Ok(Arc::new(Peer::new(Io::Http(http), events)))
    }
}

/// The folder a stdio server starts in: its own, else the connection's,
/// else home.
pub fn work_dir(conn: &crate::store::Connection, m: &McpServer) -> std::path::PathBuf {
    let dir = if !m.cwd.trim().is_empty() { m.cwd.trim() } else { conn.cwd.trim() };
    if dir.is_empty() {
        local::home()
    } else {
        local::expand(dir)
    }
}

/// A server's environment variables (stdio) or HTTP headers, from the keyring.
pub fn secret_pairs(conn: &str, m: &McpServer) -> Result<Vec<(String, String)>> {
    let text = crate::store::get_secret(&crate::store::mcp_key(conn, &m.name))?.unwrap_or_default();
    crate::store::parse_pairs(&text, if m.transport == McpTransport::Http { ':' } else { '=' })
}

/// Start a server once, wait until it runs or fails, and stop it again
/// (the "Test" button and `ccc mcp test`).
pub async fn probe(conn: &crate::store::Connection, m: &McpServer) -> Result<State> {
    let secret = secret_pairs(&conn.name, m)?;
    Ok(probe_with(conn, m, secret).await)
}

/// [`probe`] with the variables / headers given (e.g. unsaved, from the form).
pub async fn probe_with(conn: &crate::store::Connection, m: &McpServer, secret: Vec<(String, String)>) -> State {
    let c = Client::new(format!("{}/{}", conn.name, m.name), m.clone(), work_dir(conn, m), secret, Arc::new(|| {}), Arc::new(|_| {}));
    c.start();
    let deadline = Instant::now() + INIT_TIMEOUT + Duration::from_secs(10);
    let st = loop {
        let st = c.state();
        if st.status == "running" || st.status.starts_with("error") || Instant::now() > deadline {
            break st;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    c.stop();
    for _ in 0..50 {
        if c.state().status == "stopped" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    st
}

fn not_found(prog: &str) -> String {
    format!("cannot start '{prog}': program not found (is it installed and on PATH?)")
}

/// Turn a `tools/call` result into (content items JSON, is_error).
fn call_result(r: &Value) -> (String, bool) {
    let is_error = r.get("isError").and_then(Value::as_bool).unwrap_or(false);
    let mut content = r.get("content").and_then(Value::as_array).cloned().unwrap_or_default();
    if content.is_empty() {
        if let Some(sc) = r.get("structuredContent") {
            content.push(json!({"type": "text", "text": sc.to_string()}));
        }
    }
    (Value::Array(content).to_string(), is_error)
}

async fn list_tools(peer: &Arc<Peer>) -> Result<Vec<ToolDef>> {
    let mut out = vec![];
    let mut cursor: Option<String> = None;
    for _ in 0..100 {
        let params = match &cursor {
            Some(c) => json!({"cursor": c}),
            None => json!({}),
        };
        let r = peer.request("tools/list", params, LIST_TIMEOUT).await.context("tools/list")?;
        for t in r.get("tools").and_then(Value::as_array).into_iter().flatten() {
            let Some(name) = t.get("name").and_then(Value::as_str) else { continue };
            out.push(ToolDef {
                name: name.to_string(),
                description: t.get("description").and_then(Value::as_str).unwrap_or("").to_string(),
                schema: t.get("inputSchema").cloned().unwrap_or_else(|| json!({"type": "object"})),
            });
        }
        cursor = r.get("nextCursor").and_then(Value::as_str).filter(|c| !c.is_empty()).map(String::from);
        if cursor.is_none() {
            break;
        }
    }
    Ok(out)
}

enum Event {
    ToolsChanged,
    /// the HTTP server offers no stream for notifications: poll instead
    NoStream,
    Closed(String),
}

enum Io {
    Stdio { stdin: tokio::sync::Mutex<ChildStdin>, pid: Option<u32> },
    Http(Http),
}

struct Http {
    client: reqwest::Client,
    url: String,
    headers: Vec<(String, String)>,
    session: Mutex<Option<String>>,
}

type Pending = Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>;

/// A JSON-RPC connection to one MCP server.
struct Peer {
    io: Io,
    pending: Pending,
    next: AtomicU64,
    events: mpsc::UnboundedSender<Event>,
    /// negotiated protocol version (sent as a header over HTTP)
    version: Mutex<Option<String>>,
}

impl Peer {
    fn new(io: Io, events: mpsc::UnboundedSender<Event>) -> Self {
        Peer { io, pending: Default::default(), next: AtomicU64::new(1), events, version: Mutex::new(None) }
    }

    async fn request(self: &Arc<Self>, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, tx);
        let msg = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let r = tokio::time::timeout(timeout, async {
            self.send(&msg, Some(id)).await?;
            match rx.await {
                Ok(Ok(v)) => Ok(v),
                Ok(Err(e)) => Err(anyhow!(e)),
                Err(_) => Err(anyhow!("the MCP server closed the connection")),
            }
        })
        .await;
        self.pending.lock().unwrap().remove(&id);
        match r {
            Ok(r) => r,
            Err(_) => {
                let cancel = json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": id, "reason": "timed out"}});
                let me = self.clone();
                tokio::spawn(async move {
                    let _ = me.send(&cancel, None).await;
                });
                bail!("{method}: no answer within {}s", timeout.as_secs())
            }
        }
    }

    async fn notify(self: &Arc<Self>, method: &str) -> Result<()> {
        self.send(&json!({"jsonrpc": "2.0", "method": method}), None).await
    }

    /// Send one message. Over HTTP the reply comes in the response, which
    /// is read here (up to the answer to `wait`).
    async fn send(self: &Arc<Self>, msg: &Value, wait: Option<u64>) -> Result<()> {
        match &self.io {
            Io::Stdio { stdin, .. } => {
                let mut line = msg.to_string();
                line.push('\n');
                let mut w = stdin.lock().await;
                w.write_all(line.as_bytes()).await.context("write to the MCP server")?;
                w.flush().await?;
                Ok(())
            }
            Io::Http(h) => self.post(h, msg, wait).await,
        }
    }

    fn http_headers(&self, h: &Http, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        for (k, v) in &h.headers {
            req = req.header(k, v);
        }
        if let Some(s) = h.session.lock().unwrap().clone() {
            req = req.header("mcp-session-id", s);
        }
        if let Some(v) = self.version.lock().unwrap().clone() {
            req = req.header("mcp-protocol-version", v);
        }
        req
    }

    async fn post(self: &Arc<Self>, h: &Http, msg: &Value, wait: Option<u64>) -> Result<()> {
        let req = h
            .client
            .post(&h.url)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .body(msg.to_string());
        let had_session = h.session.lock().unwrap().is_some();
        let resp = self.http_headers(h, req).send().await.map_err(|e| anyhow!("cannot reach {}: {}", h.url, root_cause(&e)))?;
        if let Some(sid) = resp.headers().get("mcp-session-id").and_then(|v| v.to_str().ok()) {
            *h.session.lock().unwrap() = Some(sid.to_string());
        }
        let status = resp.status();
        if status == reqwest::StatusCode::NOT_FOUND && had_session {
            let _ = self.events.send(Event::Closed("the server ended the session".into()));
            bail!("the server ended the session");
        }
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            let body: String = body.trim().chars().take(300).collect();
            bail!("HTTP {status}{}", if body.is_empty() { String::new() } else { format!(": {body}") });
        }
        if status == reqwest::StatusCode::ACCEPTED || status == reqwest::StatusCode::NO_CONTENT {
            return Ok(());
        }
        let sse = resp.headers().get("content-type").and_then(|v| v.to_str().ok()).is_some_and(|c| c.to_ascii_lowercase().starts_with("text/event-stream"));
        if sse {
            self.read_sse(resp, wait).await
        } else {
            let b = resp.bytes().await?;
            if !b.iter().all(u8::is_ascii_whitespace) {
                self.incoming(serde_json::from_slice(&b).context("bad JSON from the MCP server")?);
            }
            Ok(())
        }
    }

    /// Read server-sent events, handing each message to `incoming`; stops at
    /// the end of the stream or once request `wait` is answered.
    async fn read_sse(self: &Arc<Self>, resp: reqwest::Response, wait: Option<u64>) -> Result<()> {
        let mut stream = resp.bytes_stream();
        let mut buf: Vec<u8> = vec![];
        let mut data = String::new();
        let answered = |p: &Self| wait.is_some_and(|id| !p.pending.lock().unwrap().contains_key(&id));
        loop {
            // stop when the session that opened this stream has ended
            let chunk = tokio::select! {
                c = stream.next() => c,
                _ = self.events.closed() => None,
            };
            let Some(chunk) = chunk else { break };
            buf.extend_from_slice(&chunk.map_err(|e| anyhow!("{}", root_cause(&e)))?);
            while let Some(pos) = buf.iter().position(|b| *b == b'\n') {
                let raw: Vec<u8> = buf.drain(..=pos).collect();
                let line = String::from_utf8_lossy(&raw);
                let line = line.trim_end_matches(['\n', '\r']);
                if line.is_empty() {
                    if !data.is_empty() {
                        if let Ok(v) = serde_json::from_str::<Value>(&data) {
                            self.incoming(v);
                        }
                        data.clear();
                        if answered(self) {
                            return Ok(());
                        }
                    }
                } else if let Some(d) = line.strip_prefix("data:") {
                    if !data.is_empty() {
                        data.push('\n');
                    }
                    data.push_str(d.strip_prefix(' ').unwrap_or(d));
                }
            }
        }
        Ok(())
    }

    /// Keep a GET stream open for server notifications (tools changed);
    /// servers without one get polled.
    fn listen_http(self: Arc<Self>) {
        let me = Arc::downgrade(&self);
        drop(self);
        tokio::spawn(async move {
            loop {
                let Some(p) = me.upgrade() else { return };
                let Io::Http(h) = &p.io else { return };
                let req = h.client.get(&h.url).header("accept", "text/event-stream");
                match p.http_headers(h, req).send().await {
                    Ok(r) if r.status().is_success() => {
                        let _ = p.read_sse(r, None).await;
                    }
                    Ok(_) => {
                        let _ = p.events.send(Event::NoStream);
                        return;
                    }
                    Err(e) => {
                        let _ = p.events.send(Event::Closed(format!("cannot reach {}: {}", h.url, root_cause(&e))));
                        return;
                    }
                }
                if p.events.is_closed() {
                    return;
                }
                drop(p);
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
        });
    }

    /// A message from the server: an answer, a request or a notification.
    fn incoming(self: &Arc<Self>, msg: Value) {
        if let Value::Array(batch) = msg {
            for m in batch {
                self.incoming(m);
            }
            return;
        }
        let method = msg.get("method").and_then(Value::as_str);
        let id = msg.get("id").filter(|v| !v.is_null()).cloned();
        match (method, id) {
            (None, Some(id)) => {
                let Some(id) = id.as_u64() else { return };
                let Some(tx) = self.pending.lock().unwrap().remove(&id) else { return };
                let r = match msg.get("error") {
                    Some(e) => Err(rpc_error(e)),
                    None => Ok(msg.get("result").cloned().unwrap_or(Value::Null)),
                };
                let _ = tx.send(r);
            }
            (Some(m), Some(id)) => {
                // requests from the server: answer what a plain client can
                let reply = match m {
                    "ping" => json!({"jsonrpc": "2.0", "id": id, "result": {}}),
                    "roots/list" => json!({"jsonrpc": "2.0", "id": id, "result": {"roots": []}}),
                    _ => json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": format!("{m} is not supported by this client")}}),
                };
                let me = self.clone();
                tokio::spawn(async move {
                    let _ = me.send(&reply, None).await;
                });
            }
            (Some("notifications/tools/list_changed"), None) => {
                let _ = self.events.send(Event::ToolsChanged);
            }
            _ => {}
        }
    }

    fn fail_all(&self, why: &str) {
        for (_, tx) in self.pending.lock().unwrap().drain() {
            let _ = tx.send(Err(why.to_string()));
        }
    }
}

fn rpc_error(e: &Value) -> String {
    let msg = e.get("message").and_then(Value::as_str).unwrap_or("error");
    match e.get("data") {
        Some(Value::String(d)) => format!("{msg}: {d}"),
        Some(d) if !d.is_null() => format!("{msg}: {d}"),
        _ => msg.to_string(),
    }
}

fn root_cause(e: &(dyn std::error::Error + 'static)) -> String {
    let mut s = e.to_string();
    let mut cur = e.source();
    while let Some(c) = cur {
        s = c.to_string();
        cur = c.source();
    }
    s
}

/// The agent's `mcp list` text: each server with its tools and schemas.
pub fn list_text(servers: &[(String, String, State)]) -> String {
    if servers.is_empty() {
        return "no MCP servers on this machine".into();
    }
    let mut out = String::new();
    for (name, access, st) in servers {
        let mut head = format!("{name}  {}", st.status);
        if !st.server.is_empty() {
            head.push_str(&format!("  [{}]", st.server));
        }
        if access == "ask" {
            head.push_str("  (each call needs the owner's approval)");
        }
        out.push_str(&head);
        out.push('\n');
        if st.status != "running" {
            continue;
        }
        if st.tools.is_empty() {
            out.push_str("  (no tools)\n");
        }
        for t in &st.tools {
            out.push_str(&format!("  {}", t.name));
            let desc = t.description.trim();
            if !desc.is_empty() {
                let mut lines = desc.lines();
                out.push_str(&format!(": {}", lines.next().unwrap_or("").trim_end()));
                for l in lines {
                    out.push_str(&format!("\n      {}", l.trim_end()));
                }
            }
            let mut schema = t.schema.clone();
            if let Some(o) = schema.as_object_mut() {
                o.remove("$schema");
            }
            out.push_str(&format!("\n    input: {schema}\n"));
        }
    }
    out.trim_end().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn client(cfg: McpServer) -> (Arc<Client>, Arc<AtomicU64>) {
        let changes = Arc::new(AtomicU64::new(0));
        let c2 = changes.clone();
        let on_change: Hook = Arc::new(move || {
            c2.fetch_add(1, Ordering::Relaxed);
        });
        let log: LogHook = Arc::new(|s| eprintln!("{s}"));
        (Client::new("test/fake".into(), cfg, std::env::temp_dir(), vec![("FAKE_GREETING".into(), "hello".into())], on_change, log), changes)
    }

    async fn until(c: &Client, what: &str, f: impl Fn(&State) -> bool) -> State {
        for _ in 0..300 {
            let st = c.state();
            if f(&st) {
                return st;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("timed out waiting for {what}: {:?}", c.state());
    }

    fn names(st: &State) -> Vec<String> {
        st.tools.iter().map(|t| t.name.clone()).collect()
    }

    /// A stdio MCP server in Python: tools `add`, `grow` (adds `mul` and
    /// says the list changed) and `die` (exits).
    #[cfg(unix)]
    const FAKE: &str = r#"
import json, os, sys
print("not json, just noise")
print("starting up", file=sys.stderr, flush=True)
tools = [{"name": "add", "description": "Add a and b.", "inputSchema": {"type": "object"}},
         {"name": "grow", "inputSchema": {"type": "object"}},
         {"name": "die", "inputSchema": {"type": "object"}}]
def send(m):
    sys.stdout.write(json.dumps(m) + "\n"); sys.stdout.flush()
for line in sys.stdin:
    m = json.loads(line)
    i, meth, p = m.get("id"), m.get("method"), m.get("params") or {}
    if meth == "initialize":
        send({"jsonrpc": "2.0", "id": i, "result": {"protocolVersion": p["protocolVersion"], "capabilities": {"tools": {"listChanged": True}}, "serverInfo": {"name": "fake", "version": "1.0"}}})
        send({"jsonrpc": "2.0", "id": "s1", "method": "ping"})
    elif meth == "tools/list":
        send({"jsonrpc": "2.0", "id": i, "result": {"tools": tools}})
    elif meth == "tools/call":
        a, name = p.get("arguments") or {}, p["name"]
        if name == "add":
            send({"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": "%s %d" % (os.environ.get("FAKE_GREETING"), a["a"] + a["b"])}]}})
        elif name == "grow":
            tools.append({"name": "mul", "inputSchema": {"type": "object"}})
            send({"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": "grown"}]}})
            send({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
        elif name == "die":
            print("dying now", file=sys.stderr, flush=True)
            sys.exit(3)
        else:
            send({"jsonrpc": "2.0", "id": i, "result": {"content": [{"type": "text", "text": "no"}], "isError": True}})
"#;

    #[cfg(unix)]
    #[tokio::test]
    async fn stdio_server() {
        if std::process::Command::new("python3").arg("-V").output().is_err() {
            eprintln!("python3 not found; skipped");
            return;
        }
        let script = std::env::temp_dir().join(format!("ccc-fake-mcp-{}.py", std::process::id()));
        std::fs::write(&script, FAKE).unwrap();
        let cfg = McpServer { name: "fake".into(), command: format!("python3 '{}'", script.display()), ..Default::default() };
        let (c, changes) = client(cfg);
        c.start();
        let st = until(&c, "running", |s| s.status == "running").await;
        assert_eq!(names(&st), ["add", "grow", "die"]);
        assert_eq!(st.server, "fake 1.0");
        assert!(changes.load(Ordering::Relaxed) > 0);

        let (out, err) = c.call("add", json!({"a": 2, "b": 3}), Duration::from_secs(10)).await.unwrap();
        assert!(!err && out.contains("hello 5"), "{out}");
        let e = c.call("nope", json!({}), Duration::from_secs(10)).await.unwrap_err().to_string();
        assert!(e.contains("has no tool 'nope'") && e.contains("add, grow, die"), "{e}");

        // the server adds a tool and says so: the list follows
        let (out, _) = c.call("grow", json!({}), Duration::from_secs(10)).await.unwrap();
        assert!(out.contains("grown"));
        until(&c, "mul", |s| s.tools.iter().any(|t| t.name == "mul")).await;

        // it crashes: the error shows its last words, then it is restarted
        let e = c.call("die", json!({}), Duration::from_secs(10)).await.unwrap_err().to_string();
        assert!(e.contains("exited"), "{e}");
        let st = until(&c, "error", |s| s.status.starts_with("error")).await;
        assert!(st.status.contains("exit code 3") && st.status.contains("dying now"), "{}", st.status);
        let st = until(&c, "restart", |s| s.status == "running").await;
        assert_eq!(names(&st), ["add", "grow", "die"]);

        c.stop();
        until(&c, "stopped", |s| s.status == "stopped").await;
        assert!(c.call("add", json!({"a": 1, "b": 1}), Duration::from_secs(5)).await.is_err());
        let _ = std::fs::remove_file(script);
    }

    #[tokio::test]
    async fn missing_program() {
        let (c, _) = client(McpServer { name: "x".into(), command: "ccc-no-such-program-here --x".into(), ..Default::default() });
        c.start();
        let st = until(&c, "error", |s| s.status.starts_with("error")).await;
        assert!(st.status.contains("not found"), "{}", st.status);
        c.stop();
    }

    /// Answer one HTTP request of the fake Streamable-HTTP server.
    async fn http_answer(mut sock: tokio::net::TcpStream, tools: Arc<Mutex<Vec<&'static str>>>) {
        let mut buf = vec![];
        let mut tmp = [0u8; 4096];
        let (head, body) = loop {
            let n = sock.read(&mut tmp).await.unwrap_or(0);
            if n == 0 {
                return;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..p]).to_string();
                let len: usize = head
                    .lines()
                    .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap_or(0)))
                    .unwrap_or(0);
                while buf.len() < p + 4 + len {
                    let n = sock.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                }
                break (head, buf[p + 4..p + 4 + len].to_vec());
            }
        };
        let reply = |status: &str, ctype: &str, extra: &str, body: &str| {
            format!("HTTP/1.1 {status}\r\ncontent-type: {ctype}\r\ncontent-length: {}\r\nconnection: close\r\n{extra}\r\n{body}", body.len())
        };
        let out = if head.starts_with("GET") || head.starts_with("DELETE") {
            reply("405 Method Not Allowed", "text/plain", "", "")
        } else {
            let m: Value = serde_json::from_slice(&body).unwrap();
            let id = m.get("id").cloned();
            let has_session = head.to_ascii_lowercase().contains("mcp-session-id: sess-1");
            let auth = head.to_ascii_lowercase().contains("authorization: bearer k");
            match m["method"].as_str().unwrap_or("") {
                _ if !auth => reply("401 Unauthorized", "text/plain", "", "no key"),
                "initialize" => {
                    let r = json!({"jsonrpc": "2.0", "id": id, "result": {"protocolVersion": PROTOCOL, "capabilities": {}, "serverInfo": {"name": "web"}}});
                    reply("200 OK", "application/json", "mcp-session-id: sess-1\r\n", &r.to_string())
                }
                _ if !has_session => reply("400 Bad Request", "text/plain", "", "no session"),
                "tools/list" => {
                    let t: Vec<Value> = tools.lock().unwrap().iter().map(|n| json!({"name": n})).collect();
                    // answered as an event stream, with a notification first
                    let ev1 = json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {}});
                    let ev2 = json!({"jsonrpc": "2.0", "id": id, "result": {"tools": t}});
                    reply("200 OK", "text/event-stream", "", &format!("event: message\ndata: {ev1}\n\ndata: {ev2}\n\n"))
                }
                "tools/call" => {
                    let r = json!({"jsonrpc": "2.0", "id": id, "result": {"content": [{"type": "text", "text": format!("called {}", m["params"]["name"])}]}});
                    reply("200 OK", "application/json", "", &r.to_string())
                }
                _ => reply("202 Accepted", "text/plain", "", ""),
            }
        };
        let _ = sock.write_all(out.as_bytes()).await;
    }

    #[tokio::test]
    async fn http_server() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let tools = Arc::new(Mutex::new(vec!["look"]));
        let t2 = tools.clone();
        tokio::spawn(async move {
            while let Ok((s, _)) = l.accept().await {
                tokio::spawn(http_answer(s, t2.clone()));
            }
        });
        let cfg = McpServer { name: "web".into(), transport: McpTransport::Http, url: format!("http://127.0.0.1:{port}/mcp"), ..Default::default() };
        let changes = Arc::new(AtomicU64::new(0));
        let log: LogHook = Arc::new(|s| eprintln!("{s}"));
        let c = Client::new("t/web".into(), cfg, std::env::temp_dir(), vec![("Authorization".into(), "Bearer k".into())], Arc::new(move || {
            changes.fetch_add(1, Ordering::Relaxed);
        }), log);
        c.start();
        let st = until(&c, "running", |s| s.status == "running").await;
        assert_eq!((names(&st), st.server.as_str()), (vec!["look".to_string()], "web"));
        let (out, err) = c.call("look", json!({}), Duration::from_secs(10)).await.unwrap();
        assert!(!err && out.contains("called \\\"look\\\""), "{out}");
        // no GET stream (405): the tool list is polled, not pushed
        tools.lock().unwrap().push("seen");
        assert_eq!(names(&c.state()), ["look"]);
        c.stop();
        until(&c, "stopped", |s| s.status == "stopped").await;
    }

    #[test]
    fn results_and_listing() {
        let (c, e) = call_result(&json!({"content": [{"type": "text", "text": "hi"}], "isError": true}));
        assert_eq!((c.as_str(), e), (r#"[{"text":"hi","type":"text"}]"#, true));
        let (c, e) = call_result(&json!({"structuredContent": {"a": 1}}));
        assert!(!e && c.contains(r#"{\"a\":1}"#), "{c}");
        let st = State {
            status: "running".into(),
            server: "fake 1.0".into(),
            tools: vec![ToolDef { name: "add".into(), description: "Add two numbers.\nReturns the sum.".into(), schema: json!({"$schema": "x", "type": "object"}) }],
            ..Default::default()
        };
        let down = State { status: "error: boom".into(), ..Default::default() };
        let t = list_text(&[("calc".into(), "ask".into(), st), ("old".into(), "allow".into(), down)]);
        assert!(t.starts_with("calc  running  [fake 1.0]  (each call needs the owner's approval)\n  add: Add two numbers.\n      Returns the sum.\n    input: {\"type\":\"object\"}"), "{t}");
        assert!(t.ends_with("old  error: boom"), "{t}");
    }
}
