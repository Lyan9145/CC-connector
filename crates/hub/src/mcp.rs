//! Minimal MCP server over stdio (JSON-RPC 2.0, newline-delimited).
//! Spawned by Claude Code; forwards tool calls to the hub daemon via IPC.

use crate::format;
use anyhow::{anyhow, bail, Context, Result};
use ccc_proto::{self as proto, Entry, IpcReq, IpcResp, JobOp, Listed, Op, OpOk, Session, Tool, CHUNK};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;

const MAX_TRANSFER: u64 = 500 << 20;

const INSTRUCTIONS: &str = "Operate on remote machines (laptops, robots) through these tools. \
Call `machines` first; refer to machines only by the listed name. Hosts and credentials are \
hidden by design. Use sudo=true (never `sudo` inside cmd) for root. Use `job` for anything \
running longer than a couple of minutes. push/pull copy between THIS server's filesystem and a machine. \
Text indented under a machine in `machines` is its owner's notes: follow them when working on it. \
`ask:` tools wait for the owner to approve each use (may take a minute or be refused); \
`denied:` tools are unavailable there, so don't try them or work around them. \
`folders:` limits where the file tools (read/write/edit/push/pull) may go; folders marked \
`ask once` prompt the owner the first time this session touches them. `read` also shows images.";

fn tools() -> Value {
    let m = json!({"type":"string","description":"machine name from `machines`"});
    json!([
        {"name":"machines","description":"List available machines with status, OS, access rules and owner notes.","inputSchema":{"type":"object","properties":{}}},
        {"name":"exec","description":"Run a shell command (bash -l on Linux, PowerShell on Windows). Returns exit code + merged stdout/stderr; long output is truncated and saved to a local file.",
         "inputSchema":{"type":"object","required":["machine","cmd"],"properties":{
            "machine":m,"cmd":{"type":"string"},
            "cwd":{"type":"string","description":"default: machine's configured dir"},
            "timeout":{"type":"integer","description":"seconds, default 120, max 3600"},
            "sudo":{"type":"boolean","description":"run whole cmd as root; password is supplied for you"}}}},
        {"name":"read","description":"Read a text file with line numbers, or look at an image (png, jpg, gif, webp, bmp).",
         "inputSchema":{"type":"object","required":["machine","path"],"properties":{
            "machine":m,"path":{"type":"string"},
            "offset":{"type":"integer","description":"1-based first line"},
            "limit":{"type":"integer","description":"max lines, default 400"}}}},
        {"name":"write","description":"Create/overwrite a file (parents created).",
         "inputSchema":{"type":"object","required":["machine","path","content"],"properties":{
            "machine":m,"path":{"type":"string"},"content":{"type":"string"}}}},
        {"name":"edit","description":"Replace exact text in a file. `old` must be unique unless all=true.",
         "inputSchema":{"type":"object","required":["machine","path","old","new"],"properties":{
            "machine":m,"path":{"type":"string"},"old":{"type":"string"},"new":{"type":"string"},"all":{"type":"boolean"}}}},
        {"name":"push","description":"Copy a file/dir from this server to a machine. dst becomes the copy.",
         "inputSchema":{"type":"object","required":["machine","src","dst"],"properties":{
            "machine":m,"src":{"type":"string","description":"server path"},"dst":{"type":"string","description":"machine path"}}}},
        {"name":"pull","description":"Copy a file/dir from a machine to this server. dst becomes the copy.",
         "inputSchema":{"type":"object","required":["machine","src","dst"],"properties":{
            "machine":m,"src":{"type":"string","description":"machine path"},"dst":{"type":"string","description":"server path"}}}},
        {"name":"job","description":"Background jobs that survive disconnects. start(cmd,cwd?,sudo?)->id + first output; status(id); tail(id,lines?); kill(id); list.",
         "inputSchema":{"type":"object","required":["machine","action"],"properties":{
            "machine":m,"action":{"type":"string","enum":["start","status","tail","kill","list"]},
            "cmd":{"type":"string"},"cwd":{"type":"string"},"sudo":{"type":"boolean"},
            "id":{"type":"string"},"lines":{"type":"integer","description":"default 50"}}}}
    ])
}

/// What one tool call returns to the agent.
pub enum Reply {
    Text(String),
    Image { mime: String, data: Vec<u8>, note: String },
}

impl From<String> for Reply {
    fn from(s: String) -> Self {
        Reply::Text(s)
    }
}

/// A new session id for this agent process; its label tells the owner
/// which Claude Code session is asking.
pub fn new_session(kind: &str) -> Session {
    let dir = std::env::current_dir().map(|d| d.display().to_string()).unwrap_or_default();
    let when = chrono::Local::now().format("%H:%M");
    let label = if dir.is_empty() { format!("{kind} started {when}") } else { format!("{dir} ({kind}, started {when})") };
    // CCC_SESSION_ID lets several `ccc-hub call`s share one session (testing)
    let id = std::env::var("CCC_SESSION_ID").ok().and_then(|v| v.parse().ok()).unwrap_or_else(|| rand::random::<u64>() | 1);
    Session { id, label }
}

pub async fn run(sock: PathBuf) -> Result<()> {
    let session = Arc::new(new_session("agent"));
    let sock = Arc::new(sock);
    let out = Arc::new(Mutex::new(tokio::io::stdout()));
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    let mut tasks = tokio::task::JoinSet::new();
    while let Some(line) = lines.next_line().await? {
        while tasks.try_join_next().is_some() {}
        if line.trim().is_empty() {
            continue;
        }
        let Ok(msg) = serde_json::from_str::<Value>(&line) else { continue };
        let sock = sock.clone();
        let out = out.clone();
        let session = session.clone();
        tasks.spawn(async move {
            if let Some(resp) = handle(&sock, &session, msg).await {
                let mut s = serde_json::to_string(&resp).unwrap();
                s.push('\n');
                let mut o = out.lock().await;
                let _ = o.write_all(s.as_bytes()).await;
                let _ = o.flush().await;
            }
        });
    }
    // stdin closed: finish in-flight requests, then release this session's grants
    while tasks.join_next().await.is_some() {}
    let _ = ipc(&sock, &IpcReq::EndSession { id: session.id }).await;
    Ok(())
}

async fn handle(sock: &Path, session: &Session, msg: Value) -> Option<Value> {
    let id = msg.get("id")?.clone(); // notifications have no id
    let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
    let params = msg.get("params").cloned().unwrap_or(json!({}));
    let result = match method {
        "initialize" => {
            let pv = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("2025-06-18");
            json!({"protocolVersion": pv, "capabilities": {"tools": {}},
                   "serverInfo": {"name": "ccc-hub", "version": proto::VERSION},
                   "instructions": INSTRUCTIONS})
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools": tools()}),
        "tools/call" => {
            let name = params.get("name").and_then(Value::as_str).unwrap_or("").to_string();
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            match call(sock, session, &name, &args).await {
                Ok(Reply::Text(t)) => json!({"content": [{"type": "text", "text": t}], "isError": false}),
                Ok(Reply::Image { mime, data, note }) => {
                    use base64::Engine;
                    let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                    json!({"content": [{"type": "text", "text": note}, {"type": "image", "data": b64, "mimeType": mime}], "isError": false})
                }
                Err(e) => json!({"content": [{"type": "text", "text": format!("error: {e:#}")}], "isError": true}),
            }
        }
        _ => return Some(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":format!("unknown method {method}")}})),
    };
    Some(json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

pub async fn ipc(sock: &Path, req: &IpcReq) -> Result<IpcResp> {
    let mut s = UnixStream::connect(sock)
        .await
        .map_err(|e| anyhow!("hub daemon not reachable at {} ({e}); start it with `ccc-hub serve`", sock.display()))?;
    proto::write_frame(&mut s, req).await?;
    proto::read_frame(&mut s).await
}

/// One agent tool call on one machine; all its ops share `call` so the owner
/// approves a multi-op call (e.g. a directory push) once.
#[derive(Clone, Copy)]
struct Call<'a> {
    sock: &'a Path,
    session: &'a Session,
    tool: Tool,
    id: u64,
}

async fn op(c: Call<'_>, machine: &str, op: Op) -> Result<OpOk> {
    let req = IpcReq::Op { machine: machine.into(), op, tool: c.tool, call: c.id, session: c.session.clone() };
    match ipc(c.sock, &req).await? {
        IpcResp::Result(r) => r.map_err(|e| anyhow!(e)),
        _ => bail!("unexpected hub response"),
    }
}

fn s<'a>(a: &'a Value, k: &str) -> Result<&'a str> {
    a.get(k).and_then(Value::as_str).with_context(|| format!("missing '{k}'"))
}
fn os(a: &Value, k: &str) -> Option<String> {
    a.get(k).and_then(Value::as_str).filter(|v| !v.is_empty()).map(String::from)
}
fn n(a: &Value, k: &str) -> Option<u64> {
    a.get(k).and_then(Value::as_u64)
}
fn b(a: &Value, k: &str) -> bool {
    a.get(k).and_then(Value::as_bool).unwrap_or(false)
}

fn text(r: OpOk) -> String {
    match r {
        OpOk::Text(t) => t,
        OpOk::Done { n } => format!("ok {n}"),
        other => format!("{other:?}"),
    }
}

pub async fn call(sock: &Path, session: &Session, name: &str, a: &Value) -> Result<Reply> {
    if name == "machines" {
        let IpcResp::Machines(list) = ipc(sock, &IpcReq::Machines).await? else { bail!("unexpected hub response") };
        return Ok(machines_text(&list).into());
    }
    let m = s(a, "machine")?;
    let tool = Tool::parse(name).with_context(|| format!("unknown tool '{name}'"))?;
    let c = Call { sock, session, tool, id: rand::random() };
    if name == "read" {
        let offset = n(a, "offset").unwrap_or(1).max(1) as usize;
        let limit = n(a, "limit").unwrap_or(400).clamp(1, 5000) as usize;
        return Ok(match op(c, m, Op::Read { path: s(a, "path")?.into(), offset, limit }).await? {
            OpOk::Lines { start, total, lines } => format::numbered(start, total, &lines).into(),
            OpOk::Image { mime, data, note } => Reply::Image { mime, data, note },
            o => text(o).into(),
        });
    }
    call_text(c, m, name, a).await.map(Reply::Text)
}

async fn call_text(c: Call<'_>, m: &str, name: &str, a: &Value) -> Result<String> {
    match name {
        "exec" => {
            let timeout = n(a, "timeout").unwrap_or(120).clamp(1, 3600);
            let r = op(c, m, Op::Exec { cmd: s(a, "cmd")?.into(), cwd: os(a, "cwd"), timeout, sudo: b(a, "sudo") }).await?;
            match r {
                OpOk::Exec { code, out, timed_out } => Ok(format::exec_result(m, code, &out, timed_out, timeout)),
                o => Ok(text(o)),
            }
        }
        "write" => {
            let content = s(a, "content")?;
            op(c, m, Op::WriteChunk { path: s(a, "path")?.into(), offset: 0, data: content.as_bytes().to_vec(), mode: None }).await?;
            Ok(format!("ok {} bytes", content.len()))
        }
        "edit" => {
            let r = op(c, m, Op::Edit { path: s(a, "path")?.into(), old: s(a, "old")?.into(), new: s(a, "new")?.into(), all: b(a, "all") }).await?;
            match r {
                OpOk::Done { n } => Ok(format!("ok {n} replacement{}", if n == 1 { "" } else { "s" })),
                o => Ok(text(o)),
            }
        }
        "push" => push(c, m, s(a, "src")?, s(a, "dst")?).await,
        "pull" => pull(c, m, s(a, "src")?, s(a, "dst")?).await,
        "job" => {
            let jop = match s(a, "action")? {
                "start" => JobOp::Start { cmd: s(a, "cmd")?.into(), cwd: os(a, "cwd"), sudo: b(a, "sudo") },
                "status" => JobOp::Status { id: s(a, "id")?.into() },
                "tail" => JobOp::Tail { id: s(a, "id")?.into(), lines: n(a, "lines").unwrap_or(50).clamp(1, 2000) as u32 },
                "kill" => JobOp::Kill { id: s(a, "id")?.into() },
                "list" => JobOp::List,
                x => bail!("unknown action '{x}'"),
            };
            Ok(format::present(m, &text(op(c, m, Op::Job(jop)).await?)))
        }
        _ => bail!("unknown tool '{name}'"),
    }
}

fn machines_text(list: &[Listed]) -> String {
    if list.is_empty() {
        return "no machines connected (is the connector running on the laptop? On a shared hub you see only machines whose token lists you)".into();
    }
    let w = list.iter().map(|l| l.name.len()).max().unwrap_or(0);
    list.iter()
        .map(|l| {
            let mut s = format!("{:w$}  {}  {}", l.name, l.info.status, l.info.os, w = w);
            if l.via != l.name {
                s.push_str(&format!("  via {}", l.via));
            }
            let mut acc = vec![];
            if !l.info.ask.is_empty() {
                acc.push(format!("ask: {}", l.info.ask.join(",")));
            }
            if !l.info.denied.is_empty() {
                acc.push(format!("denied: {}", l.info.denied.join(",")));
            }
            if !acc.is_empty() {
                s.push_str(&format!("  [{}]", acc.join("; ")));
            }
            if !l.info.folders.is_empty() {
                s.push_str(&format!("\n    folders: {}", l.info.folders));
            }
            for line in l.info.description.trim_end().lines() {
                s.push_str("\n    ");
                s.push_str(line.trim_end());
            }
            s
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn human(n: u64) -> String {
    if n >= 1 << 20 {
        format!("{:.1}MB", n as f64 / (1u64 << 20) as f64)
    } else if n >= 1024 {
        format!("{:.1}KB", n as f64 / 1024.0)
    } else {
        format!("{n}B")
    }
}

fn join(base: &str, rel: &str) -> String {
    if rel.is_empty() {
        base.to_string()
    } else {
        format!("{}/{}", base.trim_end_matches(['/', '\\']), rel)
    }
}

#[cfg(unix)]
fn mode_of(m: &std::fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    Some(m.permissions().mode() & 0o7777)
}
#[cfg(not(unix))]
fn mode_of(_: &std::fs::Metadata) -> Option<u32> {
    None
}

/// Walk a local path; entries relative to `root`.
fn walk(root: &Path) -> Result<Vec<Entry>> {
    let meta = std::fs::metadata(root).with_context(|| format!("{}", root.display()))?;
    if !meta.is_dir() {
        return Ok(vec![Entry { rel: String::new(), is_dir: false, size: meta.len(), mode: mode_of(&meta) }]);
    }
    let mut out = vec![];
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        let mut ents: Vec<_> = std::fs::read_dir(&dir)?.flatten().collect();
        ents.sort_by_key(|e| e.file_name());
        for e in ents {
            let name = e.file_name().to_string_lossy().to_string();
            let r = if rel.is_empty() { name.clone() } else { format!("{rel}/{name}") };
            let md = std::fs::metadata(e.path())?;
            if md.is_dir() {
                out.push(Entry { rel: r.clone(), is_dir: true, size: 0, mode: mode_of(&md) });
                stack.push((e.path(), r));
            } else {
                out.push(Entry { rel: r, is_dir: false, size: md.len(), mode: mode_of(&md) });
            }
        }
    }
    Ok(out)
}

async fn push(c: Call<'_>, m: &str, src: &str, dst: &str) -> Result<String> {
    let root = PathBuf::from(src);
    let ents = walk(&root)?;
    let total: u64 = ents.iter().map(|e| e.size).sum();
    if total > MAX_TRANSFER {
        bail!("{} exceeds the {} transfer limit", human(total), human(MAX_TRANSFER));
    }
    let is_dir = root.is_dir();
    if is_dir {
        op(c, m, Op::Mkdir { path: dst.into() }).await?;
    }
    let mut files = 0;
    for e in &ents {
        let rpath = join(dst, &e.rel);
        if e.is_dir {
            op(c, m, Op::Mkdir { path: rpath }).await?;
            continue;
        }
        let lpath = if e.rel.is_empty() { root.clone() } else { root.join(&e.rel) };
        let mut f = tokio::fs::File::open(&lpath).await.with_context(|| format!("{}", lpath.display()))?;
        let mut offset = 0u64;
        loop {
            let mut buf = vec![0u8; CHUNK as usize];
            let mut got = 0;
            while got < buf.len() {
                let k = f.read(&mut buf[got..]).await?;
                if k == 0 {
                    break;
                }
                got += k;
            }
            buf.truncate(got);
            let last = got < CHUNK as usize;
            op(c, m, Op::WriteChunk { path: rpath.clone(), offset, data: buf, mode: if last { e.mode } else { None } })
                .await
                .with_context(|| rpath.clone())?;
            offset += got as u64;
            if last {
                break;
            }
        }
        files += 1;
    }
    Ok(format!("ok {files} file{} {}", if files == 1 { "" } else { "s" }, human(total)))
}

async fn pull(c: Call<'_>, m: &str, src: &str, dst: &str) -> Result<String> {
    let OpOk::Entries(ents) = op(c, m, Op::List { path: src.into() }).await? else { bail!("unexpected response") };
    let total: u64 = ents.iter().map(|e| e.size).sum();
    if total > MAX_TRANSFER {
        bail!("{} exceeds the {} transfer limit", human(total), human(MAX_TRANSFER));
    }
    let root = PathBuf::from(dst);
    let single = ents.len() == 1 && ents[0].rel.is_empty() && !ents[0].is_dir;
    if !single {
        tokio::fs::create_dir_all(&root).await?;
    }
    let mut files = 0;
    for e in &ents {
        let lpath = if e.rel.is_empty() { root.clone() } else { root.join(&e.rel) };
        if e.is_dir {
            tokio::fs::create_dir_all(&lpath).await?;
            continue;
        }
        if let Some(p) = lpath.parent() {
            tokio::fs::create_dir_all(p).await?;
        }
        let rpath = join(src, &e.rel);
        let mut f = tokio::fs::File::create(&lpath).await.with_context(|| format!("{}", lpath.display()))?;
        let mut offset = 0u64;
        loop {
            let OpOk::Bytes(b) = op(c, m, Op::ReadChunk { path: rpath.clone(), offset, len: CHUNK }).await? else {
                bail!("unexpected response")
            };
            f.write_all(&b).await?;
            offset += b.len() as u64;
            if (b.len() as u32) < CHUNK {
                break;
            }
        }
        f.flush().await?;
        #[cfg(unix)]
        if let Some(mode) = e.mode {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&lpath, std::fs::Permissions::from_mode(mode));
        }
        files += 1;
    }
    Ok(format!("ok {files} file{} {}", if files == 1 { "" } else { "s" }, human(total)))
}
