//! Wire protocol shared by `ccc-hub` and the `ccc` connector.
//!
//! All messages are MessagePack-encoded (`rmp-serde`). Over WebSocket each
//! message is one binary frame; over the hub's local IPC socket each message
//! is prefixed by a 4-byte big-endian length.

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Max bytes per file chunk in push/pull.
pub const CHUNK: u32 = 1 << 20;

/// What the agent is allowed to know about a machine. Never contains host,
/// IP, user name or credentials.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MachineInfo {
    pub alias: String,
    /// e.g. "linux (Ubuntu 22.04.4 LTS)" or "windows"
    pub os: String,
    /// Owner's notes for the agent (may be multi-line).
    pub description: String,
    /// "online", "connecting", or "error: ..." (redacted)
    pub status: String,
    /// Tools (and "sudo") that need the owner's approval for each use.
    pub ask: Vec<String>,
    /// Tools (and "sudo") the owner does not allow on this machine.
    pub denied: Vec<String>,
    /// Folder rules for the file tools, e.g. "~/proj: read & write; elsewhere: ask"
    /// (empty = no folder limits).
    pub folders: String,
    /// MCP servers the owner runs on this machine.
    pub mcp: Vec<McpInfo>,
}

/// An MCP server on a machine, as the agent sees it in `machines`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct McpInfo {
    pub name: String,
    /// "running", "starting", "error: ..." (redacted)
    pub status: String,
    /// number of tools it offers (0 while not running)
    pub tools: u32,
    /// "allow", "ask" or "deny"
    pub access: String,
}

/// One agent session (one Claude Code process / MCP shim). Folder access
/// granted "for this session" is tied to it.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Session {
    pub id: u64,
    /// For the owner: e.g. "/root/project (started 14:02)".
    pub label: String,
}

/// The agent-facing tools that act on a machine. Permissions are granted per
/// tool; every request names the tool it belongs to.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Tool {
    Exec,
    Read,
    Write,
    Edit,
    Push,
    Pull,
    Job,
    Mcp,
}

impl Tool {
    pub const ALL: [Tool; 8] = [Tool::Exec, Tool::Read, Tool::Write, Tool::Edit, Tool::Push, Tool::Pull, Tool::Job, Tool::Mcp];

    pub fn name(self) -> &'static str {
        match self {
            Tool::Exec => "exec",
            Tool::Read => "read",
            Tool::Write => "write",
            Tool::Edit => "edit",
            Tool::Push => "push",
            Tool::Pull => "pull",
            Tool::Job => "job",
            Tool::Mcp => "mcp",
        }
    }

    pub fn parse(s: &str) -> Option<Tool> {
        Tool::ALL.into_iter().find(|t| t.name() == s)
    }

    /// Whether `op` is something this tool legitimately sends (so a request
    /// can't borrow a more permissive tool's name).
    pub fn permits(self, op: &Op) -> bool {
        matches!(
            (self, op),
            (Tool::Exec, Op::Exec { .. })
                | (Tool::Read, Op::Read { .. })
                | (Tool::Write, Op::WriteChunk { .. })
                | (Tool::Edit, Op::Edit { .. })
                | (Tool::Push, Op::Mkdir { .. } | Op::WriteChunk { .. })
                | (Tool::Pull, Op::List { .. } | Op::ReadChunk { .. })
                | (Tool::Job, Op::Job(_))
                | (Tool::Mcp, Op::Mcp(_))
        )
    }
}

/// Hub and connector must share major.minor (the wire format may change
/// between minor versions before 1.0).
pub fn compatible(a: &str, b: &str) -> bool {
    let mm = |v: &str| v.split('.').take(2).collect::<Vec<_>>().join(".");
    mm(a) == mm(b)
}

/// A listed filesystem entry (used by pull). `rel` is relative to the listed
/// root, with '/' separators; empty when the root itself is a file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Entry {
    pub rel: String,
    pub is_dir: bool,
    pub size: u64,
    pub mode: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum JobOp {
    Start { cmd: String, cwd: Option<String>, sudo: bool },
    Status { id: String },
    Tail { id: String, lines: u32 },
    Kill { id: String },
    List,
}

/// Talking to an MCP server on the machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum McpOp {
    /// The servers (or one server) and their tools with input schemas.
    List { server: Option<String> },
    /// Call one tool; `args` is a JSON object, `timeout` in seconds.
    Call { server: String, tool: String, args: String, timeout: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Op {
    Exec { cmd: String, cwd: Option<String>, timeout: u64, sudo: bool },
    Read { path: String, offset: usize, limit: usize },
    Edit { path: String, old: String, new: String, all: bool },
    List { path: String },
    ReadChunk { path: String, offset: u64, len: u32 },
    /// offset 0 creates/truncates the file (and parent dirs).
    WriteChunk {
        path: String,
        offset: u64,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        mode: Option<u32>,
    },
    Mkdir { path: String },
    Job(JobOp),
    Mcp(McpOp),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OpOk {
    Exec { code: Option<i32>, out: String, timed_out: bool },
    /// `start` is the 1-based number of the first returned line.
    Lines { start: usize, total: usize, lines: Vec<String> },
    Done { n: u64 },
    Entries(Vec<Entry>),
    Bytes(#[serde(with = "serde_bytes")] Vec<u8>),
    Text(String),
    /// An image returned by `read` (already downscaled for the model).
    Image {
        mime: String,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
        /// e.g. "photo.jpg: 4032x3024 JPEG, sent as 1568x1176 JPEG (212 KB)"
        note: String,
    },
    /// An MCP tool result: `content` is the JSON array of MCP content items.
    Mcp { content: String, is_error: bool },
}

pub type OpResult = Result<OpOk, String>;

/// Connector -> hub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Up {
    Hello { name: String, version: String },
    Machines(Vec<MachineInfo>),
    Resp { id: u64, result: OpResult },
}

/// Hub -> connector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Down {
    Welcome { version: String },
    /// `call` identifies the agent's tool call; one call (e.g. a directory
    /// push) can send many ops and needs only one approval.
    Req { id: u64, machine: String, op: Op, tool: Tool, call: u64, session: Session },
    /// The agent session ended; drop what was granted to it.
    EndSession { id: u64 },
}

/// Local IPC (MCP shim -> hub daemon), one request per connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcReq {
    Machines,
    Op { machine: String, op: Op, tool: Tool, call: u64, session: Session },
    EndSession { id: u64 },
    /// `ccc-hub token ...` run against a running hub; the hub applies it as
    /// the calling OS user (identified by the socket's peer credentials).
    Token(TokenReq),
}

/// Token management over the local socket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenReq {
    /// `owners`: users / `@groups` allowed to use the machine (besides the
    /// creator, for a non-admin).
    New { name: String, owners: Vec<String> },
    Pair { name: String },
    List,
    Revoke { name: String },
    Share { name: String, who: Vec<String> },
    Unshare { name: String, who: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenResp {
    /// A new secret (new token or `pair`); `pairing` is set when the hub has
    /// a public URL.
    Created { name: String, token: String, pairing: Option<String>, replaced: bool },
    List(Vec<TokenInfo>),
    Done(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenInfo {
    pub name: String,
    pub owners: Vec<String>,
    /// empty = made by the admin
    pub created_by: String,
    /// None when not known (hub not running)
    pub online: Option<bool>,
}

/// A machine as presented to the agent (name may be "connector/alias").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Listed {
    pub name: String,
    pub via: String,
    pub info: MachineInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcResp {
    Machines(Vec<Listed>),
    Result(OpResult),
    Token(Result<TokenResp, String>),
}

pub fn encode<T: Serialize>(v: &T) -> Vec<u8> {
    rmp_serde::to_vec(v).expect("msgpack encode")
}

pub fn decode<'a, T: Deserialize<'a>>(b: &'a [u8]) -> anyhow::Result<T> {
    Ok(rmp_serde::from_slice(b)?)
}

pub async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(w: &mut W, v: &T) -> anyhow::Result<()> {
    let b = encode(v);
    w.write_all(&(b.len() as u32).to_be_bytes()).await?;
    w.write_all(&b).await?;
    w.flush().await?;
    Ok(())
}

pub async fn read_frame<R: AsyncRead + Unpin, T: for<'a> Deserialize<'a>>(r: &mut R) -> anyhow::Result<T> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len).await?;
    let len = u32::from_be_bytes(len) as usize;
    anyhow::ensure!(len <= 64 << 20, "frame too large");
    let mut b = vec![0u8; len];
    r.read_exact(&mut b).await?;
    decode(&b)
}

/// Quote a string for POSIX sh using single quotes.
pub fn shq(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Quote a path for POSIX sh, keeping a leading `~` expandable.
pub fn shpath(p: &str) -> String {
    if p == "~" {
        "\"$HOME\"".into()
    } else if let Some(rest) = p.strip_prefix("~/") {
        format!("\"$HOME\"/{}", shq(rest))
    } else {
        shq(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let m = Down::Req {
            id: 7,
            machine: "robot".into(),
            op: Op::WriteChunk { path: "/tmp/x".into(), offset: 0, data: vec![0, 1, 255], mode: Some(0o755) },
            tool: Tool::Push,
            call: 9,
            session: Session { id: 3, label: "x".into() },
        };
        let b = encode(&m);
        let d: Down = decode(&b).unwrap();
        match d {
            Down::Req { id, op: Op::WriteChunk { data, .. }, session, .. } => {
                assert_eq!(id, 7);
                assert_eq!(session.id, 3);
                assert_eq!(data, vec![0, 1, 255]);
            }
            _ => panic!(),
        }
        let r = Up::Resp { id: 1, result: Err("boom".into()) };
        let d: Up = decode(&encode(&r)).unwrap();
        assert!(matches!(d, Up::Resp { result: Err(e), .. } if e == "boom"));
        let r = Up::Resp { id: 2, result: Ok(OpOk::Mcp { content: "[]".into(), is_error: true }) };
        assert!(matches!(decode::<Up>(&encode(&r)).unwrap(), Up::Resp { result: Ok(OpOk::Mcp { is_error: true, .. }), .. }));
    }

    #[test]
    fn tools() {
        assert!(Tool::Pull.permits(&Op::List { path: "/".into() }));
        assert!(!Tool::Read.permits(&Op::Exec { cmd: "x".into(), cwd: None, timeout: 1, sudo: false }));
        assert_eq!(Tool::parse("job"), Some(Tool::Job));
        assert_eq!(Tool::parse("mcp"), Some(Tool::Mcp));
        assert!(Tool::Mcp.permits(&Op::Mcp(McpOp::List { server: None })));
        assert!(!Tool::Exec.permits(&Op::Mcp(McpOp::List { server: None })));
        assert!(compatible("0.3.0", "0.3.7"));
        assert!(!compatible("0.2.1", "0.3.0"));
    }

    #[test]
    fn quoting() {
        assert_eq!(shq("a'b"), r"'a'\''b'");
        assert_eq!(shpath("~/x y"), "\"$HOME\"/'x y'");
        assert_eq!(shpath("/etc"), "'/etc'");
    }
}
