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
    pub description: String,
    /// "online", "connecting", or "error: ..." (redacted)
    pub status: String,
    pub sudo: bool,
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
    Req { id: u64, machine: String, op: Op },
}

/// Local IPC (MCP shim -> hub daemon), one request per connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcReq {
    Machines,
    Op { machine: String, op: Op },
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
        };
        let b = encode(&m);
        let d: Down = decode(&b).unwrap();
        match d {
            Down::Req { id, op: Op::WriteChunk { data, .. }, .. } => {
                assert_eq!(id, 7);
                assert_eq!(data, vec![0, 1, 255]);
            }
            _ => panic!(),
        }
        let r = Up::Resp { id: 1, result: Err("boom".into()) };
        let d: Up = decode(&encode(&r)).unwrap();
        assert!(matches!(d, Up::Resp { result: Err(e), .. } if e == "boom"));
    }

    #[test]
    fn quoting() {
        assert_eq!(shq("a'b"), r"'a'\''b'");
        assert_eq!(shpath("~/x y"), "\"$HOME\"/'x y'");
        assert_eq!(shpath("/etc"), "'/etc'");
    }
}
