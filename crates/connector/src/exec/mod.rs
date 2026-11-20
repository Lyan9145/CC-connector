//! Execution targets: the local machine or an SSH host.

pub mod local;
pub mod ssh;

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Posix,
    Windows,
}

/// Raw result of running a command on a target.
#[derive(Debug, Default)]
pub struct RawOut {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Our own guard timer fired (the process was killed).
    pub killed: bool,
}

impl RawOut {
    pub fn err_text(&self) -> String {
        let e = String::from_utf8_lossy(&self.stderr).trim().to_string();
        if e.is_empty() {
            let o = String::from_utf8_lossy(&self.stdout).trim().to_string();
            if o.is_empty() { format!("command failed (exit {:?})", self.code) } else { o }
        } else {
            e
        }
    }
}

/// Bounded output buffer. With `keep_tail`, keeps the first `head` bytes and
/// the last `tail` bytes, dropping the middle. Without it, records overflow.
pub struct CapBuf {
    head_cap: usize,
    tail_cap: usize,
    head: Vec<u8>,
    tail: std::collections::VecDeque<u8>,
    dropped: u64,
}

impl CapBuf {
    pub fn new(head_cap: usize, tail_cap: usize) -> Self {
        Self { head_cap, tail_cap, head: vec![], tail: Default::default(), dropped: 0 }
    }
    pub fn push(&mut self, mut b: &[u8]) {
        if self.head.len() < self.head_cap {
            let k = (self.head_cap - self.head.len()).min(b.len());
            self.head.extend_from_slice(&b[..k]);
            b = &b[k..];
        }
        if b.is_empty() {
            return;
        }
        if self.tail_cap == 0 {
            self.dropped += b.len() as u64;
            return;
        }
        self.tail.extend(b);
        while self.tail.len() > self.tail_cap {
            let over = self.tail.len() - self.tail_cap;
            self.tail.drain(..over);
            self.dropped += over as u64;
        }
    }
    pub fn overflowed(&self) -> bool {
        self.dropped > 0
    }
    pub fn finish(self) -> Vec<u8> {
        let mut v = self.head;
        if self.dropped > 0 && self.tail_cap > 0 {
            v.extend_from_slice(format!("\n[... {} bytes dropped by connector ...]\n", self.dropped).as_bytes());
        }
        v.extend(self.tail);
        v
    }
}

/// Output buffer for commands whose output is shown to the agent.
pub fn display_buf() -> CapBuf {
    CapBuf::new(2 << 20, 2 << 20)
}

/// Max bytes for file contents moved through shell commands.
pub const DATA_MAX: usize = 50 << 20;

pub struct Run<'a> {
    pub script: &'a str,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
    /// keep head+tail of output (display) instead of exact bytes (data)
    pub display: bool,
}

/// How sudo is applied to a POSIX command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sudo {
    No,
    /// password is fed on stdin
    WithPassword,
    /// passwordless sudo (`sudo -n`)
    NoPassword,
}

impl Sudo {
    pub fn prefix(self) -> &'static str {
        match self {
            Sudo::No => "",
            Sudo::WithPassword => "sudo -k -S -p '' ",
            Sudo::NoPassword => "sudo -n ",
        }
    }
}

/// Build the POSIX shell script for an `exec` request.
pub fn posix_exec_script(cmd: &str, cwd: Option<&str>, init: &str, timeout: u64, sudo: Sudo) -> String {
    use ccc_proto::{shpath, shq};
    let mut inner = String::from("exec 2>&1 </dev/null\n");
    if !init.trim().is_empty() {
        inner.push_str(init.trim());
        inner.push('\n');
    }
    inner.push_str(cmd);
    let mut outer = String::from("exec 2>&1\n");
    if let Some(d) = cwd {
        outer.push_str(&format!("cd {} || exit 1\n", shpath(d)));
    }
    outer.push_str(&format!("timeout -k 5 {timeout} {}bash -lc {}", sudo.prefix(), shq(&inner)));
    outer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capbuf_head_tail() {
        let mut c = CapBuf::new(4, 4);
        c.push(b"0123456789");
        assert!(c.overflowed());
        let v = String::from_utf8(c.finish()).unwrap();
        assert!(v.starts_with("0123"));
        assert!(v.ends_with("6789"));
        assert!(v.contains("2 bytes dropped"));
    }

    #[test]
    fn exec_script_shape() {
        let s = posix_exec_script("echo 'hi'", Some("~/ws"), "source x", 60, Sudo::WithPassword);
        assert!(s.contains("cd \"$HOME\"/'ws' || exit 1"));
        assert!(s.contains("timeout -k 5 60 sudo -k -S -p '' bash -lc "));
        assert!(s.contains("source x"));
    }
}
