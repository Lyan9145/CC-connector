//! Run commands on the machine the connector itself runs on.

use super::{display_buf, CapBuf, Family, RawOut, Run, DATA_MAX};
use anyhow::{Context, Result};
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

pub fn family() -> Family {
    if cfg!(windows) { Family::Windows } else { Family::Posix }
}

pub fn os_label() -> String {
    if cfg!(windows) {
        let v = std::process::Command::new("cmd").args(["/C", "ver"]).output().ok();
        let v = v.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
        if v.is_empty() { "windows".into() } else { format!("windows ({v})") }
    } else {
        let pretty = std::fs::read_to_string("/etc/os-release").ok().and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("PRETTY_NAME=").map(|v| v.trim_matches('"').to_string()))
        });
        match pretty {
            Some(p) => format!("{} ({p})", std::env::consts::OS),
            None => std::env::consts::OS.into(),
        }
    }
}

pub fn home() -> std::path::PathBuf {
    dirs::home_dir().unwrap_or_else(|| ".".into())
}

/// Expand a leading `~` to the home directory.
pub fn expand(p: &str) -> std::path::PathBuf {
    if p == "~" {
        home()
    } else if let Some(r) = p.strip_prefix("~/").or_else(|| p.strip_prefix("~\\")) {
        home().join(r)
    } else {
        p.into()
    }
}

/// Encode a PowerShell script for `-EncodedCommand`.
pub fn ps_encode(script: &str) -> String {
    use base64::Engine;
    let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    base64::engine::general_purpose::STANDARD.encode(utf16)
}

fn command(script: &str) -> Command {
    let mut c;
    if cfg!(windows) {
        c = Command::new("powershell.exe");
        c.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &ps_encode(script)]);
        #[cfg(windows)]
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    } else {
        c = Command::new("bash");
        c.arg("-c").arg(script);
        #[cfg(unix)]
        c.process_group(0);
    }
    c.current_dir(home());
    c
}

async fn kill_tree(pid: Option<u32>) {
    let Some(pid) = pid else { return };
    if cfg!(windows) {
        let _ = Command::new("taskkill").args(["/T", "/F", "/PID", &pid.to_string()]).output().await;
    } else {
        let _ = Command::new("kill").args(["-KILL", "--", &format!("-{pid}")]).output().await;
    }
}

pub async fn run(r: Run<'_>) -> Result<RawOut> {
    let mut child = command(r.script)
        .stdin(if r.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("spawn shell")?;
    let pid = child.id();
    if let (Some(data), Some(mut sin)) = (r.stdin, child.stdin.take()) {
        tokio::spawn(async move {
            let _ = sin.write_all(&data).await;
            let _ = sin.shutdown().await;
        });
    }
    let mut so = child.stdout.take().unwrap();
    let mut se = child.stderr.take().unwrap();
    let display = r.display;
    let collect = async move {
        let mut out = if display { display_buf() } else { CapBuf::new(DATA_MAX, 0) };
        let mut err = CapBuf::new(256 << 10, 0);
        let (mut a, mut b) = ([0u8; 32768], [0u8; 8192]);
        let (mut so_done, mut se_done) = (false, false);
        while !(so_done && se_done) {
            tokio::select! {
                n = so.read(&mut a), if !so_done => match n { Ok(0) | Err(_) => so_done = true, Ok(n) => out.push(&a[..n]) },
                n = se.read(&mut b), if !se_done => match n { Ok(0) | Err(_) => se_done = true, Ok(n) => err.push(&b[..n]) },
            }
        }
        let status = child.wait().await.ok();
        (out, err, status)
    };
    match tokio::time::timeout(r.timeout, collect).await {
        Ok((out, err, status)) => {
            anyhow::ensure!(display || !out.overflowed(), "output exceeds {} MB", DATA_MAX >> 20);
            Ok(RawOut { code: status.and_then(|s| s.code()), stdout: out.finish(), stderr: err.finish(), killed: false })
        }
        Err(_) => {
            kill_tree(pid).await;
            Ok(RawOut { code: None, killed: true, ..Default::default() })
        }
    }
}
