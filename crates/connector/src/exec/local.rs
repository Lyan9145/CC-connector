//! Run commands on the machine the connector itself runs on.

use super::{display_buf, CapBuf, Family, RawOut, Run, DATA_MAX};
use anyhow::{Context, Result};
use std::process::Stdio;
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

pub fn family() -> Family {
    if cfg!(windows) { Family::Windows } else { Family::Posix }
}

/// Extract "10.0.26200" from `ver` output in any display language.
pub fn parse_win_version(ver: &str) -> Option<(u32, u32, u32)> {
    ver.split(|c: char| !(c.is_ascii_digit() || c == '.')).find_map(|tok| {
        let mut it = tok.split('.').filter(|s| !s.is_empty()).map(|s| s.parse::<u32>().ok());
        match (it.next()?, it.next()?, it.next()?) {
            (Some(a), Some(b), Some(c)) => Some((a, b, c)),
            _ => None,
        }
    })
}

/// OS description shown to the agent (computed once; spawning is slow on Windows).
pub fn os_label() -> String {
    static L: OnceLock<String> = OnceLock::new();
    L.get_or_init(|| {
        if cfg!(windows) {
            let out = std::process::Command::new("cmd").args(["/C", "ver"]).output().ok();
            let raw = out.map(|o| o.stdout).unwrap_or_default();
            // `ver` prints in the console code page; only the digits matter
            let ver = String::from_utf8_lossy(&raw);
            let shell = if ps_exe().contains("pwsh") { "PowerShell 7" } else { "Windows PowerShell 5" };
            match parse_win_version(&ver) {
                Some((10, _, b)) if b >= 22000 => format!("windows 11 (build {b}, {shell})"),
                Some((a, _, b)) => format!("windows {a} (build {b}, {shell})"),
                None => format!("windows ({shell})"),
            }
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
    })
    .clone()
}

/// PowerShell 7 (`pwsh.exe`) if installed, else Windows PowerShell 5.1.
pub fn ps_exe() -> &'static str {
    static P: OnceLock<String> = OnceLock::new();
    P.get_or_init(|| {
        let mut cands: Vec<std::path::PathBuf> = std::env::var_os("PATH")
            .map(|p| std::env::split_paths(&p).map(|d| d.join("pwsh.exe")).collect())
            .unwrap_or_default();
        if let Some(pf) = std::env::var_os("ProgramFiles") {
            cands.push(std::path::PathBuf::from(pf).join("PowerShell").join("7").join("pwsh.exe"));
        }
        cands
            .into_iter()
            .find(|p| p.is_file())
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|| "powershell.exe".into())
    })
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
        c = Command::new(ps_exe());
        c.args(["-NoProfile", "-NonInteractive", "-OutputFormat", "Text", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &ps_encode(script)]);
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
        let mut k = Command::new("taskkill");
        k.args(["/T", "/F", "/PID", &pid.to_string()]);
        #[cfg(windows)]
        k.creation_flags(0x0800_0000);
        let _ = k.output().await;
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
    let mut out = if r.display { display_buf() } else { CapBuf::new(DATA_MAX, 0) };
    let mut err = CapBuf::new(256 << 10, 0);
    let (mut a, mut b) = ([0u8; 32768], [0u8; 8192]);
    let (mut so_done, mut se_done) = (false, false);
    let deadline = tokio::time::sleep(r.timeout);
    tokio::pin!(deadline);
    let mut killed = false;
    while !(so_done && se_done) {
        tokio::select! {
            n = so.read(&mut a), if !so_done => match n { Ok(0) | Err(_) => so_done = true, Ok(n) => out.push(&a[..n]) },
            n = se.read(&mut b), if !se_done => match n { Ok(0) | Err(_) => se_done = true, Ok(n) => err.push(&b[..n]) },
            _ = &mut deadline => { killed = true; break; }
        }
    }
    let code = if killed {
        // keep what was printed so far
        kill_tree(pid).await;
        let _ = child.kill().await;
        None
    } else {
        child.wait().await.ok().and_then(|s| s.code())
    };
    anyhow::ensure!(r.display || !out.overflowed(), "output exceeds {} MB", DATA_MAX >> 20);
    Ok(RawOut { code, stdout: out.finish(), stderr: err.finish(), killed })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win_version_any_language() {
        assert_eq!(parse_win_version("Microsoft Windows [\u{7248}\u{672c} 10.0.26200.9974]"), Some((10, 0, 26200)));
        assert_eq!(parse_win_version("Microsoft Windows [Version 10.0.19045.4529]"), Some((10, 0, 19045)));
        assert_eq!(parse_win_version("garbage"), None);
    }
}
