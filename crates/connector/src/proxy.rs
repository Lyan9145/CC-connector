//! Reaching the hub through an HTTP (CONNECT) or SOCKS5 proxy.
//!
//! The proxy only carries the TLS stream: it sees the hub's host name and
//! port, never the token or any traffic (the hub certificate is still
//! checked or pinned end to end).

use crate::store::{ProxyCfg, ProxyMode};
use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Http,
    Socks5,
}

/// A proxy to go through.
#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: Option<String>,
}

impl Route {
    /// For the status line, e.g. "HTTP proxy 127.0.0.1:7890".
    pub fn shown(&self) -> String {
        let k = if self.kind == Kind::Http { "HTTP" } else { "SOCKS5" };
        format!("{k} proxy {}", hostport(&self.host, self.port))
    }
}

fn hostport(h: &str, p: u16) -> String {
    if h.contains(':') { format!("[{h}]:{p}") } else { format!("{h}:{p}") }
}

/// Parse "http://host:port", "socks5://user@host:port", "socks5h://…" or a
/// bare "host:port" (HTTP). Returns the route without a password.
pub fn parse(url: &str) -> Result<Route> {
    let s = url.trim();
    if s.is_empty() {
        bail!("proxy address is empty");
    }
    let (kind, rest) = match s.split_once("://") {
        None => (Kind::Http, s),
        Some((scheme, rest)) => match scheme.to_ascii_lowercase().as_str() {
            "http" => (Kind::Http, rest),
            "socks5" | "socks5h" | "socks" => (Kind::Socks5, rest),
            "https" => bail!("HTTPS proxies (TLS to the proxy) are not supported; use http:// or socks5://"),
            "socks4" | "socks4a" => bail!("SOCKS4 is not supported; use socks5://"),
            o => bail!("unknown proxy type '{o}'; use http://host:port or socks5://host:port"),
        },
    };
    let rest = rest.trim_end_matches('/');
    let (user, hp) = match rest.rsplit_once('@') {
        Some((u, hp)) => (u.split(':').next().unwrap_or("").to_string(), hp),
        None => (String::new(), rest),
    };
    let (host, port) = if let Some(r) = hp.strip_prefix('[') {
        let (h, p) = r.split_once(']').context("bad IPv6 proxy address")?;
        (h.to_string(), p.strip_prefix(':').unwrap_or(""))
    } else {
        match hp.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p),
            None => (hp.to_string(), ""),
        }
    };
    if host.is_empty() || host.contains('/') {
        bail!("proxy address must look like host:port");
    }
    let port = if port.is_empty() {
        if kind == Kind::Http { 8080 } else { 1080 }
    } else {
        port.parse().ok().filter(|p| *p > 0).with_context(|| format!("bad proxy port '{port}'"))?
    };
    Ok(Route { kind, host, port, user, pass: None })
}

/// The proxy to use for `target` (the hub's host), or None for a direct
/// connection. `pass` is the saved proxy password.
pub fn route_for(cfg: &ProxyCfg, pass: Option<String>, target: &str) -> Result<Option<Route>> {
    let mut r = match cfg.mode {
        ProxyMode::Off => return Ok(None),
        ProxyMode::Manual => parse(&cfg.url)?,
        ProxyMode::System => match system() {
            Sys::None => return Ok(None),
            Sys::Pac(u) => bail!("the system proxy uses an auto-config script ({u}), which is not supported; enter the proxy address manually"),
            Sys::Proxy { url, bypass } => {
                if bypassed(&bypass, target) {
                    return Ok(None);
                }
                parse(&url)?
            }
        },
    };
    if !cfg.user.is_empty() {
        r.user = cfg.user.clone();
    }
    if !r.user.is_empty() {
        r.pass = pass;
    }
    Ok(Some(r))
}

/// What the operating system says about proxies.
#[derive(Debug, PartialEq)]
pub enum Sys {
    None,
    Proxy { url: String, bypass: Vec<String> },
    /// A PAC script (not supported).
    #[cfg_attr(not(windows), allow(dead_code))]
    Pac(String),
}

/// Text for the Hub page, e.g. "system proxy: http://127.0.0.1:7890".
pub fn describe_system() -> String {
    match system() {
        Sys::None => "no system proxy is set".into(),
        Sys::Proxy { url, .. } => format!("system proxy: {url}"),
        Sys::Pac(u) => format!("system uses an auto-config script ({u}): not supported"),
    }
}

pub fn system() -> Sys {
    #[cfg(windows)]
    {
        let s = windows_proxy();
        if s != Sys::None {
            return s;
        }
    }
    let env = |k: &str| std::env::var(k).ok().or_else(|| std::env::var(k.to_lowercase()).ok()).filter(|v| !v.trim().is_empty());
    match env("HTTPS_PROXY").or_else(|| env("ALL_PROXY")) {
        Some(url) => {
            let bypass = env("NO_PROXY").map(|v| v.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default();
            Sys::Proxy { url, bypass }
        }
        None => Sys::None,
    }
}

/// Windows "Internet Options" proxy (what browsers and most proxy tools such
/// as Clash or v2rayN set).
#[cfg(windows)]
fn windows_proxy() -> Sys {
    use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_CURRENT_USER, RRF_RT_REG_DWORD, RRF_RT_REG_SZ};
    let wide = |s: &str| s.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>();
    let key = wide(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
    let get_str = |name: &str| -> Option<String> {
        let n = wide(name);
        let mut buf = vec![0u16; 2048];
        let mut len = (buf.len() * 2) as u32;
        let r = unsafe {
            RegGetValueW(HKEY_CURRENT_USER, key.as_ptr(), n.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut len)
        };
        if r != 0 {
            return None;
        }
        let n = (len as usize / 2).saturating_sub(1).min(buf.len());
        Some(String::from_utf16_lossy(&buf[..n]).trim_end_matches('\0').trim().to_string()).filter(|s| !s.is_empty())
    };
    let enabled = {
        let n = wide("ProxyEnable");
        let mut v: u32 = 0;
        let mut len = 4u32;
        let r = unsafe {
            RegGetValueW(HKEY_CURRENT_USER, key.as_ptr(), n.as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), (&mut v as *mut u32).cast(), &mut len)
        };
        r == 0 && v != 0
    };
    if enabled {
        if let Some(server) = get_str("ProxyServer") {
            let bypass = get_str("ProxyOverride").map(|v| v.split(';').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()).unwrap_or_default();
            return Sys::Proxy { url: windows_server(&server), bypass };
        }
    }
    match get_str("AutoConfigURL") {
        Some(u) => Sys::Pac(u),
        None => Sys::None,
    }
}

/// "host:port", or per-protocol "http=h:p;https=h:p;socks=h:p".
#[cfg_attr(not(windows), allow(dead_code))]
fn windows_server(s: &str) -> String {
    if !s.contains('=') {
        return s.trim().to_string();
    }
    let parts: Vec<(String, String)> = s
        .split(';')
        .filter_map(|p| p.split_once('=').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())))
        .collect();
    for (want, scheme) in [("https", "http"), ("http", "http"), ("socks", "socks5")] {
        if let Some((_, v)) = parts.iter().find(|(k, _)| k == want) {
            return if v.contains("://") { v.clone() } else { format!("{scheme}://{v}") };
        }
    }
    s.trim().to_string()
}

/// Whether `host` is on the bypass list (Windows ProxyOverride or NO_PROXY
/// syntax: `*.lan`, `10.*`, `.example.com`, `<local>`, `*`).
pub fn bypassed(list: &[String], host: &str) -> bool {
    let h = host.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
    list.iter().any(|e| {
        let e = e.trim().to_ascii_lowercase();
        let e = e.split(':').next().unwrap_or("").to_string(); // ignore ports
        if e.is_empty() {
            false
        } else if e == "<local>" {
            !h.contains('.') && !h.contains(':')
        } else if e == "*" {
            true
        } else if let Some(suffix) = e.strip_prefix('.') {
            h == suffix || h.ends_with(&format!(".{suffix}"))
        } else if e.contains('*') {
            glob(&e, &h)
        } else {
            h == e || h.ends_with(&format!(".{e}"))
        }
    })
}

fn glob(p: &str, s: &str) -> bool {
    let parts: Vec<&str> = p.split('*').collect();
    let mut rest = s;
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            match rest.strip_prefix(part) {
                Some(r) => rest = r,
                None => return false,
            }
        } else if i == parts.len() - 1 {
            return rest.ends_with(part);
        } else {
            match rest.find(part) {
                Some(k) => rest = &rest[k + part.len()..],
                None => return false,
            }
        }
    }
    rest.is_empty()
}

/// Open a TCP stream to `host:port` through the proxy (reaching the proxy
/// through network adapter `iface`, or automatically when empty).
pub async fn connect(r: &Route, host: &str, port: u16, iface: &str) -> Result<TcpStream> {
    let mut s = crate::netif::connect(&r.host, r.port, iface).await.with_context(|| format!("can't reach the {}", r.shown()))?;
    match r.kind {
        Kind::Http => http_connect(&mut s, r, host, port).await?,
        Kind::Socks5 => socks5(&mut s, r, host, port).await?,
    }
    Ok(s)
}

async fn http_connect(s: &mut TcpStream, r: &Route, host: &str, port: u16) -> Result<()> {
    let hp = hostport(host, port);
    let mut req = format!("CONNECT {hp} HTTP/1.1\r\nHost: {hp}\r\nProxy-Connection: keep-alive\r\n");
    if !r.user.is_empty() {
        use base64::Engine;
        let cred = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", r.user, r.pass.as_deref().unwrap_or("")));
        req.push_str(&format!("Proxy-Authorization: Basic {cred}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;
    // read the response head byte by byte so nothing after it is consumed
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await? == 0 {
            bail!("the proxy closed the connection");
        }
        head.push(b[0]);
        if head.len() > 16 * 1024 {
            bail!("the proxy sent an oversized response");
        }
    }
    let head = String::from_utf8_lossy(&head);
    let status = head.lines().next().unwrap_or("");
    let code = status.split_whitespace().nth(1).unwrap_or("");
    match code {
        "200" => Ok(()),
        "407" => bail!("the proxy needs a user name and password (407)"),
        _ => bail!("the proxy refused the connection: {}", status.trim()),
    }
}

async fn socks5(s: &mut TcpStream, r: &Route, host: &str, port: u16) -> Result<()> {
    let auth = !r.user.is_empty();
    s.write_all(if auth { &[5, 2, 0, 2][..] } else { &[5, 1, 0][..] }).await?;
    let mut rep = [0u8; 2];
    s.read_exact(&mut rep).await.context("the proxy closed the connection")?;
    if rep[0] != 5 {
        bail!("not a SOCKS5 proxy");
    }
    match rep[1] {
        0 => {}
        2 if auth => {
            let (u, p) = (r.user.as_bytes(), r.pass.as_deref().unwrap_or("").as_bytes());
            if u.len() > 255 || p.len() > 255 {
                bail!("proxy user name or password too long");
            }
            let mut m = vec![1, u.len() as u8];
            m.extend_from_slice(u);
            m.push(p.len() as u8);
            m.extend_from_slice(p);
            s.write_all(&m).await?;
            let mut a = [0u8; 2];
            s.read_exact(&mut a).await?;
            if a[1] != 0 {
                bail!("the proxy rejected the user name or password");
            }
        }
        0xff => bail!("the proxy needs a user name and password"),
        m => bail!("the proxy wants an unsupported login method ({m})"),
    }
    let mut m = vec![5, 1, 0];
    let bare = host.trim_matches(|c| c == '[' || c == ']');
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            m.push(1);
            m.extend_from_slice(&ip.octets());
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            m.push(4);
            m.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            // let the proxy resolve the name (like socks5h)
            if bare.len() > 255 {
                bail!("host name too long");
            }
            m.push(3);
            m.push(bare.len() as u8);
            m.extend_from_slice(bare.as_bytes());
        }
    }
    m.extend_from_slice(&port.to_be_bytes());
    s.write_all(&m).await?;
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await.context("the proxy closed the connection")?;
    if h[1] != 0 {
        let why = match h[1] {
            1 => "general failure",
            2 => "not allowed by the proxy's rules",
            3 => "network unreachable",
            4 => "host unreachable",
            5 => "connection refused",
            6 => "TTL expired",
            7 => "command not supported",
            8 => "address type not supported",
            _ => "unknown error",
        };
        bail!("the proxy could not reach the hub: {why}");
    }
    let skip = match h[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        _ => bail!("bad SOCKS5 reply"),
    };
    let mut rest = vec![0u8; skip + 2];
    s.read_exact(&mut rest).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parsing() {
        let r = parse("127.0.0.1:7890").unwrap();
        assert_eq!((r.kind, r.host.as_str(), r.port), (Kind::Http, "127.0.0.1", 7890));
        let r = parse("socks5h://bob@proxy.lan:1080/").unwrap();
        assert_eq!((r.kind, r.host.as_str(), r.port, r.user.as_str()), (Kind::Socks5, "proxy.lan", 1080, "bob"));
        let r = parse("http://[::1]:3128").unwrap();
        assert_eq!((r.host.as_str(), r.port), ("::1", 3128));
        assert_eq!(parse("socks5://p").unwrap().port, 1080);
        assert!(parse("https://p:1").is_err());
        assert!(parse("http://p:0").is_err());
        assert!(parse("").is_err());
        assert_eq!(windows_server("127.0.0.1:7890"), "127.0.0.1:7890");
        assert_eq!(windows_server("http=a:1;https=b:2;socks=c:3"), "http://b:2");
        assert_eq!(windows_server("socks=c:3"), "socks5://c:3");
    }

    #[test]
    fn bypass() {
        let l: Vec<String> = ["localhost", "127.*", "*.lan", ".corp.com", "<local>", "10.0.0.5:443"].iter().map(|s| s.to_string()).collect();
        assert!(bypassed(&l, "localhost"));
        assert!(bypassed(&l, "127.0.0.1"));
        assert!(bypassed(&l, "nas.lan"));
        assert!(bypassed(&l, "a.corp.com"));
        assert!(bypassed(&l, "corp.com"));
        assert!(bypassed(&l, "printer"));
        assert!(bypassed(&l, "10.0.0.5"));
        assert!(!bypassed(&l, "hub.example.org"));
        assert!(!bypassed(&l, "1.127.0.0"));
        assert!(bypassed(&["*".into()], "x.y"));
    }

    /// Echo server behind a minimal HTTP CONNECT or SOCKS5 proxy.
    async fn echo() -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = l.accept().await {
                tokio::spawn(async move {
                    let mut b = [0u8; 64];
                    while let Ok(n) = s.read(&mut b).await {
                        if n == 0 || s.write_all(&b[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        port
    }

    async fn fake_proxy(kind: Kind, need: Option<(&'static str, &'static str)>) -> u16 {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut c, _)) = l.accept().await {
                tokio::spawn(async move {
                    let target: String = match kind {
                        Kind::Http => {
                            let mut head = Vec::new();
                            let mut b = [0u8; 1];
                            while !head.ends_with(b"\r\n\r\n") {
                                c.read_exact(&mut b).await.unwrap();
                                head.push(b[0]);
                            }
                            let head = String::from_utf8(head).unwrap();
                            if let Some((u, p)) = need {
                                use base64::Engine;
                                let want = base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"));
                                if !head.contains(&format!("Proxy-Authorization: Basic {want}")) {
                                    c.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await.unwrap();
                                    return;
                                }
                            }
                            c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.unwrap();
                            head.split_whitespace().nth(1).unwrap().to_string()
                        }
                        Kind::Socks5 => {
                            let mut h = [0u8; 2];
                            c.read_exact(&mut h).await.unwrap();
                            let mut m = vec![0u8; h[1] as usize];
                            c.read_exact(&mut m).await.unwrap();
                            if let Some((u, p)) = need {
                                c.write_all(&[5, 2]).await.unwrap();
                                let mut v = [0u8; 2];
                                c.read_exact(&mut v).await.unwrap();
                                let mut user = vec![0u8; v[1] as usize];
                                c.read_exact(&mut user).await.unwrap();
                                let mut pl = [0u8; 1];
                                c.read_exact(&mut pl).await.unwrap();
                                let mut pass = vec![0u8; pl[0] as usize];
                                c.read_exact(&mut pass).await.unwrap();
                                let ok = user == u.as_bytes() && pass == p.as_bytes();
                                c.write_all(&[1, if ok { 0 } else { 1 }]).await.unwrap();
                                if !ok {
                                    return;
                                }
                            } else {
                                c.write_all(&[5, 0]).await.unwrap();
                            }
                            let mut r = [0u8; 4];
                            c.read_exact(&mut r).await.unwrap();
                            assert_eq!(r[3], 3, "host names go to the proxy unresolved");
                            let mut l = [0u8; 1];
                            c.read_exact(&mut l).await.unwrap();
                            let mut name = vec![0u8; l[0] as usize + 2];
                            c.read_exact(&mut name).await.unwrap();
                            let port = u16::from_be_bytes([name[name.len() - 2], name[name.len() - 1]]);
                            c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.unwrap();
                            format!("{}:{port}", String::from_utf8_lossy(&name[..name.len() - 2]))
                        }
                    };
                    let mut up = TcpStream::connect(target.replace("localhost", "127.0.0.1")).await.unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut c, &mut up).await;
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn through_proxies() {
        let target = echo().await;
        for kind in [Kind::Http, Kind::Socks5] {
            for need in [None, Some(("bob", "s3cret"))] {
                let pp = fake_proxy(kind, need).await;
                let mut r = Route { kind, host: "127.0.0.1".into(), port: pp, user: String::new(), pass: None };
                if let Some((u, p)) = need {
                    // without a login the proxy refuses
                    assert!(connect(&r, "localhost", target, "").await.is_err(), "{kind:?} needs a login");
                    r.user = u.into();
                    r.pass = Some(p.into());
                }
                let mut s = connect(&r, "localhost", target, "").await.unwrap();
                s.write_all(b"ping").await.unwrap();
                let mut b = [0u8; 4];
                s.read_exact(&mut b).await.unwrap();
                assert_eq!(&b, b"ping", "{kind:?} {need:?}");
            }
        }
        let dead = Route { kind: Kind::Http, host: "127.0.0.1".into(), port: 1, user: String::new(), pass: None };
        let e = connect(&dead, "localhost", target, "").await.unwrap_err();
        assert!(format!("{e:#}").contains("can't reach the HTTP proxy 127.0.0.1:1"), "{e:#}");
    }

    #[test]
    fn routes() {
        let off = ProxyCfg::default();
        assert_eq!(route_for(&off, None, "h").unwrap(), None);
        let m = ProxyCfg { mode: ProxyMode::Manual, url: "socks5://p:9".into(), user: "u".into() };
        let r = route_for(&m, Some("pw".into()), "h").unwrap().unwrap();
        assert_eq!((r.kind, r.user.as_str(), r.pass.as_deref()), (Kind::Socks5, "u", Some("pw")));
        let m = ProxyCfg { mode: ProxyMode::Manual, url: "p:9".into(), user: String::new() };
        assert_eq!(route_for(&m, Some("pw".into()), "h").unwrap().unwrap().pass, None, "no user, no password");
    }
}
