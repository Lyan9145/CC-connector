//! Network adapters: listing them, and opening TCP connections through a
//! chosen one (for the hub link and for SSH connections).
//!
//! Windows: `IP_UNICAST_IF` forces the outgoing adapter (no admin rights
//! needed) and the socket is bound to the adapter's address.
//! Linux: `SO_BINDTODEVICE` forces it when allowed (root / CAP_NET_RAW);
//! otherwise the socket is only bound to the adapter's address and the
//! routing table still decides the path.

use anyhow::{anyhow, Context, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpSocket, TcpStream};

#[derive(Debug, Clone, PartialEq)]
pub struct Adapter {
    /// What the owner picks and the config stores: "Wi-Fi", "Ethernet 2",
    /// "eth0".
    pub name: String,
    /// Hardware / driver description (Windows), may be empty.
    pub desc: String,
    pub index: u32,
    /// Connected (operational).
    pub up: bool,
    pub v4: Vec<Ipv4Addr>,
    pub v6: Vec<Ipv6Addr>,
}

impl Adapter {
    /// e.g. "Ethernet 2 · 192.168.1.10 · Realtek USB GbE"
    pub fn label(&self) -> String {
        let mut s = self.name.clone();
        if let Some(a) = self.v4.first() {
            s.push_str(&format!(" · {a}"));
        } else if let Some(a) = self.v6.iter().find(|a| !link_local(a)) {
            s.push_str(&format!(" · {a}"));
        }
        if !self.desc.is_empty() && self.desc != self.name {
            s.push_str(&format!(" · {}", self.desc));
        }
        if !self.up {
            s.push_str(" (not connected)");
        }
        s
    }
}

fn link_local(a: &Ipv6Addr) -> bool {
    (a.segments()[0] & 0xffc0) == 0xfe80
}

/// All adapters except loopback; connected ones first.
pub fn list() -> Vec<Adapter> {
    let mut v = os_list();
    v.retain(|a| !a.name.is_empty());
    v.sort_by(|a, b| b.up.cmp(&a.up).then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    v
}

/// The adapter called `name`, if it exists and is connected.
pub fn find(name: &str) -> Result<Adapter> {
    let all = list();
    match all.into_iter().find(|a| a.name == name) {
        None => Err(anyhow!("network adapter '{name}' not found (choose another one, or Automatic)")),
        Some(a) if !a.up => Err(anyhow!("network adapter '{name}' is not connected")),
        Some(a) if a.v4.is_empty() && a.v6.is_empty() => Err(anyhow!("network adapter '{name}' has no IP address")),
        Some(a) => Ok(a),
    }
}

/// TCP connection to `host:port`; through adapter `iface` unless empty.
pub async fn connect(host: &str, port: u16, iface: &str) -> Result<TcpStream> {
    if iface.is_empty() {
        let s = TcpStream::connect((host, port)).await?;
        s.set_nodelay(true).ok();
        return Ok(s);
    }
    let a = find(iface)?;
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await.with_context(|| format!("can't resolve {host}"))?.collect();
    let mut last = None;
    for addr in addrs {
        let local: Option<IpAddr> = if addr.is_ipv4() {
            a.v4.first().map(|x| IpAddr::V4(*x))
        } else {
            a.v6.iter().find(|x| !link_local(x)).map(|x| IpAddr::V6(*x))
        };
        let Some(local) = local else {
            last = Some(anyhow!("network adapter '{iface}' has no IPv{} address for {host}", if addr.is_ipv4() { 4 } else { 6 }));
            continue;
        };
        let sock = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
        pin(&sock, &a, addr.is_ipv6())?;
        sock.bind(SocketAddr::new(local, 0)).with_context(|| format!("can't use network adapter '{iface}'"))?;
        match tokio::time::timeout(Duration::from_secs(15), sock.connect(addr)).await {
            Ok(Ok(s)) => {
                s.set_nodelay(true).ok();
                return Ok(s);
            }
            Ok(Err(e)) => last = Some(anyhow!("{e} (through network adapter '{iface}')")),
            Err(_) => last = Some(anyhow!("connect timed out (through network adapter '{iface}')")),
        }
    }
    Err(last.unwrap_or_else(|| anyhow!("can't resolve {host}")))
}

#[cfg(windows)]
fn pin(sock: &TcpSocket, a: &Adapter, v6: bool) -> Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IPPROTO_IPV6, IPV6_UNICAST_IF, IP_UNICAST_IF};
    // IPv4 wants the index in network byte order, IPv6 in host order
    let (level, opt, val) = if v6 { (IPPROTO_IPV6, IPV6_UNICAST_IF, a.index) } else { (IPPROTO_IP, IP_UNICAST_IF, a.index.to_be()) };
    let r = unsafe { setsockopt(sock.as_raw_socket() as _, level, opt, (&val as *const u32).cast(), 4) };
    if r != 0 {
        return Err(anyhow!("can't use network adapter '{}': {}", a.name, std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn pin(sock: &TcpSocket, a: &Adapter, _v6: bool) -> Result<()> {
    // needs CAP_NET_RAW; without it the bind to the adapter's address is all
    // we can do
    let _ = sock.bind_device(Some(a.name.as_bytes()));
    Ok(())
}

#[cfg(not(any(windows, target_os = "linux")))]
fn pin(_sock: &TcpSocket, _a: &Adapter, _v6: bool) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn os_list() -> Vec<Adapter> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6};
    const LOOPBACK: u32 = 24; // IF_TYPE_SOFTWARE_LOOPBACK
    const OPER_UP: i32 = 1; // IfOperStatusUp
    let wstr = |p: *const u16| -> String {
        if p.is_null() {
            return String::new();
        }
        let mut n = 0;
        unsafe {
            while *p.add(n) != 0 {
                n += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(p, n))
        }
    };
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size: u32 = 32 * 1024;
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..4 {
        buf = vec![0u64; (size as usize).div_ceil(8)];
        let r = unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, std::ptr::null(), buf.as_mut_ptr().cast(), &mut size) };
        match r {
            0 => break,
            111 => continue, // ERROR_BUFFER_OVERFLOW: size was updated
            _ => return vec![],
        }
    }
    let mut out = vec![];
    let mut p = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
    while !p.is_null() {
        let a = unsafe { &*p };
        if a.IfType != LOOPBACK {
            let mut ad = Adapter {
                name: wstr(a.FriendlyName),
                desc: wstr(a.Description),
                index: unsafe { a.Anonymous1.Anonymous.IfIndex },
                up: a.OperStatus == OPER_UP,
                v4: vec![],
                v6: vec![],
            };
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                let ua = unsafe { &*u };
                let sa = ua.Address.lpSockaddr;
                if !sa.is_null() {
                    let fam = unsafe { (*sa).sa_family };
                    if fam == AF_INET {
                        let s = unsafe { &*(sa as *const SOCKADDR_IN) };
                        ad.v4.push(Ipv4Addr::from(u32::from_be(unsafe { s.sin_addr.S_un.S_addr })));
                    } else if fam == AF_INET6 {
                        let s = unsafe { &*(sa as *const SOCKADDR_IN6) };
                        ad.v6.push(Ipv6Addr::from(unsafe { s.sin6_addr.u.Byte }));
                    }
                }
                u = ua.Next;
            }
            out.push(ad);
        }
        p = a.Next;
    }
    out
}

#[cfg(unix)]
fn os_list() -> Vec<Adapter> {
    use std::ffi::CStr;
    let mut out: Vec<Adapter> = vec![];
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return out;
    }
    let mut p = head;
    while !p.is_null() {
        let ifa = unsafe { &*p };
        p = ifa.ifa_next;
        let flags = ifa.ifa_flags;
        if flags & libc::IFF_LOOPBACK as u32 != 0 || ifa.ifa_name.is_null() {
            continue;
        }
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }.to_string_lossy().to_string();
        let i = match out.iter().position(|a| a.name == name) {
            Some(i) => i,
            None => {
                let c = std::ffi::CString::new(name.clone()).unwrap_or_default();
                out.push(Adapter {
                    index: unsafe { libc::if_nametoindex(c.as_ptr()) },
                    up: flags & (libc::IFF_UP | libc::IFF_RUNNING) as u32 == (libc::IFF_UP | libc::IFF_RUNNING) as u32,
                    name,
                    desc: String::new(),
                    v4: vec![],
                    v6: vec![],
                });
                out.len() - 1
            }
        };
        if ifa.ifa_addr.is_null() {
            continue;
        }
        match unsafe { (*ifa.ifa_addr).sa_family } as i32 {
            libc::AF_INET => {
                let s = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
                out[i].v4.push(Ipv4Addr::from(u32::from_be(s.sin_addr.s_addr)));
            }
            libc::AF_INET6 => {
                let s = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in6) };
                out[i].v6.push(Ipv6Addr::from(s.sin6_addr.s6_addr));
            }
            _ => {}
        }
    }
    unsafe { libc::freeifaddrs(head) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn listing() {
        let all = list();
        assert!(all.iter().all(|a| !a.name.is_empty()));
        // connected adapters come first
        if let Some(k) = all.iter().position(|a| !a.up) {
            assert!(all[k..].iter().all(|a| !a.up));
        }
        assert!(format!("{:#}", find("no-such-adapter-xyz").unwrap_err()).contains("not found"));
        let a = Adapter { name: "Ethernet 2".into(), desc: "Realtek USB GbE".into(), index: 7, up: false, v4: vec![Ipv4Addr::new(192, 168, 1, 10)], v6: vec![] };
        assert_eq!(a.label(), "Ethernet 2 · 192.168.1.10 · Realtek USB GbE (not connected)");
    }

    /// Connect to a local server through a real adapter (the one with an
    /// IPv4 address that is up), and through "Automatic".
    #[tokio::test]
    async fn through_adapter() {
        let l = tokio::net::TcpListener::bind("0.0.0.0:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, peer)) = l.accept().await {
                let _ = s.write_all(peer.ip().to_string().as_bytes()).await;
            }
        });
        let mut s = connect("127.0.0.1", port, "").await.unwrap();
        let mut b = String::new();
        s.read_to_string(&mut b).await.unwrap();
        assert_eq!(b, "127.0.0.1");
        if let Some(a) = list().into_iter().find(|a| a.up && !a.v4.is_empty()) {
            let ip = a.v4[0];
            let mut s = connect(&ip.to_string(), port, &a.name).await.unwrap();
            let mut b = String::new();
            s.read_to_string(&mut b).await.unwrap();
            assert_eq!(b, ip.to_string(), "the connection comes from the adapter's address");
        }
        let e = connect("127.0.0.1", port, "no-such-adapter-xyz").await.unwrap_err();
        assert!(format!("{e:#}").contains("not found"));
    }
}
