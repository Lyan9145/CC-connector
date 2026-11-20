//! Hub daemon: accepts connector WebSockets and serves local IPC requests
//! from the MCP shim, routing them to the right connector.

use crate::config::HubConfig;
use anyhow::{Context, Result};
use ccc_proto::{self as proto, Down, IpcReq, IpcResp, Listed, MachineInfo, Op, OpResult, Up};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
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
    tx: mpsc::UnboundedSender<Down>,
    machines: Vec<MachineInfo>,
}

#[derive(Default)]
struct Hub {
    conns: Mutex<HashMap<u64, Conn>>,
    pending: Mutex<HashMap<u64, (u64, oneshot::Sender<OpResult>)>>,
    next: AtomicU64,
}

impl Hub {
    fn id(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed) + 1
    }

    fn listed(&self) -> Vec<(Listed, u64)> {
        let conns = self.conns.lock().unwrap();
        let mut count: HashMap<&str, usize> = HashMap::new();
        for c in conns.values() {
            for m in &c.machines {
                *count.entry(m.alias.as_str()).or_default() += 1;
            }
        }
        let mut out = vec![];
        for (cid, c) in conns.iter() {
            for m in &c.machines {
                let name = if count[m.alias.as_str()] > 1 { format!("{}/{}", c.name, m.alias) } else { m.alias.clone() };
                out.push((Listed { name, via: c.name.clone(), info: m.clone() }, *cid));
            }
        }
        out.sort_by(|a, b| a.0.name.cmp(&b.0.name));
        out
    }

    async fn request(&self, machine: &str, op: Op) -> OpResult {
        let found = self.listed().into_iter().find(|(l, _)| l.name == machine);
        let Some((listed, cid)) = found else {
            let names: Vec<String> = self.listed().into_iter().map(|(l, _)| l.name).collect();
            return Err(format!("unknown machine '{machine}'. available: {}", if names.is_empty() { "(none)".into() } else { names.join(", ") }));
        };
        let timeout = match &op {
            Op::Exec { timeout, .. } => Duration::from_secs(timeout + 30),
            _ => Duration::from_secs(600),
        };
        let id = self.id();
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(id, (cid, tx));
        let sent = {
            let conns = self.conns.lock().unwrap();
            conns.get(&cid).map(|c| c.tx.send(Down::Req { id, machine: listed.info.alias.clone(), op }).is_ok())
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
    let cfg = Arc::new(cfg);

    // Local IPC for the MCP shim.
    let sock = cfg.socket_path();
    if let Some(d) = sock.parent() {
        std::fs::create_dir_all(d)?;
    }
    let _ = std::fs::remove_file(&sock);
    let ipc = UnixListener::bind(&sock).with_context(|| format!("bind {}", sock.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    }
    eprintln!("ipc socket: {}", sock.display());
    let h = hub.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = ipc.accept().await else { continue };
            let h = h.clone();
            tokio::spawn(async move {
                let Ok(req) = proto::read_frame::<_, IpcReq>(&mut s).await else { return };
                let resp = match req {
                    IpcReq::Machines => IpcResp::Machines(h.listed().into_iter().map(|(l, _)| l).collect()),
                    IpcReq::Op { machine, op } => IpcResp::Result(h.request(&machine, op).await),
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
    if cfg.tokens.is_empty() {
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
        let cfg = cfg.clone();
        let tls = tls.clone();
        tokio::spawn(async move {
            let r = match tls {
                Some(acc) => match acc.accept(tcp).await {
                    Ok(s) => handle(hub, cfg, s).await,
                    Err(e) => Err(e.into()),
                },
                None => handle(hub, cfg, tcp).await,
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
async fn handle<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(hub: Arc<Hub>, cfg: Arc<HubConfig>, stream: S) -> Result<()> {
    let mut token_name = None;
    let ws = tokio_tungstenite::accept_hdr_async(stream, |req: &Request, resp: Response| {
        let tok = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or("");
        match cfg.check_token(tok) {
            Some(n) => {
                token_name = Some(n);
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
    let token_name = token_name.unwrap_or_default();
    let (mut sink, mut stream) = ws.split();

    // First message must be Hello.
    let name = loop {
        match stream.next().await {
            Some(Ok(Message::Binary(b))) => match proto::decode::<Up>(&b)? {
                Up::Hello { name, version } => {
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
        // A reconnect replaces the stale session of the same connector.
        conns.retain(|_, c| c.name != name);
        conns.insert(cid, Conn { name: name.clone(), tx: tx.clone(), machines: vec![] });
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
            Ok(Up::Resp { id, result }) => {
                if let Some((_, tx)) = hub.pending.lock().unwrap().remove(&id) {
                    let _ = tx.send(result);
                }
            }
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
