//! SSH targets (robot, other LAN hosts) via russh, with a pooled connection
//! and trust-on-first-use host key checking.

use super::{display_buf, CapBuf, RawOut, Run, DATA_MAX};
use crate::store::{Auth, Connection, Secrets};
use anyhow::{anyhow, bail, Context, Result};
use russh::keys::{HashAlg, PrivateKeyWithHashAlg};
use russh::{client, ChannelMsg, Disconnect};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Client {
    expected: String,
    seen: Arc<Mutex<Option<String>>>,
}

impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &russh::keys::PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        let fp = key.public_key().fingerprint(HashAlg::Sha256).to_string();
        *self.seen.lock().unwrap() = Some(fp.clone());
        Ok(self.expected.is_empty() || self.expected == fp)
    }
}

/// Called with (connection name, fingerprint) when a host key is first trusted.
pub type KeyCallback = Box<dyn Fn(&str, &str) + Send + Sync>;

pub struct SshTarget {
    pub conn: Connection,
    pub secrets: Secrets,
    handle: tokio::sync::Mutex<Option<Arc<client::Handle<Client>>>>,
    /// Called with the fingerprint when a host key is trusted for the first time.
    on_new_key: KeyCallback,
}

impl SshTarget {
    pub fn new(conn: Connection, secrets: Secrets, on_new_key: KeyCallback) -> Self {
        Self { conn, secrets, handle: Default::default(), on_new_key }
    }

    pub async fn is_connected(&self) -> bool {
        self.handle.lock().await.as_ref().is_some_and(|h| !h.is_closed())
    }

    pub async fn disconnect(&self) {
        if let Some(h) = self.handle.lock().await.take() {
            let _ = h.disconnect(Disconnect::ByApplication, "", "en").await;
        }
    }

    async fn get(&self) -> Result<Arc<client::Handle<Client>>> {
        let mut g = self.handle.lock().await;
        if let Some(h) = g.as_ref() {
            if !h.is_closed() {
                return Ok(h.clone());
            }
        }
        let h = Arc::new(tokio::time::timeout(Duration::from_secs(20), self.connect()).await.map_err(|_| anyhow!("connect timed out"))??);
        *g = Some(h.clone());
        Ok(h)
    }

    /// Connect and authenticate. Returns the host key fingerprint seen.
    async fn connect(&self) -> Result<client::Handle<Client>> {
        let c = &self.conn;
        if c.host.is_empty() || c.user.is_empty() {
            bail!("host and user must be set");
        }
        let cfg = Arc::new(client::Config {
            inactivity_timeout: None,
            keepalive_interval: Some(Duration::from_secs(20)),
            keepalive_max: 3,
            nodelay: true,
            ..Default::default()
        });
        let seen = Arc::new(Mutex::new(None));
        let handler = Client { expected: c.host_key.clone(), seen: seen.clone() };
        let res = client::connect(cfg, (c.host.as_str(), c.port), handler).await;
        let fp = seen.lock().unwrap().clone();
        let mut h = match res {
            Ok(h) => h,
            Err(e) => {
                if let Some(fp) = &fp {
                    if !c.host_key.is_empty() && *fp != c.host_key {
                        bail!(
                            "HOST KEY MISMATCH: trusted {}, server presented {fp}. If the machine was \
                             reinstalled, use 'forget host key' in the connector",
                            c.host_key
                        );
                    }
                }
                return Err(anyhow!("connect failed: {e}"));
            }
        };
        let ok = match c.auth {
            Auth::Password => {
                let pw = self.secrets.password.clone().context("no password saved for this connection")?;
                h.authenticate_password(&c.user, pw).await?.success()
            }
            Auth::Key => {
                let path = crate::exec::local::expand(&c.key_path);
                let key = russh::keys::load_secret_key(&path, self.secrets.passphrase.as_deref())
                    .map_err(|e| anyhow!("load key {}: {e}", c.key_path))?;
                let hash = h.best_supported_rsa_hash().await?.flatten();
                h.authenticate_publickey(&c.user, PrivateKeyWithHashAlg::new(Arc::new(key), hash)).await?.success()
            }
        };
        if !ok {
            bail!("authentication failed");
        }
        if c.host_key.is_empty() {
            if let Some(fp) = fp {
                (self.on_new_key)(&c.name, &fp);
            }
        }
        Ok(h)
    }

    /// Run a POSIX script (always through bash, independent of login shell).
    pub async fn run(&self, r: Run<'_>) -> Result<RawOut> {
        let h = self.get().await?;
        let mut ch = match h.channel_open_session().await {
            Ok(ch) => ch,
            Err(_) => {
                // stale connection: reconnect once
                *self.handle.lock().await = None;
                self.get().await?.channel_open_session().await?
            }
        };
        let cmd = format!("bash -c {}", ccc_proto::shq(r.script));
        ch.exec(true, cmd.as_bytes()).await?;
        if let Some(data) = r.stdin {
            ch.data(&data[..]).await?;
        }
        ch.eof().await?;
        let display = r.display;
        let collect = async {
            let mut out = if display { display_buf() } else { CapBuf::new(DATA_MAX, 0) };
            let mut err = CapBuf::new(256 << 10, 0);
            let mut code = None;
            while let Some(msg) = ch.wait().await {
                match msg {
                    ChannelMsg::Data { data } => out.push(&data),
                    ChannelMsg::ExtendedData { data, .. } => err.push(&data),
                    ChannelMsg::ExitStatus { exit_status } => code = Some(exit_status as i32),
                    ChannelMsg::ExitSignal { .. } => code = code.or(Some(-1)),
                    _ => {}
                }
            }
            (out, err, code)
        };
        match tokio::time::timeout(r.timeout, collect).await {
            Ok((out, err, code)) => {
                anyhow::ensure!(display || !out.overflowed(), "output exceeds {} MB", DATA_MAX >> 20);
                Ok(RawOut { code, stdout: out.finish(), stderr: err.finish(), killed: false })
            }
            Err(_) => Ok(RawOut { code: None, killed: true, ..Default::default() }),
        }
    }

    /// Detect OS on the remote side.
    pub async fn probe(&self) -> Result<String> {
        let o = self
            .run(Run {
                script: "uname -s; (. /etc/os-release 2>/dev/null && echo \"$PRETTY_NAME\")",
                stdin: None,
                timeout: Duration::from_secs(15),
                display: true,
            })
            .await?;
        let s = String::from_utf8_lossy(&o.stdout);
        let mut it = s.lines();
        let kernel = it.next().unwrap_or("").trim().to_lowercase();
        if kernel.is_empty() {
            bail!("unexpected probe output (non-POSIX host?)");
        }
        Ok(match it.next().map(str::trim).filter(|s| !s.is_empty()) {
            Some(p) => format!("{kernel} ({p})"),
            None => kernel,
        })
    }
}
