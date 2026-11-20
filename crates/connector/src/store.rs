//! Connector configuration (non-secret, TOML) and secrets (OS keyring).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    #[default]
    Ssh,
    Local,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Auth {
    #[default]
    Password,
    Key,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Connection {
    pub name: String,
    pub kind: Kind,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub auth: Auth,
    pub key_path: String,
    pub description: String,
    /// Default working directory for exec/jobs.
    pub cwd: String,
    /// Prepended to every command, e.g. `source /opt/ros/humble/setup.bash`.
    pub init: String,
    pub enabled: bool,
    pub allow_sudo: bool,
    /// Trusted host key fingerprint (TOFU), e.g. "SHA256:...".
    pub host_key: String,
}

impl Default for Connection {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: Kind::Ssh,
            host: String::new(),
            port: 22,
            user: String::new(),
            auth: Auth::Password,
            key_path: String::new(),
            description: String::new(),
            cwd: String::new(),
            init: String::new(),
            enabled: true,
            allow_sudo: true,
            host_key: String::new(),
        }
    }
}

impl Connection {
    /// Fields that require reconnecting when changed.
    pub fn same_endpoint(&self, o: &Connection) -> bool {
        self.kind == o.kind
            && self.host == o.host
            && self.port == o.port
            && self.user == o.user
            && self.auth == o.auth
            && self.key_path == o.key_path
            && self.host_key == o.host_key
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Name of this connector as shown on the hub.
    pub name: String,
    /// e.g. wss://server.example.com/ccc
    pub hub_url: String,
    pub paused: bool,
    #[serde(rename = "connection")]
    pub connections: Vec<Connection>,
}

impl Config {
    pub fn get(&self, name: &str) -> Option<&Connection> {
        self.connections.iter().find(|c| c.name == name)
    }
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Connection> {
        self.connections.iter_mut().find(|c| c.name == name)
    }
}

pub fn dir() -> PathBuf {
    if let Ok(d) = std::env::var("CCC_DIR") {
        return PathBuf::from(d);
    }
    dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("ccc")
}

pub fn config_path() -> PathBuf {
    dir().join("config.toml")
}

pub fn load() -> Result<Config> {
    let p = config_path();
    if !p.exists() {
        return Ok(Config { name: hostname(), ..Default::default() });
    }
    let s = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
    let mut c: Config = toml::from_str(&s).with_context(|| format!("parse {}", p.display()))?;
    if c.name.is_empty() {
        c.name = hostname();
    }
    Ok(c)
}

pub fn save(c: &Config) -> Result<()> {
    std::fs::create_dir_all(dir())?;
    let p = config_path();
    let tmp = p.with_extension("toml.tmp");
    std::fs::write(&tmp, toml::to_string_pretty(c)?)?;
    std::fs::rename(&tmp, &p)?;
    Ok(())
}

pub fn validate_name(n: &str) -> Result<()> {
    if n.is_empty() || n.len() > 40 || !n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.') {
        bail!("name must be 1-40 chars of a-z, 0-9, '-', '_', '.'");
    }
    Ok(())
}

pub fn hostname() -> String {
    let h = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .unwrap_or_else(|| "connector".into());
    let h: String = h.trim().chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-').collect();
    if h.is_empty() { "connector".into() } else { h.to_lowercase() }
}

// ---------------------------------------------------------------- secrets

const SERVICE: &str = "cc-connector";
pub const HUB_TOKEN: &str = "hub-token";

pub fn pw_key(conn: &str) -> String {
    format!("conn/{conn}/password")
}
pub fn pp_key(conn: &str) -> String {
    format!("conn/{conn}/passphrase")
}

/// `CCC_SECRETS=file` stores secrets in a 0600 TOML file instead of the OS
/// keyring (for headless machines without a Secret Service).
fn file_backend() -> bool {
    std::env::var("CCC_SECRETS").map(|v| v == "file").unwrap_or(false)
}

fn secrets_file() -> PathBuf {
    dir().join("secrets.toml")
}

fn file_load() -> Result<std::collections::BTreeMap<String, String>> {
    let p = secrets_file();
    if !p.exists() {
        return Ok(Default::default());
    }
    Ok(toml::from_str(&std::fs::read_to_string(p)?)?)
}

fn file_save(m: &std::collections::BTreeMap<String, String>) -> Result<()> {
    std::fs::create_dir_all(dir())?;
    let p = secrets_file();
    std::fs::write(&p, toml::to_string(m)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn keyring_hint(e: keyring::Error) -> anyhow::Error {
    anyhow::anyhow!(
        "OS keyring unavailable: {e}. On a headless Linux box start a Secret Service \
         (e.g. gnome-keyring) or set CCC_SECRETS=file to use a 0600 file instead"
    )
}

pub fn get_secret(key: &str) -> Result<Option<String>> {
    if file_backend() {
        return Ok(file_load()?.get(key).cloned());
    }
    match keyring::Entry::new(SERVICE, key).map_err(keyring_hint)?.get_password() {
        Ok(p) => Ok(Some(p)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(keyring_hint(e)),
    }
}

pub fn set_secret(key: &str, val: &str) -> Result<()> {
    if file_backend() {
        let mut m = file_load()?;
        m.insert(key.into(), val.into());
        return file_save(&m);
    }
    keyring::Entry::new(SERVICE, key).map_err(keyring_hint)?.set_password(val).map_err(keyring_hint)
}

pub fn del_secret(key: &str) -> Result<()> {
    if file_backend() {
        let mut m = file_load()?;
        m.remove(key);
        return file_save(&m);
    }
    match keyring::Entry::new(SERVICE, key).map_err(keyring_hint)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(keyring_hint(e)),
    }
}

/// Secrets of one connection, held in memory by the running connector.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Secrets {
    pub password: Option<String>,
    pub passphrase: Option<String>,
}

pub fn conn_secrets(name: &str) -> Result<Secrets> {
    Ok(Secrets { password: get_secret(&pw_key(name))?, passphrase: get_secret(&pp_key(name))? })
}

pub fn rename_secrets(old: &str, new: &str) -> Result<()> {
    for (o, n) in [(pw_key(old), pw_key(new)), (pp_key(old), pp_key(new))] {
        if let Some(v) = get_secret(&o)? {
            set_secret(&n, &v)?;
            del_secret(&o)?;
        }
    }
    Ok(())
}

pub fn delete_conn_secrets(name: &str) -> Result<()> {
    del_secret(&pw_key(name))?;
    del_secret(&pp_key(name))
}
