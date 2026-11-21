//! Connector configuration (non-secret, TOML) and secrets (OS keyring).

use anyhow::{bail, Context, Result};
pub use ccc_proto::Tool;
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

/// How the agent may use a tool on a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Access {
    #[default]
    Allow,
    /// The owner approves each use in the GUI (refused when headless).
    Ask,
    Deny,
}

/// Per-connection permissions: one level per tool plus one for sudo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Perms {
    pub exec: Access,
    pub read: Access,
    pub write: Access,
    pub edit: Access,
    pub push: Access,
    pub pull: Access,
    pub job: Access,
    /// Running anything as root (exec/job with sudo=true).
    pub sudo: Access,
}

/// Something a permission is set for: a tool, or sudo.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Perm {
    Tool(Tool),
    Sudo,
}

impl Perm {
    pub const ALL: [Perm; 8] = [
        Perm::Tool(Tool::Exec),
        Perm::Tool(Tool::Read),
        Perm::Tool(Tool::Write),
        Perm::Tool(Tool::Edit),
        Perm::Tool(Tool::Push),
        Perm::Tool(Tool::Pull),
        Perm::Tool(Tool::Job),
        Perm::Sudo,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Perm::Tool(t) => t.name(),
            Perm::Sudo => "sudo",
        }
    }

    pub fn parse(s: &str) -> Option<Perm> {
        if s == "sudo" { Some(Perm::Sudo) } else { Tool::parse(s).map(Perm::Tool) }
    }

    /// Human description for the GUI.
    pub fn label(self) -> &'static str {
        match self {
            Perm::Tool(Tool::Exec) => "Run commands",
            Perm::Tool(Tool::Read) => "Read files",
            Perm::Tool(Tool::Write) => "Create / overwrite files",
            Perm::Tool(Tool::Edit) => "Edit files",
            Perm::Tool(Tool::Push) => "Upload from server",
            Perm::Tool(Tool::Pull) => "Download to server",
            Perm::Tool(Tool::Job) => "Background jobs",
            Perm::Sudo => "Run as root (sudo)",
        }
    }
}

/// Named permission sets offered in the GUI and CLI.
pub const PRESETS: [(&str, &str, Perms); 4] = [
    ("full", "Full access", Perms::uniform(Access::Allow)),
    ("ask", "Ask before changes", Perms::read_only(Access::Ask)),
    ("ask-all", "Ask for everything", Perms::uniform(Access::Ask)),
    ("read-only", "Read only", Perms::read_only(Access::Deny)),
];

impl Perms {
    pub const fn uniform(a: Access) -> Perms {
        Perms { exec: a, read: a, write: a, edit: a, push: a, pull: a, job: a, sudo: a }
    }

    /// Reading allowed; everything else set to `rest`.
    pub const fn read_only(rest: Access) -> Perms {
        Perms { read: Access::Allow, pull: Access::Allow, ..Perms::uniform(rest) }
    }

    pub fn get(&self, p: Perm) -> Access {
        *self.slot(p)
    }

    pub fn set(&mut self, p: Perm, a: Access) {
        *self.slot_mut(p) = a;
    }

    fn slot(&self, p: Perm) -> &Access {
        match p {
            Perm::Tool(Tool::Exec) => &self.exec,
            Perm::Tool(Tool::Read) => &self.read,
            Perm::Tool(Tool::Write) => &self.write,
            Perm::Tool(Tool::Edit) => &self.edit,
            Perm::Tool(Tool::Push) => &self.push,
            Perm::Tool(Tool::Pull) => &self.pull,
            Perm::Tool(Tool::Job) => &self.job,
            Perm::Sudo => &self.sudo,
        }
    }

    fn slot_mut(&mut self, p: Perm) -> &mut Access {
        match p {
            Perm::Tool(Tool::Exec) => &mut self.exec,
            Perm::Tool(Tool::Read) => &mut self.read,
            Perm::Tool(Tool::Write) => &mut self.write,
            Perm::Tool(Tool::Edit) => &mut self.edit,
            Perm::Tool(Tool::Push) => &mut self.push,
            Perm::Tool(Tool::Pull) => &mut self.pull,
            Perm::Tool(Tool::Job) => &mut self.job,
            Perm::Sudo => &mut self.sudo,
        }
    }

    /// Key of the matching preset, if any.
    pub fn preset(&self) -> Option<&'static str> {
        PRESETS.iter().find(|(_, _, p)| p == self).map(|(k, _, _)| *k)
    }

    pub fn names_with(&self, a: Access) -> Vec<String> {
        Perm::ALL.into_iter().filter(|p| self.get(*p) == a).map(|p| p.name().to_string()).collect()
    }

    /// One-line summary, e.g. "full" or "ask: exec,write; deny: sudo".
    pub fn summary(&self) -> String {
        if let Some(k) = self.preset() {
            return k.to_string();
        }
        let mut parts = vec![];
        for (a, n) in [(Access::Ask, "ask"), (Access::Deny, "deny")] {
            let v = self.names_with(a);
            if !v.is_empty() {
                parts.push(format!("{n}: {}", v.join(",")));
            }
        }
        parts.join("; ")
    }
}

/// What the file tools may do inside a folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum FolderAccess {
    /// Read and write.
    #[default]
    Full,
    /// Read; writing needs the owner's OK once per agent session.
    ReadAsk,
    /// Read only.
    Read,
    /// Anything needs the owner's OK once per agent session.
    Ask,
    /// No access.
    Deny,
}

impl FolderAccess {
    pub const ALL: [FolderAccess; 5] = [FolderAccess::Full, FolderAccess::ReadAsk, FolderAccess::Read, FolderAccess::Ask, FolderAccess::Deny];

    pub fn key(self) -> &'static str {
        match self {
            FolderAccess::Full => "full",
            FolderAccess::ReadAsk => "read-ask",
            FolderAccess::Read => "read",
            FolderAccess::Ask => "ask",
            FolderAccess::Deny => "deny",
        }
    }

    pub fn parse(s: &str) -> Option<FolderAccess> {
        FolderAccess::ALL.into_iter().find(|a| a.key() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            FolderAccess::Full => "Read & write",
            FolderAccess::ReadAsk => "Read; ask to write",
            FolderAccess::Read => "Read only",
            FolderAccess::Ask => "Ask once per session",
            FolderAccess::Deny => "No access",
        }
    }

    /// Short form for the agent.
    pub fn agent_label(self) -> &'static str {
        match self {
            FolderAccess::Full => "read & write",
            FolderAccess::ReadAsk => "read; ask once to write",
            FolderAccess::Read => "read only",
            FolderAccess::Ask => "ask once",
            FolderAccess::Deny => "no access",
        }
    }

    /// Level for reading (`write` = false) or writing in such a folder.
    pub fn level(self, write: bool) -> Access {
        match (self, write) {
            (FolderAccess::Full, _) | (FolderAccess::ReadAsk | FolderAccess::Read, false) => Access::Allow,
            (FolderAccess::ReadAsk, true) | (FolderAccess::Ask, _) => Access::Ask,
            (FolderAccess::Read, true) | (FolderAccess::Deny, _) => Access::Deny,
        }
    }
}

/// A folder and what the file tools may do in it (sub-folders included;
/// the most specific rule wins).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct FolderRule {
    pub path: String,
    pub access: FolderAccess,
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
    /// Notes for the agent (multi-line; e.g. what the machine is and rules
    /// to follow on it).
    pub description: String,
    /// Default working directory for exec/jobs.
    pub cwd: String,
    /// Prepended to every command, e.g. `source /opt/ros/humble/setup.bash`.
    pub init: String,
    pub enabled: bool,
    /// Trusted host key fingerprint (TOFU), e.g. "SHA256:...".
    pub host_key: String,
    /// What the agent may do on this connection.
    pub perms: Perms,
    /// Folder rules for the file tools (read/write/edit/push/pull).
    #[serde(rename = "folder", skip_serializing_if = "Vec::is_empty")]
    pub folders: Vec<FolderRule>,
    /// Access outside all listed folders (Full = no folder limits).
    pub elsewhere: FolderAccess,
    /// Pre-0.3 config; migrated into `perms.sudo` on load.
    #[serde(skip_serializing)]
    pub allow_sudo: Option<bool>,
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
            host_key: String::new(),
            perms: Perms::default(),
            folders: vec![],
            elsewhere: FolderAccess::Full,
            allow_sudo: None,
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

    /// Whether folder rules limit the file tools at all.
    pub fn has_folder_limits(&self) -> bool {
        self.elsewhere != FolderAccess::Full || self.folders.iter().any(|f| f.access != FolderAccess::Full)
    }

    /// Folder rules as told to the agent ("" when there are no limits).
    pub fn folders_summary(&self) -> String {
        if !self.has_folder_limits() {
            return String::new();
        }
        let mut parts: Vec<String> = self.folders.iter().map(|f| format!("{}: {}", f.path, f.access.agent_label())).collect();
        parts.push(format!("elsewhere: {}", self.elsewhere.agent_label()));
        parts.join("; ")
    }
}

/// What a security filter does when it matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FilterAction {
    Off,
    /// Allow, but alert the owner.
    #[default]
    Warn,
    /// Always ask the owner first (even if the tool is allowed).
    Ask,
    /// Refuse.
    Block,
}

impl FilterAction {
    pub const ALL: [FilterAction; 4] = [FilterAction::Off, FilterAction::Warn, FilterAction::Ask, FilterAction::Block];

    pub fn key(self) -> &'static str {
        match self {
            FilterAction::Off => "off",
            FilterAction::Warn => "warn",
            FilterAction::Ask => "ask",
            FilterAction::Block => "block",
        }
    }

    pub fn parse(s: &str) -> Option<FilterAction> {
        FilterAction::ALL.into_iter().find(|a| a.key() == s)
    }

    pub fn label(self) -> &'static str {
        match self {
            FilterAction::Off => "Off",
            FilterAction::Warn => "Warn me",
            FilterAction::Ask => "Ask me",
            FilterAction::Block => "Block",
        }
    }
}

/// A user-defined security filter.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct FilterRule {
    pub name: String,
    /// Regular expression (Rust `regex` syntax).
    pub pattern: String,
    /// What it is matched against: "cmd" (exec / job commands), "read"
    /// (paths read), "write" (paths written), "content" (text written).
    pub on: Vec<String>,
    pub action: FilterAction,
}

impl Default for FilterRule {
    fn default() -> Self {
        Self { name: String::new(), pattern: String::new(), on: vec!["cmd".into()], action: FilterAction::Ask }
    }
}

/// Security filter settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Security {
    pub enabled: bool,
    /// Built-in filter id -> action, where it differs from the default.
    pub builtin: std::collections::BTreeMap<String, FilterAction>,
    #[serde(rename = "rule")]
    pub custom: Vec<FilterRule>,
}

impl Default for Security {
    fn default() -> Self {
        Self { enabled: true, builtin: Default::default(), custom: vec![] }
    }
}

/// How the connector reaches the hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProxyMode {
    /// Connect directly.
    #[default]
    Off,
    /// Use the operating system's proxy (Windows Internet settings, or the
    /// HTTPS_PROXY / ALL_PROXY environment variables).
    System,
    /// Use `url`.
    Manual,
}

/// Proxy for the hub connection. The password (if any) is in the keyring
/// under [`PROXY_PW`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ProxyCfg {
    pub mode: ProxyMode,
    /// e.g. http://127.0.0.1:7890 or socks5://proxy.lan:1080
    pub url: String,
    /// User name for proxies that need a login (empty = none).
    pub user: String,
}

impl ProxyCfg {
    pub fn is_off(&self) -> bool {
        self.mode == ProxyMode::Off && self.url.is_empty() && self.user.is_empty()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Name of this connector as shown on the hub.
    pub name: String,
    /// e.g. wss://server.example.com/ccc
    pub hub_url: String,
    /// Pinned hub certificate ("SHA256:<hex>") for self-signed hubs; empty =
    /// verify against public CAs.
    pub hub_cert: String,
    pub paused: bool,
    #[serde(skip_serializing_if = "ProxyCfg::is_off")]
    pub proxy: ProxyCfg,
    #[serde(rename = "connection")]
    pub connections: Vec<Connection>,
    pub security: Security,
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
    for conn in &mut c.connections {
        if conn.allow_sudo.take() == Some(false) {
            conn.perms.sudo = Access::Deny;
        }
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
pub const PROXY_PW: &str = "proxy-password";

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

/// What "Clear data" removes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ClearWhat {
    /// connections, their saved passwords and trusted host keys
    pub connections: bool,
    /// hub URL, token, pinned certificate, proxy and connector name
    pub hub: bool,
    /// security filter settings
    pub security: bool,
}

/// Remove saved settings and secrets (statistics and logs are the
/// runtime's: see `Runtime::clear_activity`).
pub fn clear_data(w: ClearWhat) -> Result<()> {
    let mut c = load()?;
    if w.connections {
        for x in &c.connections {
            delete_conn_secrets(&x.name)?;
        }
        c.connections.clear();
    }
    if w.hub {
        del_secret(HUB_TOKEN)?;
        del_secret(PROXY_PW)?;
        c.hub_url.clear();
        c.hub_cert.clear();
        c.proxy = ProxyCfg::default();
        c.name = hostname();
        c.paused = false;
    }
    if w.security {
        c.security = Security::default();
    }
    save(&c)
}

/// Decoded pairing code from `ccc-hub token new/pair`.
pub struct Pairing {
    pub url: String,
    pub token: String,
    pub cert: Option<String>,
}

pub fn parse_pairing(code: &str) -> Result<Pairing> {
    use base64::Engine;
    let body = code.trim().strip_prefix("ccc1:").context("not a pairing code (should start with ccc1:)")?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(body.trim_end_matches('='))
        .context("pairing code is damaged (copy the whole line)")?;
    let v: serde_json::Value = serde_json::from_slice(&raw).context("pairing code is damaged")?;
    let s = |k: &str| v.get(k).and_then(|x| x.as_str()).map(String::from);
    let (Some(url), Some(token)) = (s("u"), s("t")) else { bail!("pairing code is missing the URL or token") };
    Ok(Pairing { url, token, cert: s("f") })
}

/// Save a pairing (URL, pinned cert, token) to config + keyring.
pub fn apply_pairing(code: &str) -> Result<Pairing> {
    let p = parse_pairing(code)?;
    let mut c = load()?;
    c.hub_url = p.url.clone();
    c.hub_cert = p.cert.clone().unwrap_or_default();
    set_secret(HUB_TOKEN, &p.token)?;
    save(&c)?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perms_toml_and_migration() {
        let old = "name = \"x\"\n[[connection]]\nname = \"r\"\nkind = \"local\"\nallow_sudo = false\n\
                   description = \"\"\"\nline one\nline two\"\"\"\n";
        let mut c: Config = toml::from_str(old).unwrap();
        assert_eq!(c.connections[0].allow_sudo, Some(false));
        for conn in &mut c.connections {
            if conn.allow_sudo.take() == Some(false) {
                conn.perms.sudo = Access::Deny;
            }
        }
        assert_eq!(c.connections[0].perms.summary(), "deny: sudo");
        assert_eq!(c.connections[0].description, "line one\nline two");
        c.connections[0].perms = Perms::read_only(Access::Ask);
        let s = toml::to_string_pretty(&c).unwrap();
        assert!(!s.contains("allow_sudo"), "{s}");
        let back: Config = toml::from_str(&s).unwrap();
        assert_eq!(back.connections[0].perms.preset(), Some("ask"));
        assert_eq!(back.connections[0].description, "line one\nline two");
    }
}
