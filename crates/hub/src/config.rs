use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub name: String,
    /// hex sha256 of the token string
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct HubConfig {
    pub listen: String,
    /// Optional PEM cert/key for built-in TLS (wss://). Leave empty when a
    /// reverse proxy terminates TLS.
    pub tls_cert: String,
    pub tls_key: String,
    /// Unix socket for the MCP shim. Empty = default.
    pub socket: String,
    #[serde(rename = "token")]
    pub tokens: Vec<Token>,
}

impl Default for HubConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:8765".into(),
            tls_cert: String::new(),
            tls_key: String::new(),
            socket: String::new(),
            tokens: vec![],
        }
    }
}

pub fn dir() -> PathBuf {
    if let Ok(d) = std::env::var("CCC_HUB_DIR") {
        return PathBuf::from(d);
    }
    dirs::config_dir().unwrap_or_else(|| PathBuf::from(".")).join("ccc-hub")
}

pub fn path() -> PathBuf {
    dir().join("hub.toml")
}

impl HubConfig {
    pub fn load() -> Result<Self> {
        let p = path();
        if !p.exists() {
            return Ok(Self::default());
        }
        let s = std::fs::read_to_string(&p).with_context(|| format!("read {}", p.display()))?;
        toml::from_str(&s).with_context(|| format!("parse {}", p.display()))
    }

    pub fn save(&self) -> Result<()> {
        let d = dir();
        std::fs::create_dir_all(&d)?;
        let p = path();
        std::fs::write(&p, toml::to_string_pretty(self)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn socket_path(&self) -> PathBuf {
        socket_path_for(&self.socket)
    }

    /// Returns the token name if `token` matches a configured token.
    pub fn check_token(&self, token: &str) -> Option<String> {
        let h = hash(token);
        self.tokens
            .iter()
            .find(|t| ct_eq(t.sha256.as_bytes(), h.as_bytes()))
            .map(|t| t.name.clone())
    }
}

pub fn socket_path_for(configured: &str) -> PathBuf {
    if let Ok(s) = std::env::var("CCC_HUB_SOCK") {
        return PathBuf::from(s);
    }
    if !configured.is_empty() {
        return PathBuf::from(configured);
    }
    dir().join("hub.sock")
}

pub fn hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub fn new_token() -> String {
    use rand::RngCore;
    let mut b = [0u8; 24];
    rand::thread_rng().fill_bytes(&mut b);
    format!("ccc_{}", hex::encode(b))
}
