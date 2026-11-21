use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// URL connectors use to reach this hub, e.g. wss://example.com:22624
    /// (used to build pairing codes).
    pub public_url: String,
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
            public_url: String::new(),
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

}

/// The configured token matching `token`, if any.
pub fn check_token(tokens: &[Token], token: &str) -> Option<Token> {
    let h = hash(token);
    tokens.iter().find(|t| ct_eq(t.sha256.as_bytes(), h.as_bytes())).cloned()
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

/// SHA-256 fingerprint ("SHA256:<hex>") of the first certificate in a PEM file.
pub fn cert_fingerprint(pem_path: &str) -> Result<String> {
    let mut rd = std::io::BufReader::new(std::fs::File::open(pem_path).with_context(|| format!("open {pem_path}"))?);
    let der = rustls_pemfile::certs(&mut rd).next().context("no certificate in PEM")??;
    Ok(format!("SHA256:{}", hex::encode(Sha256::digest(der.as_ref()))))
}

/// Generate a self-signed certificate for `names` into the hub dir and
/// return (cert_path, key_path).
pub fn self_signed(names: Vec<String>) -> Result<(String, String)> {
    let ck = rcgen::generate_simple_self_signed(names).context("generate certificate")?;
    let d = dir().join("tls");
    std::fs::create_dir_all(&d)?;
    let cert = d.join("cert.pem");
    let key = d.join("key.pem");
    std::fs::write(&cert, ck.cert.pem())?;
    std::fs::write(&key, ck.signing_key.serialize_pem())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok((cert.to_string_lossy().into(), key.to_string_lossy().into()))
}

/// One-line pairing code for a connector: url + token + pinned cert.
pub fn pairing_code(url: &str, token: &str, fingerprint: Option<&str>) -> String {
    use base64::Engine;
    let mut v = serde_json::json!({ "u": url, "t": token });
    if let Some(f) = fingerprint {
        v["f"] = serde_json::Value::String(f.to_string());
    }
    format!("ccc1:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(v.to_string()))
}
