mod config;
mod format;
mod mcp;
mod server;

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use config::{HubConfig, Token};

/// CC-connector hub: runs on the Claude Code server.
#[derive(Parser)]
#[command(name = "ccc-hub", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the hub daemon (connectors dial in here).
    Serve {
        /// Override listen address, e.g. 0.0.0.0:8765
        #[arg(long)]
        listen: Option<String>,
    },
    /// MCP stdio server; register with `claude mcp add remote -- ccc-hub mcp`.
    Mcp,
    /// Manage connector tokens.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Call a tool directly (for testing), e.g. `ccc-hub call exec '{"machine":"laptop","cmd":"ls"}'`.
    Call { tool: String, #[arg(default_value = "{}")] args: String },
    /// Print a systemd unit for `ccc-hub serve`.
    PrintSystemd,
    /// Manage built-in TLS.
    Tls {
        #[command(subcommand)]
        cmd: TlsCmd,
    },
    /// Show config file location and settings.
    Config {
        /// Set listen address
        #[arg(long)]
        listen: Option<String>,
        /// Set TLS cert (PEM) path; empty string disables
        #[arg(long)]
        tls_cert: Option<String>,
        /// Set TLS key (PEM) path
        #[arg(long)]
        tls_key: Option<String>,
        /// URL connectors use, e.g. wss://example.com:22624 (for pairing codes)
        #[arg(long)]
        public_url: Option<String>,
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Create a token for a connector; prints a pairing code (shown once).
    New { name: String },
    /// Replace a connector's token and print a new pairing code.
    Pair { name: String },
    List,
    Revoke { name: String },
}

#[derive(Subcommand)]
enum TlsCmd {
    /// Generate a self-signed certificate and enable wss://. Connectors pin
    /// its fingerprint via the pairing code, so no CA is needed.
    SelfSigned {
        /// Host names / IPs to put in the certificate (default: from public_url)
        names: Vec<String>,
    },
    /// Disable built-in TLS (plain ws://, or TLS terminated by a proxy).
    Off,
    /// Show TLS status and certificate fingerprint.
    Show,
}

fn fingerprint(cfg: &HubConfig) -> Option<String> {
    if cfg.tls_cert.is_empty() {
        None
    } else {
        config::cert_fingerprint(&cfg.tls_cert).ok()
    }
}

fn print_pairing(cfg: &HubConfig, token: &str) {
    if cfg.public_url.is_empty() {
        eprintln!("hint: set `ccc-hub config --public-url wss://<host>:<port>` to get a one-line pairing code");
        return;
    }
    let fp = fingerprint(cfg);
    println!("\npairing code (paste into the connector: GUI 'Hub' tab or `ccc hub --pair <code>`):\n");
    println!("{}\n", config::pairing_code(&cfg.public_url, token, fp.as_deref()));
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1)?;
    let hostport = rest.split('/').next()?;
    let host = if hostport.starts_with('[') {
        hostport.split(']').next()?.trim_start_matches('[').to_string()
    } else {
        hostport.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| hostport.to_string())
    };
    (!host.is_empty()).then_some(host)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve { listen } => {
            let mut cfg = HubConfig::load()?;
            if let Some(l) = listen {
                cfg.listen = l;
            }
            server::serve(cfg).await
        }
        Cmd::Mcp => {
            let cfg = HubConfig::load().unwrap_or_default();
            mcp::run(cfg.socket_path()).await
        }
        Cmd::Call { tool, args } => {
            let cfg = HubConfig::load()?;
            let a: serde_json::Value = serde_json::from_str(&args)?;
            match mcp::call(&cfg.socket_path(), &tool, &a).await {
                Ok(t) => {
                    println!("{t}");
                    Ok(())
                }
                Err(e) => {
                    println!("error: {e:#}");
                    std::process::exit(1)
                }
            }
        }
        Cmd::Token { cmd } => {
            let mut cfg = HubConfig::load()?;
            match cmd {
                TokenCmd::New { name } => {
                    if cfg.tokens.iter().any(|t| t.name == name) {
                        bail!("token '{name}' exists; use `ccc-hub token pair {name}` to replace it");
                    }
                    let t = config::new_token();
                    cfg.tokens.push(Token { name: name.clone(), sha256: config::hash(&t) });
                    cfg.save()?;
                    println!("token: {t}");
                    print_pairing(&cfg, &t);
                    eprintln!("token '{name}' created (shown only once). A running hub picks it up within a few seconds.");
                }
                TokenCmd::Pair { name } => {
                    let t = config::new_token();
                    cfg.tokens.retain(|x| x.name != name);
                    cfg.tokens.push(Token { name: name.clone(), sha256: config::hash(&t) });
                    cfg.save()?;
                    println!("token: {t}");
                    print_pairing(&cfg, &t);
                    eprintln!("token '{name}' replaced; a running hub disconnects the old one within a few seconds.");
                }
                TokenCmd::List => {
                    for t in &cfg.tokens {
                        println!("{}", t.name);
                    }
                }
                TokenCmd::Revoke { name } => {
                    let n = cfg.tokens.len();
                    cfg.tokens.retain(|t| t.name != name);
                    if n == cfg.tokens.len() {
                        bail!("no token '{name}'");
                    }
                    cfg.save()?;
                    eprintln!("revoked; a running hub disconnects connectors using it within a few seconds.");
                }
            }
            Ok(())
        }
        Cmd::Config { listen, tls_cert, tls_key, public_url } => {
            let mut cfg = HubConfig::load()?;
            let changed = listen.is_some() || tls_cert.is_some() || tls_key.is_some() || public_url.is_some();
            if let Some(v) = public_url {
                if !(v.starts_with("ws://") || v.starts_with("wss://")) {
                    bail!("public URL must start with wss:// or ws://");
                }
                cfg.public_url = v;
            }
            if let Some(v) = listen {
                cfg.listen = v;
            }
            if let Some(v) = tls_cert {
                cfg.tls_cert = v;
            }
            if let Some(v) = tls_key {
                cfg.tls_key = v;
            }
            if changed {
                cfg.save()?;
            }
            println!("config: {}", config::path().display());
            println!("listen: {}", cfg.listen);
            println!("public: {}", if cfg.public_url.is_empty() { "(not set)" } else { &cfg.public_url });
            println!("tls:    {}", if cfg.tls_cert.is_empty() { "off".into() } else { format!("{} / {}", cfg.tls_cert, cfg.tls_key) });
            if let Some(fp) = fingerprint(&cfg) {
                println!("cert:   {fp}");
            }
            println!("socket: {}", cfg.socket_path().display());
            println!("tokens: {}", cfg.tokens.len());
            Ok(())
        }
        Cmd::Tls { cmd } => {
            let mut cfg = HubConfig::load()?;
            match cmd {
                TlsCmd::SelfSigned { mut names } => {
                    if names.is_empty() {
                        names.extend(host_of(&cfg.public_url));
                    }
                    if names.is_empty() {
                        bail!("give a host name, e.g. `ccc-hub tls self-signed example.com`, or set --public-url first");
                    }
                    let (c, k) = config::self_signed(names.clone())?;
                    cfg.tls_cert = c;
                    cfg.tls_key = k;
                    if cfg.public_url.starts_with("ws://") {
                        cfg.public_url = cfg.public_url.replacen("ws://", "wss://", 1);
                    }
                    cfg.save()?;
                    println!("self-signed certificate for {} created", names.join(", "));
                    println!("fingerprint: {}", fingerprint(&cfg).unwrap_or_default());
                    println!("restart the hub (systemctl restart ccc-hub) to load the certificate, then pair connectors with `ccc-hub token pair <name>`");
                }
                TlsCmd::Off => {
                    cfg.tls_cert.clear();
                    cfg.tls_key.clear();
                    if cfg.public_url.starts_with("wss://") {
                        cfg.public_url = cfg.public_url.replacen("wss://", "ws://", 1);
                    }
                    cfg.save()?;
                    println!("built-in TLS disabled; restart the hub");
                }
                TlsCmd::Show => match fingerprint(&cfg) {
                    Some(fp) => println!("tls on\ncert: {}\nfingerprint: {fp}", cfg.tls_cert),
                    None => println!("tls off"),
                },
            }
            Ok(())
        }
        Cmd::PrintSystemd => {
            let exe = std::env::current_exe()?;
            println!(
                "# save as /etc/systemd/system/ccc-hub.service, then: systemctl daemon-reload && systemctl enable --now ccc-hub\n\
[Unit]\nDescription=CC-connector hub\nAfter=network-online.target\n\n\
[Service]\nUser={user}\nExecStart={exe} serve\nRestart=always\nRestartSec=3\n\n\
[Install]\nWantedBy=multi-user.target",
                user = std::env::var("USER").unwrap_or_else(|_| "root".into()),
                exe = exe.display()
            );
            Ok(())
        }
    }
}
