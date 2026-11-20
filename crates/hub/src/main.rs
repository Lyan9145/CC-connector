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
    },
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Create a token for a connector (printed once).
    New { name: String },
    List,
    Revoke { name: String },
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
                        bail!("token '{name}' exists; revoke it first");
                    }
                    let t = config::new_token();
                    cfg.tokens.push(Token { name: name.clone(), sha256: config::hash(&t) });
                    cfg.save()?;
                    println!("{t}");
                    eprintln!("token '{name}' created; paste it into the connector (shown only once). Restart `ccc-hub serve` to apply.");
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
                    eprintln!("revoked; restart `ccc-hub serve` to apply");
                }
            }
            Ok(())
        }
        Cmd::Config { listen, tls_cert, tls_key } => {
            let mut cfg = HubConfig::load()?;
            let changed = listen.is_some() || tls_cert.is_some() || tls_key.is_some();
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
            println!("tls:    {}", if cfg.tls_cert.is_empty() { "off".into() } else { format!("{} / {}", cfg.tls_cert, cfg.tls_key) });
            println!("socket: {}", cfg.socket_path().display());
            println!("tokens: {}", cfg.tokens.len());
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
