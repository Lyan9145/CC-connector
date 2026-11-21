mod config;
mod format;
mod mcp;
mod server;
mod tokens;
mod users;

use anyhow::{anyhow, bail, Result};
use ccc_proto::{IpcReq, IpcResp, TokenReq, TokenResp};
use clap::{Parser, Subcommand};
use config::HubConfig;

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
    /// Manage connector tokens. Works for every local user on a multi-user
    /// hub: each manages their own tokens.
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
        /// Share this hub between OS users (on/off): socket at
        /// /run/ccc-hub/hub.sock, open to all; each user sees only their machines.
        #[arg(long, value_name = "on|off", value_parser = on_off)]
        multi_user: Option<bool>,
        /// Root and the hub's user see every machine (on/off). Off: only
        /// tokens without owners and those listing them.
        #[arg(long, value_name = "on|off", value_parser = on_off)]
        root_all_access: Option<bool>,
        /// Let non-admin users create their own tokens (on/off).
        #[arg(long, value_name = "on|off", value_parser = on_off)]
        self_service: Option<bool>,
        /// Most self-service tokens one user may have.
        #[arg(long, value_name = "N")]
        max_tokens_per_user: Option<usize>,
    },
}

fn on_off(s: &str) -> Result<bool, String> {
    match s {
        "on" | "true" | "yes" | "1" => Ok(true),
        "off" | "false" | "no" | "0" => Ok(false),
        _ => Err("use on or off".into()),
    }
}

#[derive(Subcommand)]
enum TokenCmd {
    /// Create a token for a connector; prints a pairing code (shown once).
    /// A non-admin's token is named "<user>:<name>" and owned by them.
    New {
        name: String,
        /// User or @group whose agents may use the machines (repeatable).
        #[arg(long = "owner", value_name = "USER|@GROUP")]
        owners: Vec<String>,
    },
    /// Replace a connector's token and print a new pairing code.
    Pair { name: String },
    /// List the tokens you may use or manage.
    List,
    Revoke { name: String },
    /// Let more users / @groups use a token's machines.
    Share {
        name: String,
        #[arg(required = true, value_name = "USER|@GROUP")]
        who: Vec<String>,
    },
    /// Take users / @groups off a token.
    Unshare {
        name: String,
        #[arg(required = true, value_name = "USER|@GROUP")]
        who: Vec<String>,
    },
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

fn print_pairing(pairing: Option<&str>) {
    let Some(code) = pairing else {
        eprintln!("hint: the hub admin can set `ccc-hub config --public-url wss://<host>:<port>` to get a one-line pairing code");
        return;
    };
    println!("\npairing code (paste into the connector: GUI 'Hub' tab or `ccc hub --pair <code>`):\n");
    println!("{code}\n");
}

/// Run a token command: through the running hub (as whoever runs this), or,
/// when it isn't running, directly on this user's own hub.toml.
async fn token_cmd(req: TokenReq) -> Result<()> {
    let sock = config::client_socket();
    let (resp, live) = match mcp::ipc(&sock, &IpcReq::Token(req.clone())).await {
        Ok(IpcResp::Token(r)) => (r.map_err(|e| anyhow!(e))?, true),
        Ok(_) => bail!("unexpected answer from the hub (is it older than this ccc-hub?)"),
        Err(e) if !config::path().exists() => return Err(e),
        Err(_) => {
            // hub stopped (or older than this ccc-hub): edit hub.toml, as its admin
            let mut cfg = HubConfig::load()?;
            let who = users::Caller { admin: true, ..users::Caller::current() };
            let (mut r, changed) = tokens::apply(&mut cfg, &who, req, &users::owner_exists)?;
            if changed {
                cfg.save()?;
            }
            if let TokenResp::Created { token, pairing, .. } = &mut r {
                *pairing = config::pairing_for(&cfg, token);
            }
            (r, false)
        }
    };
    let later = if live { "" } else { " A running hub picks this up within a few seconds." };
    match resp {
        TokenResp::Created { name, token, pairing, replaced } => {
            println!("token: {token}");
            print_pairing(pairing.as_deref());
            if replaced {
                eprintln!("token '{name}' replaced (shown only once); the old one no longer works.{later}");
            } else {
                eprintln!("token '{name}' created (shown only once).{later}");
            }
        }
        TokenResp::List(list) => {
            if list.is_empty() {
                eprintln!("no tokens (create one with `ccc-hub token new <name>`)");
            }
            let w = list.iter().map(|t| t.name.len()).max().unwrap_or(0);
            for t in list {
                let online = match t.online {
                    Some(true) => "online ",
                    Some(false) => "offline",
                    None => "",
                };
                let by = if t.created_by.is_empty() { String::new() } else { format!("  (by {})", t.created_by) };
                println!("{:w$}  {online}  owners: {}{by}", t.name, tokens::owners_text(&t.owners), w = w);
            }
        }
        TokenResp::Done(msg) => eprintln!("{msg}{later}"),
    }
    Ok(())
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
        Cmd::Mcp => mcp::run(config::client_socket()).await,
        Cmd::Call { tool, args } => {
            let a: serde_json::Value = serde_json::from_str(&args)?;
            match mcp::call(&config::client_socket(), &mcp::new_session("ccc-hub call"), &tool, &a).await {
                Ok(mcp::Reply::Text(t)) => {
                    println!("{t}");
                    Ok(())
                }
                Ok(mcp::Reply::Image { mime, data, note }) => {
                    // save it so a human (or a test) can look at what the agent would see
                    let ext = mime.rsplit('/').next().unwrap_or("bin");
                    let p = std::env::temp_dir().join(format!("ccc-call-image.{ext}"));
                    std::fs::write(&p, &data)?;
                    println!("{note}\n[image {mime}, {} bytes, saved to {}]", data.len(), p.display());
                    Ok(())
                }
                Err(e) => {
                    println!("error: {e:#}");
                    std::process::exit(1)
                }
            }
        }
        Cmd::Token { cmd } => {
            token_cmd(match cmd {
                TokenCmd::New { name, owners } => TokenReq::New { name, owners },
                TokenCmd::Pair { name } => TokenReq::Pair { name },
                TokenCmd::List => TokenReq::List,
                TokenCmd::Revoke { name } => TokenReq::Revoke { name },
                TokenCmd::Share { name, who } => TokenReq::Share { name, who },
                TokenCmd::Unshare { name, who } => TokenReq::Unshare { name, who },
            })
            .await
        }
        Cmd::Config { listen, tls_cert, tls_key, public_url, multi_user, root_all_access, self_service, max_tokens_per_user } => {
            let mut cfg = HubConfig::load()?;
            let changed = listen.is_some()
                || tls_cert.is_some()
                || tls_key.is_some()
                || public_url.is_some()
                || multi_user.is_some()
                || root_all_access.is_some()
                || self_service.is_some()
                || max_tokens_per_user.is_some();
            if let Some(v) = multi_user {
                if v != cfg.multi_user {
                    eprintln!("multi_user {}: restart the hub (systemctl restart ccc-hub) to move the socket", if v { "on" } else { "off" });
                }
                cfg.multi_user = v;
            }
            if let Some(v) = root_all_access {
                cfg.root_all_access = v;
            }
            if let Some(v) = self_service {
                cfg.self_service = v;
            }
            if let Some(v) = max_tokens_per_user {
                cfg.max_tokens_per_user = v;
            }
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
            let onoff = |b: bool| if b { "on" } else { "off" };
            println!("multi-user:      {}", onoff(cfg.multi_user));
            println!("root all access: {}", onoff(cfg.root_all_access));
            println!("self-service:    {} (up to {} tokens per user)", onoff(cfg.self_service), cfg.max_tokens_per_user);
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
