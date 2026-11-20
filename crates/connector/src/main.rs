mod exec;
#[cfg(feature = "gui")]
mod gui;
mod ops;
mod redact;
mod runtime;
mod store;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use store::{Auth, Connection, Kind};

/// CC-connector: lets Claude Code on your server work on this machine and on
/// SSH hosts reachable from it. Run without arguments to open the GUI.
#[derive(Parser)]
#[command(name = "ccc", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Open the GUI (default).
    Gui,
    /// Run headless (no GUI), logging activity to stderr.
    Run,
    /// Show or set hub settings.
    Hub {
        /// Hub URL, e.g. wss://server.example.com/ccc
        #[arg(long)]
        url: Option<String>,
        /// Prompt for the hub token (from `ccc-hub token new`).
        #[arg(long)]
        token: bool,
        /// Read the hub token from stdin instead of prompting.
        #[arg(long)]
        token_stdin: bool,
        /// Name of this connector as shown to the hub.
        #[arg(long)]
        name: Option<String>,
    },
    /// Add a connection.
    Add {
        name: String,
        #[command(flatten)]
        o: ConnArgs,
    },
    /// Change a connection.
    Edit {
        name: String,
        /// Rename the connection.
        #[arg(long)]
        rename: Option<String>,
        #[command(flatten)]
        o: ConnArgs,
    },
    /// Remove a connection and its saved secrets.
    Rm { name: String },
    /// List connections.
    List,
    /// Test a connection (trusts the host key on first use).
    Test { name: String },
    /// Forget the trusted host key of a connection.
    ForgetHostkey { name: String },
    /// Pause/resume: while paused the agent sees no machines.
    Pause {
        #[arg(long)]
        off: bool,
    },
    /// Print a systemd user unit for `ccc run`.
    PrintSystemd,
}

#[derive(Args, Default)]
struct ConnArgs {
    /// This machine itself (no SSH).
    #[arg(long)]
    local: bool,
    #[arg(long)]
    host: Option<String>,
    #[arg(long)]
    port: Option<u16>,
    #[arg(long)]
    user: Option<String>,
    /// Use this private key file instead of password login.
    #[arg(long)]
    key: Option<String>,
    /// Use password login (switches auth back from key).
    #[arg(long)]
    password_auth: bool,
    /// Prompt for the password (SSH login and/or sudo).
    #[arg(long)]
    password: bool,
    /// Read the password from stdin.
    #[arg(long)]
    password_stdin: bool,
    /// Prompt for the private key passphrase.
    #[arg(long)]
    passphrase: bool,
    /// Remove the saved password.
    #[arg(long)]
    clear_password: bool,
    #[arg(long)]
    desc: Option<String>,
    /// Default working directory.
    #[arg(long)]
    cwd: Option<String>,
    /// Shell lines prepended to every command (e.g. source a ROS setup).
    #[arg(long)]
    init: Option<String>,
    #[arg(long)]
    sudo: bool,
    #[arg(long)]
    no_sudo: bool,
    #[arg(long)]
    enable: bool,
    #[arg(long)]
    disable: bool,
}

fn read_stdin_line() -> Result<String> {
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim_end_matches(['\r', '\n']).to_string())
}

fn apply(c: &mut Connection, o: &ConnArgs) -> Result<()> {
    if o.local {
        c.kind = Kind::Local;
    }
    if let Some(v) = &o.host {
        c.kind = Kind::Ssh;
        c.host = v.clone();
    }
    if let Some(v) = o.port {
        c.port = v;
    }
    if let Some(v) = &o.user {
        c.user = v.clone();
    }
    if let Some(v) = &o.key {
        c.auth = Auth::Key;
        c.key_path = v.clone();
    }
    if o.password_auth {
        c.auth = Auth::Password;
    }
    if let Some(v) = &o.desc {
        c.description = v.clone();
    }
    if let Some(v) = &o.cwd {
        c.cwd = v.clone();
    }
    if let Some(v) = &o.init {
        c.init = v.clone();
    }
    if o.sudo {
        c.allow_sudo = true;
    }
    if o.no_sudo {
        c.allow_sudo = false;
    }
    if o.enable {
        c.enabled = true;
    }
    if o.disable {
        c.enabled = false;
    }
    if c.kind == Kind::Ssh && (c.host.is_empty() || c.user.is_empty()) {
        bail!("SSH connections need --host and --user (or use --local)");
    }
    Ok(())
}

fn save_secrets(name: &str, o: &ConnArgs) -> Result<()> {
    if o.clear_password {
        store::del_secret(&store::pw_key(name))?;
    }
    let pw = if o.password_stdin {
        Some(read_stdin_line()?)
    } else if o.password {
        Some(rpassword::prompt_password(format!("password for {name}: "))?)
    } else {
        None
    };
    if let Some(p) = pw {
        store::set_secret(&store::pw_key(name), &p)?;
    }
    if o.passphrase {
        let p = rpassword::prompt_password(format!("key passphrase for {name}: "))?;
        store::set_secret(&store::pp_key(name), &p)?;
    }
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Gui) {
        Cmd::Gui => {
            #[cfg(feature = "gui")]
            {
                gui::run()
            }
            #[cfg(not(feature = "gui"))]
            bail!("built without GUI; use `ccc run`")
        }
        Cmd::Run => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(async {
                let r = runtime::Runtime::new(true);
                for l in r.log.lock().unwrap().iter() {
                    eprintln!("{l}");
                }
                eprintln!("config: {}", store::config_path().display());
                r.start();
                tokio::signal::ctrl_c().await?;
                Ok(())
            })
        }
        Cmd::Hub { url, token, token_stdin, name } => {
            let mut c = store::load()?;
            if let Some(u) = url {
                if !(u.starts_with("ws://") || u.starts_with("wss://")) {
                    bail!("hub URL must start with wss:// (or ws:// for testing)");
                }
                c.hub_url = u;
            }
            if let Some(n) = name {
                store::validate_name(&n)?;
                c.name = n;
            }
            let tok = if token_stdin {
                Some(read_stdin_line()?)
            } else if token {
                Some(rpassword::prompt_password("hub token: ")?)
            } else {
                None
            };
            if let Some(t) = tok {
                store::set_secret(store::HUB_TOKEN, t.trim())?;
            }
            store::save(&c)?;
            println!("name:  {}", c.name);
            println!("url:   {}", if c.hub_url.is_empty() { "(not set)" } else { &c.hub_url });
            println!("token: {}", if store::get_secret(store::HUB_TOKEN)?.is_some() { "saved" } else { "(not set)" });
            println!("config: {}", store::config_path().display());
            Ok(())
        }
        Cmd::Add { name, o } => {
            store::validate_name(&name)?;
            let mut c = store::load()?;
            if c.get(&name).is_some() {
                bail!("connection '{name}' exists; use `ccc edit`");
            }
            let mut conn = Connection { name: name.clone(), ..Default::default() };
            apply(&mut conn, &o)?;
            save_secrets(&name, &o)?;
            if conn.kind == Kind::Ssh && conn.auth == Auth::Password && store::get_secret(&store::pw_key(&name))?.is_none() {
                eprintln!("note: no password saved; add one with `ccc edit {name} --password`");
            }
            c.connections.push(conn);
            store::save(&c)?;
            println!("added '{name}'. Try `ccc test {name}`");
            Ok(())
        }
        Cmd::Edit { name, rename, o } => {
            let mut c = store::load()?;
            let conn = c.get_mut(&name).with_context(|| format!("no connection '{name}'"))?;
            let old_endpoint = (conn.host.clone(), conn.port);
            apply(conn, &o)?;
            if (conn.host.clone(), conn.port) != old_endpoint {
                conn.host_key.clear();
            }
            let mut final_name = name.clone();
            if let Some(n) = rename {
                store::validate_name(&n)?;
                conn.name = n.clone();
                final_name = n;
            }
            if final_name != name {
                if c.connections.iter().filter(|x| x.name == final_name).count() > 1 {
                    bail!("connection '{final_name}' exists");
                }
                store::rename_secrets(&name, &final_name)?;
            }
            save_secrets(&final_name, &o)?;
            store::save(&c)?;
            println!("updated '{final_name}'");
            Ok(())
        }
        Cmd::Rm { name } => {
            let mut c = store::load()?;
            let n = c.connections.len();
            c.connections.retain(|x| x.name != name);
            if n == c.connections.len() {
                bail!("no connection '{name}'");
            }
            store::delete_conn_secrets(&name)?;
            store::save(&c)?;
            println!("removed '{name}'");
            Ok(())
        }
        Cmd::List => {
            let c = store::load()?;
            println!("connector '{}' -> {}{}", c.name, if c.hub_url.is_empty() { "(no hub URL)" } else { &c.hub_url }, if c.paused { "  [PAUSED]" } else { "" });
            for x in &c.connections {
                let pw = store::get_secret(&store::pw_key(&x.name)).ok().flatten().is_some();
                let what = match x.kind {
                    Kind::Local => "local".to_string(),
                    Kind::Ssh => format!(
                        "ssh {}@{}:{} ({})",
                        x.user,
                        x.host,
                        x.port,
                        match x.auth {
                            Auth::Password => "password".to_string(),
                            Auth::Key => format!("key {}", x.key_path),
                        }
                    ),
                };
                println!(
                    "{:12} {:8} {}{}{}{}",
                    x.name,
                    if x.enabled { "enabled" } else { "disabled" },
                    what,
                    if pw { "  pw:saved" } else { "" },
                    if x.allow_sudo { "  sudo" } else { "" },
                    if x.description.is_empty() { String::new() } else { format!("  \"{}\"", x.description) }
                );
            }
            Ok(())
        }
        Cmd::Test { name } => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let rt = tokio::runtime::Runtime::new()?;
            let r = rt.block_on(runtime::test_connection(&name))?;
            println!("{r}");
            Ok(())
        }
        Cmd::ForgetHostkey { name } => {
            let mut c = store::load()?;
            c.get_mut(&name).with_context(|| format!("no connection '{name}'"))?.host_key.clear();
            store::save(&c)?;
            println!("forgot host key of '{name}'; the next connection trusts the new key");
            Ok(())
        }
        Cmd::Pause { off } => {
            let mut c = store::load()?;
            c.paused = !off;
            store::save(&c)?;
            println!("{}", if c.paused { "paused" } else { "resumed" });
            Ok(())
        }
        Cmd::PrintSystemd => {
            let exe = std::env::current_exe()?;
            println!(
                "# save as ~/.config/systemd/user/ccc.service, then:\n#   systemctl --user daemon-reload && systemctl --user enable --now ccc\n\
                 #   loginctl enable-linger $USER   # keep running when logged out\n\
[Unit]\nDescription=CC-connector\nAfter=network-online.target\n\n\
[Service]\nExecStart={} run\nRestart=always\nRestartSec=5\n\n\
[Install]\nWantedBy=default.target",
                exe.display()
            );
            Ok(())
        }
    }
}
