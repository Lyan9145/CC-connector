#[cfg(feature = "gui")]
mod analytics;
mod exec;
mod filters;
#[cfg(feature = "gui")]
mod gui;
mod ops;
mod paths;
mod pin;
mod proxy;
mod redact;
mod runtime;
mod stats;
mod store;

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use store::{Access, Auth, Connection, FilterAction, FolderAccess, Kind, Perm};

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
        /// Pairing code from `ccc-hub token new/pair` (sets URL, token, certificate).
        #[arg(long)]
        pair: Option<String>,
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
        /// Reach the hub through a proxy: http://host:port, socks5://host:port,
        /// `system` (the OS proxy settings) or `off`.
        #[arg(long)]
        proxy: Option<String>,
        /// User name for the proxy (empty = none); prompts for its password.
        #[arg(long)]
        proxy_user: Option<String>,
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
    /// Show one connection in full (permissions, notes).
    Show { name: String },
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
    /// Security filters: list them, change what they do, or test a command.
    Security {
        #[command(subcommand)]
        cmd: Option<SecCmd>,
    },
    /// Open the GUI with generated statistics on the Activity tab (design preview).
    #[command(hide = true)]
    Preview,
}

#[derive(Subcommand)]
enum SecCmd {
    /// List the filters and what each does.
    List,
    /// Set what a filter does: off, warn, ask or block (built-in id or custom name).
    Set { filter: String, action: String },
    /// Turn all filters on or off.
    Enable {
        #[arg(long)]
        off: bool,
    },
    /// Add your own filter (a regular expression).
    Add {
        name: String,
        pattern: String,
        /// What to match: cmd, read, write, content (comma-separated).
        #[arg(long, default_value = "cmd")]
        on: String,
        /// off, warn, ask or block.
        #[arg(long, default_value = "ask")]
        action: String,
    },
    /// Remove one of your own filters.
    Rm { name: String },
    /// Show which filters a command would trigger.
    Test {
        text: String,
        /// Treat the text as: cmd, read, write or content.
        #[arg(long, default_value = "cmd")]
        on: String,
    },
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
    /// Notes for the agent (may be multi-line; shown with the machine list).
    #[arg(long)]
    desc: Option<String>,
    /// Read the notes for the agent from a file.
    #[arg(long, value_name = "FILE")]
    desc_file: Option<String>,
    /// Default working directory.
    #[arg(long)]
    cwd: Option<String>,
    /// Shell lines prepended to every command (e.g. source a ROS setup).
    #[arg(long)]
    init: Option<String>,
    /// Permission preset: full, ask (ask before changes), ask-all, read-only.
    #[arg(long, value_name = "PRESET")]
    access: Option<String>,
    /// Allow these without asking, e.g. --allow read,pull  (tools: exec read
    /// write edit push pull job sudo, or "all"). Applied after --access.
    #[arg(long, value_name = "TOOLS")]
    allow: Vec<String>,
    /// Ask the owner (in the GUI) before each use of these.
    #[arg(long, value_name = "TOOLS")]
    ask: Vec<String>,
    /// Never allow these.
    #[arg(long, value_name = "TOOLS")]
    deny: Vec<String>,
    /// Folder rule for the file tools, LEVEL=PATH (repeatable). Levels: full,
    /// read-ask (read; ask once per session to write), read, ask (ask once per
    /// session), deny. `none=PATH` removes the rule for PATH.
    #[arg(long, value_name = "LEVEL=PATH")]
    folder: Vec<String>,
    /// Access outside the listed folders (same levels; full = no folder limits).
    #[arg(long, value_name = "LEVEL")]
    elsewhere: Option<String>,
    /// Same as --allow sudo.
    #[arg(long)]
    sudo: bool,
    /// Same as --deny sudo.
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

fn perm_list(s: &str) -> Result<Vec<Perm>> {
    if s.trim() == "all" {
        return Ok(Perm::ALL.to_vec());
    }
    s.split([',', ' '])
        .filter(|x| !x.is_empty())
        .map(|x| Perm::parse(x).with_context(|| format!("unknown tool '{x}' (exec read write edit push pull job sudo)")))
        .collect()
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
        c.description = v.replace("\\n", "\n");
    }
    if let Some(f) = &o.desc_file {
        c.description = std::fs::read_to_string(f).with_context(|| format!("read {f}"))?.trim_end().to_string();
    }
    if let Some(v) = &o.cwd {
        c.cwd = v.clone();
    }
    if let Some(v) = &o.init {
        c.init = v.clone();
    }
    if let Some(p) = &o.access {
        let Some((_, _, perms)) = store::PRESETS.iter().find(|(k, _, _)| k == p) else {
            bail!("unknown preset '{p}' (full, ask, ask-all, read-only)");
        };
        c.perms = *perms;
    }
    for (list, level) in [(&o.allow, Access::Allow), (&o.ask, Access::Ask), (&o.deny, Access::Deny)] {
        for l in list {
            for p in perm_list(l)? {
                c.perms.set(p, level);
            }
        }
    }
    for f in &o.folder {
        let Some((lvl, path)) = f.split_once('=') else { bail!("--folder takes LEVEL=PATH, e.g. full=~/project") };
        let path = path.trim().to_string();
        if path.is_empty() {
            bail!("--folder: empty path");
        }
        c.folders.retain(|r| r.path != path);
        if lvl != "none" {
            let access = FolderAccess::parse(lvl).with_context(|| format!("unknown folder level '{lvl}' (full, read-ask, read, ask, deny, none)"))?;
            c.folders.push(store::FolderRule { path, access });
        }
    }
    if let Some(l) = &o.elsewhere {
        c.elsewhere = FolderAccess::parse(l).with_context(|| format!("unknown folder level '{l}' (full, read-ask, read, ask, deny)"))?;
    }
    if o.sudo {
        c.perms.sudo = Access::Allow;
    }
    if o.no_sudo {
        c.perms.sudo = Access::Deny;
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
        Cmd::Preview => {
            #[cfg(feature = "gui")]
            {
                gui::run_with(true)
            }
            #[cfg(not(feature = "gui"))]
            bail!("built without GUI")
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
                r.save_stats();
                Ok(())
            })
        }
        Cmd::Hub { pair, url, token, token_stdin, name, proxy, proxy_user } => {
            if let Some(code) = pair {
                let p = store::apply_pairing(&code)?;
                println!("paired with {}{}", p.url, if p.cert.is_some() { " (pinned self-signed certificate)" } else { "" });
            }
            let mut c = store::load()?;
            if let Some(u) = url {
                if !(u.starts_with("ws://") || u.starts_with("wss://")) {
                    bail!("hub URL must start with wss:// (or ws:// for testing)");
                }
                if u != c.hub_url {
                    c.hub_cert.clear();
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
            if let Some(p) = proxy {
                match p.trim() {
                    "off" | "none" | "" => c.proxy.mode = store::ProxyMode::Off,
                    "system" => c.proxy.mode = store::ProxyMode::System,
                    u => {
                        let r = proxy::parse(u)?;
                        c.proxy.mode = store::ProxyMode::Manual;
                        c.proxy.url = u.to_string();
                        if !r.user.is_empty() && proxy_user.is_none() {
                            c.proxy.user = r.user;
                        }
                    }
                }
            }
            if let Some(u) = proxy_user {
                c.proxy.user = u.trim().to_string();
                if c.proxy.user.is_empty() {
                    store::del_secret(store::PROXY_PW)?;
                } else {
                    let pw = rpassword::prompt_password("proxy password (empty = none): ")?;
                    if pw.is_empty() {
                        store::del_secret(store::PROXY_PW)?;
                    } else {
                        store::set_secret(store::PROXY_PW, &pw)?;
                    }
                }
            }
            store::save(&c)?;
            println!("name:  {}", c.name);
            println!("url:   {}", if c.hub_url.is_empty() { "(not set)" } else { &c.hub_url });
            println!("token: {}", if store::get_secret(store::HUB_TOKEN)?.is_some() { "saved" } else { "(not set)" });
            if !c.hub_cert.is_empty() {
                println!("cert:  {} (pinned)", c.hub_cert);
            }
            match c.proxy.mode {
                store::ProxyMode::Off => println!("proxy: off"),
                store::ProxyMode::System => println!("proxy: system ({})", proxy::describe_system()),
                store::ProxyMode::Manual => println!("proxy: {}", c.proxy.url),
            }
            if !c.proxy.user.is_empty() {
                println!("proxy user: {}", c.proxy.user);
            }
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
                let first = x.description.lines().next().unwrap_or("");
                let more = if x.description.lines().count() > 1 { " …" } else { "" };
                println!(
                    "{:12} {:8} {}{}  access: {}{}",
                    x.name,
                    if x.enabled { "enabled" } else { "disabled" },
                    what,
                    if pw { "  pw:saved" } else { "" },
                    x.perms.summary(),
                    if first.is_empty() { String::new() } else { format!("  \"{first}{more}\"") }
                );
            }
            Ok(())
        }
        Cmd::Show { name } => {
            let c = store::load()?;
            let x = c.get(&name).with_context(|| format!("no connection '{name}'"))?;
            println!("name:     {}{}", x.name, if x.enabled { "" } else { "  (disabled: hidden from the agent)" });
            match x.kind {
                Kind::Local => println!("type:     this computer"),
                Kind::Ssh => println!("type:     ssh {}@{}:{}", x.user, x.host, x.port),
            }
            if !x.cwd.is_empty() {
                println!("cwd:      {}", x.cwd);
            }
            if !x.init.is_empty() {
                println!("init:     {}", x.init.replace('\n', "\n          "));
            }
            println!("access:   {}", x.perms.summary());
            for p in Perm::ALL {
                println!("  {:6} {}", p.name(), format!("{:?}", x.perms.get(p)).to_lowercase());
            }
            if x.has_folder_limits() {
                println!("folders (file tools):");
                for f in &x.folders {
                    println!("  {:22} {}", f.access.label(), f.path);
                }
                println!("  {:22} everywhere else", x.elsewhere.label());
            } else {
                println!("folders:  no limits");
            }
            println!("notes for the agent:");
            if x.description.is_empty() {
                println!("  (none)");
            }
            for l in x.description.lines() {
                println!("  {l}");
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
        Cmd::Security { cmd } => security_cmd(cmd.unwrap_or(SecCmd::List)),
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

fn security_cmd(cmd: SecCmd) -> Result<()> {
    let mut c = store::load()?;
    let parse_action = |a: &str| FilterAction::parse(a).with_context(|| format!("unknown action '{a}' (off, warn, ask, block)"));
    let parse_on = |on: &str| -> Result<Vec<String>> {
        on.split(',')
            .map(|x| {
                let x = x.trim();
                filters::Scope::parse(x).map(|s| s.key().to_string()).with_context(|| format!("unknown target '{x}' (cmd, read, write, content)"))
            })
            .collect()
    };
    match cmd {
        SecCmd::List => {
            println!("security filters are {}", if c.security.enabled { "ON" } else { "OFF (ccc security enable)" });
            for b in filters::BUILTIN {
                let a = c.security.builtin.get(b.id).copied().unwrap_or(b.default);
                let on: Vec<&str> = b.on.iter().map(|s| s.key()).collect();
                println!("  {:6} {:18} {}  [{}]", a.key(), b.id, b.name, on.join(","));
            }
            for r in &c.security.custom {
                println!("  {:6} {:18} {}  [{}]  /{}/", r.action.key(), "(custom)", r.name, r.on.join(","), r.pattern);
            }
            Ok(())
        }
        SecCmd::Set { filter, action } => {
            let a = parse_action(&action)?;
            if let Some(b) = filters::BUILTIN.iter().find(|b| b.id == filter) {
                if a == b.default {
                    c.security.builtin.remove(b.id);
                } else {
                    c.security.builtin.insert(b.id.into(), a);
                }
            } else if let Some(r) = c.security.custom.iter_mut().find(|r| r.name == filter) {
                r.action = a;
            } else {
                bail!("no filter '{filter}' (see `ccc security list`)");
            }
            store::save(&c)?;
            println!("{filter}: {}", a.label());
            Ok(())
        }
        SecCmd::Enable { off } => {
            c.security.enabled = !off;
            store::save(&c)?;
            println!("security filters {}", if off { "off" } else { "on" });
            Ok(())
        }
        SecCmd::Add { name, pattern, on, action } => {
            filters::compile(&pattern).map_err(|e| anyhow::anyhow!("bad pattern: {e}"))?;
            let rule = store::FilterRule { name: name.clone(), pattern, on: parse_on(&on)?, action: parse_action(&action)? };
            c.security.custom.retain(|r| r.name != name);
            c.security.custom.push(rule);
            store::save(&c)?;
            println!("added filter '{name}'");
            Ok(())
        }
        SecCmd::Rm { name } => {
            let n = c.security.custom.len();
            c.security.custom.retain(|r| r.name != name);
            if n == c.security.custom.len() {
                bail!("no custom filter '{name}'");
            }
            store::save(&c)?;
            println!("removed filter '{name}'");
            Ok(())
        }
        SecCmd::Test { text, on } => {
            let scope = filters::Scope::parse(&on).with_context(|| format!("unknown target '{on}'"))?;
            let (fl, errs) = filters::build(&c.security);
            for e in errs {
                eprintln!("warning: {e}");
            }
            let hits = filters::check(&fl, &[(scope, text)]);
            if hits.is_empty() {
                println!("no filter matches");
            }
            for h in hits {
                println!("{:6} {}  (matched `{}`)", h.action.key(), h.name, h.matched);
            }
            Ok(())
        }
    }
}
