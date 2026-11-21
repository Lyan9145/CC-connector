# CC-connector

Let **Claude Code** running on a server work on other machines (your Windows or Ubuntu laptop,
WSL, a robot computer on the laptop's LAN) **without installing Claude Code on them**, and
without ever showing the agent an IP address, user name or password.

```
 Claude Code ──MCP (stdio)──> ccc-hub mcp ──unix socket──> ccc-hub serve        ← server
                                                                ▲
                                     WebSocket over TLS, dialled OUT by the laptop
                                                                │
                      laptop:  ccc   (GUI · CLI · headless) ────┘
                                 ├─ "This computer"   → runs commands on the laptop (PowerShell / bash)
                                 └─ SSH connections   → WSL, robot, any LAN host (nothing installed there)
```

| Part | Runs on | What it does |
|---|---|---|
| `ccc-hub` | the Claude Code server | Accepts connectors, gives Claude 8 MCP tools, routes requests |
| `ccc` | your laptop | Stores connections (passwords in the OS keyring), dials the hub, executes requests |

The agent only sees each machine's **name, OS, status, access rules and your notes**. You decide,
per machine and per tool, what it may do: allow, ask you first, or deny.

---

## Contents

- [Quick start](#quick-start)
- [Full guide](#full-guide)
  - [1. Server: the hub](#1-server-the-hub)
  - [2. Laptop: the connector](#2-laptop-the-connector)
  - [3. Adding machines](#3-adding-machines) ([notes for the agent](#notes-for-the-agent), [permissions](#permissions))
  - [4. Using it from Claude Code](#4-using-it-from-claude-code)
- [Agent tools reference](#agent-tools-reference)
- [Security model](#security-model)
- [Command reference](#command-reference)
- [Files and environment variables](#files-and-environment-variables)
- [Troubleshooting](#troubleshooting)
- [Limits](#limits)
- [Building from source](#building-from-source)

---

## Quick start

You need: a Linux server running Claude Code that your laptop can reach on one TCP port, and
the release files `ccc-hub-linux-x86_64` (server) and `ccc-windows-x86_64.exe` or
`ccc-linux-x86_64` (laptop).

### On the server (as root)

```bash
install -m755 ccc-hub-linux-x86_64 /usr/local/bin/ccc-hub

# where the laptop will reach the hub (pick any free port, open it in your firewall)
ccc-hub config --listen 0.0.0.0:22624 --public-url wss://your.server.com:22624
ccc-hub tls self-signed                       # encrypted, no CA or domain validation needed

ccc-hub print-systemd > /etc/systemd/system/ccc-hub.service
systemctl daemon-reload && systemctl enable --now ccc-hub

ccc-hub token new laptop                      # prints a PAIRING CODE (ccc1:…), shown once

claude mcp add remote --scope user -- /usr/local/bin/ccc-hub mcp
```

### On the laptop

1. Run `ccc-windows-x86_64.exe` (Windows may warn that the file is unsigned: *More info → Run
   anyway*) or `./ccc-linux-x86_64` on Ubuntu.
2. **Hub** tab → paste the pairing code → **Pair**. The top-left badge turns green **CONNECTED**.
3. **Connections** tab → **+ Add connection**:
   - *This computer*, named e.g. `laptop`, for the laptop itself;
   - *SSH host* for the robot (host, user, password) → **Save and test**.
4. Keep the window open while Claude should have access.

### In Claude Code

Start a new session and ask, for example:

> List my machines, then check the free disk space and running ROS nodes on `robot`.

---

## Full guide

### 1. Server: the hub

#### Install

```bash
install -m755 ccc-hub-linux-x86_64 /usr/local/bin/ccc-hub
ccc-hub --version
```

The hub keeps its settings in `~/.config/ccc-hub/hub.toml` of the user that runs it (for a root
service: `/root/.config/ccc-hub/`). Run `ccc-hub config` to see them.

#### Choose how the laptop reaches the hub

Pick a port, allow it in the server's firewall (and in your cloud provider's security group),
and tell the hub both the listen address and the public URL:

```bash
ccc-hub config --listen 0.0.0.0:22624 --public-url wss://your.server.com:22624
```

The public URL is only used to build pairing codes; it may be a domain name or an IP.

#### Encryption (pick one)

| Option | Setup | Notes |
|---|---|---|
| **Self-signed (recommended)** | `ccc-hub tls self-signed` | Certificate is generated locally. Connectors **pin** its fingerprint from the pairing code, so it is as safe as a CA certificate and needs no domain validation. |
| Your own certificate | `ccc-hub config --tls-cert fullchain.pem --tls-key privkey.pem` | e.g. from Let's Encrypt. Connectors verify it against public CAs. |
| Reverse proxy | `ccc-hub tls off`, listen on `127.0.0.1`, proxy WebSockets to it | See the examples below. Use `--public-url wss://your.server.com/ccc`. |
| Plain `ws://` | `ccc-hub tls off` | **Unencrypted**: the token and all traffic are readable on the network. Testing only. |

`ccc-hub tls self-signed` with no arguments uses the host from `--public-url`; you can also list
names/IPs explicitly: `ccc-hub tls self-signed your.server.com 203.0.113.7`.
`ccc-hub tls show` prints the certificate fingerprint.
After any TLS change: `systemctl restart ccc-hub`, then re-pair connectors (`ccc-hub token pair <name>`),
because the pinned fingerprint changes.

Reverse-proxy examples:

```
# Caddy
your.server.com {
    handle_path /ccc* {
        reverse_proxy 127.0.0.1:8765
    }
}
```

```nginx
# nginx
location /ccc {
    proxy_pass http://127.0.0.1:8765;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 1h;
}
```

#### Run as a service

```bash
ccc-hub print-systemd > /etc/systemd/system/ccc-hub.service   # runs `ccc-hub serve` as the current user
systemctl daemon-reload && systemctl enable --now ccc-hub
journalctl -u ccc-hub -f                                        # logs: connects, disconnects, errors
```

#### Tokens and pairing codes

Every connector (laptop) needs its own token.

```bash
ccc-hub token new laptop      # create; prints the token and a pairing code (shown only once)
ccc-hub token pair laptop     # replace the token and print a new pairing code
ccc-hub token list
ccc-hub token revoke laptop
```

Token changes apply to the running hub within about 2 seconds, with no restart: a new token works
at once, and a connector whose token was revoked or replaced is disconnected immediately. (Only
`config` and `tls` changes need `systemctl restart ccc-hub`.)

A **pairing code** (`ccc1:…`) is one line containing the hub URL, the token and the hub
certificate fingerprint. Treat it like a password. The hub stores only a SHA-256 hash of each
token, so a lost code cannot be shown again: issue a new one with `token pair`.

#### Register with Claude Code

```bash
claude mcp add remote --scope user -- /usr/local/bin/ccc-hub mcp   # all your projects
claude mcp list                                                      # should show: remote … ✔ Connected
```

Use `--scope project` instead to enable it for one project only. New Claude Code sessions pick
up the tools; already-running sessions do not.

---

### 2. Laptop: the connector

#### Install and start

- **Windows 10/11:** download `ccc-windows-x86_64.exe` (rename it to `ccc.exe` if you like) and
  double-click it. The console window hides itself when started from Explorer.
- **Ubuntu (desktop):** `chmod +x ccc-linux-x86_64 && ./ccc-linux-x86_64`.
- **Headless Linux:** use the CLI and `ccc run` (see [Headless and CLI use](#headless-and-cli-use)).

The connector is active **while it runs**: closing the window disconnects all machines.

#### Pair with the hub

**Hub** tab → *Quick setup* → paste the pairing code → **Pair**.
The badge in the top-left corner shows the state:

| Badge | Meaning |
|---|---|
| **CONNECTED** (green) + *encrypted* | linked to the hub over TLS |
| **CONNECTED** + *unencrypted ws://* (amber) | linked, but without encryption |
| **STARTING** (amber) | connecting |
| **OFFLINE** (red) | not linked; hover the badge or open the Hub tab for the reason |
| **PAUSED** (grey) | *Pause agent access* is on |

*Manual settings* (connector name, URL, token) are there if you prefer not to use a pairing
code. The connector name is how this laptop is labelled on the hub (default: the computer name).

#### The window

- **Connections:** your machines. The dot shows each one's status (green online, amber
  connecting, red error, grey hidden/paused); hover for the detail. A red dot is a **retry
  button**: hover it and it turns into a retry arrow, click to reconnect now. The switch on the
  right shows or hides the machine from the agent in one click.
- **Top badge:** when it says **OFFLINE**, click it to reconnect to the hub immediately instead of
  waiting for the next automatic retry.
- **Hub:** pairing and hub status.
- **Activity:** analytics of what the agent did, plus the request log (see below). Temporary
  "allow for 15 min" grants are listed at the top with a **Revoke** button.
- **Approval needed** pop-up: appears (and flashes the taskbar) when the agent uses a tool set to
  *Ask*. See [Permissions](#permissions).
- **Pause agent access** (top right): instantly hides all machines from the agent and refuses
  requests, without closing anything.

#### The Activity tab

Pick a period (**last 24 hours / 7 days / 30 days**) and optionally one machine; clicking a
machine in the *Machines* list does the same.

| Part | Shows |
|---|---|
| Summary tiles | **Requests** (agent tool calls; a multi-file push is one), **Success rate** (a command that exits non-zero or times out counts as failed), **Needed you** (approval pop-ups, approved / refused), **Data moved** (up to machines / down to the server), **Typical duration** (median, and the time 95% finish within). Changes are compared with the previous period. |
| Requests chart | Stacked columns per hour, 6 hours or day: succeeded, failed, refused. Hover a column for its numbers. |
| Machines | Requests per machine, % of time online, last activity; hover for all-time totals. |
| Tools | Calls per tool. |
| Availability | One cell per period and machine, darker or lighter blue by the share of time it was reachable; an outlined cell means the connector wasn't running. |
| Recent activity | The request log with a filter box: e.g. `14:02:11 robot: exec [sudo] apt-get update`, including refused requests and approvals. |

Statistics are saved in `stats.json` next to the connector config and survive restarts: hourly
detail for 30 days, all-time totals per machine until you press **Clear statistics** (click twice).
Availability is sampled once a minute while the connector runs. `ccc preview` opens the window
with generated sample data, to look at the page before you have history.

---

### 3. Adding machines

**Connections → + Add connection**, fill in the form, then **Save** or **Save and test**.

| Field | Meaning |
|---|---|
| Name | What the agent calls the machine (`laptop`, `robot`, `wsl`). Letters, digits, `-` `_` `.`; max 40. |
| Type | *This computer* (no SSH) or *SSH host*. |
| Host / Port / User | SSH address and login (SSH only). **Never shown to the agent.** |
| Login | *Password* or *Private key* (key file such as `~/.ssh/id_ed25519`, optional passphrase). |
| Password / sudo password | For password login this is the SSH password; it is also used for `sudo`. With key login or *This computer* it is only the sudo password. Saved in the OS keyring; leave empty to keep the saved one. |
| Notes for agent | Multi-line text shown to the agent with the machine list. Use it as a system prompt for this machine: what it is, where things are, rules to follow (see below). |
| Default directory | Where commands start (empty = home). |
| Init commands | Run before every command, e.g. `source /opt/ros/humble/setup.bash`. |
| Visible to the agent | Untick to hide the machine completely without deleting it. |
| Agent access | Allow / Ask / Deny for each tool and for sudo, or pick a preset (see [Permissions](#permissions)). |
| Host key | Trusted on first connection and pinned afterwards; *Forget* after reinstalling the machine. |

**Save and test** saves, connects, reports the OS, checks that sudo works, and pins the host key.

#### Notes for the agent

The notes are shown under the machine every time Claude lists machines, and Claude is told to
follow them. For example:

```
UR5 arm controller. ROS 2 Humble, workspace ~/ros_ws (colcon build --symlink-install).
The arm driver runs as the systemd service ur-driver; restart it with sudo, never kill it.
Never publish to /cmd_vel or move the arm without asking me first.
Logs: ~/ros_ws/log. Don't delete bags in ~/bags.
```

Keep them short: they cost tokens each time Claude lists machines.

#### Permissions

Each connection has one level per tool, plus one for running things as root:

| Permission | Agent tool | Covers |
|---|---|---|
| Run commands | `exec` | any shell command |
| Read files | `read` | reading text files |
| Create / overwrite files | `write` | writing whole files |
| Edit files | `edit` | find-and-replace in files |
| Upload from server | `push` | copying files from the server to the machine |
| Download to server | `pull` | copying files from the machine to the server |
| Background jobs | `job` | starting and killing jobs (looking at jobs is always allowed unless *Deny*) |
| Run as root (sudo) | `sudo=true` on `exec`/`job` | applies on top of the tool's own level |

Levels:

- **Allow:** runs without asking.
- **Ask:** the connector shows an **Approval needed** pop-up with the full command, file path,
  or edit (old and new text). Choose **Allow** (this request only), **Allow *tool* for 15 min**
  (no more questions for that tool on that machine; revoke in *Activity*), or **Deny**. With no
  answer in 2 minutes the request is refused. A multi-file `push`/`pull` is approved once for
  the whole transfer. When the connector runs without its window (`ccc run`), *Ask* means
  refused.
- **Deny:** always refused. Claude sees `denied:` in the machine list and is told not to try.

Presets: **Full access** (everything allowed, the default), **Ask before changes** (reading and
downloading allowed, everything else asks), **Ask for everything**, **Read only** (reading and
downloading only). Any other mix shows as *Custom*.

What Claude sees:

```
robot  online  linux (Ubuntu 22.04.5 LTS)  via lab-pc  [ask: exec,write,edit,push,job,sudo]
    UR5 arm controller. ROS 2 Humble, workspace ~/ros_ws ...
```

Keep in mind that `exec` can do anything a shell can: allowing `exec` while denying `write`
does not really stop writes. For a machine Claude should only inspect, use **Read only**, or set
`exec` to *Ask*.

#### Typical setups

**The laptop itself (Windows or Linux):** type *This computer*. On Windows, commands run in
PowerShell 7 (`pwsh`) if installed, else Windows PowerShell 5.1; `sudo` is not available, so start
`ccc` as Administrator if the agent needs admin rights.

**A robot or other Linux box on the LAN:** type *SSH host*, its IP, user and password (or key).
The robot only needs an SSH server:

```bash
sudo apt install openssh-server && sudo systemctl enable --now ssh
```

**WSL on the same laptop:** WSL needs an SSH server too:

```bash
sudo apt install openssh-server
sudo sed -i 's/^#\?Port .*/Port 2222/' /etc/ssh/sshd_config      # avoid clashing with Windows' port 22
sudo service ssh start                                              # or enable systemd in /etc/wsl.conf
```

Then add an *SSH host* with host `localhost`, port `2222`, your WSL user and password.

#### Headless and CLI use

Everything in the GUI is also available from the command line (useful on a headless Ubuntu box,
or for scripting). Passwords are always prompted for, never passed as arguments.

```bash
ccc hub --pair 'ccc1:…' --name lab-pc        # pair (sets URL, token, certificate pin)
ccc add laptop --local --desc "lab PC" --access ask
ccc add robot --host 192.168.1.50 --user ubuntu --password \
        --desc-file robot-notes.txt --init "source /opt/ros/humble/setup.bash" --cwd "~/ros_ws"
ccc edit robot --access read-only --allow exec --deny sudo   # preset, then exceptions
ccc test robot
ccc list
ccc show robot                                # full permissions and notes
ccc run                                       # headless; logs activity to the terminal
```

To keep it running in the background on Linux:

```bash
mkdir -p ~/.config/systemd/user && ccc print-systemd > ~/.config/systemd/user/ccc.service
systemctl --user daemon-reload && systemctl --user enable --now ccc
loginctl enable-linger $USER                  # keep running while logged out
```

On a headless box without a keyring service, set `CCC_SECRETS=file` (see
[Files and environment variables](#files-and-environment-variables)).

The GUI and CLI share the same settings; changes made with the CLI are picked up by a running
connector within a few seconds.

---

### 4. Using it from Claude Code

Talk to Claude normally and name the machine:

> On `robot`, build the workspace in ~/ros_ws and show me any compiler errors.

> Copy ./config/params.yaml from this server to `robot` at ~/ros_ws/config/params.yaml, then restart the driver as a background job.

> Install htop on `wsl`.  (Claude uses `sudo=true`; you never type the password.)

> Pull ~/logs from `robot` to /tmp/robot-logs and summarise the errors.

Claude calls `machines` first, then uses the tools below. Watch the **Activity** tab to see what
it does, and **Pause agent access** to stop it at any time.

---

## Agent tools reference

The MCP server is called `remote`. All results are plain text, kept short for token efficiency.

| Tool | Parameters | Returns |
|---|---|---|
| `machines` | — | one line per machine, e.g. `robot  online  linux (Ubuntu 22.04.5 LTS)  via laptop  [ask: exec; denied: sudo]`, then the owner's notes indented below it |
| `exec` | `machine`, `cmd`, `cwd`?, `timeout`? (s, default 120, max 3600), `sudo`? | `exit=<code>` then merged stdout/stderr |
| `read` | `machine`, `path`, `offset`? (1-based line), `limit`? (default 400) | numbered lines, plus `[lines a-b of n]` when partial |
| `write` | `machine`, `path`, `content` | `ok <n> bytes` (parent folders are created) |
| `edit` | `machine`, `path`, `old`, `new`, `all`? | `ok 1 replacement`; error if `old` is missing or not unique |
| `push` | `machine`, `src` (server path), `dst` (machine path) | `ok <files> <size>`: copies a file or folder to the machine |
| `pull` | `machine`, `src` (machine path), `dst` (server path) | `ok <files> <size>`: copies a file or folder to the server |
| `job` | `machine`, `action` = `start` / `status` / `tail` / `kill` / `list`, `cmd`?, `cwd`?, `sudo`?, `id`?, `lines`? | background jobs that keep running if the connection drops |

Output handling:

- ANSI colours are stripped and `\r` progress bars collapse to their final state.
- Long output keeps the first 40 and last 120 lines (max 16 KB). The full text is saved on the
  server as `/tmp/ccc-out/<machine>-<time>.log` (deleted after a day), so Claude can search it
  locally.
- A timed-out command returns what it printed so far, marked `exit=timeout(…)`.
- On Windows, PowerShell errors and warnings become single `ERROR: …` / `WARNING: …` lines.
- Machine names are unique across connectors; if two laptops use the same name, the hub shows
  them as `<connector>/<name>`.

Jobs store their state in `~/.ccc/jobs/` on the target machine. `start` returns the job id and
the first output after one second; `status` shows the state and last lines; `kill` stops the whole
process tree.

---

## Security model

- **Secrets stay on the laptop.** SSH passwords, key passphrases and the hub token are kept in
  the OS keyring (Windows Credential Manager, or the Secret Service on Linux). The connector's
  config file contains no secrets.
- **The hub never learns hosts, users or passwords.** It receives machine names, OS, status and
  the results of requests, nothing else.
- **sudo without exposing the password.** With `sudo=true` the connector runs
  `sudo -S` and writes the saved password to sudo's standard input only; the agent's command,
  its environment and its variables never contain it. Without a saved password, `sudo -n` is used
  (works only with passwordless sudo). Set *Run as root* to *Deny* to forbid root on a machine.
- **Redaction.** Before anything leaves the laptop, configured hosts/IPs are replaced by
  `<name-host>`, and saved passwords, passphrases and the hub token by `***`. This is best effort:
  commands such as `ip addr` can still reveal network details, and `pull` copies files byte for
  byte.
- **Encrypted, authenticated link.** The laptop dials out to the hub; no port needs to be open on
  the laptop or the robot. With a self-signed hub certificate the connector accepts only the
  pinned certificate from the pairing code. Each connector has its own revocable token.
- **SSH host keys** are trusted on first use and pinned; a changed key is refused until you
  *Forget* it.
- **Permissions are enforced on the laptop.** Each request carries the tool it belongs to, and
  the connector checks it against that machine's settings (a request can't borrow another tool's
  name). The hub and the agent can't change permissions.
- **You stay in control:** per-tool Allow / Ask / Deny, *Pause agent access*, per-machine
  *Visible to the agent*, and the *Activity* log.

---

## Command reference

### `ccc-hub` (server)

| Command | Purpose |
|---|---|
| `ccc-hub serve [--listen ADDR]` | run the hub (normally via systemd) |
| `ccc-hub mcp` | MCP server for Claude Code (started by Claude Code) |
| `ccc-hub config [--listen ADDR] [--public-url URL] [--tls-cert F --tls-key F]` | show or change settings |
| `ccc-hub tls self-signed [NAMES…]` · `tls show` · `tls off` | built-in TLS |
| `ccc-hub token new NAME` · `token pair NAME` · `token list` · `token revoke NAME` | connector tokens and pairing codes |
| `ccc-hub call TOOL 'JSON'` | call a tool directly, e.g. `ccc-hub call exec '{"machine":"robot","cmd":"uptime"}'` |
| `ccc-hub print-systemd` | print a systemd unit |

### `ccc` (laptop)

| Command | Purpose |
|---|---|
| `ccc` | open the GUI |
| `ccc run` | run without GUI |
| `ccc hub [--pair CODE] [--url URL] [--token] [--name NAME]` | pair / show hub settings |
| `ccc add NAME (--local \| --host H --user U) [options]` | add a connection |
| `ccc edit NAME [--rename NEW] [options]` | change a connection |
| `ccc rm NAME` · `ccc list` · `ccc test NAME` | remove / list / test |
| `ccc show NAME` | full details: permissions per tool and notes |
| `ccc forget-hostkey NAME` | accept a new SSH host key on next connect |
| `ccc pause` · `ccc pause --off` | pause / resume agent access |
| `ccc print-systemd` | print a systemd user unit for `ccc run` |

Connection options for `add`/`edit`: `--port N`, `--key FILE`, `--password-auth`, `--password`
(prompt), `--password-stdin`, `--passphrase` (prompt), `--clear-password`, `--desc TEXT` (a
literal `\n` becomes a line break), `--desc-file FILE`, `--cwd DIR`, `--init CMDS`,
`--enable` / `--disable`.

Permission options: `--access full|ask|ask-all|read-only` (preset), then `--allow TOOLS`,
`--ask TOOLS`, `--deny TOOLS`, where TOOLS is a comma list of `exec read write edit push pull job
sudo` or `all`. These may be repeated and apply after the preset. `--sudo` / `--no-sudo` are
short for `--allow sudo` / `--deny sudo`.

---

## Files and environment variables

| What | Where |
|---|---|
| Hub settings, tokens (hashed), TLS certificate | `~/.config/ccc-hub/` (`hub.toml`, `tls/`) |
| Hub socket for the MCP shim | `~/.config/ccc-hub/hub.sock` |
| Saved long outputs | `/tmp/ccc-out/` on the server |
| Connector settings (no secrets) | Windows `%APPDATA%\ccc\config.toml`, Linux `~/.config/ccc/config.toml` |
| Connector secrets | OS keyring, service `cc-connector` (entries `hub-token`, `conn/<name>/password`, `conn/<name>/passphrase`) |
| Connector statistics | `stats.json` next to the connector config |
| Background jobs | `~/.ccc/jobs/` on each target machine |

| Variable | Effect |
|---|---|
| `CCC_SECRETS=file` | connector stores secrets in a `0600` file (`secrets.toml` next to the config) instead of the keyring; for headless Linux without a Secret Service |
| `CCC_DIR` | connector config directory |
| `CCC_HUB_DIR`, `CCC_HUB_SOCK` | hub config directory / socket path |

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Badge **OFFLINE**, "Connection refused" or "connect timed out" | Hub not running (`systemctl status ccc-hub`), or the port is blocked by a firewall / cloud security group. |
| "hub rejected token (401)" | Token revoked or replaced. Issue a new code with `ccc-hub token pair NAME` and pair again (no hub restart needed). |
| "hub certificate … does not match the pinned …" | The hub's certificate changed (`tls self-signed` was re-run). Pair again with a fresh code. |
| "invalid peer certificate: UnknownIssuer" | The hub uses a self-signed certificate but the connector has no pin: pair with a pairing code instead of typing the URL. |
| Claude says "no machines connected" | The connector isn't running or isn't paired, or *Pause agent access* is on, or all machines are hidden. |
| A machine shows **error: …** | Use **Save and test** on it for details (wrong password, host unreachable, SSH not installed…). |
| "HOST KEY MISMATCH" | The SSH host was reinstalled or its address now points elsewhere. If expected, press *Forget* (or `ccc forget-hostkey NAME`). |
| "sudo FAILED" in the test, or sudo errors from the agent | Save the correct sudo password for that machine, and make sure the user is in the `sudo` group. |
| "needs the owner's approval, but the connector is running without its window" | That tool is set to *Ask* and nobody can answer. Open the GUI, or change it to *Allow*. |
| "the owner of '…' does not allow `…`" | Set to *Deny* in that machine's *Agent access*. |
| "hub closed the connection: connector v… does not match hub v…" | Hub and connector must have the same major.minor version (e.g. both 0.3.x). Update the older one. |
| "OS keyring unavailable" on Linux | Start a desktop session / gnome-keyring, or set `CCC_SECRETS=file`. |
| Claude Code doesn't show the `remote` tools | Start a new session; check `claude mcp list`. |

---

## Limits

- SSH targets must be Linux/POSIX (bash, coreutils). The laptop itself may be Windows or Linux.
- No `sudo` on Windows; run the connector as Administrator if needed.
- Transfers are capped at 500 MB per call; `exec` runs at most one hour (use `job` for longer).
- Redaction is best effort (see [Security model](#security-model)).

---

## Building from source

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install mingw-w64 libdbus-1-dev pkg-config libxkbcommon-dev libgtk-3-dev
scripts/build-release.sh                                  # → dist/ (Linux hub + connector, Windows connector)
python3 scripts/make-icon.py <bold-font.ttf> crates/connector/assets   # regenerate the icon (needs Pillow)
cargo test
```

| Path | Contents |
|---|---|
| `crates/proto` | wire protocol shared by hub and connector |
| `crates/hub` | `ccc-hub`: WebSocket hub, MCP server, output formatting, TLS and pairing |
| `crates/connector` | `ccc`: GUI, CLI, local and SSH executors, jobs, keyring, redaction |
| `scripts/` | release build and icon generation |
