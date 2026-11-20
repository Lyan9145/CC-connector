# CC-connector

Let Claude Code running on a server work on other machines (your Windows/Ubuntu
laptop, a robot computer on the laptop's LAN) **without installing Claude Code
on them**, and without showing the agent any IP address, user name or password.

```
 Claude Code ──stdio MCP──> ccc-hub mcp ──unix socket──> ccc-hub serve   (server)
                                                              ▲
                                       WebSocket (laptop dials out to a URL you choose)
                                                              │
                     laptop:  ccc  (GUI / CLI / headless) ────┤
                                ├─ "This computer"  → runs commands locally (bash / PowerShell)
                                └─ SSH connections  → robot / any LAN host (nothing installed there)
```

* **ccc-hub** runs on the Claude Code server. It accepts connectors and exposes MCP tools to Claude.
* **ccc** runs on your laptop. It keeps your saved connections (passwords in the OS keyring),
  dials out to the hub, and executes the agent's requests locally or over SSH.
* The agent only ever sees connection **names**, OS, status and your description.

## Agent tools (MCP server `remote`)

| tool | what it does |
|---|---|
| `machines` | list machines: `robot  online  linux (Ubuntu 22.04)  via laptop  sudo  "UR5 arm"` |
| `exec` | run a command (bash -l / PowerShell). `sudo=true` runs it as root; the connector feeds the saved password to sudo |
| `read` / `write` / `edit` | line-numbered reads, file writes, exact-string replacement |
| `push` / `pull` | copy files/directories between the server and a machine |
| `job` | background jobs that survive disconnects: `start`, `status`, `tail`, `kill`, `list` (also with `sudo`) |

Output is kept small for the agent: ANSI colours and `\r` progress spam are stripped, long
output is cut to head + tail with the full text saved to `/tmp/ccc-out/…` on the server (so the
agent can grep it locally), and per-connection **init commands** (e.g. `source
/opt/ros/humble/setup.bash`) and **default directory** are applied automatically.

## Setup

### 1. Server (where Claude Code runs)

```bash
sudo install -m755 ccc-hub-linux-x86_64 /usr/local/bin/ccc-hub

ccc-hub config --listen 0.0.0.0:22624 --public-url wss://your.server.com:22624
ccc-hub tls self-signed                     # built-in TLS, no CA or domain validation needed

ccc-hub print-systemd | sudo tee /etc/systemd/system/ccc-hub.service
sudo systemctl daemon-reload && sudo systemctl enable --now ccc-hub

ccc-hub token new laptop                    # prints a one-line pairing code (shown once)
sudo systemctl restart ccc-hub              # tokens are loaded at start

claude mcp add remote --scope user -- /usr/local/bin/ccc-hub mcp
```

The **pairing code** (`ccc1:…`) bundles the hub URL, the token and the hub certificate's
fingerprint. The connector pins that fingerprint, so a self-signed certificate is as safe as a
CA-signed one, and a man-in-the-middle is rejected. `ccc-hub token pair <name>` issues a new code
(and invalidates the old token after a restart).

Using a real certificate instead (Let's Encrypt, or a reverse proxy) also works:
`ccc-hub config --tls-cert fullchain.pem --tls-key privkey.pem`, or `ccc-hub tls off` behind a
proxy. Then connectors verify against public CAs, and no pin is stored.

Reverse proxy examples (WebSockets must be passed through):

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

Plain `ws://` (`ccc-hub tls off` without a proxy) works but sends the token and all traffic
unencrypted; use it only for testing.

### 2. Laptop

**Windows:** run `ccc-windows-x86_64.exe`. **Ubuntu:** `chmod +x ccc-linux-x86_64 && ./ccc-linux-x86_64`.

1. **Hub** tab: paste the pairing code → **Pair**. (Or fill in URL and token manually.)
2. **Connections** tab:
   * add *This computer* (e.g. name `laptop`) so the agent can work on the laptop itself;
   * add an *SSH host* for the robot (host/IP, user, password or key). Press **Test**: it
     connects, trusts the host key on first use, and checks sudo.
3. Keep the window open while the agent should have access. *Pause agent access* hides all
   machines instantly; the **Activity** tab shows every request the agent makes.

The same can be done from the CLI (handy for a headless Ubuntu box):

```bash
ccc hub --pair 'ccc1:…' --name laptop
ccc add laptop --local --desc "my laptop"
ccc add robot --host 192.168.1.50 --user ubuntu --password \
        --desc "UR5 arm, ROS 2 Humble" --init "source /opt/ros/humble/setup.bash" --cwd "~/ros_ws"
ccc test robot
ccc list
ccc run                       # headless; `ccc print-systemd` prints a user service unit
```

Other commands: `ccc edit NAME [--rename NEW] [--password] [--key FILE] [--disable] …`,
`ccc rm NAME`, `ccc forget-hostkey NAME`, `ccc pause [--off]`.

## Security model

* **Secrets stay on the laptop.** SSH passwords, key passphrases and the hub token are stored in
  the OS keyring (Windows Credential Manager / Secret Service). The config file
  (`%APPDATA%\ccc\config.toml`, `~/.config/ccc/config.toml`) has no secrets. On a headless Linux
  box without a Secret Service set `CCC_SECRETS=file` to use a `0600` file instead.
* **The hub never receives hosts, users or passwords**, only names/OS/status and the results
  of requests.
* **sudo:** the password is written only to `sudo -S`'s stdin. It never appears in the agent's
  command, its environment, or any variable the command could read. When no password is saved,
  `sudo -n` is used (passwordless sudo). Turn off *Allow sudo* per connection to forbid root.
* **Redaction:** before anything leaves the laptop, configured hosts/IPs are replaced by
  `<name-host>`, and saved passwords, passphrases and the hub token by `***`. This is best effort:
  commands like `ip addr` can still reveal network details, and `pull` copies files byte-for-byte.
* **Host keys** are trusted on first use and pinned; a changed key refuses the connection
  until you *Forget* it.
* **Hub auth:** each connector needs a token (`ccc-hub token new/pair/list/revoke`); the hub
  stores only its SHA-256. With a self-signed hub certificate the connector pins its fingerprint
  (from the pairing code) and refuses any other certificate.

## Limits

* SSH targets must be Linux/POSIX (bash, coreutils). The laptop itself can be Windows or Linux.
* On Windows, `sudo` isn't available; run `ccc` as Administrator if the agent needs admin rights.
  Commands run in PowerShell 7 (`pwsh`) when installed, else Windows PowerShell 5.1.
* Transfers are capped at 500 MB per call; `exec` timeout is at most 1 h (use `job` for longer).

## Building

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install mingw-w64 libdbus-1-dev pkg-config     # plus GUI deps: libxkbcommon-dev libgtk-3-dev
scripts/build-release.sh                                # → dist/
python3 scripts/make-icon.py <bold.ttf> crates/connector/assets   # regenerate the app icon (needs Pillow)
```

Crates: `crates/proto` (wire protocol), `crates/hub` (`ccc-hub`), `crates/connector` (`ccc`).
`ccc-hub call <tool> '<json>'` calls a tool without Claude, for testing.
