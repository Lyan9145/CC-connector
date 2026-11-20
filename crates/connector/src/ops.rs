//! Executes protocol operations against a target.

use crate::exec::{local, posix_exec_script, ssh::SshTarget, Family, RawOut, Run, Sudo, DATA_MAX};
use crate::store::{Connection, Secrets};
use anyhow::{anyhow, bail, Context, Result};
use ccc_proto::{shpath, shq, Entry, JobOp, Op, OpOk};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub enum Target {
    Local,
    Ssh(Arc<SshTarget>),
}

pub struct Ctx<'a> {
    pub target: &'a Target,
    pub conn: &'a Connection,
    pub secrets: &'a Secrets,
}

impl Ctx<'_> {
    fn family(&self) -> Family {
        match self.target {
            Target::Local => local::family(),
            Target::Ssh(_) => Family::Posix,
        }
    }

    fn sudo(&self, want: bool) -> Result<Sudo> {
        if !want {
            return Ok(Sudo::No);
        }
        if !self.conn.allow_sudo {
            bail!("sudo is disabled for this machine (enable 'allow sudo' in the connector)");
        }
        if self.family() == Family::Windows {
            bail!("sudo is not available on Windows; run the connector as Administrator instead");
        }
        Ok(if self.secrets.password.is_some() { Sudo::WithPassword } else { Sudo::NoPassword })
    }

    fn sudo_stdin(&self, s: Sudo) -> Option<Vec<u8>> {
        match s {
            Sudo::WithPassword => self.secrets.password.as_ref().map(|p| format!("{p}\n").into_bytes()),
            _ => None,
        }
    }

    fn default_cwd(&self, cwd: Option<String>) -> Option<String> {
        cwd.or_else(|| Some(self.conn.cwd.clone()).filter(|c| !c.trim().is_empty()))
    }

    async fn run(&self, script: &str, stdin: Option<Vec<u8>>, timeout: Duration, display: bool) -> Result<RawOut> {
        let r = Run { script, stdin, timeout, display };
        match self.target {
            Target::Local => local::run(r).await,
            Target::Ssh(t) => t.run(r).await,
        }
    }

    /// Run a shell snippet for a data operation; error on non-zero exit.
    async fn sh(&self, script: &str, stdin: Option<Vec<u8>>) -> Result<Vec<u8>> {
        let o = self.run(script, stdin, Duration::from_secs(300), false).await?;
        if o.killed {
            bail!("timed out");
        }
        if o.code != Some(0) {
            bail!("{}", o.err_text());
        }
        Ok(o.stdout)
    }

    fn remote(&self) -> bool {
        matches!(self.target, Target::Ssh(_))
    }
}

pub async fn handle(ctx: &Ctx<'_>, op: Op) -> Result<OpOk, String> {
    run_op(ctx, op).await.map_err(|e| format!("{e:#}"))
}

async fn run_op(ctx: &Ctx<'_>, op: Op) -> Result<OpOk> {
    match op {
        Op::Exec { cmd, cwd, timeout, sudo } => exec(ctx, &cmd, ctx.default_cwd(cwd), timeout, sudo).await,
        Op::Read { path, offset, limit } => {
            let data = read_all(ctx, &path).await?;
            if data.iter().take(8000).any(|&b| b == 0) {
                bail!("binary file ({} bytes); use pull to copy it", data.len());
            }
            let text = String::from_utf8_lossy(&data);
            let mut lines: Vec<&str> = text.split('\n').collect();
            if text.ends_with('\n') {
                lines.pop();
            }
            let total = lines.len();
            let start = offset.max(1);
            let sel: Vec<String> =
                lines.iter().skip(start - 1).take(limit).map(|l| l.strip_suffix('\r').unwrap_or(l).to_string()).collect();
            Ok(OpOk::Lines { start, total, lines: sel })
        }
        Op::Edit { path, old, new, all } => {
            if old.is_empty() {
                bail!("old must not be empty");
            }
            let data = read_all(ctx, &path).await?;
            let s = String::from_utf8(data).map_err(|_| anyhow!("file is not UTF-8 text"))?;
            let n = s.matches(old.as_str()).count();
            if n == 0 {
                bail!("old text not found in {path}");
            }
            if n > 1 && !all {
                bail!("old text found {n} times; add more context or set all=true");
            }
            let out = if all { s.replace(old.as_str(), &new) } else { s.replacen(old.as_str(), &new, 1) };
            write_chunk(ctx, &path, 0, out.into_bytes(), None).await?;
            Ok(OpOk::Done { n: if all { n as u64 } else { 1 } })
        }
        Op::List { path } => Ok(OpOk::Entries(list(ctx, &path).await?)),
        Op::ReadChunk { path, offset, len } => Ok(OpOk::Bytes(read_chunk(ctx, &path, offset, len).await?)),
        Op::WriteChunk { path, offset, data, mode } => {
            let n = data.len() as u64;
            write_chunk(ctx, &path, offset, data, mode).await?;
            Ok(OpOk::Done { n })
        }
        Op::Mkdir { path } => {
            if ctx.remote() {
                ctx.sh(&format!("mkdir -p {}", shpath(&path)), None).await?;
            } else {
                tokio::fs::create_dir_all(local::expand(&path)).await.with_context(|| path.clone())?;
            }
            Ok(OpOk::Done { n: 0 })
        }
        Op::Job(j) => Ok(OpOk::Text(job(ctx, j).await?)),
    }
}

// ------------------------------------------------------------------ exec

pub fn psq(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Turn error/warning records into one short line each (instead of
/// PowerShell's multi-line, localized error view) and stream as text.
const PS_FMT: &str = "ForEach-Object { if ($_ -is [System.Management.Automation.ErrorRecord]) { 'ERROR: ' + $_.Exception.Message } \
elseif ($_ -is [System.Management.Automation.WarningRecord]) { 'WARNING: ' + $_.Message } else { $_ } } | Out-String -Stream -Width 250";

/// Body that runs `init` + `cmd` with merged, compact output; sets `$code`.
fn ps_body(init: &str, cmd: &str) -> String {
    // Compile the user's code at run time so syntax errors are caught and
    // reported as one line, like any other error.
    let code = psq(&format!("{init}\n{cmd}"));
    format!(
        "$global:LASTEXITCODE=0\n$code=0\ntry {{\n& ([ScriptBlock]::Create({code})) *>&1 | {PS_FMT}\n\
         if ($LASTEXITCODE) {{ $code=$LASTEXITCODE }}\n}} catch {{\n'ERROR: ' + ($_.Exception.Message -replace '\\s*\\r?\\n\\s*', ' ')\n$code=1\n}}\n"
    )
}

const PS_HEAD: &str = "$ProgressPreference='SilentlyContinue'\n$ErrorActionPreference='Continue'\n\
    [Console]::OutputEncoding=[System.Text.Encoding]::UTF8\n$OutputEncoding=[System.Text.Encoding]::UTF8\n";

fn ps_exec_script(cmd: &str, cwd: Option<&str>, init: &str) -> String {
    let mut s = String::from(PS_HEAD);
    if let Some(d) = cwd {
        s.push_str(&format!("Set-Location -LiteralPath {}\n", psq(&local::expand(d).to_string_lossy())));
    }
    s.push_str(&ps_body(init, cmd));
    s.push_str("exit $code\n");
    s
}

async fn exec(ctx: &Ctx<'_>, cmd: &str, cwd: Option<String>, timeout: u64, sudo: bool) -> Result<OpOk> {
    let sudo = ctx.sudo(sudo)?;
    let started = Instant::now();
    let (o, timed_out) = match ctx.family() {
        Family::Posix => {
            let script = posix_exec_script(cmd, cwd.as_deref(), &ctx.conn.init, timeout, sudo);
            let o = ctx.run(&script, ctx.sudo_stdin(sudo), Duration::from_secs(timeout + 15), true).await?;
            let to = o.killed || (started.elapsed().as_secs() + 1 >= timeout && matches!(o.code, Some(124) | Some(137)));
            (o, to)
        }
        Family::Windows => {
            let script = ps_exec_script(cmd, cwd.as_deref(), &ctx.conn.init);
            let o = ctx.run(&script, None, Duration::from_secs(timeout), true).await?;
            let to = o.killed;
            (o, to)
        }
    };
    let mut out = String::from_utf8_lossy(&o.stdout).to_string();
    if !o.stderr.is_empty() {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&String::from_utf8_lossy(&o.stderr));
    }
    Ok(OpOk::Exec { code: o.code, out, timed_out })
}

// ------------------------------------------------------------------ files

async fn read_all(ctx: &Ctx<'_>, path: &str) -> Result<Vec<u8>> {
    if ctx.remote() {
        let p = shpath(path);
        return ctx.sh(&format!("test -f {p} || {{ echo \"not a regular file: {}\" >&2; exit 1; }}; head -c {DATA_MAX} {p}", path.replace('"', "")), None).await;
    }
    let p = local::expand(path);
    let md = tokio::fs::metadata(&p).await.with_context(|| path.to_string())?;
    if !md.is_file() {
        bail!("not a regular file: {path}");
    }
    if md.len() as usize > DATA_MAX {
        bail!("file too large ({} bytes)", md.len());
    }
    Ok(tokio::fs::read(&p).await?)
}

async fn read_chunk(ctx: &Ctx<'_>, path: &str, offset: u64, len: u32) -> Result<Vec<u8>> {
    if ctx.remote() {
        return ctx.sh(&format!("tail -c +{} {} | head -c {len}", offset + 1, shpath(path)), None).await;
    }
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let mut f = tokio::fs::File::open(local::expand(path)).await.with_context(|| path.to_string())?;
    f.seek(std::io::SeekFrom::Start(offset)).await?;
    let mut buf = vec![0u8; len as usize];
    let mut got = 0;
    while got < buf.len() {
        let k = f.read(&mut buf[got..]).await?;
        if k == 0 {
            break;
        }
        got += k;
    }
    buf.truncate(got);
    Ok(buf)
}

async fn write_chunk(ctx: &Ctx<'_>, path: &str, offset: u64, data: Vec<u8>, mode: Option<u32>) -> Result<()> {
    if ctx.remote() {
        let p = shpath(path);
        let mut s = if offset == 0 {
            format!("d=$(dirname {p}) && mkdir -p \"$d\" && cat > {p}")
        } else {
            format!("cat >> {p}")
        };
        if let Some(m) = mode {
            s.push_str(&format!(" && chmod {:o} {p}", m & 0o7777));
        }
        ctx.sh(&s, Some(data)).await?;
        return Ok(());
    }
    use tokio::io::{AsyncSeekExt, AsyncWriteExt};
    let p = local::expand(path);
    let mut f = if offset == 0 {
        if let Some(d) = p.parent() {
            if !d.as_os_str().is_empty() {
                tokio::fs::create_dir_all(d).await?;
            }
        }
        tokio::fs::File::create(&p).await.with_context(|| path.to_string())?
    } else {
        let mut f = tokio::fs::OpenOptions::new().write(true).open(&p).await.with_context(|| path.to_string())?;
        f.seek(std::io::SeekFrom::Start(offset)).await?;
        f
    };
    f.write_all(&data).await?;
    f.flush().await?;
    #[cfg(unix)]
    if let Some(m) = mode {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(&p, std::fs::Permissions::from_mode(m & 0o7777)).await?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    Ok(())
}

async fn list(ctx: &Ctx<'_>, path: &str) -> Result<Vec<Entry>> {
    if ctx.remote() {
        let out = ctx.sh(&format!("find {} -printf '%y\\t%s\\t%m\\t%P\\n'", shpath(path)), None).await?;
        let mut v = vec![];
        for line in String::from_utf8_lossy(&out).lines() {
            let mut it = line.splitn(4, '\t');
            let (Some(t), Some(sz), Some(m), Some(rel)) = (it.next(), it.next(), it.next(), it.next()) else { continue };
            let is_dir = t == "d";
            if !(is_dir || t == "f" || t == "l") || (is_dir && rel.is_empty()) {
                continue;
            }
            v.push(Entry {
                rel: rel.to_string(),
                is_dir,
                size: if is_dir { 0 } else { sz.parse().unwrap_or(0) },
                mode: u32::from_str_radix(m, 8).ok(),
            });
        }
        return Ok(v);
    }
    let root = local::expand(path);
    tokio::task::spawn_blocking(move || walk(&root)).await?
}

fn walk(root: &std::path::Path) -> Result<Vec<Entry>> {
    #[cfg(unix)]
    fn mode(m: &std::fs::Metadata) -> Option<u32> {
        use std::os::unix::fs::PermissionsExt;
        Some(m.permissions().mode() & 0o7777)
    }
    #[cfg(not(unix))]
    fn mode(_: &std::fs::Metadata) -> Option<u32> {
        None
    }
    let md = std::fs::metadata(root).with_context(|| root.display().to_string())?;
    if !md.is_dir() {
        return Ok(vec![Entry { rel: String::new(), is_dir: false, size: md.len(), mode: mode(&md) }]);
    }
    let mut out = vec![];
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, rel)) = stack.pop() {
        for e in std::fs::read_dir(&dir)?.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let r = if rel.is_empty() { name } else { format!("{rel}/{name}") };
            let Ok(md) = std::fs::metadata(e.path()) else { continue };
            if md.is_dir() {
                out.push(Entry { rel: r.clone(), is_dir: true, size: 0, mode: mode(&md) });
                stack.push((e.path(), r));
            } else {
                out.push(Entry { rel: r, is_dir: false, size: md.len(), mode: mode(&md) });
            }
            if out.len() > 200_000 {
                bail!("too many files");
            }
        }
    }
    Ok(out)
}

/// PowerShell script that starts a detached Windows job.
fn win_job_start(p: &str, id: &str, cmd: &str, cwd: &std::path::Path, init: &str, jdir: &std::path::Path) -> String {
    let f = |ext: &str| jdir.join(format!("{id}.{ext}")).to_string_lossy().to_string();
    // The job script itself, and a hidden wrapper that runs it,
    // waits, and records its real exit code (also for `exit N`).
    let job = ps_exec_script(cmd, None, init);
    let wrapper = format!(
        "$p = Start-Process {psexe} -ArgumentList '-NoProfile','-NonInteractive','-OutputFormat','Text','-ExecutionPolicy','Bypass','-File',{jobq} \
         -WorkingDirectory {cwdq} -NoNewWindow -Wait -PassThru -RedirectStandardOutput {logq} -RedirectStandardError {errq}\n\
         Set-Content -LiteralPath {exitq} -Value $p.ExitCode\n",
        psexe = psq(local::ps_exe()),
        jobq = psq(&format!("\"{}\"", f("ps1"))),
        cwdq = psq(&cwd.to_string_lossy()),
        logq = psq(&f("log")),
        errq = psq(&f("err")),
        exitq = psq(&f("exit")),
    );
    format!(
        "{p}New-Item -ItemType Directory -Force -Path $J | Out-Null\n\
         $bom = New-Object System.Text.UTF8Encoding $true\n\
         [IO.File]::WriteAllText({jobf}, {jobs}, $bom)\n\
         [IO.File]::WriteAllText({runf}, {runs}, $bom)\n\
         Set-Content -LiteralPath (Join-Path $J '{id}.cmd') -Value {cmdq}\n\
         $proc = Start-Process {psexe} -ArgumentList '-NoProfile','-NonInteractive','-OutputFormat','Text','-ExecutionPolicy','Bypass','-File',{runq} -WindowStyle Hidden -PassThru\n\
         Set-Content -LiteralPath (Join-Path $J '{id}.pid') -Value $proc.Id\nStart-Sleep 1\nst '{id}'\n'--- output:'\n\
         Get-Content (Join-Path $J '{id}.log') -Tail 20 -ErrorAction SilentlyContinue\n",
        jobf = psq(&f("ps1")),
        jobs = psq(&job),
        runf = psq(&f("run.ps1")),
        runs = psq(&wrapper),
        runq = psq(&format!("\"{}\"", f("run.ps1"))),
        cmdq = psq(cmd),
        psexe = psq(local::ps_exe()),
    )
}

// ------------------------------------------------------------------ jobs

fn valid_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 16 || !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()) {
        bail!("invalid job id '{id}'");
    }
    Ok(())
}

fn new_id() -> String {
    use rand::Rng;
    format!("j{:05x}", rand::thread_rng().gen_range(0..0xfffff))
}

const SH_PRELUDE: &str = r#"J="$HOME/.ccc/jobs"
st() {
  id=$1
  [ -e "$J/$id.pid" ] || { echo "$id: no such job"; return 1; }
  pid=$(cat "$J/$id.pid")
  if [ -e "$J/$id.exit" ]; then s="exited $(cat "$J/$id.exit")"
  elif ps -p "$pid" >/dev/null 2>&1; then s=running
  else s="dead (no exit code)"; fi
  age=$(( $(date +%s) - $(stat -c %Y "$J/$id.pid") ))
  printf '%s  %s  age=%ss  %s\n' "$id" "$s" "$age" "$(head -c 100 "$J/$id.cmd" | tr '\n' ' ')"
}
"#;

const PS_PRELUDE: &str = r#"
function st($id) {
  $p = Join-Path $J "$id.pid"
  if (-not (Test-Path $p)) { "${id}: no such job"; return }
  $procId = [int](Get-Content $p)
  $e = Join-Path $J "$id.exit"
  if (Test-Path $e) { $s = 'exited ' + (Get-Content $e -Raw).Trim() }
  elseif (Get-Process -Id $procId -ErrorAction SilentlyContinue) { $s = 'running' }
  else { $s = 'dead (no exit code)' }
  $age = [int]((Get-Date) - (Get-Item $p).LastWriteTime).TotalSeconds
  $c = (Get-Content (Join-Path $J "$id.cmd") -Raw)
  if ($c.Length -gt 100) { $c = $c.Substring(0,100) }
  "$id  $s  age=${age}s  " + ($c -replace "`r?`n",' ')
}
"#;

#[allow(clippy::needless_late_init)]
async fn job(ctx: &Ctx<'_>, j: JobOp) -> Result<String> {
    let script;
    let mut stdin = None;
    match ctx.family() {
        Family::Posix => {
            let p = SH_PRELUDE;
            script = match &j {
                JobOp::Start { cmd, cwd, sudo } => {
                    let sudo = ctx.sudo(*sudo)?;
                    stdin = ctx.sudo_stdin(sudo);
                    let id = new_id();
                    let cwd = ctx.default_cwd(cwd.clone());
                    let mut inner = String::new();
                    if !ctx.conn.init.trim().is_empty() {
                        inner.push_str(ctx.conn.init.trim());
                        inner.push('\n');
                    }
                    inner.push_str(cmd);
                    let runner = r#"bash -lc "$1"; echo $? > "$2""#;
                    let launch = format!(
                        r#"setsid nohup bash -c {} ccc "$2" "$1/{id}.exit" > "$1/{id}.log" 2>&1 < /dev/null & echo $!"#,
                        shq(runner)
                    );
                    let cd = cwd.map(|d| format!("cd {} || exit 1\n", shpath(&d))).unwrap_or_default();
                    let mark = if sudo != Sudo::No { format!("touch \"$J/{id}.sudo\"\n") } else { String::new() };
                    format!(
                        "{p}mkdir -p \"$J\" || exit 1\nprintf '%s\\n' {cmdq} > \"$J/{id}.cmd\"\n{cd}\
                         pid=$({pre}bash -c {launchq} ccc \"$J\" {innerq}) || exit 1\n\
                         echo \"$pid\" > \"$J/{id}.pid\"\n{mark}sleep 1\nst {id}\necho '--- output:'\ntail -n 20 \"$J/{id}.log\"\n",
                        cmdq = shq(cmd),
                        pre = sudo.prefix(),
                        launchq = shq(&launch),
                        innerq = shq(&inner),
                    )
                }
                JobOp::Status { id } => {
                    valid_id(id)?;
                    format!("{p}st {id} || exit 0\necho '--- last lines:'\ntail -n 5 \"$J/{id}.log\"\n")
                }
                JobOp::Tail { id, lines } => {
                    valid_id(id)?;
                    format!("{p}st {id} || exit 0\necho '---'\ntail -n {lines} \"$J/{id}.log\"\n")
                }
                JobOp::Kill { id } => {
                    valid_id(id)?;
                    let pre = if ctx.secrets.password.is_some() { Sudo::WithPassword } else { Sudo::NoPassword };
                    stdin = ctx.sudo_stdin(pre);
                    let k = r#"kill -TERM -- -"$1" 2>/dev/null || kill -TERM "$1" 2>/dev/null
for i in 1 2 3 4 5; do ps -p "$1" >/dev/null 2>&1 || exit 0; sleep 1; done
kill -KILL -- -"$1" 2>/dev/null; kill -KILL "$1" 2>/dev/null; exit 0"#;
                    format!(
                        "{p}st {id} >/dev/null || {{ echo \"{id}: no such job\"; exit 0; }}\npid=$(cat \"$J/{id}.pid\")\n\
                         if [ -e \"$J/{id}.sudo\" ]; then {pre}bash -c {kq} ccc \"$pid\"; else bash -c {kq} ccc \"$pid\"; fi\n\
                         [ -e \"$J/{id}.exit\" ] || echo killed > \"$J/{id}.exit\"\nst {id}\n",
                        pre = pre.prefix(),
                        kq = shq(k)
                    )
                }
                JobOp::List => format!(
                    "{p}n=0\nfor f in \"$J\"/*.pid; do [ -e \"$f\" ] || continue; st \"$(basename \"$f\" .pid)\"; n=1; done\n\
                     [ $n = 1 ] || echo 'no jobs'\n"
                ),
            };
        }
        Family::Windows => {
            let jdir = local::home().join(".ccc").join("jobs");
            let jq = psq(&jdir.to_string_lossy());
            let p = format!("$J = {jq}\n{PS_PRELUDE}");
            script = match &j {
                JobOp::Start { cmd, cwd, sudo } => {
                    ctx.sudo(*sudo)?;
                    let id = new_id();
                    let cwd = ctx.default_cwd(cwd.clone()).map(|d| local::expand(&d)).unwrap_or_else(local::home);
                    win_job_start(&p, &id, cmd, &cwd, &ctx.conn.init, &jdir)
                }
                JobOp::Status { id } => {
                    valid_id(id)?;
                    format!("{p}st '{id}'\n'--- last lines:'\nGet-Content (Join-Path $J '{id}.log') -Tail 5 -ErrorAction SilentlyContinue\n")
                }
                JobOp::Tail { id, lines } => {
                    valid_id(id)?;
                    format!(
                        "{p}st '{id}'\n'---'\nGet-Content (Join-Path $J '{id}.log') -Tail {lines} -ErrorAction SilentlyContinue\n\
                         Get-Content (Join-Path $J '{id}.err') -Tail {lines} -ErrorAction SilentlyContinue\n"
                    )
                }
                JobOp::Kill { id } => {
                    valid_id(id)?;
                    format!(
                        "{p}$pf = Join-Path $J '{id}.pid'\nif (Test-Path $pf) {{ taskkill /T /F /PID ([int](Get-Content $pf)) | Out-Null\n\
                         $e = Join-Path $J '{id}.exit'; if (-not (Test-Path $e)) {{ Set-Content -LiteralPath $e -Value 'killed' }} }}\nst '{id}'\n"
                    )
                }
                JobOp::List => format!(
                    "{p}$f = Get-ChildItem $J -Filter *.pid -ErrorAction SilentlyContinue\nif ($f) {{ $f | ForEach-Object {{ st $_.BaseName }} }} else {{ 'no jobs' }}\n"
                ),
            };
        }
    }
    let o = ctx.run(&script, stdin, Duration::from_secs(60), true).await?;
    if o.killed {
        bail!("job command timed out");
    }
    let mut out = String::from_utf8_lossy(&o.stdout).to_string();
    if o.code != Some(0) {
        let e = String::from_utf8_lossy(&o.stderr);
        out.push_str(&e);
        if out.trim().is_empty() {
            bail!("job command failed (exit {:?})", o.code);
        }
    }
    Ok(out.trim_end().to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore]
    fn print_win_job_script() {
        let p = format!("$J = {}\n{}", super::psq(r"C:\Users\BEN91\.ccc\jobs"), super::PS_PRELUDE);
        let s = super::win_job_start(&p, "jtest1", "\"hello\"; exit 3", std::path::Path::new(r"C:\Users\BEN91"), "", std::path::Path::new(r"C:\Users\BEN91\.ccc\jobs"));
        std::fs::write("/tmp/win_job.ps1", s).unwrap();
        for (i, c) in ["if ( { broken", "\"before\"; exit 4", "Get-Date -Format yyyy; Write-Warning w"].iter().enumerate() {
            std::fs::write(format!("/tmp/win_exec{i}.ps1"), super::ps_exec_script(c, Some(r"C:\Users\BEN91"), "")).unwrap();
        }
    }
}
