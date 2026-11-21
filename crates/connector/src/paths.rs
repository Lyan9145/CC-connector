//! Folder rules: resolving the paths the agent names (following symlinks, so
//! a link can't lead out of an allowed folder) and matching them to rules.

use crate::exec::local;
use crate::store::{Connection, FolderAccess};
use ccc_proto::shpath;
use std::path::{Component, Path, PathBuf};

/// A path resolved on its machine.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    /// Absolute path with symlinks resolved, in the machine's own syntax.
    pub abs: String,
    pub is_dir: bool,
    pub exists: bool,
}

/// How paths compare on a machine.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Style {
    pub windows: bool,
}

impl Style {
    /// Comparison key: '/' separators, no trailing separator, lower case on
    /// Windows.
    pub fn key(self, abs: &str) -> String {
        let mut s = if self.windows { abs.replace('\\', "/").to_lowercase() } else { abs.to_string() };
        while s.len() > 1 && s.ends_with('/') && !(self.windows && s.len() == 3 && s.as_bytes()[1] == b':') {
            s.pop();
        }
        s
    }

    /// Whether `path` is `dir` or inside it (both keys).
    pub fn within(self, path: &str, dir: &str) -> bool {
        path == dir || (path.starts_with(dir) && (dir.ends_with('/') || path.as_bytes().get(dir.len()) == Some(&b'/')))
    }

    /// Parent of an absolute path (None at the root).
    pub fn parent(self, abs: &str) -> Option<String> {
        let seps: &[char] = if self.windows { &['\\', '/'] } else { &['/'] };
        let t = abs.trim_end_matches(seps);
        let i = t.rfind(seps)?;
        let p = &t[..i];
        if p.is_empty() {
            Some(if t.len() > 1 { "/".into() } else { return None })
        } else if self.windows && p.len() == 2 && p.ends_with(':') {
            Some(format!("{p}\\"))
        } else {
            Some(p.to_string())
        }
    }

    /// `abs` with the home directory shown as `~`.
    pub fn tilde(self, abs: &str, home: &str) -> String {
        if home.is_empty() {
            return abs.to_string();
        }
        let (k, h) = (self.key(abs), self.key(home));
        if k == h {
            "~".into()
        } else if self.within(&k, &h) {
            let sep = if self.windows { "\\" } else { "/" };
            format!("~{sep}{}", &abs[home.trim_end_matches(['/', '\\']).len() + 1..])
        } else {
            abs.to_string()
        }
    }
}

/// Strip Windows' `\\?\` verbatim prefix from canonicalized paths.
fn plain(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(r) = s.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{r}"));
    }
    if let Some(r) = s.strip_prefix(r"\\?\") {
        return PathBuf::from(r);
    }
    p
}

/// Resolve a path on this computer: `~` expanded, made absolute, `..`
/// applied, and symlinks resolved for the part that exists.
pub fn resolve_local(p: &str) -> Resolved {
    let e = local::expand(p.trim());
    let abs = if e.is_absolute() { e } else { std::env::current_dir().unwrap_or_else(|_| local::home()).join(e) };
    let mut cur = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::ParentDir => {
                // resolve links before stepping up, like the OS does
                if let Ok(r) = std::fs::canonicalize(&cur) {
                    cur = plain(r);
                }
                cur.pop();
            }
            Component::CurDir => {}
            c => cur.push(c.as_os_str()),
        }
    }
    // canonicalize the longest existing prefix, keep the rest as typed
    let mut base = cur.clone();
    let mut tail = vec![];
    let real = loop {
        if let Ok(r) = std::fs::canonicalize(&base) {
            break plain(r);
        }
        match (base.file_name().map(|n| n.to_os_string()), base.parent().map(Path::to_path_buf)) {
            (Some(n), Some(par)) => {
                tail.push(n);
                base = par;
            }
            _ => break cur.clone(),
        }
    };
    let mut out = real;
    let exists = tail.is_empty();
    for n in tail.into_iter().rev() {
        out.push(n);
    }
    Resolved { is_dir: exists && out.is_dir(), exists, abs: out.to_string_lossy().to_string() }
}

/// Shell script that prints `$HOME`, then for each path its resolved form
/// and a type line (d = dir, f = exists, n = missing).
pub fn remote_script(paths: &[&str]) -> String {
    let mut s = String::from(
        "printf '%s\\n' \"$HOME\"\nr() { x=$(realpath -m -- \"$1\" 2>/dev/null || readlink -m -- \"$1\" 2>/dev/null) || { echo '?'; echo n; return; }\n\
         printf '%s\\n' \"$x\"; if [ -d \"$x\" ]; then echo d; elif [ -e \"$x\" ]; then echo f; else echo n; fi; }\n",
    );
    for p in paths {
        s.push_str(&format!("r {}\n", shpath(p.trim())));
    }
    s
}

/// Parse the output of `remote_script`: (home, resolved paths).
pub fn parse_remote(out: &str, n: usize) -> Option<(String, Vec<Resolved>)> {
    let mut it = out.lines();
    let home = it.next()?.to_string();
    let mut v = vec![];
    for _ in 0..n {
        let abs = it.next()?.to_string();
        let t = it.next()?;
        if abs == "?" || !abs.starts_with('/') {
            return None;
        }
        v.push(Resolved { abs, is_dir: t == "d", exists: t != "n" });
    }
    Some((home, v))
}

/// Which rule applies to `key`: the most specific listed folder containing
/// it, or `elsewhere`. Returns (access, index of the rule).
pub fn rule_for(style: Style, conn: &Connection, rule_keys: &[String], key: &str) -> (FolderAccess, Option<usize>) {
    let mut best: Option<(usize, usize)> = None;
    for (i, rk) in rule_keys.iter().enumerate() {
        if !rk.is_empty() && style.within(key, rk) && best.is_none_or(|(_, l)| rk.len() > l) {
            best = Some((i, rk.len()));
        }
    }
    match best {
        Some((i, _)) => (conn.folders[i].access, Some(i)),
        None => (conn.elsewhere, None),
    }
}

/// Folders the owner can choose to grant for `target`, most specific first:
/// the target's folder and its parents, up to `stop` (a rule folder) or
/// the root.
pub fn grant_choices(style: Style, target: &Resolved, stop: Option<&str>) -> Vec<String> {
    let first = if target.is_dir { Some(target.abs.clone()) } else { style.parent(&target.abs) };
    let mut out = vec![];
    let mut cur = first;
    while let Some(c) = cur {
        out.push(c.clone());
        if stop.is_some_and(|s| style.key(s) == style.key(&c)) || out.len() >= 12 {
            break;
        }
        cur = style.parent(&c);
    }
    if out.is_empty() {
        out.push(target.abs.clone());
    }
    out
}

/// Sub-folders of a folder on this computer: (absolute path, names).
/// An empty path lists the drives on Windows (and home elsewhere).
pub fn list_local_dirs(p: &str) -> std::io::Result<(String, Vec<String>)> {
    #[cfg(windows)]
    if p.trim().is_empty() {
        let v = (b'A'..=b'Z').map(|c| format!("{}:\\", c as char)).filter(|d| Path::new(d).exists()).collect();
        return Ok((String::new(), v));
    }
    let r = resolve_local(if p.trim().is_empty() { "~" } else { p });
    let mut v = vec![];
    for e in std::fs::read_dir(&r.abs)?.flatten() {
        if e.path().is_dir() {
            v.push(e.file_name().to_string_lossy().to_string());
        }
    }
    sort_dirs(&mut v);
    Ok((r.abs, v))
}

/// Folders first by name, hidden ones (".x") last.
pub fn sort_dirs(v: &mut [String]) {
    v.sort_by_key(|n| (n.starts_with('.'), n.to_lowercase()));
}

/// Shell script listing the sub-folders of `p`: prints $HOME, the absolute
/// path, then one folder name per line.
pub fn remote_list_script(p: &str) -> String {
    format!(
        "cd -- {} || exit 3\nprintf '%s\\n' \"$HOME\"\npwd -P\nfor d in * .*; do [ \"$d\" = . ] || [ \"$d\" = .. ] || {{ [ -d \"$d\" ] && printf '%s\\n' \"$d\"; }}; done\nexit 0\n",
        shpath(if p.trim().is_empty() { "~" } else { p.trim() })
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_within() {
        let u = Style { windows: false };
        assert!(u.within("/home/a/proj/x", "/home/a/proj"));
        assert!(u.within("/home/a/proj", "/home/a/proj"));
        assert!(!u.within("/home/a/project", "/home/a/proj"));
        assert!(u.within("/etc", "/"));
        assert_eq!(u.key("/home/a/"), "/home/a");
        assert_eq!(u.key("/"), "/");
        let w = Style { windows: true };
        assert_eq!(w.key(r"C:\Users\Ben\"), "c:/users/ben");
        assert_eq!(w.key(r"C:\"), "c:/");
        assert!(w.within(&w.key(r"C:\Users\BEN\x.txt"), &w.key(r"c:\users\ben")));
        assert!(w.within(&w.key(r"D:\data"), &w.key(r"D:\")));
        assert_eq!(w.parent(r"C:\Users"), Some(r"C:\".into()));
        assert_eq!(w.parent(r"C:\"), None);
        assert_eq!(u.parent("/home"), Some("/".into()));
        assert_eq!(u.parent("/"), None);
        assert_eq!(u.tilde("/home/a/proj", "/home/a"), "~/proj");
        assert_eq!(u.tilde("/home/a", "/home/a"), "~");
        assert_eq!(w.tilde(r"C:\Users\Ben\proj", r"C:\Users\Ben"), r"~\proj");
    }

    #[test]
    fn rules_and_choices() {
        let u = Style { windows: false };
        let conn = Connection {
            folders: vec![
                crate::store::FolderRule { path: "~".into(), access: FolderAccess::Read },
                crate::store::FolderRule { path: "~/proj".into(), access: FolderAccess::Full },
            ],
            elsewhere: FolderAccess::Ask,
            ..Default::default()
        };
        let keys = vec!["/home/a".to_string(), "/home/a/proj".to_string()];
        assert_eq!(rule_for(u, &conn, &keys, "/home/a/proj/src/x.rs"), (FolderAccess::Full, Some(1)));
        assert_eq!(rule_for(u, &conn, &keys, "/home/a/.bashrc"), (FolderAccess::Read, Some(0)));
        assert_eq!(rule_for(u, &conn, &keys, "/etc/hosts"), (FolderAccess::Ask, None));
        let t = Resolved { abs: "/home/a/data/raw/x.csv".into(), is_dir: false, exists: true };
        assert_eq!(grant_choices(u, &t, Some("/home/a")), vec!["/home/a/data/raw", "/home/a/data", "/home/a"]);
        let t = Resolved { abs: "/srv/d".into(), is_dir: true, exists: true };
        assert_eq!(grant_choices(u, &t, None), vec!["/srv/d", "/srv", "/"]);
    }

    #[test]
    fn remote_parse() {
        let out = "/home/a\n/home/a/x\nf\n/etc/new\nn\n";
        let (h, v) = parse_remote(out, 2).unwrap();
        assert_eq!(h, "/home/a");
        assert!(v[0].exists && !v[0].is_dir);
        assert!(!v[1].exists);
        assert!(parse_remote("/h\n?\nn\n", 1).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn local_symlinks() {
        let d = std::env::temp_dir().join(format!("ccc-paths-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join("allowed")).unwrap();
        std::fs::create_dir_all(d.join("secret")).unwrap();
        std::os::unix::fs::symlink(d.join("secret"), d.join("allowed/link")).unwrap();
        let real = std::fs::canonicalize(&d).unwrap();
        let r = resolve_local(&format!("{}/allowed/link/key.txt", d.display()));
        assert_eq!(r.abs, format!("{}/secret/key.txt", real.display()));
        assert!(!r.exists);
        let r = resolve_local(&format!("{}/allowed/../secret", d.display()));
        assert_eq!(r.abs, format!("{}/secret", real.display()));
        assert!(r.is_dir);
        let r = resolve_local(&format!("{}/allowed/link/../x", d.display()));
        // `link/..` is the parent of the link's target, as the OS sees it
        assert_eq!(r.abs, format!("{}/x", real.display()));
        let _ = std::fs::remove_dir_all(&d);
    }
}
