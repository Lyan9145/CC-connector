//! Token-saving output formatting for the agent.

use std::path::PathBuf;

pub const HEAD: usize = 40;
pub const TAIL: usize = 120;
pub const MAX_BYTES: usize = 16 * 1024;
pub const LINE_MAX: usize = 2000;

/// Strip ANSI escape sequences and collapse carriage-return progress output
/// to the final state of each line.
pub fn clean(s: &str) -> String {
    let mut no_ansi = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\x1b' {
            match it.peek() {
                Some('[') => {
                    it.next();
                    // CSI: params then a final byte in @..~
                    for d in it.by_ref() {
                        if ('@'..='~').contains(&d) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    it.next();
                    // OSC: until BEL or ESC \
                    while let Some(d) = it.next() {
                        if d == '\x07' {
                            break;
                        }
                        if d == '\x1b' && it.peek() == Some(&'\\') {
                            it.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    it.next();
                }
                None => {}
            }
        } else {
            no_ansi.push(c);
        }
    }
    let mut out = String::with_capacity(no_ansi.len());
    for (i, line) in no_ansi.split('\n').enumerate() {
        if i > 0 {
            out.push('\n');
        }
        let line = line.strip_suffix('\r').unwrap_or(line);
        // keep the last non-empty segment after a bare '\r'
        let seg = line.rsplit('\r').find(|p| !p.is_empty()).unwrap_or("");
        out.push_str(seg);
    }
    out
}

fn cut_line(l: &str) -> String {
    if l.len() <= LINE_MAX {
        return l.to_string();
    }
    let mut end = LINE_MAX;
    while !l.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [+{} chars]", &l[..end], l.len() - end)
}

/// Returns the text to show and whether it was truncated.
pub fn truncate(s: &str) -> (String, bool) {
    let s = s.trim_end_matches('\n');
    let lines: Vec<&str> = s.split('\n').collect();
    let long_line = lines.iter().any(|l| l.len() > LINE_MAX);
    if lines.len() <= HEAD + TAIL && s.len() <= MAX_BYTES && !long_line {
        return (s.to_string(), false);
    }
    let mut out = String::new();
    if lines.len() <= HEAD + TAIL {
        // few but long lines: cut each, then bound total bytes
        for l in &lines {
            out.push_str(&cut_line(l));
            out.push('\n');
        }
    } else {
        for l in &lines[..HEAD] {
            out.push_str(&cut_line(l));
            out.push('\n');
        }
        out.push_str(&format!("[... {} lines omitted ...]\n", lines.len() - HEAD - TAIL));
        for l in &lines[lines.len() - TAIL..] {
            out.push_str(&cut_line(l));
            out.push('\n');
        }
    }
    if out.len() > MAX_BYTES {
        let head = MAX_BYTES / 4;
        let tail = MAX_BYTES - head;
        let mut a = head;
        while !out.is_char_boundary(a) {
            a -= 1;
        }
        let mut b = out.len() - tail;
        while !out.is_char_boundary(b) {
            b += 1;
        }
        out = format!("{}\n[... {} bytes omitted ...]\n{}", &out[..a], b - a, &out[b..]);
    }
    (out.trim_end_matches('\n').to_string(), true)
}

/// Save full output to a server-side file the agent can Read/Grep locally.
pub fn save_full(machine: &str, s: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join("ccc-out");
    std::fs::create_dir_all(&dir).ok()?;
    // best-effort cleanup of files older than a day
    if let Ok(rd) = std::fs::read_dir(&dir) {
        for e in rd.flatten() {
            if let Ok(m) = e.metadata() {
                if m.modified().ok().and_then(|t| t.elapsed().ok()).is_some_and(|d| d.as_secs() > 86400) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
    }
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_millis();
    let safe: String = machine.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    let p = dir.join(format!("{safe}-{ts}.log"));
    std::fs::write(&p, s).ok()?;
    Some(p)
}

/// Clean, truncate, and point to the full log if needed.
pub fn present(machine: &str, raw: &str) -> String {
    let c = clean(raw);
    let (t, cut) = truncate(&c);
    if cut {
        match save_full(machine, &c) {
            Some(p) => format!("{t}\n[full output: {}]", p.display()),
            None => t,
        }
    } else {
        t
    }
}

pub fn exec_result(machine: &str, code: Option<i32>, out: &str, timed_out: bool, timeout: u64) -> String {
    let head = if timed_out {
        format!("exit=timeout({timeout}s; use job for long tasks)")
    } else {
        match code {
            Some(c) => format!("exit={c}"),
            None => "exit=killed".into(),
        }
    };
    let body = present(machine, out);
    let mut s = if body.trim().is_empty() { format!("{head} (no output)") } else { format!("{head}\n{body}") };
    if out.contains("a terminal is required to read the password") || out.contains("sudo: a password is required") {
        s.push_str("\n[hint: don't call sudo inside cmd; pass sudo=true to run the whole cmd as root]");
    }
    s
}

pub fn numbered(start: usize, total: usize, lines: &[String]) -> String {
    let mut out = String::new();
    for (i, l) in lines.iter().enumerate() {
        out.push_str(&format!("{:>6}\t{}\n", start + i, cut_line(l)));
    }
    let end = start + lines.len().saturating_sub(1);
    if lines.is_empty() {
        out.push_str(&format!("[empty range; file has {total} lines]"));
    } else if end < total || start > 1 {
        out.push_str(&format!("[lines {start}-{end} of {total}]"));
    }
    out.trim_end_matches('\n').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ansi_and_cr() {
        assert_eq!(clean("\x1b[31mred\x1b[0m"), "red");
        assert_eq!(clean("10%\r50%\r100%\ndone\r\n"), "100%\ndone\n");
        assert_eq!(clean("\x1b]0;title\x07ok"), "ok");
    }

    #[test]
    fn truncates_many_lines() {
        let s: String = (0..1000).map(|i| format!("line{i}\n")).collect();
        let (t, cut) = truncate(&s);
        assert!(cut);
        assert!(t.contains("line0\n"));
        assert!(t.contains("line999"));
        assert!(t.contains("[... 840 lines omitted ...]"));
        assert!(!t.contains("line500\n"));
    }

    #[test]
    fn short_untouched() {
        assert_eq!(truncate("a\nb\n"), ("a\nb".into(), false));
    }

    #[test]
    fn bounds_bytes() {
        let s = "x".repeat(100_000);
        let (t, cut) = truncate(&s);
        assert!(cut && t.len() <= MAX_BYTES + 100);
    }

    #[test]
    fn sudo_hint() {
        let s = exec_result("m", Some(1), "sudo: a terminal is required to read the password; either", false, 120);
        assert!(s.contains("sudo=true"));
    }
}
