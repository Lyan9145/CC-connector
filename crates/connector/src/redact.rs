//! Remove hosts and secrets from anything sent to the hub.

use ccc_proto::{OpOk, OpResult};

#[derive(Default, Clone)]
pub struct Redactor {
    /// (needle, replacement), longest needle first
    pats: Vec<(String, String)>,
}

impl Redactor {
    pub fn new(mut pats: Vec<(String, String)>) -> Self {
        pats.retain(|(n, _)| !n.is_empty());
        pats.sort_by_key(|p| std::cmp::Reverse(p.0.len()));
        pats.dedup_by(|a, b| a.0 == b.0);
        Self { pats }
    }

    pub fn add_host(v: &mut Vec<(String, String)>, alias: &str, host: &str) {
        if host.len() >= 3 {
            v.push((host.to_string(), format!("<{alias}-host>")));
        }
    }

    pub fn add_secret(v: &mut Vec<(String, String)>, secret: &str) {
        // very short secrets would mangle ordinary output
        if secret.len() >= 4 {
            v.push((secret.to_string(), "***".into()));
        }
    }

    pub fn text(&self, s: &str) -> String {
        let mut out = s.to_string();
        for (n, r) in &self.pats {
            if out.contains(n.as_str()) {
                out = out.replace(n.as_str(), r);
            }
        }
        out
    }

    pub fn result(&self, r: OpResult) -> OpResult {
        match r {
            Err(e) => Err(self.text(&e)),
            Ok(OpOk::Exec { code, out, timed_out }) => Ok(OpOk::Exec { code, out: self.text(&out), timed_out }),
            Ok(OpOk::Lines { start, total, lines }) => {
                Ok(OpOk::Lines { start, total, lines: lines.iter().map(|l| self.text(l)).collect() })
            }
            Ok(OpOk::Text(t)) => Ok(OpOk::Text(self.text(&t))),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces() {
        let mut v = vec![];
        Redactor::add_host(&mut v, "robot", "192.168.1.50");
        Redactor::add_secret(&mut v, "hunter22");
        Redactor::add_secret(&mut v, "ab");
        let r = Redactor::new(v);
        assert_eq!(r.text("ssh 192.168.1.50 pw hunter22 ab"), "ssh <robot-host> pw *** ab");
    }
}
