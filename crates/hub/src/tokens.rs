//! `ccc-hub token ...`: the same rules whether the running hub applies them
//! (for any local user, over the socket) or the admin edits hub.toml
//! directly while the hub is stopped.

use crate::config::{self, can_manage, can_use, HubConfig, Token};
use crate::users::Caller;
use anyhow::{bail, Result};
use ccc_proto::{TokenInfo, TokenReq, TokenResp};

/// Apply `req` for `who`. Returns the answer and whether `cfg` changed (and
/// must be saved). `exists` checks that a user / @group exists.
pub fn apply(cfg: &mut HubConfig, who: &Caller, req: TokenReq, exists: &dyn Fn(&str) -> bool) -> Result<(TokenResp, bool)> {
    match req {
        TokenReq::List => {
            let list = cfg
                .tokens
                .iter()
                .filter(|t| who.admin || can_manage(t, who) || can_use(t, who, false))
                .map(|t| TokenInfo { name: t.name.clone(), owners: t.owners.clone(), created_by: t.created_by.clone(), online: None })
                .collect();
            Ok((TokenResp::List(list), false))
        }
        TokenReq::New { name, owners } => {
            check_owners(&owners, exists)?;
            let (name, mut all) = if who.admin {
                if name.trim().is_empty() {
                    bail!("empty token name");
                }
                (name, vec![])
            } else {
                if !cfg.self_service {
                    bail!("self-service tokens are turned off on this hub; ask its admin for a pairing code");
                }
                let base = name.strip_prefix(&format!("{}:", who.name)).unwrap_or(&name);
                if base.is_empty() || !base.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
                    bail!("token name may use letters, digits, '.', '_' and '-'");
                }
                let mine = cfg.tokens.iter().filter(|t| t.created_by == who.name).count();
                if mine >= cfg.max_tokens_per_user {
                    bail!("you have {mine} tokens, the most this hub allows; revoke one first (`ccc-hub token list`)");
                }
                (format!("{}:{base}", who.name), vec![who.name.clone()])
            };
            if cfg.tokens.iter().any(|t| t.name == name) {
                bail!("token '{name}' exists; use `ccc-hub token pair {name}` to replace it");
            }
            for o in owners {
                if !all.contains(&o) {
                    all.push(o);
                }
            }
            let secret = config::new_token();
            let created_by = if who.admin { String::new() } else { who.name.clone() };
            cfg.tokens.push(Token { name: name.clone(), sha256: config::hash(&secret), owners: all, created_by });
            Ok((TokenResp::Created { name, token: secret, pairing: None, replaced: false }, true))
        }
        TokenReq::Pair { name } => {
            // the admin may pair a name that doesn't exist yet (= new)
            if who.admin && !cfg.tokens.iter().any(|t| t.name == name) {
                return apply(cfg, who, TokenReq::New { name, owners: vec![] }, exists);
            }
            let i = find(cfg, who, &name)?;
            let secret = config::new_token();
            cfg.tokens[i].sha256 = config::hash(&secret);
            let name = cfg.tokens[i].name.clone();
            Ok((TokenResp::Created { name, token: secret, pairing: None, replaced: true }, true))
        }
        TokenReq::Revoke { name } => {
            let i = find(cfg, who, &name)?;
            let t = cfg.tokens.remove(i);
            Ok((TokenResp::Done(format!("token '{}' revoked; connectors using it are disconnected.", t.name)), true))
        }
        TokenReq::Share { name, who: add } => {
            if add.is_empty() {
                bail!("name a user or @group to share with");
            }
            check_owners(&add, exists)?;
            let i = find(cfg, who, &name)?;
            let t = &mut cfg.tokens[i];
            for o in add {
                if !t.owners.contains(&o) {
                    t.owners.push(o);
                }
            }
            Ok((TokenResp::Done(format!("'{}' owners: {}", t.name, owners_text(&t.owners))), true))
        }
        TokenReq::Unshare { name, who: rm } => {
            let i = find(cfg, who, &name)?;
            let t = &mut cfg.tokens[i];
            let missing: Vec<&String> = rm.iter().filter(|o| !t.owners.contains(o)).collect();
            if !missing.is_empty() {
                bail!("not an owner of '{}': {}", t.name, missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "));
            }
            t.owners.retain(|o| !rm.contains(o));
            Ok((TokenResp::Done(format!("'{}' owners: {}", t.name, owners_text(&t.owners))), true))
        }
    }
}

pub fn owners_text(owners: &[String]) -> String {
    if owners.is_empty() {
        "(admin only)".into()
    } else {
        owners.join(", ")
    }
}

fn check_owners(owners: &[String], exists: &dyn Fn(&str) -> bool) -> Result<()> {
    for o in owners {
        if o.is_empty() || o == "@" {
            bail!("empty owner name");
        }
        if !exists(o) {
            match o.strip_prefix('@') {
                Some(g) => bail!("no group '{g}' on this server"),
                None => bail!("no user '{o}' on this server (groups are written @name)"),
            }
        }
    }
    Ok(())
}

/// Index of the token `name` that `who` may manage. A non-admin may leave
/// out their "user:" prefix. Tokens they can't manage are reported as
/// missing, so the answer doesn't tell whether someone else's exists.
fn find(cfg: &HubConfig, who: &Caller, name: &str) -> Result<usize> {
    let mut names = vec![name.to_string()];
    if !who.admin && !name.contains(':') {
        names.insert(0, format!("{}:{name}", who.name));
    }
    for n in &names {
        if let Some(i) = cfg.tokens.iter().position(|t| &t.name == n && can_manage(t, who)) {
            return Ok(i);
        }
    }
    bail!("no token '{name}' that you manage (see `ccc-hub token list`)")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, groups: &[&str]) -> Caller {
        Caller { uid: 1000, name: name.into(), groups: groups.iter().map(|s| s.to_string()).collect(), admin: false }
    }
    fn admin() -> Caller {
        Caller { uid: 0, name: "root".into(), groups: vec!["root".into()], admin: true }
    }
    fn any(_: &str) -> bool {
        true
    }
    fn new(cfg: &mut HubConfig, who: &Caller, name: &str, owners: &[&str]) -> Result<String> {
        let req = TokenReq::New { name: name.into(), owners: owners.iter().map(|s| s.to_string()).collect() };
        match apply(cfg, who, req, &any)?.0 {
            TokenResp::Created { name, .. } => Ok(name),
            r => panic!("{r:?}"),
        }
    }
    fn names(cfg: &mut HubConfig, who: &Caller) -> Vec<String> {
        match apply(cfg, who, TokenReq::List, &any).unwrap().0 {
            TokenResp::List(l) => l.into_iter().map(|t| t.name).collect(),
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn self_service_prefixes_and_owns() {
        let mut cfg = HubConfig::default();
        let alice = user("alice", &[]);
        assert_eq!(new(&mut cfg, &alice, "laptop", &[]).unwrap(), "alice:laptop");
        // her own prefix is accepted too
        assert!(new(&mut cfg, &alice, "alice:laptop", &[]).unwrap_err().to_string().contains("exists"));
        let t = &cfg.tokens[0];
        assert_eq!(t.owners, vec!["alice"]);
        assert_eq!(t.created_by, "alice");
        assert!(new(&mut cfg, &alice, "bad name", &[]).is_err());
        assert!(new(&mut cfg, &alice, "bob:x", &[]).is_err());
    }

    #[test]
    fn admin_tokens_are_admin_only_by_default() {
        let mut cfg = HubConfig::default();
        assert_eq!(new(&mut cfg, &admin(), "lab", &[]).unwrap(), "lab");
        let t = &cfg.tokens[0];
        assert!(t.owners.is_empty() && t.created_by.is_empty());
        assert!(can_use(t, &admin(), false));
        assert!(!can_use(t, &user("alice", &[]), true));
    }

    #[test]
    fn others_cannot_see_or_manage() {
        let mut cfg = HubConfig::default();
        let alice = user("alice", &[]);
        let bob = user("bob", &[]);
        new(&mut cfg, &alice, "laptop", &[]).unwrap();
        assert!(names(&mut cfg, &bob).is_empty());
        for req in [
            TokenReq::Pair { name: "alice:laptop".into() },
            TokenReq::Revoke { name: "alice:laptop".into() },
            TokenReq::Share { name: "alice:laptop".into(), who: vec!["bob".into()] },
        ] {
            let e = apply(&mut cfg, &bob, req, &any).unwrap_err().to_string();
            assert!(e.contains("no token"), "{e}");
        }
        // bob's own "laptop" doesn't clash with alice's
        assert_eq!(new(&mut cfg, &bob, "laptop", &[]).unwrap(), "bob:laptop");
        assert_eq!(names(&mut cfg, &admin()), vec!["alice:laptop", "bob:laptop"]);
    }

    #[test]
    fn share_with_user_and_group() {
        let mut cfg = HubConfig::default();
        let alice = user("alice", &[]);
        new(&mut cfg, &alice, "robot", &["@lab"]).unwrap();
        apply(&mut cfg, &alice, TokenReq::Share { name: "robot".into(), who: vec!["bob".into()] }, &any).unwrap();
        let t = cfg.tokens[0].clone();
        assert_eq!(t.owners, vec!["alice", "@lab", "bob"]);
        assert!(can_use(&t, &user("bob", &[]), false));
        assert!(can_use(&t, &user("carol", &["lab"]), false));
        assert!(!can_use(&t, &user("dave", &["other"]), false));
        // a sharer can use it and sees it, but can't manage it
        let bob = user("bob", &[]);
        assert_eq!(names(&mut cfg, &bob), vec!["alice:robot"]);
        assert!(apply(&mut cfg, &bob, TokenReq::Revoke { name: "alice:robot".into() }, &any).is_err());
        apply(&mut cfg, &alice, TokenReq::Unshare { name: "robot".into(), who: vec!["bob".into()] }, &any).unwrap();
        assert!(!can_use(&cfg.tokens[0], &bob, false));
        assert!(apply(&mut cfg, &alice, TokenReq::Unshare { name: "robot".into(), who: vec!["bob".into()] }, &any).is_err());
    }

    #[test]
    fn root_all_access_switch() {
        let mut cfg = HubConfig::default();
        new(&mut cfg, &user("alice", &[]), "laptop", &[]).unwrap();
        let t = &cfg.tokens[0];
        assert!(can_use(t, &admin(), true));
        assert!(!can_use(t, &admin(), false));
        // the admin still manages it either way
        assert!(can_manage(t, &admin()));
    }

    #[test]
    fn pair_keeps_owners() {
        let mut cfg = HubConfig::default();
        let alice = user("alice", &[]);
        new(&mut cfg, &alice, "laptop", &["bob"]).unwrap();
        let before = cfg.tokens[0].clone();
        let (r, changed) = apply(&mut cfg, &alice, TokenReq::Pair { name: "laptop".into() }, &any).unwrap();
        assert!(changed && matches!(r, TokenResp::Created { replaced: true, .. }));
        assert_ne!(cfg.tokens[0].sha256, before.sha256);
        assert_eq!(cfg.tokens[0].owners, before.owners);
    }

    #[test]
    fn admin_pair_creates_missing() {
        let mut cfg = HubConfig::default();
        let (r, _) = apply(&mut cfg, &admin(), TokenReq::Pair { name: "laptop".into() }, &any).unwrap();
        assert!(matches!(r, TokenResp::Created { replaced: false, .. }));
        assert!(apply(&mut cfg, &user("alice", &[]), TokenReq::Pair { name: "x".into() }, &any).is_err());
    }

    #[test]
    fn limits_and_switches() {
        let mut cfg = HubConfig { max_tokens_per_user: 2, ..Default::default() };
        let alice = user("alice", &[]);
        new(&mut cfg, &alice, "a", &[]).unwrap();
        new(&mut cfg, &alice, "b", &[]).unwrap();
        assert!(new(&mut cfg, &alice, "c", &[]).unwrap_err().to_string().contains("most"));
        cfg.self_service = false;
        assert!(new(&mut cfg, &user("bob", &[]), "x", &[]).unwrap_err().to_string().contains("turned off"));
        // unknown owners are refused
        let none = |_: &str| false;
        let req = TokenReq::New { name: "z".into(), owners: vec!["@nolab".into()] };
        assert!(apply(&mut cfg, &admin(), req, &none).unwrap_err().to_string().contains("no group"));
    }
}
