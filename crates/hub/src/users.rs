//! Who is on the other end of the local socket: OS user, groups, admin.

use std::ffi::{CStr, CString};

/// The OS user calling the hub over the local socket.
#[derive(Debug, Clone, PartialEq)]
pub struct Caller {
    pub uid: u32,
    /// user name (the uid as text when it has no passwd entry)
    pub name: String,
    /// names of all groups the user is in
    pub groups: Vec<String>,
    /// root or the user the hub runs as
    pub admin: bool,
}

impl Caller {
    pub fn from_uid(uid: u32) -> Caller {
        let (name, gid) = match passwd_by_uid(uid) {
            Some((n, g)) => (n, Some(g)),
            None => (uid.to_string(), None),
        };
        let groups = gid.map(|g| group_names(&name, g)).unwrap_or_default();
        Caller { uid, name, groups, admin: uid == 0 || uid == euid() }
    }

    /// The user running this process.
    pub fn current() -> Caller {
        Caller::from_uid(euid())
    }

    /// Whether `owner` ("alice" or "@group") names this caller.
    pub fn matches(&self, owner: &str) -> bool {
        match owner.strip_prefix('@') {
            Some(g) => self.groups.iter().any(|x| x == g),
            None => owner == self.name,
        }
    }
}

pub fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Whether `owner` ("alice" or "@group") exists on this system.
pub fn owner_exists(owner: &str) -> bool {
    match owner.strip_prefix('@') {
        Some(g) => group_gid(g).is_some(),
        None => user_exists(owner),
    }
}

const BUF: usize = 16384;

fn passwd_by_uid(uid: u32) -> Option<(String, u32)> {
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; BUF];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid for the call; buf outlives the reads below.
    let r = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if r != 0 || out.is_null() {
        return None;
    }
    let name = unsafe { CStr::from_ptr(pw.pw_name) }.to_string_lossy().into_owned();
    Some((name, pw.pw_gid))
}

fn user_exists(name: &str) -> bool {
    let Ok(c) = CString::new(name) else { return false };
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; BUF];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: as above.
    let r = unsafe { libc::getpwnam_r(c.as_ptr(), &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    r == 0 && !out.is_null()
}

fn group_gid(name: &str) -> Option<u32> {
    let c = CString::new(name).ok()?;
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; BUF];
    let mut out: *mut libc::group = std::ptr::null_mut();
    // SAFETY: as above.
    let r = unsafe { libc::getgrnam_r(c.as_ptr(), &mut gr, buf.as_mut_ptr(), buf.len(), &mut out) };
    (r == 0 && !out.is_null()).then_some(gr.gr_gid)
}

fn group_name(gid: u32) -> Option<String> {
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; BUF];
    let mut out: *mut libc::group = std::ptr::null_mut();
    // SAFETY: as above.
    let r = unsafe { libc::getgrgid_r(gid, &mut gr, buf.as_mut_ptr(), buf.len(), &mut out) };
    if r != 0 || out.is_null() {
        return None;
    }
    Some(unsafe { CStr::from_ptr(gr.gr_name) }.to_string_lossy().into_owned())
}

/// Names of every group `user` is in (primary `gid` included). Looked up
/// on each call so /etc/group changes apply without a restart.
fn group_names(user: &str, gid: u32) -> Vec<String> {
    let mut out: Vec<String> = vec![];
    for g in group_ids(user, gid) {
        if let Some(n) = group_name(g) {
            if !out.contains(&n) {
                out.push(n);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn group_ids(user: &str, gid: u32) -> Vec<u32> {
    let Ok(c) = CString::new(user) else { return vec![gid] };
    let mut n: libc::c_int = 64;
    loop {
        let mut v = vec![0 as libc::gid_t; n as usize];
        let want = n;
        // SAFETY: v has room for `n` gids; getgrouplist writes at most that
        // many and sets `n` to the real count.
        let r = unsafe { libc::getgrouplist(c.as_ptr(), gid, v.as_mut_ptr(), &mut n) };
        if r >= 0 {
            v.truncate(n as usize);
            return v;
        }
        if n <= want {
            n = want * 2; // some libcs don't report the needed size
        }
        if n > 65536 {
            return vec![gid];
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn group_ids(user: &str, gid: u32) -> Vec<u32> {
    let Ok(c) = CString::new(user) else { return vec![gid] };
    let mut n: libc::c_int = 256;
    let mut v = vec![0 as libc::c_int; n as usize];
    // SAFETY: as above (BSD/macOS take and return int gids).
    let r = unsafe { libc::getgrouplist(c.as_ptr(), gid as libc::c_int, v.as_mut_ptr(), &mut n) };
    if r < 0 {
        return vec![gid];
    }
    v.truncate(n.max(0) as usize);
    v.into_iter().map(|g| g as u32).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_known() {
        let c = Caller::from_uid(0);
        assert_eq!(c.name, "root");
        assert!(c.admin);
        assert!(c.matches("root"));
        assert!(!c.matches("@no-such-group-xyz"));
        assert!(owner_exists("root"));
        assert!(!owner_exists("no-such-user-xyz"));
        assert!(!owner_exists("@no-such-group-xyz"));
    }

    #[test]
    fn unknown_uid_falls_back_to_number() {
        let c = Caller::from_uid(3_999_999_999);
        assert_eq!(c.name, "3999999999");
        assert!(c.groups.is_empty());
    }
}
