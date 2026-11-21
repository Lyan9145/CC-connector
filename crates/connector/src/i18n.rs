//! Translations of the desktop window.
//!
//! The English text is the key: `tr("Save")` looks it up in the current
//! language's table and falls back to the English text. Text with values in
//! it uses named placeholders, so translations can reorder them:
//! `tf!("Allow {tool} for 15 min", tool = name)`.
//!
//! Each language is one file in `i18n/` holding `(English, translation)`
//! pairs. The `complete` test lists every `tr(...)` / `tf!(...)` text in the
//! GUI sources and fails when a table misses one, has a stale one, or
//! changes the placeholders.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

mod de;
mod es;
mod fr;
mod ja;
mod ko;
mod pt_br;
mod ru;
mod zh_cn;
mod zh_tw;

type Table = &'static [(&'static str, &'static str)];

pub struct Lang {
    /// BCP 47 code saved in the config
    pub code: &'static str,
    /// the language's own name, for the picker
    pub name: &'static str,
    table: Table,
}

pub const LANGS: &[Lang] = &[
    Lang { code: "en", name: "English", table: &[] },
    Lang { code: "zh-CN", name: "简体中文", table: zh_cn::T },
    Lang { code: "zh-TW", name: "繁體中文", table: zh_tw::T },
    Lang { code: "ja", name: "日本語", table: ja::T },
    Lang { code: "ko", name: "한국어", table: ko::T },
    Lang { code: "es", name: "Español", table: es::T },
    Lang { code: "fr", name: "Français", table: fr::T },
    Lang { code: "de", name: "Deutsch", table: de::T },
    Lang { code: "pt-BR", name: "Português (Brasil)", table: pt_br::T },
    Lang { code: "ru", name: "Русский", table: ru::T },
];

static CUR: AtomicUsize = AtomicUsize::new(0);

fn maps() -> &'static [HashMap<&'static str, &'static str>] {
    static M: OnceLock<Vec<HashMap<&'static str, &'static str>>> = OnceLock::new();
    M.get_or_init(|| LANGS.iter().map(|l| l.table.iter().copied().collect()).collect())
}

/// Index into `LANGS` for a saved or OS language code; None if unsupported.
fn find(code: &str) -> Option<usize> {
    let c = code.trim().replace('_', "-").to_ascii_lowercase();
    let c = c.split(['.', '@']).next().unwrap_or("");
    if c.is_empty() {
        return None;
    }
    if let Some(i) = LANGS.iter().position(|l| l.code.eq_ignore_ascii_case(c)) {
        return Some(i);
    }
    let base = c.split('-').next().unwrap_or("");
    let code = match base {
        // Traditional script: Taiwan, Hong Kong, Macau, or an explicit "Hant"
        "zh" if c.contains("hant") || c.ends_with("-tw") || c.ends_with("-hk") || c.ends_with("-mo") => "zh-TW",
        "zh" => "zh-CN",
        "pt" => "pt-BR",
        b => b,
    };
    LANGS.iter().position(|l| l.code.eq_ignore_ascii_case(code))
}

/// The OS language, if it is one of ours (else English).
pub fn system() -> &'static Lang {
    let loc = sys_locale::get_locale().unwrap_or_default();
    &LANGS[find(&loc).unwrap_or(0)]
}

/// Use `code` ("" = follow the OS).
pub fn set(code: &str) {
    let i = if code.is_empty() { find(system().code) } else { find(code) };
    CUR.store(i.unwrap_or(0), Ordering::Relaxed);
}

pub fn current() -> &'static Lang {
    &LANGS[CUR.load(Ordering::Relaxed).min(LANGS.len() - 1)]
}

/// `s` in the current language (`s` itself when there is no translation).
pub fn tr(s: &str) -> &str {
    tr_in(CUR.load(Ordering::Relaxed), s)
}

fn tr_in(lang: usize, s: &str) -> &str {
    match lang {
        0 => s,
        i => maps().get(i).and_then(|m| m.get(s).copied()).unwrap_or(s),
    }
}

/// Translate a template and fill in its `{name}` placeholders.
macro_rules! tf {
    ($s:literal $(, $k:ident = $v:expr)* $(,)?) => {{
        #[allow(unused_mut)]
        let mut s = $crate::i18n::tr($s).to_string();
        $( s = s.replace(concat!("{", stringify!($k), "}"), &$v.to_string()); )*
        s
    }};
}
pub(crate) use tf;

/// Status words the runtime reports; translated at the front of a status.
pub const STATUS_WORDS: [&str; 8] = ["online", "connecting", "connected", "disconnected", "starting", "disabled", "paused", "error"];

/// A runtime status like "online" or "error: connection lost": the leading
/// word translated, details (from the system) kept as they are.
pub fn status(s: &str) -> String {
    status_in(CUR.load(Ordering::Relaxed), s)
}

fn status_in(lang: usize, s: &str) -> String {
    for w in STATUS_WORDS {
        if let Some(rest) = s.strip_prefix(w) {
            if rest.is_empty() || rest.starts_with([':', ' ']) {
                return format!("{}{rest}", tr_in(lang, w));
            }
        }
    }
    s.to_string()
}

/// What happened to a flagged request (set by the runtime in English).
#[cfg_attr(not(test), allow(dead_code))]
pub const OUTCOMES: [&str; 6] = ["blocked", "allowed", "refused (no window open to ask)", "not approved in time", "refused by you", "approved by you"];

/// Font files with CJK glyphs to fall back on, best first: the faces for the
/// current language, then Korean (Chinese and Japanese fonts lack Hangul),
/// then Chinese (for the language picker). `CCC_FONT=path[#face]` comes first.
pub fn cjk_fonts() -> Vec<(PathBuf, u32)> {
    let code = current().code;
    // (Windows file, macOS path, Noto CJK collection face)
    let han_sc: &[&str] = &["msyh.ttc", "simhei.ttf", "simsun.ttc"];
    let han_tc: &[&str] = &["msjh.ttc", "mingliu.ttc"];
    let han_jp: &[&str] = &["YuGothM.ttc", "meiryo.ttc", "msgothic.ttc"];
    let hangul: &[&str] = &["malgun.ttf", "gulim.ttc"];
    let mac_sc: &[&str] = &["/System/Library/Fonts/Hiragino Sans GB.ttc", "/System/Library/Fonts/STHeiti Light.ttc", "/System/Library/Fonts/PingFang.ttc"];
    let mac_tc: &[&str] = &["/System/Library/Fonts/STHeiti Light.ttc"];
    let mac_jp: &[&str] = &["/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc", "/System/Library/Fonts/Hiragino Sans GB.ttc"];
    let mac_kr: &[&str] = &["/System/Library/Fonts/AppleSDGothicNeo.ttc", "/System/Library/Fonts/Supplemental/AppleGothic.ttf"];
    let mac_all: &[&str] = &["/System/Library/Fonts/Supplemental/Arial Unicode.ttf", "/Library/Fonts/Arial Unicode.ttf"];
    // faces in NotoSansCJK-Regular.ttc: JP, KR, SC, TC
    let (sc, tc, jp, kr) = ((han_sc, mac_sc, 2u32, "sc"), (han_tc, mac_tc, 3, "tc"), (han_jp, mac_jp, 0, "jp"), (hangul, mac_kr, 1, "kr"));
    let order = match code {
        "zh-TW" => vec![tc, sc, kr],
        "ja" => vec![jp, sc, kr],
        "ko" => vec![kr, sc],
        _ => vec![sc, kr],
    };
    let mut out: Vec<(PathBuf, u32)> = vec![];
    let mut push = |p: PathBuf, face: u32| {
        if !out.iter().any(|(q, _)| *q == p) {
            out.push((p, face));
        }
    };
    if let Ok(v) = std::env::var("CCC_FONT") {
        let (p, face) = match v.rsplit_once('#') {
            Some((p, f)) if f.parse::<u32>().is_ok() => (p.to_string(), f.parse().unwrap_or(0)),
            _ => (v.clone(), 0),
        };
        push(PathBuf::from(p), face);
    }
    let windir = std::env::var("WINDIR").or_else(|_| std::env::var("SystemRoot")).unwrap_or_else(|_| r"C:\Windows".into());
    for (win, mac, noto, short) in order {
        // first existing file of this group
        let mut group: Vec<(PathBuf, u32)> = vec![];
        if cfg!(windows) {
            group.extend(win.iter().map(|f| (PathBuf::from(&windir).join("Fonts").join(f), 0)));
        } else if cfg!(target_os = "macos") {
            group.extend(mac.iter().chain(mac_all).map(|f| (PathBuf::from(f), 0)));
        } else {
            for d in ["/usr/share/fonts/opentype/noto", "/usr/share/fonts/noto-cjk", "/usr/share/fonts/google-noto-cjk", "/usr/share/fonts/noto"] {
                group.push((PathBuf::from(d).join("NotoSansCJK-Regular.ttc"), noto));
                group.push((PathBuf::from(d).join(format!("NotoSansCJK{short}-Regular.otf")), 0));
            }
            if short == "kr" {
                group.push(("/usr/share/fonts/truetype/nanum/NanumGothic.ttf".into(), 0));
            } else {
                group.push(("/usr/share/fonts/truetype/wqy/wqy-microhei.ttc".into(), 0));
                group.push(("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc".into(), 0));
            }
            group.push(("/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf".into(), 0));
        }
        if let Some((p, f)) = group.into_iter().find(|(p, _)| p.is_file()) {
            push(p, f);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Undo Rust string escapes (as written in the sources).
    fn unescape(s: &str) -> String {
        let mut out = String::new();
        let mut it = s.chars().peekable();
        while let Some(c) = it.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match it.next() {
                Some('n') => out.push('\n'),
                Some('t') => out.push('\t'),
                Some('"') => out.push('"'),
                Some('\'') => out.push('\''),
                Some('\\') => out.push('\\'),
                Some('\n') => {
                    while it.peek().is_some_and(|c| c.is_whitespace()) {
                        it.next();
                    }
                }
                Some(o) => panic!("unexpected escape \\{o}"),
                None => {}
            }
        }
        out
    }

    /// Every text that the window passes through `tr` / `tf!`.
    fn keys() -> BTreeSet<String> {
        let re = regex::Regex::new(r#"(?s)\b(?:tr\(|tf!\(\s*)"((?:[^"\\]|\\.)*)""#).unwrap();
        let mut k = BTreeSet::new();
        for src in [include_str!("gui.rs"), include_str!("analytics.rs")] {
            // Windows checkouts may have CRLF line ends
            let src = src.replace("\r\n", "\n");
            for c in re.captures_iter(&src) {
                k.insert(unescape(&c[1]));
            }
        }
        // labels defined elsewhere, translated where they are shown
        k.extend(STATUS_WORDS.iter().chain(&OUTCOMES).map(|s| s.to_string()));
        k.extend(crate::store::Perm::ALL.iter().map(|p| p.label().to_string()));
        k.extend(crate::store::FolderAccess::ALL.iter().map(|a| a.label().to_string()));
        k.extend(crate::store::FilterAction::ALL.iter().map(|a| a.label().to_string()));
        k.extend(crate::store::PRESETS.iter().map(|p| p.1.to_string()));
        k.extend(crate::filters::Scope::ALL.iter().map(|s| s.label().to_string()));
        k.extend(crate::filters::BUILTIN.iter().flat_map(|b| [b.name.to_string(), b.why.to_string()]));
        k.extend([crate::stats::Range::Day, crate::stats::Range::Week, crate::stats::Range::Month].iter().map(|r| r.label().to_string()));
        k
    }

    fn placeholders(s: &str) -> BTreeSet<String> {
        regex::Regex::new(r"\{[a-z_]+\}").unwrap().find_iter(s).map(|m| m.as_str().to_string()).collect()
    }

    #[test]
    fn complete() {
        let keys = keys();
        assert!(keys.len() > 300, "found only {} texts", keys.len());
        let mut problems = vec![];
        for l in &LANGS[1..] {
            let mut seen = BTreeSet::new();
            for (en, t) in l.table {
                if !seen.insert(*en) {
                    problems.push(format!("{}: duplicate {en:?}", l.code));
                }
                if !keys.contains(*en) {
                    problems.push(format!("{}: not used any more {en:?}", l.code));
                }
                // a translation may leave out a value (when the grammar needs it), not add one
                if !placeholders(t).is_subset(&placeholders(en)) {
                    problems.push(format!("{}: unknown placeholder in {en:?} -> {t:?}", l.code));
                }
                if en.starts_with('%') && chrono::format::StrftimeItems::new(t).any(|i| i == chrono::format::Item::Error) {
                    problems.push(format!("{}: bad date format {t:?}", l.code));
                }
                if t.trim().is_empty() {
                    problems.push(format!("{}: empty translation of {en:?}", l.code));
                }
            }
            for k in &keys {
                if !seen.contains(k.as_str()) {
                    problems.push(format!("{}: missing {k:?}", l.code));
                }
            }
        }
        assert!(problems.is_empty(), "{} problems:\n{}", problems.len(), problems.join("\n"));
    }

    #[test]
    fn codes() {
        assert_eq!(find("zh_CN.UTF-8").map(|i| LANGS[i].code), Some("zh-CN"));
        assert_eq!(find("zh-Hans-CN").map(|i| LANGS[i].code), Some("zh-CN"));
        assert_eq!(find("zh-Hant-TW").map(|i| LANGS[i].code), Some("zh-TW"));
        assert_eq!(find("zh-HK").map(|i| LANGS[i].code), Some("zh-TW"));
        assert_eq!(find("pt-PT").map(|i| LANGS[i].code), Some("pt-BR"));
        assert_eq!(find("de-AT").map(|i| LANGS[i].code), Some("de"));
        assert_eq!(find("en-US").map(|i| LANGS[i].code), Some("en"));
        assert_eq!(find("C"), None);
        assert_eq!(find("xx"), None);
    }

    #[test]
    fn status_words() {
        let de = find("de").unwrap();
        assert_eq!(status_in(de, "error: connection lost"), format!("{}: connection lost", tr_in(de, "error")));
        assert_eq!(status_in(de, "connected (TLS)"), format!("{} (TLS)", tr_in(de, "connected")));
        assert_ne!(tr_in(de, "connected"), "connected");
        assert_eq!(status_in(de, "whatever"), "whatever");
        assert_eq!(status_in(de, "onlineish"), "onlineish");
    }
}
