//! Usage statistics per connection, in hourly buckets kept for 30 days plus
//! lifetime totals. Saved to `stats.json` next to the config so they survive
//! restarts.

use crate::store;
use ccc_proto::Tool;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};

/// How long hourly buckets are kept.
pub const KEEP_HOURS: i64 = 24 * 30;
/// Upper bounds (ms) of the duration histogram bins; the last is open-ended.
pub const LAT_BOUNDS: [u64; 10] = [50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, u64::MAX];

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Outcome {
    Ok,
    Failed,
    /// blocked by a permission (Deny, refused or unanswered approval)
    Refused,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Counts {
    /// agent tool calls (a multi-file push is one call)
    pub calls: u32,
    pub ok: u32,
    pub failed: u32,
    pub refused: u32,
    /// approval pop-ups shown / approved by the owner
    pub asked: u32,
    pub approved: u32,
    /// calls per tool, in `Tool::ALL` order
    pub tools: [u32; 7],
    /// operation durations, binned by `LAT_BOUNDS`
    pub lat: [u32; 10],
    /// bytes server -> machine (push, write) and machine -> server (pull)
    pub up: u64,
    pub down: u64,
    /// availability samples (one per minute while the connector runs)
    pub samples: u32,
    pub online: u32,
}

impl Counts {
    pub fn add(&mut self, o: &Counts) {
        self.calls += o.calls;
        self.ok += o.ok;
        self.failed += o.failed;
        self.refused += o.refused;
        self.asked += o.asked;
        self.approved += o.approved;
        for i in 0..7 {
            self.tools[i] += o.tools[i];
        }
        for i in 0..LAT_BOUNDS.len() {
            self.lat[i] += o.lat[i];
        }
        self.up += o.up;
        self.down += o.down;
        self.samples += o.samples;
        self.online += o.online;
    }

    /// Duration (ms, bin upper bound) below which `q` of operations finished.
    pub fn quantile_ms(&self, q: f64) -> Option<u64> {
        let n: u32 = self.lat.iter().sum();
        if n == 0 {
            return None;
        }
        let want = (q * n as f64).ceil().max(1.0) as u32;
        let mut acc = 0;
        for (i, c) in self.lat.iter().enumerate() {
            acc += c;
            if acc >= want {
                return Some(if i + 1 == LAT_BOUNDS.len() { 60_000 } else { LAT_BOUNDS[i] });
            }
        }
        None
    }

    pub fn success_rate(&self) -> Option<f64> {
        let d = self.ok + self.failed;
        (d > 0).then(|| self.ok as f64 / d as f64)
    }

    pub fn availability(&self) -> Option<f64> {
        (self.samples > 0).then(|| self.online as f64 / self.samples as f64)
    }
}

pub fn tool_index(t: Tool) -> usize {
    Tool::ALL.iter().position(|x| *x == t).unwrap_or(0)
}

/// Where the outcome of a call was counted, so a later failing op of the
/// same call (e.g. a push chunk) can move it from ok to failed.
#[derive(Clone)]
struct CallRec {
    hour: i64,
    machine: String,
    outcome: Outcome,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Stats {
    /// unix hour -> machine -> counts
    pub hours: BTreeMap<i64, BTreeMap<String, Counts>>,
    /// totals since the statistics were last cleared
    pub lifetime: BTreeMap<String, Counts>,
    /// unix seconds of the last request per machine
    pub last_active: BTreeMap<String, i64>,
    #[serde(skip)]
    calls: HashMap<u64, CallRec>,
    #[serde(skip)]
    pub dirty: bool,
}

pub fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

pub fn hour_of(secs: i64) -> i64 {
    secs.div_euclid(3600)
}

fn path() -> std::path::PathBuf {
    store::dir().join("stats.json")
}

impl Stats {
    pub fn load() -> Stats {
        std::fs::read(path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    pub fn save(&mut self) -> anyhow::Result<()> {
        let cutoff = hour_of(now_secs()) - KEEP_HOURS;
        self.hours.retain(|h, _| *h > cutoff);
        std::fs::create_dir_all(store::dir())?;
        let tmp = path().with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(self)?)?;
        std::fs::rename(&tmp, path())?;
        self.dirty = false;
        Ok(())
    }

    pub fn clear(&mut self) {
        self.hours.clear();
        self.lifetime.clear();
        self.last_active.clear();
        self.calls.clear();
        self.dirty = true;
    }

    fn bump(&mut self, hour: i64, machine: &str, f: impl Fn(&mut Counts)) {
        f(self.hours.entry(hour).or_default().entry(machine.to_string()).or_default());
        f(self.lifetime.entry(machine.to_string()).or_default());
        self.dirty = true;
    }

    /// Record one operation. The first op of a call counts the call.
    #[allow(clippy::too_many_arguments)]
    pub fn record(&mut self, machine: &str, tool: Tool, call: u64, outcome: Outcome, ms: Option<u64>, up: u64, down: u64) {
        let now = now_secs();
        let hour = hour_of(now);
        self.last_active.insert(machine.to_string(), now);
        if self.calls.len() > 4096 {
            self.calls.clear();
        }
        match self.calls.get(&call).cloned() {
            None => {
                self.calls.insert(call, CallRec { hour, machine: machine.into(), outcome });
                let ti = tool_index(tool);
                self.bump(hour, machine, |c| {
                    c.calls += 1;
                    c.tools[ti] += 1;
                    match outcome {
                        Outcome::Ok => c.ok += 1,
                        Outcome::Failed => c.failed += 1,
                        Outcome::Refused => c.refused += 1,
                    }
                });
            }
            Some(rec) if rec.outcome == Outcome::Ok && outcome != Outcome::Ok => {
                // a later op of a counted call failed: the call failed
                self.calls.insert(call, CallRec { outcome, ..rec.clone() });
                self.bump(rec.hour, &rec.machine, |c| {
                    c.ok = c.ok.saturating_sub(1);
                    match outcome {
                        Outcome::Failed => c.failed += 1,
                        _ => c.refused += 1,
                    }
                });
            }
            Some(_) => {}
        }
        if ms.is_some() || up > 0 || down > 0 {
            let bin = ms.map(|ms| LAT_BOUNDS.iter().position(|b| ms <= *b).unwrap_or(LAT_BOUNDS.len() - 1));
            self.bump(hour, machine, |c| {
                if let Some(b) = bin {
                    c.lat[b] += 1;
                }
                c.up += up;
                c.down += down;
            });
        }
    }

    pub fn asked(&mut self, machine: &str, approved: bool) {
        let hour = hour_of(now_secs());
        self.bump(hour, machine, |c| {
            c.asked += 1;
            if approved {
                c.approved += 1;
            }
        });
    }

    /// One availability sample (called once a minute per enabled machine).
    pub fn sample(&mut self, machine: &str, online: bool) {
        let hour = hour_of(now_secs());
        self.bump(hour, machine, |c| {
            c.samples += 1;
            if online {
                c.online += 1;
            }
        });
    }

    /// Aggregate for the analytics page.
    pub fn view(&self, range: Range, machine: Option<&str>, now: i64) -> View {
        let (n, bh) = range.buckets();
        let end = hour_of(now) + 1; // exclusive
        let start = end - n * bh;
        let mut buckets = vec![Counts::default(); n as usize];
        let mut prev = Counts::default();
        let mut per: BTreeMap<String, (Counts, Vec<Counts>)> = BTreeMap::new();
        for (h, ms) in self.hours.range(start - n * bh..end) {
            for (m, c) in ms {
                if machine.is_some_and(|x| x != m) {
                    continue;
                }
                if *h < start {
                    prev.add(c);
                    continue;
                }
                let i = ((h - start) / bh) as usize;
                buckets[i].add(c);
                let e = per.entry(m.clone()).or_insert_with(|| (Counts::default(), vec![Counts::default(); n as usize]));
                e.0.add(c);
                e.1[i].add(c);
            }
        }
        let mut total = Counts::default();
        for b in &buckets {
            total.add(b);
        }
        View {
            start_hour: start,
            bucket_hours: bh,
            buckets,
            total,
            prev,
            per_machine: per.into_iter().map(|(m, (t, b))| (m, t, b)).collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Range {
    Day,
    Week,
    Month,
}

impl Range {
    /// (number of buckets, hours per bucket)
    pub fn buckets(self) -> (i64, i64) {
        match self {
            Range::Day => (24, 1),
            Range::Week => (28, 6),
            Range::Month => (30, 24),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Range::Day => "24 hours",
            Range::Week => "7 days",
            Range::Month => "30 days",
        }
    }
}

pub struct View {
    pub start_hour: i64,
    pub bucket_hours: i64,
    pub buckets: Vec<Counts>,
    pub total: Counts,
    /// the period just before this one, for deltas
    pub prev: Counts,
    /// (machine, total, per-bucket)
    pub per_machine: Vec<(String, Counts, Vec<Counts>)>,
}

/// Plausible fake history for previews and tests.
pub fn demo() -> Stats {
    let mut s = Stats::default();
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        (seed % 10_000) as f64 / 10_000.0
    };
    let now = hour_of(now_secs());
    // (name, activity level, tool mix, typical availability)
    let machines: [(&str, f64, [f64; 7], f64); 4] = [
        ("robot", 1.0, [0.45, 0.2, 0.05, 0.08, 0.06, 0.04, 0.12], 0.93),
        ("Fx16", 0.55, [0.35, 0.3, 0.1, 0.12, 0.05, 0.05, 0.03], 1.0),
        ("Fx16_WLS", 0.35, [0.5, 0.2, 0.06, 0.1, 0.04, 0.04, 0.06], 0.99),
        ("lab-pc", 0.12, [0.3, 0.5, 0.0, 0.0, 0.0, 0.2, 0.0], 0.7),
    ];
    for h in (now - KEEP_HOURS + 1)..=now {
        use chrono::{Datelike, Timelike};
        let t = chrono::DateTime::from_timestamp(h * 3600, 0).unwrap_or_default().with_timezone(&chrono::Local);
        let work = if (9..23).contains(&t.hour()) { 1.0 } else { 0.08 };
        let weekend = if t.weekday().number_from_monday() >= 6 { 0.35 } else { 1.0 };
        for (m, level, mix, avail) in machines {
            let mut c = Counts::default();
            let base = 26.0 * level * work * weekend * (0.4 + 1.2 * rnd());
            c.calls = base.round() as u32;
            for (i, w) in mix.iter().enumerate() {
                c.tools[i] = (c.calls as f64 * w * (0.7 + 0.6 * rnd())).round() as u32;
            }
            c.calls = c.tools.iter().sum();
            c.refused = (c.calls as f64 * 0.03 * rnd() * 2.0).round() as u32;
            c.failed = (c.calls as f64 * 0.05 * rnd() * 2.0).round() as u32;
            c.ok = c.calls.saturating_sub(c.refused + c.failed);
            c.asked = (c.calls as f64 * 0.08 * rnd()).round() as u32;
            c.approved = (c.asked as f64 * 0.85).round() as u32;
            for _ in 0..c.calls {
                let r = rnd();
                let bin = if r < 0.35 { 1 } else if r < 0.6 { 2 } else if r < 0.78 { 3 } else if r < 0.9 { 4 } else if r < 0.96 { 6 } else { 8 };
                c.lat[bin] += 1;
            }
            c.up = (c.tools[4] as f64 * 2.0e6 * rnd()) as u64 + c.tools[2] as u64 * 3000;
            c.down = (c.tools[5] as f64 * 1.5e6 * rnd()) as u64;
            c.samples = 60;
            // outages: lab-pc mostly off at night; robot drops for a few hours mid-month
            let down = (m == "lab-pc" && work < 1.0) || (m == "robot" && (300..306).contains(&(now - h)));
            c.online = if down { (60.0 * rnd() * 0.2) as u32 } else { (60.0 * (avail + (1.0 - avail) * rnd())).min(60.0) as u32 };
            if c.calls > 0 {
                s.last_active.insert(m.into(), h * 3600 + 1800);
            }
            s.lifetime.entry(m.into()).or_default().add(&c);
            s.hours.entry(h).or_default().insert(m.into(), c);
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counting_calls() {
        let mut s = Stats::default();
        s.record("m", Tool::Push, 1, Outcome::Ok, Some(30), 100, 0);
        s.record("m", Tool::Push, 1, Outcome::Ok, Some(30), 100, 0);
        s.record("m", Tool::Push, 1, Outcome::Failed, Some(30), 0, 0);
        s.record("m", Tool::Exec, 2, Outcome::Refused, None, 0, 0);
        let v = s.view(Range::Day, None, now_secs());
        assert_eq!(v.total.calls, 2);
        assert_eq!((v.total.ok, v.total.failed, v.total.refused), (0, 1, 1));
        assert_eq!(v.total.up, 200);
        assert_eq!(v.total.tools[tool_index(Tool::Push)], 1);
        assert_eq!(v.total.quantile_ms(0.5), Some(50));
        let d = demo();
        let v = d.view(Range::Week, Some("robot"), now_secs());
        assert_eq!(v.buckets.len(), 28);
        assert_eq!(v.per_machine.len(), 1);
        assert!(v.total.calls > 0 && v.prev.calls > 0);
    }
}
