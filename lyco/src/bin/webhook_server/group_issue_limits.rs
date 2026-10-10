//! Group-member issue submission budget (fail-closed, persistent across bot restarts).
//! All values are based on validated QQ OpenIDs, never user-supplied text.
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::Path;

const WINDOW_SECS: i64 = 24 * 60 * 60;
const COOLDOWN_SECS: i64 = 15 * 60;
const PER_USER_LIMIT: usize = 2;
const GLOBAL_LIMIT: usize = 20;
const MAX_AUDIT_BYTES: u64 = 4 * 1024 * 1024;

fn check_budget(actor: &str, now: i64, existing: &str) -> Result<(), &'static str> {
    if actor.is_empty()
        || actor.len() > 256
        || !actor.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        return Err("无法确认 QQ 发送者身份，拒绝提单");
    }
    let mut all = 0usize;
    let mut user = 0usize;
    let mut last = None::<i64>;
    for line in existing.lines() {
        let Some((stamp, owner)) = line.split_once('\t') else { continue; };
        let Ok(stamp) = stamp.parse::<i64>() else { continue; };
        if stamp > now || now.saturating_sub(stamp) >= WINDOW_SECS { continue; }
        all += 1;
        if owner == actor {
            user += 1;
            last = Some(last.map_or(stamp, |prior| prior.max(stamp)));
        }
    }
    if all >= GLOBAL_LIMIT { return Err("今日群友提单总量已达上限（20 条），请明天再试"); }
    if user >= PER_USER_LIMIT { return Err("你在过去 24 小时已提交 2 次，请稍后再试"); }
    if last.is_some_and(|stamp| now - stamp < COOLDOWN_SECS) {
        return Err("提单太频繁，请间隔至少 15 分钟");
    }
    Ok(())
}

/// Reserve the rate-limit budget before launching AI or GitHub.
/// A failed issue attempt counts against the rate budget to prevent retry storms.
pub(crate) fn reserve(actor: &str, now: i64) -> Result<(), String> {
    let file = std::env::var("GH_ISSUE_AUDIT_FILE")
        .unwrap_or_else(|_| "issue-submissions.log".to_string());
    let path = Path::new(&file);
    let contents = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(err) if err.kind() == ErrorKind::NotFound => String::new(),
        Err(_) => return Err("提单记录不可读取，已安全拒绝写入".into()),
    };
    if contents.len() as u64 >= MAX_AUDIT_BYTES {
        return Err("提单记录需要管理员维护，暂时停止公开提单".into());
    }
    check_budget(actor, now, &contents).map_err(str::to_string)?;
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut out = options.open(path)
        .map_err(|_| "提单记录不可写入，已安全拒绝创建 Issue".to_string())?;
    writeln!(out, "{now}\t{actor}")
        .and_then(|_| out.flush())
        .map_err(|_| "提单记录保存失败，已安全拒绝创建 Issue".to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn first_report_allowed_but_invalid_actor_rejected() {
        assert!(check_budget("USER_abcdef-123", 1_000_000, "").is_ok());
        assert!(check_budget("", 1_000_000, "").is_err());
        assert!(check_budget("bad\nid", 1_000_000, "").is_err());
    }
    #[test]
    fn cooldown_and_two_per_day() {
        let now = 1_000_000;
        assert!(check_budget("A", now, "999800\tA\n").is_err());
        assert!(check_budget("A", now, "997000\tA\n").is_ok());
        assert!(check_budget("A", now, "997000\tA\n996000\tA\n").is_err());
        assert!(check_budget("B", now, "997000\tA\n996000\tA\n").is_ok());
    }
    #[test]
    fn global_quota_and_old_entries() {
        let now = 1_000_000;
        let global = (0..20).map(|n| format!("999000\tuser{n}\n")).collect::<String>();
        assert!(check_budget("new", now, &global).is_err());
        let old = (0..40).map(|n| format!("900000\tuser{n}\n")).collect::<String>();
        assert!(check_budget("new", now, &old).is_ok());
    }
}
