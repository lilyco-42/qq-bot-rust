//! Safe CLI adapter for an administrator's own QuarkPan installation.
//! Never run arbitrary chat text in a shell or pass bot credentials to child processes.
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static SAVE_BUSY: AtomicBool = AtomicBool::new(false);
struct BusyGuard;
impl Drop for BusyGuard {
    fn drop(&mut self) { SAVE_BUSY.store(false, Ordering::Release); }
}

fn accepted_url(raw: &str) -> Option<&str> {
    if raw.len() > 180 || raw.chars().any(char::is_whitespace) { return None; }
    let tail = raw.strip_prefix("https://pan.quark.cn/s/")?;
    let (share, query) = tail.split_once('?').unwrap_or((tail, ""));
    if !(5..=64).contains(&share.len()) || !share.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    if !query.is_empty() {
        let code = query.strip_prefix("pwd=")?;
        if !(4..=12).contains(&code.len()) || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return None;
        }
    }
    Some(raw)
}

fn is_authorized(actor: &str, allowed: &str) -> bool {
    !actor.is_empty() && allowed.split(',').map(str::trim).any(|id| !id.is_empty() && id == actor)
}

/// Transfer one shared resource into the bot operator's own Quark drive.
/// Must be explicitly enabled and whitelisted by QQ user OpenID.
pub(crate) fn save_share(raw: &str, actor: &str) -> String {
    if std::env::var("QUARK_SAVE_ENABLED").ok().as_deref() != Some("1") {
        return "夸克转存未启用：管理员需要先配置 CLI、账号和转存权限。".into();
    }
    let allowed = std::env::var("QUARK_SAVE_ALLOWED_OPENIDS").unwrap_or_default();
    if !is_authorized(actor, &allowed) {
        return "仅已授权的 QQ 管理员可以使用夸克转存。".into();
    }
    let Some(url) = accepted_url(raw.trim()) else {
        return "仅接受夸克分享链接：/夸克转存 https://pan.quark.cn/s/分享ID （可带 ?pwd=提取码）".into();
    };
    if SAVE_BUSY.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire).is_err() {
        return "已有网盘转存任务运行，请在它完成后再试。".into();
    }
    let _guard = BusyGuard;
    let cli = std::env::var("QUARKPAN_BIN").unwrap_or_else(|_| "quarkpan".into());
    let folder = std::env::var("QUARK_SAVE_FOLDER").unwrap_or_else(|_| "/来自QQ群/".into());
    if folder.len() > 128 || folder.contains(['\n', '\r', '\0']) || !folder.starts_with('/') {
        return "夸克转存目录配置无效，请联系管理员。".into();
    }
    // No shell, no untrusted folder parameter, and no leaked QQ/NIM/AI API credentials.
    let mut command = Command::new(&cli);
    command
        .args(["save", url, "--folder", &folder, "--save-all", "--wait", "--timeout", "90"])
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .env_clear();
    for key in ["HOME", "PATH", "LANG", "LC_ALL", "XDG_CONFIG_HOME", "APPDATA", "LOCALAPPDATA", "USERPROFILE"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
    let Ok(mut child) = command.spawn() else {
        return "夸克 CLI 未安装或无法启动；请先在 Bot 所在设备安装 QuarkPan 并完成账号登录。".into();
    };
    let started = Instant::now();
    let deadline = Duration::from_secs(105);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    "夸克 CLI 已返回转存成功状态。可到网盘目标文件夹核对文件。".into()
                } else {
                    "夸克转存失败：可能是未登录、链接失效、容量不足或网盘服务拒绝。".into()
                };
            }
            Ok(None) if started.elapsed() < deadline => std::thread::sleep(Duration::from_millis(200)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return "夸克转存已超过 105 秒并被终止；请在网盘确认是否已部分保存。".into();
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return "夸克转存状态查询失败；请检查 Bot 设备上的 CLI。".into();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{accepted_url, is_authorized};
    #[test]
    fn only_whitelisted_qq_openid_is_allowed() {
        assert!(is_authorized("abc123", "def456, abc123"));
        assert!(!is_authorized("abc123", "def456, abc1234"));
        assert!(!is_authorized("", "abc123"));
        assert!(!is_authorized("abc123", ""));
    }
    #[test]
    fn exact_https_quark_share_link_only() {
        assert_eq!(accepted_url("https://pan.quark.cn/s/abc123"), Some("https://pan.quark.cn/s/abc123"));
        assert!(accepted_url("https://pan.quark.cn/s/abc123?pwd=Ab12").is_some());
        for bad in [
            "https://example.com/s/abc123",
            "http://pan.quark.cn/s/abc123",
            "https://pan.quark.cn.evil.test/s/abc123",
            "https://pan.quark.cn/s/abc123;rm -rf",
            "https://pan.quark.cn/s/abc123?url=https://evil.test",
            "https://pan.quark.cn/s/abc123\n--folder /",
            "https://pan.quark.cn/s/",
        ] { assert!(accepted_url(bad).is_none(), "accepted invalid link: {bad}"); }
    }
}
