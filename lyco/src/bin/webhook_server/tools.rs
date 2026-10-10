//! 资源调用层：gh cli / 网页抓取 / Minecraft 服务器后台。
//!
//! # 安全基线（对照 botgo issue #61）
//!
//! - **不执行任意命令**：只按白名单拼接固定子命令的参数（如 `gh issue list`），
//!   参数来自用户输入的部分一律作为独立 argv 传入，不经 shell，杜绝命令注入；
//! - **写操作默认关闭**：`gh issue create` 之类的写动作需显式 `GH_WRITE=1`，
//!   避免群成员随意在仓库建 issue/推代码；
//! - **防 SSRF**：网页抓取默认拒绝内网地址（bot 本身就在局域网里，
//!   放任抓取等于把内网服务暴露给群成员）；
//! - **超时 + 截断**：所有外部调用都有超时，返回文本统一截断，不把巨量正文灌进群。

use std::time::Duration;

/// gh 调用配置（`GH_REPO` / `GH_WRITE` / `GH_TIMEOUT_SECS`）。
#[derive(Clone)]
pub struct GhConfig {
    /// 目标仓库 `owner/repo`；为空时沿用 gh 当前目录仓库（bot 通常无仓库上下文）。
    pub repo: String,
    /// 是否允许写操作（建 issue 等）。
    pub write_enabled: bool,
    /// 单次调用超时。
    pub timeout: Duration,
}

/// 网页抓取配置（`WEB_FETCH_ALLOW_PRIVATE` / `WEB_MAX_CHARS`）。
#[derive(Clone)]
pub struct WebConfig {
    /// 是否允许抓取内网地址（默认否）。
    pub allow_private: bool,
    /// 返回文本截断字数。
    pub max_chars: usize,
}

/// Minecraft 后台配置（`MINECRAFT_API_URL`）。
///
/// 按需求「先做兼容」：配了地址就直接查，没配则明确告知未配置，
/// 不假装成功、也不阻塞其它能力。
#[derive(Clone)]
pub struct McConfig {
    /// 后台 HTTP 地址（如 `http://<host>:<port>/status`）。
    pub api_url: String,
}

/// 搜索仓库 issue（只读）。
///
/// 未配置 `GH_REPO` 或 gh 未登录时给出**可操作的提示**而非裸错误。
pub fn gh_issue_search(cfg: &GhConfig, query: &str, limit: u32) -> Result<String, String> {
    let mut args = vec![
        "issue".to_string(),
        "list".to_string(),
        "--search".to_string(),
        query.to_string(),
        "--limit".to_string(),
        limit.to_string(),
    ];
    if !cfg.repo.is_empty() {
        args.push("--repo".to_string());
        args.push(cfg.repo.clone());
    }
    let raw = crate::run_capture("gh", &args, cfg.timeout).map_err(gh_hint)?;
    let text = crate::clean_answer(&raw);
    if text.trim().is_empty() {
        return Ok("没有匹配到相关 issue".to_string());
    }
    Ok(text)
}

/// 创建 issue（写操作，需 [`GhConfig::write_enabled`]）。
pub fn gh_issue_create(cfg: &GhConfig, title: &str, body: &str) -> Result<String, String> {
    if !cfg.write_enabled {
        return Err("gh 写操作未开启（设 GH_WRITE=1 后才允许建 issue）".to_string());
    }
    let mut args = vec![
        "issue".to_string(),
        "create".to_string(),
        "--title".to_string(),
        title.to_string(),
        "--body".to_string(),
        body.to_string(),
    ];
    if !cfg.repo.is_empty() {
        args.push("--repo".to_string());
        args.push(cfg.repo.clone());
    }
    let raw = crate::run_capture("gh", &args, cfg.timeout).map_err(gh_hint)?;
    Ok(crate::clean_answer(&raw))
}

/// 抓取网页正文（去标签 + 取标题 + 截断）。
pub fn web_fetch(agent: &ureq::Agent, cfg: &WebConfig, url: &str) -> Result<String, String> {
    let url = url.trim();
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err("仅支持 http/https 地址".to_string());
    }
    if !cfg.allow_private && is_private_host(url) {
        return Err("拒绝抓取内网地址（防 SSRF；确需放开请设 WEB_FETCH_ALLOW_PRIVATE=1）".to_string());
    }
    let body = crate::http_get_text(agent, url)?;
    let summary = summarize_html(&body);
    Ok(crate::truncate_answer(&summary, cfg.max_chars))
}

/// 查询 Minecraft 服务器后台（`MINECRAFT_API_URL`）。
///
/// 「先做兼容」的三态设计，任何一态都不假装成功：
/// - 未配置 → 明确告知环境变量名；
/// - 配了但连不上（后台没启动是常态）→ 说清「没启动」而不是抛裸网络错误；
/// - 连上 → 把 `{"ok","running","ip"}` 渲染成人话。
pub fn mc_status(agent: &ureq::Agent, cfg: &McConfig) -> Result<String, String> {
    if cfg.api_url.is_empty() {
        return Err(
            "我的世界后台未配置：设置 MINECRAFT_API_URL（如 http://<host>:<port>/api/status）后可用"
                .to_string(),
        );
    }
    match crate::http_get_text(agent, &cfg.api_url) {
        Ok(body) => Ok(render_mc_status(&body)),
        Err(err) => Ok(format!(
            "我的世界后台现在连不上（{}）。\n多半是控制台没启动：在 Radxa 上运行 radxa_console.py 后再查。",
            first_line(&err)
        )),
    }
}

/// 把后台 JSON 渲染成一句话状态；认不出的 JSON 就原样截断返回（不吞内容）。
fn render_mc_status(body: &str) -> String {
    let running = json_scalar(body, "running");
    let ip = json_scalar(body, "ip");
    if running.is_none() && ip.is_none() {
        return crate::truncate_answer(&crate::clean_answer(body), 300);
    }
    let state = match running.as_deref() {
        Some("true") => "运行中",
        Some("false") => "已停止",
        _ => "状态未知",
    };
    let mut out = format!("我的世界服务器：{state}");
    if let Some(ip) = ip.filter(|s| !s.is_empty() && s != "null") {
        out.push_str(&format!("\n地址：{ip}:25565"));
    }
    if json_scalar(body, "ok").as_deref() == Some("false") {
        out.push_str("\n（后台返回 ok=false）");
    }
    out
}

/// 取 JSON 顶层标量字段（`true`/`false`/数字/字符串）。
///
/// 后台只返回三个扁平字段，为此引入完整 JSON 解析器不划算；
/// 解析不出就返回 `None`，由调用方降级为原文展示。
fn json_scalar(json: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\"");
    let at = json.find(&pat)?;
    let rest = json[at + pat.len()..].trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    if let Some(v) = rest.strip_prefix('"') {
        let end = v.find('"')?;
        return Some(v[..end].to_string());
    }
    let end = rest
        .find(|c: char| c == ',' || c == '}' || c == ']' || c.is_whitespace())
        .unwrap_or(rest.len());
    let raw = rest[..end].trim();
    if raw.is_empty() { None } else { Some(raw.to_string()) }
}

/// 错误信息只取第一行：ureq 的错误常带多行上下文，灌进群里很吵。
pub(super) fn first_line(err: &str) -> &str {
    err.split('\n').next().unwrap_or("").trim()
}

/// 把 gh 的失败转成可操作提示（最常见的是没登录）。
fn gh_hint(err: String) -> String {
    let lower = err.to_lowercase();
    if lower.contains("not logged") || lower.contains("auth login") || lower.contains("gh auth") {
        return "gh 未登录：请先在 Radxa 上执行 `gh auth login`（或注入 GH_TOKEN）".to_string();
    }
    if lower.contains("no such file") || lower.contains("not found") && lower.contains("gh") {
        return "gh 不可用：未找到 gh 可执行文件".to_string();
    }
    err
}

/// 是否内网/本机地址（`allow_private` 未开时拒绝）。
fn is_private_host(url: &str) -> bool {
    let host = match url.split_once("://") {
        Some((_, rest)) => rest.split(['/', ':', '?']).next().unwrap_or(""),
        None => return true,
    };
    let host = host.trim_matches(['[', ']']);
    if host == "localhost" || host == "::1" || host.ends_with(".local") {
        return true;
    }
    if host.starts_with("127.") || host.starts_with("10.") || host.starts_with("192.168.") {
        return true;
    }
    // 172.16.0.0 – 172.31.255.255
    if let Some(second) = host.strip_prefix("172.") {
        let octet = second.split('.').next().unwrap_or("").parse::<u8>().ok();
        if matches!(octet, Some(16..=31)) {
            return true;
        }
    }
    false
}

/// 抽取网页可读文本：标题 + 去标签后的正文（压缩空白）。
fn summarize_html(html: &str) -> String {
    let lower = html.to_lowercase();
    let title = lower
        .find("<title")
        .and_then(|start| {
            let from = lower[start..].find('>')? + start + 1;
            let end = lower[from..].find("</title")? + from;
            Some(html[from..end].trim().to_string())
        })
        .unwrap_or_default();

    let mut text = String::new();
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => text.push(c),
            _ => {}
        }
    }
    let text = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if title.is_empty() {
        text
    } else {
        format!("标题：{title}\n{text}")
    }
}

#[cfg(test)]
mod tests {
    use super::{is_private_host, json_scalar, mc_status, render_mc_status, summarize_html};
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// SSRF 防护：局域网与本机一律视为内网。
    #[test]
    fn private_ranges_are_rejected() {
        for url in [
            "http://127.0.0.1:8080/",
            "http://localhost/admin",
            "http://192.168.10.165/",
            "http://10.0.0.5/status",
            "http://172.16.3.4/",
            "http://172.31.255.255/",
        ] {
            assert!(is_private_host(url), "should be private: {url}");
        }
    }

    /// 公网地址不应被误杀（172.32 已超出私网段）。
    #[test]
    fn public_addresses_are_allowed() {
        for url in [
            "https://github.com/",
            "https://lain42.top/healthz",
            "http://172.32.0.1/",
        ] {
            assert!(!is_private_host(url), "should be public: {url}");
        }
    }

    /// MC 状态：把后台 JSON 渲染成人话（已停止 + 地址）。
    #[test]
    fn mc_status_renders_json() {
        let out = render_mc_status(r#"{"ok":true,"running":false,"ip":"192.168.10.165"}"#);
        assert!(out.contains("已停止"), "state missing: {out}");
        assert!(out.contains("192.168.10.165"), "ip missing: {out}");
        assert!(!out.contains("ok=false"), "ok flag misread: {out}");

        let out = render_mc_status(r#"{"ok": true, "running": true, "ip": "10.0.0.7"}"#);
        assert!(out.contains("运行中"), "state missing: {out}");
    }

    /// MC 状态：认不出的 JSON 降级为原文，不吞掉内容。
    #[test]
    fn mc_status_falls_back_to_raw() {
        let out = render_mc_status("<html>后台首页</html>");
        assert!(out.contains("后台首页"), "raw not preserved: {out}");
    }

    /// JSON 标量：三种值类型都要取对。
    #[test]
    fn json_scalar_reads_bool_number_and_string() {
        let json = r#"{"ok":true,"running":false,"ip":"1.2.3.4","port":25565}"#;
        assert_eq!(json_scalar(json, "ok").as_deref(), Some("true"));
        assert_eq!(json_scalar(json, "running").as_deref(), Some("false"));
        assert_eq!(json_scalar(json, "ip").as_deref(), Some("1.2.3.4"));
        assert_eq!(json_scalar(json, "port").as_deref(), Some("25565"));
        assert_eq!(json_scalar(json, "missing"), None);
    }

    /// 起一个最小 HTTP 服务模拟 radxa_console 的 `/api/status`，验证真实请求链路。
    #[test]
    fn mc_status_reads_local_backend() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(1) {
                let mut stream = match stream {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf);
                let body = r#"{"ok":true,"running":true,"ip":"192.168.10.165"}"#;
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.flush();
            }
        });

        let agent = ureq::AgentBuilder::new().build();
        let cfg = super::McConfig {
            api_url: format!("http://127.0.0.1:{port}/api/status"),
        };
        let out = mc_status(&agent, &cfg).expect("mc query should succeed");
        assert!(out.contains("运行中"), "state missing: {out}");
        assert!(out.contains("192.168.10.165"), "ip missing: {out}");
    }

    /// 后台没启动（端口无人监听）时给「连不上」+ 启动指引，而不是裸网络错误。
    #[test]
    fn mc_status_reports_unreachable_backend() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener); // 释放端口 → 后续连接被拒

        let agent = ureq::AgentBuilder::new().build();
        let cfg = super::McConfig {
            api_url: format!("http://127.0.0.1:{port}/api/status"),
        };
        let out = mc_status(&agent, &cfg).expect("unreachable must not be an Err");
        assert!(out.contains("连不上"), "hint missing: {out}");
        assert!(out.contains("radxa_console"), "how-to-start missing: {out}");
    }

    /// HTML 摘要：抽出标题并剥掉标签。
    #[test]
    fn summarize_extracts_title_and_strips_tags() {
        let html = "<html><head><title>卫戍协议</title></head><body><p>你好 世界</p></body></html>";
        let out = summarize_html(html);
        assert!(out.contains("卫戍协议"), "title missing: {out}");
        assert!(out.contains("你好 世界"), "text missing: {out}");
        assert!(!out.contains("<p>"), "tags not stripped: {out}");
    }
}
