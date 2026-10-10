//! 指令分发：消息正文 → 回复正文（纯函数，无 IO、无全局状态）。
//!
//! 新增指令 = 在 [`dispatch`] 的 match 加一个臂 + 一行帮助文案；
//! 时间与随机数由调用方注入（[`Clock`]/随机 u64），保证可测且无隐式
//! 全局状态（反模式④）。

use crate::error::Result;
use alloc::format;
use alloc::string::{String, ToString};

/// 时间源：注入 unix 秒，库内不读时钟。
pub type Clock = i64;

/// 指令匹配结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// 需要回复的文本。
    Text(String),
    /// 需要 AI 问答的正文（非 `/` 指令的普通消息，问题原样携带）。
    Ask(String),
    /// 需要查询服务器状态（对局/等待），由调用方发起网络请求。
    ///
    /// 分发层保持纯函数（无 IO）：只声明意图，实际请求在接收端完成，
    /// 与 [`Reply::Ask`] 同一模式。
    ServerStatus,
    /// 需要查询组队大厅房间列表（等待中的房间），由调用方发起网络请求。
    ///
    /// 与 [`Reply::ServerStatus`] 同一模式：分发层无 IO，只声明意图；
    /// 实际请求（需机器人专用账号登录）在接收端完成。
    LobbyRooms,
    /// 需要「记住」的内容（`/记`）：由调用方写入记忆库（重要事实，重要度高）。
    Remember(String),
    /// 需要「回忆」的关键词（`/忆`）：由调用方检索记忆库。
    ///
    /// 空串表示不带关键词——回忆该作用域下最重要的若干条（概览）。
    Recall(String),
    /// 需要查询「是否有人问过同类问题」（`/issue`）：由调用方先查本地记忆，
    /// 再用 gh cli 搜仓库 issue，两者合并成文。
    IssueSearch(String),
    /// 需要创建一条 issue（`/提单 <标题>`）：**写操作**，是否放行由接收端的
    /// `GH_WRITE` 决定（默认关闭，避免群成员随意在仓库建单）。
    IssueCreate(String),
    /// 需要展示当前群默认话题（`/话题`）。
    Topic,
    /// 需要抓取网页正文（`/网站 <url>`）。
    WebFetch(String),
    /// 需要查询我的世界服务器后台（`/mc`）。
    Minecraft,
    /// 需要展示构建版本与运行时长（`/版本`）。
    Version,
    /// 只读查询客户端仓库最新 Release（区别于机器人自身版本）。
    ClientRelease,
    /// 需要逐条接缝体检（`/自检`）：记忆库 / 问答后端 / gh / 网页 / MC。
    ///
    /// 与其它意图同样只声明：真正的探测在接收端（无 IO 是这一层的契约）。
    SelfCheck,
    /// 不需要回复（如空内容、无法构成回复的输入）。
    Skip,
}

/// 分发一条消息正文，产出回复。
///
/// - 空/纯空白正文 → [`Reply::Skip`]（媒体消息等无文本场景，无话可回）；
/// - `/` 前缀 → 指令；未知 `/xxx` → 短提示（显式回应，不是吞错；
///   避免机器人装死）；
/// - 其余正文 → [`Reply::Ask`]，由调用方路由到 AI 问答（零栈单次问答）；
/// - `clock`/`random` 为调用方注入的时钟与随机源，库内无全局状态。
pub fn dispatch(content: &str, clock: Clock, random: u64) -> Result<Reply> {
    let text = content.trim();
    if text.is_empty() {
        return Ok(Reply::Skip);
    }
    // 指令必须以 `/` 开头；无前缀的普通消息交给 AI 问答。
    let Some(after_slash) = text.strip_prefix('/') else {
        if text.contains("客户端") && (text.contains("最新版本") || text.contains("版本号")) {
            return Ok(Reply::ClientRelease);
        }
        return Ok(Reply::Ask(text.to_string()));
    };
    // 指令 = 斜杠后首个空白分隔 token。
    let (head, rest) = match after_slash.find(char::is_whitespace) {
        Some(idx) => (&after_slash[..idx], after_slash[idx..].trim()),
        None => (after_slash, ""),
    };
    let reply = match head {
        "帮助" | "help" | "?" | "？" => Reply::Text(help_text()),
        "关于" | "about" => Reply::Text(about_text()),
        "时间" | "time" => Reply::Text(format_time(clock)),
        "随机" | "random" => Reply::Text(random_reply(rest, random)),
        "复读" | "echo" => Reply::Text(echo_reply(rest)),
        // 服务器对局/等待状态：声明意图，网络请求在接收端完成。
        "对局" | "状态" | "服务器" | "status" | "server" => Reply::ServerStatus,
        // 组队大厅房间列表（等待中的房间）：需机器人专用账号，请求在接收端完成。
        "房间" | "组队" | "大厅" | "rooms" | "lobby" => Reply::LobbyRooms,
        // 记忆：写入/检索持久化记忆库（接收端完成；未启用 memory 时给出提示）。
        "记" | "记住" | "remember" => remember_reply(rest),
        // 回忆：空关键词 = 概览（该作用域下最重要的若干条），故不判空。
        "忆" | "回忆" | "recall" => Reply::Recall(rest.to_string()),
        // 同类 issue 检索：本地记忆 + gh cli 搜仓库，接收端合并成文。
        "issue" | "问题" | "问过" | "issues" => issue_reply(rest),
        // 建 issue（写操作）：意图同样只声明，能否执行由接收端 GH_WRITE 决定。
        "提单" | "建单" | "newissue" => issue_create_reply(rest),
        // 群默认话题。
        "话题" | "topic" => Reply::Topic,
        // 网页抓取与我的世界后台（资源调用；接收端完成，未配置时明确提示）。
        "网站" | "web" | "抓" => web_reply(rest),
        "mc" | "我的世界" | "minecraft" => Reply::Minecraft,
        // 运维自省：版本与体检（排障入口，不要求群成员懂服务器）。
        "版本" | "version" => Reply::Version,
        "客户端版本" | "最新版本" | "clientversion" => Reply::ClientRelease,
        "自检" | "体检" | "健康" | "selfcheck" | "health" => Reply::SelfCheck,
        _ => Reply::Text(String::from("未识别指令。发送「/帮助」查看可用指令")),
    };
    Ok(reply)
}

/// 帮助文案。
fn help_text() -> String {
    String::from(
        "可用指令：\n\
         /帮助 — 显示本列表\n\
         /时间 — 当前时间（UTC+8）\n\
         /随机 [n] — 1..=n 随机数（默认 100）\n\
         /复读 <文本> — 原样返回（≤140 字）\n\
         /对局 — 服务器对局/等待状态\n\
         /房间 — 组队大厅等待中的房间\n\
         /记 <内容> — 记下重要信息（会强化、不易忘）\n\
         /忆 [关键词] — 回忆（不带词=重要记忆概览）\n\
         /issue <关键词> — 查是否有人问过（记忆+仓库 issue）\n\
         /提单 <标题> — 在仓库建一条 issue（需开启 GH_WRITE）\n\
         /话题 — 当前群默认话题\n\
         /网站 <url> — 抓取网页正文\n\
         /mc — 我的世界服务器状态\n\
         /版本 — 构建版本与运行时长\n\
         /客户端版本 — 查询 GitHub 客户端仓库最新 Release\n\
         /自检 — 各接缝体检（记忆/问答/gh/网页/MC）\n\
         /关于 — 版本信息\n\
         直接发文字可向 AI 提问",
    )
}

/// 关于文案。
fn about_text() -> String {
    format!(
        "qq_bot_rust v{} · no_std + wtx · webhook",
        env!("CARGO_PKG_VERSION")
    )
}

/// 时间文案：unix 秒 → UTC+8 民用时间。
///
/// 不引 chrono：平台只需展示，自实现儒略日换算（无依赖、no_std）。
fn format_time(clock: Clock) -> String {
    // UTC+8 固定偏移。
    let shifted = clock + 8 * 3600;
    let days = shifted.div_euclid(86_400);
    let secs = shifted.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (secs / 3600, (secs / 60) % 60, secs % 60);
    format!("当前时间 {year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} (UTC+8)")
}

/// Howard Hinnant `civil_from_days`：1970-01-01 起的天数 → 年月日。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 随机数文案：`随机 [n]` → 1..=n。
///
/// 参数非正整数 → 用法提示（用户输入错误不是库错误，显式回应而非吞掉）。
fn random_reply(arg: &str, random: u64) -> String {
    let upper: u64 = match arg {
        "" => 100,
        other => match other.parse::<u64>() {
            Ok(n) => n.clamp(1, 1_000_000),
            Err(_) => return String::from("用法：随机 [n]，n 为 1..=1000000 的整数"),
        },
    };
    // 调用方注入的随机源取模；上限收敛防滥用。
    let value = random % upper + 1;
    format!("随机数（1..={upper}）：{value}")
}

/// 复读：缺参数给用法，非空截断到 140 字（平台单条文本上限内）。
fn echo_reply(arg: &str) -> String {
    if arg.is_empty() {
        return String::from("用法：复读 <文本>");
    }
    arg.chars().take(140).collect()
}

/// `/记`：缺参数给用法，否则声明「写入记忆」意图（内容保守截断）。
fn remember_reply(arg: &str) -> Reply {
    if arg.is_empty() {
        return Reply::Text(String::from("用法：/记 <要记住的内容>"));
    }
    Reply::Remember(arg.chars().take(500).collect())
}

/// `/issue`：缺参数给用法，否则声明「同类 issue 检索」意图。
fn issue_reply(arg: &str) -> Reply {
    if arg.is_empty() {
        return Reply::Text(String::from(
            "用法：/issue <关键词> — 查是否有人问过（本地记忆 + 仓库 issue）",
        ));
    }
    Reply::IssueSearch(arg.chars().take(200).collect())
}

/// `/提单`：缺参数给用法，否则声明「创建 issue」意图（写操作）。
fn issue_create_reply(arg: &str) -> Reply {
    if arg.is_empty() {
        return Reply::Text(String::from(
            "用法：/提单 <标题> — 在仓库建一条 issue（需 GH_WRITE=1）",
        ));
    }
    Reply::IssueCreate(arg.chars().take(200).collect())
}

/// `/网站`：缺参数或非 http(s) 地址给用法，否则声明「抓取网页」意图。
fn web_reply(arg: &str) -> Reply {
    let url = arg.trim();
    if url.is_empty() {
        return Reply::Text(String::from("用法：/网站 <http(s) 地址>"));
    }
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Reply::Text(String::from("用法：/网站 <http(s) 地址>（仅支持 http/https）"));
    }
    Reply::WebFetch(String::from(url))
}

#[cfg(test)]
mod tests {
    use super::{Reply, dispatch};

    /// 2026-10-09 00:22:29 (UTC+8)（Radxa 抓取事件的时间戳）。
    const SAMPLE_UNIX: i64 = 1_791_476_549;

    #[test]
    fn empty_content_is_skipped() {
        assert_eq!(dispatch("", 0, 0).unwrap(), Reply::Skip);
        assert_eq!(dispatch("   \n\t ", 0, 0).unwrap(), Reply::Skip);
    }

    #[test]
    fn help_commands_reply_with_listing() {
        for input in ["/帮助", "/help", "/?", "/？", "  /帮助  "] {
            let Reply::Text(text) = dispatch(input, 0, 0).unwrap() else {
                panic!("帮助 must reply: {input}");
            };
            assert!(text.contains("可用指令"), "listing missing: {text}");
            assert!(text.contains("/复读"), "command missing: {text}");
        }
    }

    #[test]
    fn time_reports_utc8_from_injected_clock() {
        let Reply::Text(text) = dispatch("/时间", SAMPLE_UNIX, 0).unwrap() else {
            panic!("时间 must reply");
        };
        assert_eq!(text, "当前时间 2026-10-09 00:22:29 (UTC+8)");
        // 零点基准：unix 0 → 1970-01-01 08:00:00 (UTC+8)。
        let Reply::Text(text) = dispatch("/time", 0, 0).unwrap() else {
            panic!("time must reply");
        };
        assert_eq!(text, "当前时间 1970-01-01 08:00:00 (UTC+8)");
    }

    #[test]
    fn random_uses_injected_source_and_bounds() {
        // random=7, n=10 → 7 % 10 + 1 = 8。
        let Reply::Text(text) = dispatch("/随机 10", 0, 7).unwrap() else {
            panic!("随机 must reply");
        };
        assert_eq!(text, "随机数（1..=10）：8");
        // 缺省 n=100。
        let Reply::Text(text) = dispatch("/随机", 0, 7).unwrap() else {
            panic!("随机 must reply");
        };
        assert_eq!(text, "随机数（1..=100）：8");
        // 非整数参数 → 用法提示（显式回应）。
        let Reply::Text(text) = dispatch("/随机 abc", 0, 7).unwrap() else {
            panic!("随机 abc must reply");
        };
        assert!(text.contains("用法"), "usage hint missing: {text}");
        // 越界参数收敛。
        let Reply::Text(text) = dispatch("/随机 0", 0, 7).unwrap() else {
            panic!("随机 0 must reply");
        };
        assert_eq!(text, "随机数（1..=1）：1");
    }

    #[test]
    fn echo_returns_text_verbatim_and_truncates() {
        let Reply::Text(text) = dispatch("/复读 hello world", 0, 0).unwrap() else {
            panic!("复读 must reply");
        };
        assert_eq!(text, "hello world");
        // 缺参数 → 用法。
        let Reply::Text(text) = dispatch("/复读", 0, 0).unwrap() else {
            panic!("复读 must reply");
        };
        assert_eq!(text, "用法：复读 <文本>");
        // 超长截断到 140 字。
        let long = "字".repeat(200);
        let input = format!("/复读 {long}");
        let Reply::Text(text) = dispatch(&input, 0, 0).unwrap() else {
            panic!("复读 must reply");
        };
        assert_eq!(text.chars().count(), 140);
    }

    #[test]
    fn about_and_unknown_are_explicit_replies() {
        let Reply::Text(text) = dispatch("/关于", 0, 0).unwrap() else {
            panic!("关于 must reply");
        };
        assert!(text.contains("qq_bot_rust"), "version missing: {text}");
        // 未知斜杠指令不装死：给出提示。
        let Reply::Text(text) = dispatch("/123", 0, 0).unwrap() else {
            panic!("unknown command must not be silent");
        };
        assert!(text.contains("/帮助"), "hint missing: {text}");
        // 裸斜杠（无指令名）同样提示。
        let Reply::Text(text) = dispatch("/", 0, 0).unwrap() else {
            panic!("bare slash must not be silent");
        };
        assert!(text.contains("/帮助"), "hint missing: {text}");
    }

    #[test]
    fn status_command_declares_server_query() {
        // `/对局` 及其别名 → ServerStatus（由接收端发起网络请求）。
        for input in [
            "/对局",
            "/状态",
            "/服务器",
            "/status",
            "/server",
            "  /对局  ",
        ] {
            assert_eq!(
                dispatch(input, 0, 0).unwrap(),
                Reply::ServerStatus,
                "input={input}"
            );
        }
        // 帮助里列出该指令。
        let Reply::Text(text) = dispatch("/帮助", 0, 0).unwrap() else {
            panic!("帮助 must reply");
        };
        assert!(text.contains("/对局"), "help missing /对局: {text}");
    }

    #[test]
    fn lobby_command_declares_room_query() {
        // `/房间` 及别名 → LobbyRooms（由接收端带账号登录取房间列表）。
        for input in ["/房间", "/组队", "/大厅", "/rooms", "/lobby", "  /房间  "] {
            assert_eq!(
                dispatch(input, 0, 0).unwrap(),
                Reply::LobbyRooms,
                "input={input}"
            );
        }
        // 帮助里列出该指令。
        let Reply::Text(text) = dispatch("/帮助", 0, 0).unwrap() else {
            panic!("帮助 must reply");
        };
        assert!(text.contains("/房间"), "help missing /房间: {text}");
    }

    #[test]
    fn client_version_query_uses_readonly_intent() {
        assert_eq!(dispatch("/客户端版本", 0, 0).unwrap(), Reply::ClientRelease);
        assert_eq!(dispatch("手机客户端最新版本是什么", 0, 0).unwrap(), Reply::ClientRelease);
        assert!(matches!(dispatch("客户端怎么安装", 0, 0).unwrap(), Reply::Ask(_)));
    }

    #[test]
    fn plain_text_routes_to_ai_ask() {
        // 无 `/` 前缀 → Ask，问题原样（trim 后）携带。
        for input in [
            "你好，这是什么群？",
            "Rust 的所有权怎么理解",
            "  今天天气  ",
        ] {
            let Reply::Ask(question) = dispatch(input, 0, 0).unwrap() else {
                panic!("plain text must route to Ask: {input}");
            };
            assert_eq!(question, input.trim());
        }
        // 非指令的纯数字/英文同样进问答。
        assert!(matches!(dispatch("123", 0, 0).unwrap(), Reply::Ask(_)));
        assert!(matches!(dispatch("help", 0, 0).unwrap(), Reply::Ask(_)));
    }

    #[test]
    fn memory_commands_declare_intents() {
        // `/记` 带内容 → Remember（内容原样携带）。
        let Reply::Remember(content) = dispatch("/记 服务器 IP 是 1.2.3.4", 0, 0).unwrap() else {
            panic!("/记 must declare Remember");
        };
        assert_eq!(content, "服务器 IP 是 1.2.3.4");
        // `/记` 空参数 → 用法提示（不装死）。
        let Reply::Text(text) = dispatch("/记", 0, 0).unwrap() else {
            panic!("/记 without arg must reply usage");
        };
        assert!(text.contains("用法"), "usage missing: {text}");
        // `/忆` 带关键词 → Recall。
        let Reply::Recall(keyword) = dispatch("/忆 掉线", 0, 0).unwrap() else {
            panic!("/忆 must declare Recall");
        };
        assert_eq!(keyword, "掉线");
        // `/忆` 不带关键词 → 空串（由接收端解释为「重要记忆概览」）。
        assert_eq!(dispatch("/忆", 0, 0).unwrap(), Reply::Recall(String::new()));
    }

    #[test]
    fn issue_and_tool_commands_declare_intents() {
        let Reply::IssueSearch(query) = dispatch("/issue 卫戍协议", 0, 0).unwrap() else {
            panic!("/issue must declare IssueSearch");
        };
        assert_eq!(query, "卫戍协议");
        let Reply::Text(text) = dispatch("/issue", 0, 0).unwrap() else {
            panic!("/issue without arg must reply usage");
        };
        assert!(text.contains("用法"), "usage missing: {text}");
        assert_eq!(dispatch("/话题", 0, 0).unwrap(), Reply::Topic);
        assert_eq!(dispatch("/mc", 0, 0).unwrap(), Reply::Minecraft);
        // 运维自省：两个别名集合都要能落到对应意图（排障入口不能失联）。
        assert_eq!(dispatch("/版本", 0, 0).unwrap(), Reply::Version);
        assert_eq!(dispatch("/version", 0, 0).unwrap(), Reply::Version);
        assert_eq!(dispatch("/自检", 0, 0).unwrap(), Reply::SelfCheck);
        assert_eq!(dispatch("/体检", 0, 0).unwrap(), Reply::SelfCheck);
        let Reply::WebFetch(url) = dispatch("/网站 https://example.com", 0, 0).unwrap() else {
            panic!("/网站 must declare WebFetch");
        };
        assert_eq!(url, "https://example.com");
        // 非 http(s) 地址拦截在分发层（连意图都不声明）。
        let Reply::Text(text) = dispatch("/网站 ftp://x", 0, 0).unwrap() else {
            panic!("non-http url must reply usage");
        };
        assert!(text.contains("用法"), "usage missing: {text}");
        // `/提单`：建 issue 的写操作意图（能否执行由接收端 GH_WRITE 决定）。
        let Reply::IssueCreate(title) = dispatch("/提单 卫戍协议掉线", 0, 0).unwrap() else {
            panic!("/提单 must declare IssueCreate");
        };
        assert_eq!(title, "卫戍协议掉线");
        let Reply::Text(text) = dispatch("/提单", 0, 0).unwrap() else {
            panic!("/提单 without arg must reply usage");
        };
        assert!(text.contains("用法"), "usage missing: {text}");
    }

    #[test]
    fn help_lists_memory_and_tool_commands() {
        let Reply::Text(text) = dispatch("/帮助", 0, 0).unwrap() else {
            panic!("帮助 must reply");
        };
        for cmd in ["/记", "/忆", "/issue", "/提单", "/话题", "/网站", "/mc"] {
            assert!(text.contains(cmd), "help missing {cmd}: {text}");
        }
    }
}
