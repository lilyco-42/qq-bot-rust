//! op=0 事件推送的定向字段提取：消息类事件 → 回复寻址信息。
//!
//! 与 [`crate::callback`]（握手/验签用的通用提取）分工：本模块只服务
//! 于「收到消息 → 被动回复」链路，按根对象直接子键严格取值：
//! `d.id` 不会误中 `author.id`，形态非法一律上抛（反模式⑤）。
//!
//! 非消息类事件（如 `GROUP_MEMBER_ADD`）由 [`is_message_event`] 分流，
//! 不进入解析，避免对无消息结构的事件误报缺失字段。

use crate::callback::{json_top_text, object_scope};
use crate::error::{Error, Result};
use alloc::string::String;

/// 单聊（私聊）消息事件。
pub const MSG_C2C: &str = "C2C_MESSAGE_CREATE";
/// 群聊 @ 机器人消息事件。
pub const MSG_GROUP_AT: &str = "GROUP_AT_MESSAGE_CREATE";

/// 可作为被动回复目标的消息类事件类型。
pub const MESSAGE_EVENTS: [&str; 2] = [MSG_C2C, MSG_GROUP_AT];

/// 消息事件解析结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageEvent {
    /// 事件类型（顶层 `t`，即 [`MESSAGE_EVENTS`] 之一）。
    pub event_type: String,
    /// 消息 id（`d.id`）：被动回复的 `msg_id`。
    pub msg_id: String,
    /// 消息正文（`d.content`，已解码 JSON 转义；可能为空串）。
    pub content: String,
    /// QQ 事件是否包含非空 attachments 数组（不暴露附件 URL）。
    pub has_attachments: bool,
    /// 发送者 openid（`d.author.user_openid`）：单聊回复目标。
    pub user_openid: Option<String>,
    /// 群 openid（`d.group_openid`）：群聊回复目标。
    pub group_openid: Option<String>,
}

/// 提取顶层 `t` 事件类型；不存在返回 `Ok(None)`，形态非法返回错误。
pub fn event_type(body: &[u8]) -> Result<Option<String>> {
    json_top_text(body, b"t")
}

/// 事件是否属于可被动回复的消息类事件。
pub fn is_message_event(event_type: &str) -> bool {
    MESSAGE_EVENTS.contains(&event_type)
}

/// 解析消息类事件的回复寻址信息。
///
/// 严格性约定：
/// - `d` 对象、`d.id`（msg_id）缺失即报错（没有它无法构成有效回复）；
/// - 回复目标至少一个：`d.group_openid`（群聊）或 `d.author.user_openid`
///   （单聊），两者皆缺 → [`Error::NoReplyTarget`]；`author` 缺失视为
///   无 `user_openid`（不直接报错，由目标完整性检查兜底）；
/// - `d.content` 缺失视为「无正文」（媒体消息等）→ 空串，由调用方
///   决定不回复；存在但非字符串 → [`Error::MalformedJson`]。
///
/// `event_type` 必须是 [`MESSAGE_EVENTS`] 之一（由调用方经
/// [`is_message_event`] 过滤）；不匹配返回 [`Error::NotMessageEvent`]。
pub fn parse_message_event(body: &[u8], event_type: &str) -> Result<MessageEvent> {
    if !is_message_event(event_type) {
        return Err(Error::NotMessageEvent);
    }
    let d = object_scope(body, b"d")?.ok_or(Error::MissingField("d"))?;
    let msg_id = json_top_text(d, b"id")?
        .filter(|value| !value.is_empty())
        .ok_or(Error::MissingField("d.id"))?;
    // content 可缺省（媒体消息）；存在但形态非法则上抛。
    let content = json_top_text(d, b"content")?.unwrap_or_default();
    let has_attachments = has_nonempty_attachments(d);
    let group_openid = json_top_text(d, b"group_openid")?;
    // author 缺失 = 无 user_openid（不报错，由目标完整性检查兜底）；
    // author 存在但 user_openid 形态非法 → 错误上抛，不吞。
    let user_openid = match object_scope(d, b"author")? {
        Some(author) => {
            Some(json_top_text(author, b"user_openid")?.filter(|value| !value.is_empty()))
        }
        None => None,
    }
    .flatten();
    if group_openid.is_none() && user_openid.is_none() {
        return Err(Error::NoReplyTarget);
    }
    Ok(MessageEvent {
        event_type: String::from(event_type),
        msg_id,
        content,
        has_attachments,
        user_openid,
        group_openid,
    })
}

/// 不信任群聊的任意外链，也不提取图片 URL；只探知 attachments 非空。
fn has_nonempty_attachments(event_data: &[u8]) -> bool {
    let needle = b"\"attachments\"";
    let Some(at) = event_data.windows(needle.len()).position(|part| part == needle) else {
        return false;
    };
    let rest = &event_data[at + needle.len()..];
    let rest = rest.iter().copied().skip_while(u8::is_ascii_whitespace).collect::<alloc::vec::Vec<_>>();
    if rest.first() != Some(&b':') { return false; }
    let rest = rest[1..].iter().copied().skip_while(u8::is_ascii_whitespace).collect::<alloc::vec::Vec<_>>();
    if rest.first() != Some(&b'[') { return false; }
    let rest = rest[1..].iter().copied().skip_while(u8::is_ascii_whitespace).collect::<alloc::vec::Vec<_>>();
    rest.first().is_some_and(|byte| *byte != b']')
}

#[cfg(test)]
mod tests {
    use super::{MSG_C2C, MSG_GROUP_AT, event_type, is_message_event, parse_message_event};
    use crate::error::Error;

    /// 真实单聊事件报文（Radxa 抓取；中文按 UTF-8 字节转义）。
    const C2C_EVENT: &[u8] = b"{\"op\":0,\"id\":\"C2C_MESSAGE_CREATE:sfyoo42bh\",\"d\":{\"id\":\"ROBOT1.0_oC3JDEal\",\"content\":\"\xe5\xb8\xae\xe5\x8a\xa9\",\"timestamp\":\"2026-10-09T00:22:29+08:00\",\"author\":{\"id\":\"DE8C8AEC\",\"username\":\"\",\"bot\":false,\"user_openid\":\"DE8C8AECAF13F8D144240291E8D7B0A7\",\"union_openid\":\"\"},\"message_type\":0},\"t\":\"C2C_MESSAGE_CREATE\",\"seq\":1}";

    /// 真实群事件报文结构（群成员进群，无正文、无消息 id）。
    const GROUP_MEMBER_ADD: &[u8] = b"{\"op\":0,\"id\":\"GROUP_MEMBER_ADD:x\",\"d\":{\"timestamp\":\"2026-10-09T00:19:16+08:00\",\"group_openid\":\"3D54AA8E\",\"member_openid\":\"095AF6EF\",\"union_openid\":\"095AF6EF\",\"operator_openid\":\"095AF6EF\",\"scene\":\"add\"},\"t\":\"GROUP_MEMBER_ADD\",\"seq\":3}";

    /// 群 @ 消息（合成：结构对齐官方文档）。
    const GROUP_AT_EVENT: &[u8] = b"{\"op\":0,\"id\":\"GROUP_AT_MESSAGE_CREATE:g\",\"d\":{\"author\":{\"id\":\"79BE\",\"user_openid\":\"79BE66EF\"},\"content\":\"help me\",\"group_openid\":\"3D54AA8E\",\"id\":\"ROBOT1.0_grp\",\"message_type\":0},\"t\":\"GROUP_AT_MESSAGE_CREATE\",\"seq\":1}";

    #[test]
    fn classifies_message_events() {
        assert!(is_message_event(MSG_C2C));
        assert!(is_message_event(MSG_GROUP_AT));
        assert!(!is_message_event("GROUP_MEMBER_ADD"));
        assert_eq!(event_type(C2C_EVENT).unwrap().as_deref(), Some(MSG_C2C));
        assert_eq!(
            event_type(GROUP_MEMBER_ADD).unwrap().as_deref(),
            Some("GROUP_MEMBER_ADD")
        );
        assert_eq!(event_type(b"{\"op\":13}").unwrap(), None);
    }

    #[test]
    fn parses_real_c2c_event() {
        let event = parse_message_event(C2C_EVENT, MSG_C2C).unwrap();
        assert_eq!(event.event_type, MSG_C2C);
        // d.id 而非外层事件 id。
        assert_eq!(event.msg_id, "ROBOT1.0_oC3JDEal");
        // 中文正文按 UTF-8 解码。
        assert_eq!(event.content, "\u{5e2e}\u{52a9}");
        assert_eq!(
            event.user_openid.as_deref(),
            Some("DE8C8AECAF13F8D144240291E8D7B0A7")
        );
        assert_eq!(event.group_openid, None);
    }

    #[test]
    fn parses_group_event_target() {
        let event = parse_message_event(GROUP_AT_EVENT, MSG_GROUP_AT).unwrap();
        assert_eq!(event.msg_id, "ROBOT1.0_grp");
        assert_eq!(event.content, "help me");
        assert_eq!(event.group_openid.as_deref(), Some("3D54AA8E"));
        assert_eq!(event.user_openid.as_deref(), Some("79BE66EF"));
    }

    #[test]
    fn rejects_non_message_event_type() {
        assert_eq!(
            parse_message_event(C2C_EVENT, "GROUP_MEMBER_ADD"),
            Err(Error::NotMessageEvent)
        );
    }

    #[test]
    fn group_member_add_is_not_a_message_event() {
        // 非消息事件根本不进 parse（调用方按 t 分流），此处只验证分流判定。
        assert!(!is_message_event("GROUP_MEMBER_ADD"));
    }

    #[test]
    fn reports_structural_errors() {
        // 缺 d。
        assert_eq!(
            parse_message_event(b"{\"t\":\"C2C_MESSAGE_CREATE\"}", MSG_C2C),
            Err(Error::MissingField("d"))
        );
        // 缺 d.id。
        assert_eq!(
            parse_message_event(
                b"{\"d\":{\"content\":\"x\"},\"t\":\"C2C_MESSAGE_CREATE\"}",
                MSG_C2C
            ),
            Err(Error::MissingField("d.id"))
        );
        // 无任何回复目标。
        assert_eq!(
            parse_message_event(
                b"{\"d\":{\"id\":\"m\",\"content\":\"x\"},\"t\":\"C2C_MESSAGE_CREATE\"}",
                MSG_C2C
            ),
            Err(Error::NoReplyTarget)
        );
        // content 存在但非字符串 → 上抛不吞。
        assert_eq!(
            parse_message_event(
                b"{\"d\":{\"id\":\"m\",\"content\":5,\"author\":{\"user_openid\":\"u\"}},\"t\":\"C2C_MESSAGE_CREATE\"}",
                MSG_C2C
            ),
            Err(Error::MalformedJson)
        );
        // author 存在但 user_openid 形态非法 → 上抛不吞。
        assert_eq!(
            parse_message_event(
                b"{\"d\":{\"id\":\"m\",\"author\":{\"user_openid\":7}},\"t\":\"C2C_MESSAGE_CREATE\"}",
                MSG_C2C
            ),
            Err(Error::MalformedJson)
        );
    }

    #[test]
    fn detects_group_image_attachments_without_download() {
        let body = r#"{"t":"GROUP_AT_MESSAGE_CREATE","d":{"id":"m","group_openid":"g","content":"帮我记录这个 bug","attachments":[{"content_type":"image/png","url":"https://example.invalid/a.png"}]}}"#.as_bytes();
        let ev = parse_message_event(body, MSG_GROUP_AT).unwrap();
        assert!(ev.has_attachments);
        assert_eq!(ev.content, "帮我记录这个 bug");
        let empty = br#"{"t":"GROUP_AT_MESSAGE_CREATE","d":{"id":"m","group_openid":"g","attachments":[]}}"#;
        assert!(!parse_message_event(empty, MSG_GROUP_AT).unwrap().has_attachments);
    }

    #[test]
    fn missing_content_is_empty_string() {
        // 媒体消息无 content → 空串（调用方不回复），不是错误。
        let event = parse_message_event(
            b"{\"d\":{\"id\":\"m\",\"author\":{\"user_openid\":\"u\"}},\"t\":\"C2C_MESSAGE_CREATE\"}",
            MSG_C2C,
        )
        .unwrap();
        assert_eq!(event.content, "");
    }
}
