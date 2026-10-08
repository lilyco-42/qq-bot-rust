//! QQ 回调报文（webhook payload）的最小解析与握手应答。
//!
//! 只实现本 SDK 实际需要的两个字段提取：整型 `op` 与字符串字段
//! （`plain_token`/`event_ts`）。事件正文（op=0）不做结构化解析——
//! 验签直接作用于原始字节，日志输出原文化内容，避免解析器与
//! 签名边界不一致。
//!
//! 设计约束（botgo issue #61 反模式⑤「解析失败只打日志继续跑」）：
//! 找到 key 但值形态非法一律返回错误，绝不降级为 `None`。

use crate::crypto::webhook::sign_challenge;
use crate::error::{Error, Result};
use alloc::string::String;

/// 回调协议 op：回调整体握手（校验回调地址）。
pub const OP_CHALLENGE: i64 = 13;
/// 回调协议 op：事件推送。
pub const OP_EVENT: i64 = 0;

/// op=13 握手应答体。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeResponse {
    /// 原样回传的 `plain_token`。
    pub plain_token: String,
    /// `event_ts || plain_token` 的 Ed25519 签名（小写 hex）。
    pub signature: String,
}

impl ChallengeResponse {
    /// 序列化为官方文档规定的应答 JSON。
    ///
    /// `plain_token` 与 `signature` 均为平台生成的 hex/签名串，
    /// 解析阶段已排除引号与控制字符，可直接内联。
    pub fn to_json(&self) -> String {
        alloc::format!(
            "{{\"plain_token\":\"{}\",\"signature\":\"{}\"}}",
            self.plain_token,
            self.signature
        )
    }
}

/// 处理 op=13 握手请求：提取字段并生成应答。
///
/// - `op` 缺失或不等于 13 → [`Error::UnexpectedOp`] / [`Error::MissingField`]；
/// - 字段值形态非法（非字符串、含转义）→ [`Error::MalformedJson`]。
pub fn challenge_response(secret: &str, body: &[u8]) -> Result<ChallengeResponse> {
    match json_i64(body, b"op")? {
        Some(OP_CHALLENGE) => {}
        Some(other) => return Err(Error::UnexpectedOp(other)),
        None => return Err(Error::MissingField("op")),
    }
    let plain_token = json_str(body, b"plain_token")?.ok_or(Error::MissingField("plain_token"))?;
    let event_ts = json_str(body, b"event_ts")?.ok_or(Error::MissingField("event_ts"))?;
    Ok(ChallengeResponse {
        plain_token: String::from(plain_token),
        signature: sign_challenge(secret, event_ts, plain_token)?,
    })
}

/// 提取字符串字段值；key 不存在返回 `Ok(None)`。
///
/// 平台生成的协议字段（`plain_token`、`event_ts`）不含 JSON 转义序列；
/// 一旦出现 `\` 立即报错（严格模式：宁可拒绝握手也不猜解码语义）。
pub fn json_str<'a>(body: &'a [u8], key: &[u8]) -> Result<Option<&'a str>> {
    let Some(value) = find_value(body, key, false)? else {
        return Ok(None);
    };
    let Some(rest) = value.strip_prefix(b"\"") else {
        return Err(Error::MalformedJson);
    };
    let end = memchr_byte(rest, b'"').ok_or(Error::MalformedJson)?;
    let raw = &rest[..end];
    if raw.contains(&b'\\') {
        return Err(Error::MalformedJson);
    }
    core::str::from_utf8(raw)
        .map(Some)
        .map_err(|_| Error::MalformedJson)
}

/// 提取整型字段值；key 不存在返回 `Ok(None)`，值非整型返回错误。
pub fn json_i64(body: &[u8], key: &[u8]) -> Result<Option<i64>> {
    let Some(value) = find_value(body, key, false)? else {
        return Ok(None);
    };
    // find_value 返回值起点到文档尾；整型 token 到分隔符（空白/,/}/]）截止。
    let end = value
        .iter()
        .position(|byte| byte.is_ascii_whitespace() || matches!(byte, b',' | b'}' | b']'))
        .unwrap_or(value.len());
    let text = core::str::from_utf8(&value[..end]).map_err(|_| Error::MalformedJson)?;
    text.parse::<i64>()
        .map(Some)
        .map_err(|_| Error::MalformedJson)
}

/// 提取根对象**直接子键**的字符串值并解码 JSON 转义；key 不存在返回 `Ok(None)`。
///
/// 与 [`json_str`]（扁平扫描、出现转义即报错）的区别：
///
/// - 只匹配根对象的直接子键（depth==1）——在 `d` 作用域内取 `id`
///   不会误中 `author.id`；
/// - 解码 `"\\n"`/`"\\"`/`"\\uXXXX"`（含代理对）——消息正文可含任意文本。
///
/// 形态非法（找到 key 但值不是字符串/未闭合/孤立代理项）一律报错。
pub fn json_top_text(body: &[u8], key: &[u8]) -> Result<Option<String>> {
    let Some(value) = find_value(body, key, true)? else {
        return Ok(None);
    };
    if value.first() != Some(&b'"') {
        return Err(Error::MalformedJson);
    }
    let close = scan_string_end(value, 1).ok_or(Error::MalformedJson)?;
    decode_json_string(&value[1..close]).map(Some)
}

/// 取 `"key": {...}` 对象本身（含花括号的完整切片，根对象直接子键
/// 匹配）；key 不存在返回 `Ok(None)`。
///
/// 返回值是完整对象文档，可继续交给 [`json_top_text`] 等 `top_only`
/// 提取器取其直接子键（深度语义保持一致）。找到 key 但值不是对象
/// （如 `"d":5`）→ [`Error::MalformedJson`]；对象未闭合 → 同样报错
/// （严格模式：不返回半截作用域）。
pub fn object_scope<'a>(body: &'a [u8], key: &[u8]) -> Result<Option<&'a [u8]>> {
    let Some(value) = find_value(body, key, true)? else {
        return Ok(None);
    };
    if value.first() != Some(&b'{') {
        return Err(Error::MalformedJson);
    }
    let close = scan_object_end(value, 0).ok_or(Error::MalformedJson)?;
    Ok(Some(&value[..=close]))
}

/// 提取数值字段：接受 JSON 数字或数字字符串两种形态。
///
/// 平台文档对同一字段（如 `expires_in`）在规格表与返回示例中
/// 数字/字符串并存，按严格 [`json_i64`] 会误拒，故提供宽松变体。
pub fn json_numeric(body: &[u8], key: &[u8]) -> Result<Option<i64>> {
    let Some(value) = find_value(body, key, false)? else {
        return Ok(None);
    };
    if value.first() == Some(&b'"') {
        let close = scan_string_end(value, 1).ok_or(Error::MalformedJson)?;
        let text = core::str::from_utf8(&value[1..close]).map_err(|_| Error::MalformedJson)?;
        return text
            .parse::<i64>()
            .map(Some)
            .map_err(|_| Error::MalformedJson);
    }
    let end = value
        .iter()
        .position(|byte| byte.is_ascii_whitespace() || matches!(byte, b',' | b'}' | b']'))
        .unwrap_or(value.len());
    let text = core::str::from_utf8(&value[..end]).map_err(|_| Error::MalformedJson)?;
    text.parse::<i64>()
        .map(Some)
        .map_err(|_| Error::MalformedJson)
}

/// 解码 JSON 字符串字节（不含包裹引号）：处理 `\"` `\\` `\/` `\b`
/// `\f` `\n` `\r` `\t` `\uXXXX`（含 UTF-16 代理对）。
fn decode_json_string(raw: &[u8]) -> Result<String> {
    if !raw.contains(&b'\\') {
        return core::str::from_utf8(raw)
            .map(String::from)
            .map_err(|_| Error::MalformedJson);
    }
    let mut out = String::with_capacity(raw.len());
    let mut idx = 0usize;
    let mut run_start = 0usize;
    while idx < raw.len() {
        if raw[idx] != b'\\' {
            idx += 1;
            continue;
        }
        out.push_str(core::str::from_utf8(&raw[run_start..idx]).map_err(|_| Error::MalformedJson)?);
        idx += 1;
        let escape = *raw.get(idx).ok_or(Error::MalformedJson)?;
        idx += 1;
        match escape {
            b'"' => out.push('"'),
            b'\\' => out.push('\\'),
            b'/' => out.push('/'),
            b'b' => out.push('\u{8}'),
            b'f' => out.push('\u{c}'),
            b'n' => out.push('\n'),
            b'r' => out.push('\r'),
            b't' => out.push('\t'),
            b'u' => {
                let hi = hex4(raw.get(idx..).ok_or(Error::MalformedJson)?)?;
                idx += 4;
                let scalar = if (0xD800..0xDC00).contains(&hi) {
                    // 高代理项必须紧跟 `\uXXXX` 低代理项。
                    let tail = raw.get(idx..).ok_or(Error::MalformedJson)?;
                    if !tail.starts_with(b"\\u") {
                        return Err(Error::MalformedJson);
                    }
                    idx += 2;
                    let lo = hex4(raw.get(idx..).ok_or(Error::MalformedJson)?)?;
                    idx += 4;
                    if !(0xDC00..0xE000).contains(&lo) {
                        return Err(Error::MalformedJson);
                    }
                    0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                } else if (0xDC00..0xE000).contains(&hi) {
                    // 孤立低代理项。
                    return Err(Error::MalformedJson);
                } else {
                    hi
                };
                out.push(char::from_u32(scalar).ok_or(Error::MalformedJson)?);
            }
            _ => return Err(Error::MalformedJson),
        }
        run_start = idx;
    }
    out.push_str(core::str::from_utf8(&raw[run_start..idx]).map_err(|_| Error::MalformedJson)?);
    Ok(out)
}

/// 从 `start`（`{` 所在下标）扫描到配对的 `}`，返回 `}` 下标。
fn scan_object_end(body: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut idx = start;
    while idx < body.len() {
        match body[idx] {
            b'"' => {
                let end = scan_string_end(body, idx + 1)?;
                idx = end + 1;
                continue;
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
        idx += 1;
    }
    None
}

/// 解析 4 位十六进制（`\uXXXX` 转义用）。
fn hex4(bytes: &[u8]) -> Result<u32> {
    let slice = bytes.get(..4).ok_or(Error::MalformedJson)?;
    let mut value = 0u32;
    for byte in slice {
        let digit = match byte {
            b'0'..=b'9' => u32::from(byte - b'0'),
            b'a'..=b'f' => u32::from(byte - b'a') + 10,
            b'A'..=b'F' => u32::from(byte - b'A') + 10,
            _ => return Err(Error::MalformedJson),
        };
        value = value * 16 + digit;
    }
    Ok(value)
}

/// 定位 `"key"` 对应的值字节切片（跳过字符串内部出现的同名文本）。
///
/// 顶层扫描遇到 `"` 即整体跳过该字符串（含转义），因此字符串内部的
/// `"op"` 之类文本不会被误判为 key；找到 key 后要求紧跟 `:`，
/// 否则视为报文非法。
///
/// `top_only = true` 时只匹配**根对象的直接子键**（按花括号深度过滤，
/// 根对象自身的 `{` 计入深度，故其子键位于 depth==1），用于在 `d`
/// 作用域内取 `id`/`content` 等不会与更深层同名键（如 `author.id`）
/// 混淆的字段。此时 `body` 必须是完整对象文档（[`object_scope`] 的
/// 返回值即满足）。
fn find_value<'a>(body: &'a [u8], key: &[u8], top_only: bool) -> Result<Option<&'a [u8]>> {
    let mut idx = 0usize;
    let mut depth = 0usize;
    while idx < body.len() {
        match body[idx] {
            b'"' => {
                let start = idx + 1;
                let Some(end) = scan_string_end(body, start) else {
                    return Err(Error::MalformedJson);
                };
                if (!top_only || depth == 1) && &body[start..end] == key {
                    let mut cursor = end + 1;
                    while cursor < body.len() && body[cursor].is_ascii_whitespace() {
                        cursor += 1;
                    }
                    let Some(b':') = body.get(cursor) else {
                        return Err(Error::MalformedJson);
                    };
                    cursor += 1;
                    while cursor < body.len() && body[cursor].is_ascii_whitespace() {
                        cursor += 1;
                    }
                    return body
                        .get(cursor..)
                        .filter(|rest| !rest.is_empty())
                        .map(Some)
                        .ok_or(Error::MalformedJson);
                }
                idx = end + 1;
            }
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                idx += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                idx += 1;
            }
            _ => idx += 1,
        }
    }
    Ok(None)
}

/// 从 `start`（开引号后首个字节）扫描到闭引号，返回闭引号下标。
fn scan_string_end(body: &[u8], start: usize) -> Option<usize> {
    let mut idx = start;
    let mut escaped = false;
    while idx < body.len() {
        match body[idx] {
            b'\\' if !escaped => escaped = true,
            b'"' if !escaped => return Some(idx),
            _ => escaped = false,
        }
        idx += 1;
    }
    None
}

/// 查找字节（无 `memchr` feature 时的朴素实现；报文 ≤ 1 MiB，代价可忽略）。
fn memchr_byte(haystack: &[u8], needle: u8) -> Option<usize> {
    haystack.iter().position(|byte| *byte == needle)
}

#[cfg(test)]
mod tests {
    use super::{
        challenge_response, json_i64, json_numeric, json_str, json_top_text, object_scope,
    };
    use crate::error::Error;

    /// 官方《Webhook 方式》演示向量。
    const DOC_SECRET: &str = "DG5g3B4j9X2KOErG";
    const CHALLENGE_BODY: &[u8] =
        br#"{"op":13,"d":{"event_ts":"1725442341","plain_token":"Arq0D5A61EgUu4OxUvOp"}}"#;

    #[test]
    fn answers_official_challenge_vector() {
        let response = challenge_response(DOC_SECRET, CHALLENGE_BODY).unwrap();
        assert_eq!(response.plain_token, "Arq0D5A61EgUu4OxUvOp");
        assert_eq!(
            response.signature,
            "87befc99c42c651b3aac0278e71ada338433ae26fcb24307bdc5ad38c1adc2d01bcfcadc0842edac85e85205028a1132afe09280305f13aa6909ffc2d652c706"
        );
        assert_eq!(
            response.to_json(),
            alloc::format!(
                "{{\"plain_token\":\"Arq0D5A61EgUu4OxUvOp\",\"signature\":\"{}\"}}",
                response.signature
            )
        );
    }

    #[test]
    fn field_order_is_irrelevant() {
        let body =
            br#"{"d":{"plain_token":"Arq0D5A61EgUu4OxUvOp","event_ts":"1725442341"},"op":13}"#;
        assert_eq!(
            challenge_response(DOC_SECRET, body).unwrap(),
            challenge_response(DOC_SECRET, CHALLENGE_BODY).unwrap()
        );
    }

    #[test]
    fn rejects_wrong_op() {
        assert_eq!(
            challenge_response(DOC_SECRET, br#"{"op":0,"d":{}}"#),
            Err(Error::UnexpectedOp(0))
        );
        assert_eq!(
            challenge_response(DOC_SECRET, br#"{"d":{}}"#),
            Err(Error::MissingField("op"))
        );
    }

    #[test]
    fn rejects_missing_or_malformed_fields() {
        assert_eq!(
            challenge_response(DOC_SECRET, br#"{"op":13,"d":{"event_ts":"1"}}"#),
            Err(Error::MissingField("plain_token"))
        );
        assert_eq!(
            challenge_response(DOC_SECRET, br#"{"op":13,"d":{"plain_token":"x"}}"#),
            Err(Error::MissingField("event_ts"))
        );
        // key 找到但值不是字符串。
        assert_eq!(
            challenge_response(DOC_SECRET, br#"{"op":13,"d":{"plain_token":123}}"#),
            Err(Error::MalformedJson)
        );
        // 值带转义：严格拒绝。
        assert_eq!(
            challenge_response(
                DOC_SECRET,
                br#"{"op":13,"d":{"plain_token":"a\"b","event_ts":"1"}}"#
            ),
            Err(Error::MalformedJson)
        );
        // op 后缺值。
        assert_eq!(
            challenge_response(DOC_SECRET, br#"{"op":}"#),
            Err(Error::MalformedJson)
        );
    }

    #[test]
    fn does_not_match_keys_inside_string_values() {
        let body = br#"{"t":"MESSAGE","d":{"content":"he said \"op\": 99"},"op":0}"#;
        assert_eq!(json_i64(body, b"op").unwrap(), Some(0));
        // 字符串值里的 "op" 不构成 key。
        let body = br#"{"note":"op appears here","op":13}"#;
        assert_eq!(json_i64(body, b"op").unwrap(), Some(13));
        // 只有字符串内部文本时 key 视为不存在。
        let body = br#"{"note":"plain_token is here"}"#;
        assert_eq!(json_str(body, b"plain_token").unwrap(), None);
    }

    #[test]
    fn key_prefix_is_not_matched() {
        let body = br#"{"opcode":7,"op":13}"#;
        assert_eq!(json_i64(body, b"op").unwrap(), Some(13));
        assert_eq!(json_i64(body, b"opcode").unwrap(), Some(7));
    }

    #[test]
    fn malformed_inputs_report_errors() {
        // op 值缺失（key 后直接结束）。
        assert_eq!(json_i64(br#"{"op":"#, b"op"), Err(Error::MalformedJson));
        // op 值带非法尾随字符（无法解析为整数）。
        assert_eq!(json_i64(br#"{"op":1x}"#, b"op"), Err(Error::MalformedJson));
        // op 值非整型。
        assert_eq!(
            json_i64(br#"{"op":true}"#, b"op"),
            Err(Error::MalformedJson)
        );
        // 字符串未闭合。
        assert_eq!(
            json_str(br#"{"plain_token":"abc"#, b"plain_token"),
            Err(Error::MalformedJson)
        );
        // 非 UTF-8。
        assert_eq!(
            json_str(b"{\"plain_token\":\"\xff\"}", b"plain_token"),
            Err(Error::MalformedJson)
        );
        // key 后没有冒号。
        assert_eq!(json_i64(br#"{"op" 13}"#, b"op"), Err(Error::MalformedJson));
        // 纯垃圾 → 视为 key 不存在。
        assert_eq!(json_i64(b"not json at all", b"op"), Ok(None));
    }

    /// 真实单聊事件报文（Radxa 抓取，正文/结构未改动；中文按 UTF-8 字节转义）。
    const C2C_EVENT: &[u8] = b"{\"op\":0,\"id\":\"C2C_MESSAGE_CREATE:sfyo\",\"d\":{\"id\":\"ROBOT1.0_msg\",\"content\":\"\xe5\xb8\xae\xe5\x8a\xa9\",\"timestamp\":\"2026-10-09T00:19:33+08:00\",\"author\":{\"id\":\"DE8C8AEC\",\"username\":\"\",\"bot\":false,\"user_openid\":\"DE8C8AECAF13F8D144240291E8D7B0A7\",\"union_openid\":\"\"},\"message_type\":0},\"t\":\"C2C_MESSAGE_CREATE\",\"seq\":1}";

    #[test]
    fn top_text_matches_direct_children_only() {
        // 顶层 t。
        assert_eq!(
            json_top_text(C2C_EVENT, b"t").unwrap().as_deref(),
            Some("C2C_MESSAGE_CREATE")
        );
        // 扁平扫描与 top 版都命中外层 id（根直接子键 = 事件 id）；
        // d.id 需先进入 d 作用域再取（object_scope_returns_whole_object 覆盖）。
        assert_eq!(
            json_top_text(C2C_EVENT, b"id").unwrap().as_deref(),
            Some("C2C_MESSAGE_CREATE:sfyo")
        );
        assert_eq!(
            json_str(C2C_EVENT, b"id").unwrap(),
            Some("C2C_MESSAGE_CREATE:sfyo")
        );
        // 不存在的直接子键。
        assert_eq!(json_top_text(C2C_EVENT, b"group_openid").unwrap(), None);
    }

    #[test]
    fn object_scope_returns_whole_object() {
        let d = object_scope(C2C_EVENT, b"d").unwrap().unwrap();
        assert!(d.starts_with(b"{"), "必须含花括号");
        assert!(d.ends_with(b"}"));
        // 作用域内继续用 top 提取：author.user_openid。
        let author = object_scope(d, b"author").unwrap().unwrap();
        assert_eq!(
            json_top_text(author, b"user_openid").unwrap().as_deref(),
            Some("DE8C8AECAF13F8D144240291E8D7B0A7")
        );
        // author 内不存在的键。
        assert_eq!(json_top_text(author, b"group_openid").unwrap(), None);
        // 顶层作用域取不到 d 里的键（深度过滤）。
        assert_eq!(object_scope(C2C_EVENT, b"author").unwrap(), None);
    }

    #[test]
    fn top_text_decodes_escapes_including_surrogates() {
        let body = b"{\"d\":{\"content\":\"line1\\nline2 \\\"q\\\" \\\\ \xe4\xb8\xad\xf0\x9f\x98\x80\"},\"t\":\"X\"}";
        let d = object_scope(body, b"d").unwrap().unwrap();
        assert_eq!(
            json_top_text(d, b"content").unwrap().as_deref(),
            Some("line1\nline2 \"q\" \\ 中😀")
        );
        // 顶层 t 正常。
        assert_eq!(json_top_text(body, b"t").unwrap().as_deref(), Some("X"));
    }

    #[test]
    fn top_text_reports_malformed_shapes() {
        // 值不是字符串。
        assert_eq!(
            json_top_text(br#"{"d":5}"#, b"d"),
            Err(Error::MalformedJson)
        );
        // 字符串未闭合。
        assert_eq!(
            json_top_text(br#"{"t":"abc"#, b"t"),
            Err(Error::MalformedJson)
        );
        // 孤立高代理项。
        assert_eq!(
            json_top_text(br#"{"t":"\ud800"}"#, b"t"),
            Err(Error::MalformedJson)
        );
        // 未配对 \u 转义。
        assert_eq!(
            json_top_text(br#"{"t":"\u12"}"#, b"t"),
            Err(Error::MalformedJson)
        );
        // 非法转义字符。
        assert_eq!(
            json_top_text(br#"{"t":"a\qb"}"#, b"t"),
            Err(Error::MalformedJson)
        );
    }

    #[test]
    fn object_scope_reports_shape_errors() {
        // key 存在但值不是对象。
        assert_eq!(object_scope(br#"{"d":5}"#, b"d"), Err(Error::MalformedJson));
        // 对象未闭合。
        assert_eq!(
            object_scope(br#"{"d":{"id":"x""#, b"d"),
            Err(Error::MalformedJson)
        );
        // key 不存在 → None。
        assert_eq!(object_scope(br#"{"a":1}"#, b"d").unwrap(), None);
    }

    #[test]
    fn numeric_accepts_number_or_string_forms() {
        // 文档示例字符串形态。
        assert_eq!(
            json_numeric(br#"{"expires_in":"7200"}"#, b"expires_in").unwrap(),
            Some(7200)
        );
        // 规格表数字形态。
        assert_eq!(
            json_numeric(br#"{"expires_in":7200,"x":1}"#, b"expires_in").unwrap(),
            Some(7200)
        );
        // 两种形态都不可用时才报错。
        assert_eq!(
            json_numeric(br#"{"expires_in":"abc"}"#, b"expires_in"),
            Err(Error::MalformedJson)
        );
        assert_eq!(
            json_numeric(br#"{"expires_in":true}"#, b"expires_in"),
            Err(Error::MalformedJson)
        );
        // 缺失 → None。
        assert_eq!(json_numeric(br#"{"a":1}"#, b"expires_in").unwrap(), None);
    }
}
