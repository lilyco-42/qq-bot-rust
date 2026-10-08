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
    let Some(value) = find_value(body, key)? else {
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
    let Some(value) = find_value(body, key)? else {
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

/// 定位 `"key"` 对应的值字节切片（跳过字符串内部出现的同名文本）。
///
/// 顶层扫描遇到 `"` 即整体跳过该字符串（含转义），因此字符串内部的
/// `"op"` 之类文本不会被误判为 key；找到 key 后要求紧跟 `:`，
/// 否则视为报文非法。
fn find_value<'a>(body: &'a [u8], key: &[u8]) -> Result<Option<&'a [u8]>> {
    let mut idx = 0usize;
    while idx < body.len() {
        match body[idx] {
            b'"' => {
                let start = idx + 1;
                let Some(end) = scan_string_end(body, start) else {
                    return Err(Error::MalformedJson);
                };
                if &body[start..end] == key {
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
    use super::{challenge_response, json_i64, json_str};
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
}
