//! OpenAPI 协议层：出站请求构造与应答解析（纯函数，不含传输）。
//!
//! 依据官方《获取访问凭证》《发送单聊消息》《发送群聊消息》文档：
//! - 鉴权头：`Authorization: QQBot {access_token}`；
//! - 业务错误可能以 HTTP 200 + `{"code"/"err_code":非0}` 返回，必须按码
//!   判定，不能只看 HTTP 状态（botgo issue #61 反模式③的诱因之一）。
//!
//! 本模块只做字节进出，HTTP 发送由 bin 层（std）完成——协议与传输解耦，
//! 协议层保持可测、no_std。

use crate::callback::{json_i64, json_numeric, json_str};
use crate::error::{Error, Result};
use crate::secret::SecretString;
use alloc::format;
use alloc::string::String;

/// OpenAPI 统一入口（国内区，官方文档《API 调用指南》）。
pub const API_BASE: &str = "https://api.bot.qq.com";

/// 单聊消息路径模板：`/v2/users/{user_openid}/messages`。
const C2C_MESSAGE_PATH: &str = "/v2/users/";
/// 群聊消息路径模板：`/v2/groups/{group_openid}/messages`。
const GROUP_MESSAGE_PATH: &str = "/v2/groups/";
/// 消息路径后缀。
const MESSAGES_SUFFIX: &str = "/messages";
/// 获取 AppAccessToken 路径。
const APP_TOKEN_PATH: &str = "/app/getAppAccessToken";

/// 出站 API 请求（URL + JSON 体；鉴权由调用方附加）。
///
/// 不派生 `Debug`：`body` 可能含 clientSecret（token 请求），
/// 结构上杜绝被日志框架整对象打印。
pub struct ApiRequest {
    /// 完整 URL。
    pub url: String,
    /// JSON 请求体。
    pub body: String,
}

/// AppAccessToken 凭证。
pub struct AppToken {
    /// 访问令牌（脱敏包装；取明文唯一入口 [`SecretString::expose`]）。
    pub token: SecretString,
    /// 有效期（秒），按文档数字或字符串形态解析。
    pub expires_in: i64,
}

/// 已发送成功的消息回执。
pub struct SentMessage {
    /// 平台生成的消息 id。
    pub id: String,
}

/// 构造 `POST /app/getAppAccessToken` 请求。
///
/// body：`{"appId":"...","clientSecret":"..."}`——secret 仅存在于
/// 该字节串的生命周期内，不落日志。
pub fn app_token_request(app_id: &str, client_secret: &str) -> ApiRequest {
    ApiRequest {
        url: format!("{API_BASE}{APP_TOKEN_PATH}"),
        body: format!(
            "{{\"appId\":\"{}\",\"clientSecret\":\"{}\"}}",
            json_escape(app_id),
            json_escape(client_secret),
        ),
    }
}

/// 解析 token 应答：先查业务码（HTTP 200 也可能带错误码），再取字段。
pub fn parse_app_token(status: u16, body: &str) -> Result<AppToken> {
    // 平台失败示例：HTTP 200 + {"code":100016,"message":...}。
    if let Some(code) = json_i64(body.as_bytes(), b"code")?
        && code != 0
    {
        return Err(Error::Api(code));
    }
    if !(200..300).contains(&status) {
        return Err(Error::Api(i64::from(status)));
    }
    let token = json_str(body.as_bytes(), b"access_token")?
        .filter(|value| !value.is_empty())
        .ok_or(Error::MissingField("access_token"))?;
    let expires_in =
        json_numeric(body.as_bytes(), b"expires_in")?.ok_or(Error::MissingField("expires_in"))?;
    Ok(AppToken {
        token: SecretString::new(String::from(token)),
        expires_in,
    })
}

/// 构造 `POST /v2/users|groups/{openid}/messages` 请求（被动回复）。
///
/// - `content`：回复正文（非空，平台拒发空消息 50006）；
/// - `msg_id`：被回复消息的 `d.id`；
/// - `msg_seq`：同 `msg_id` 下的回复序号，从 1 起。
///
/// openid 做路径段百分号编码，防路径注入。
pub fn send_message_request(
    is_group: bool,
    openid: &str,
    content: &str,
    msg_id: &str,
    msg_seq: u32,
) -> Result<ApiRequest> {
    if openid.is_empty() {
        return Err(Error::MissingField("openid"));
    }
    if content.is_empty() {
        return Err(Error::MissingField("content"));
    }
    if msg_id.is_empty() {
        return Err(Error::MissingField("msg_id"));
    }
    let base = if is_group {
        GROUP_MESSAGE_PATH
    } else {
        C2C_MESSAGE_PATH
    };
    Ok(ApiRequest {
        url: format!(
            "{API_BASE}{base}{}{MESSAGES_SUFFIX}",
            percent_encode_path(openid)
        ),
        body: format!(
            "{{\"content\":\"{}\",\"msg_type\":0,\"msg_id\":\"{}\",\"msg_seq\":{}}}",
            json_escape(content),
            json_escape(msg_id),
            msg_seq,
        ),
    })
}

/// 解析发送消息应答：先查 `err_code`/`code`（HTTP 200 也可能带错误码），
/// 再校验 HTTP 状态，最后取消息 id。
pub fn parse_send_response(status: u16, body: &str) -> Result<SentMessage> {
    for key in [b"err_code".as_slice(), b"code".as_slice()] {
        if let Some(code) = json_i64(body.as_bytes(), key)?
            && code != 0
        {
            return Err(Error::Api(code));
        }
    }
    if !(200..300).contains(&status) {
        return Err(Error::Api(i64::from(status)));
    }
    let id = json_str(body.as_bytes(), b"id")?
        .filter(|value| !value.is_empty())
        .ok_or(Error::MissingField("id"))?;
    Ok(SentMessage {
        id: String::from(id),
    })
}

/// JSON 字符串内容转义（不含包裹引号）：防 JSON 注入。
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// 路径段百分号编码（RFC 3986 unreserved 之外全编码）。
fn percent_encode_path(segment: &str) -> String {
    let mut out = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn builds_app_token_request() {
        let request = app_token_request("1903680813", "s3cr\"et\\x");
        assert_eq!(request.url, "https://api.bot.qq.com/app/getAppAccessToken");
        // secret 被 JSON 转义后内联，请求结构可断言（本体不落日志）。
        assert_eq!(
            request.body,
            "{\"appId\":\"1903680813\",\"clientSecret\":\"s3cr\\\"et\\\\x\"}"
        );
    }

    #[test]
    fn parses_token_numeric_and_string_expiry() {
        let token = parse_app_token(200, r#"{"access_token":"abc123","expires_in":7200}"#).unwrap();
        assert_eq!(token.token.expose(), "abc123");
        assert_eq!(token.expires_in, 7200);

        // 文档示例：expires_in 为字符串。
        let token =
            parse_app_token(200, r#"{"access_token":"abc123","expires_in":"7200"}"#).unwrap();
        assert_eq!(token.expires_in, 7200);
    }

    #[test]
    fn token_business_error_beats_http_ok() {
        // 官方失败示例：HTTP 200 + code 非 0。
        assert_eq!(
            parse_app_token(200, r#"{"code":100016,"message":"secret invalid"}"#).err(),
            Some(Error::Api(100016))
        );
        // 非 2xx 无 code → 状态码兜底。
        assert_eq!(
            parse_app_token(502, "bad gateway").err(),
            Some(Error::Api(502))
        );
        assert_eq!(
            parse_app_token(401, r#"{"code":401,"message":"unauthorized"}"#).err(),
            Some(Error::Api(401))
        );
    }

    #[test]
    fn token_missing_fields_reported() {
        assert_eq!(
            parse_app_token(200, r#"{"expires_in":7200}"#).err(),
            Some(Error::MissingField("access_token"))
        );
        assert_eq!(
            parse_app_token(200, r#"{"access_token":""}"#).err(),
            Some(Error::MissingField("access_token"))
        );
        assert_eq!(
            parse_app_token(200, r#"{"access_token":"a"}"#).err(),
            Some(Error::MissingField("expires_in"))
        );
    }

    #[test]
    fn builds_c2c_and_group_message_requests() {
        let request = send_message_request(
            false,
            "DE8C8AEC",
            "\u{4f60}\u{597d}\n\"x\"",
            "ROBOT1.0_m",
            1,
        )
        .unwrap();
        assert_eq!(
            request.url,
            "https://api.bot.qq.com/v2/users/DE8C8AEC/messages"
        );
        assert_eq!(
            request.body,
            "{\"content\":\"\u{4f60}\u{597d}\\n\\\"x\\\"\",\"msg_type\":0,\"msg_id\":\"ROBOT1.0_m\",\"msg_seq\":1}"
        );

        let request = send_message_request(true, "3D54AA8E", "help", "m", 2).unwrap();
        assert_eq!(
            request.url,
            "https://api.bot.qq.com/v2/groups/3D54AA8E/messages"
        );
        assert_eq!(
            request.body,
            "{\"content\":\"help\",\"msg_type\":0,\"msg_id\":\"m\",\"msg_seq\":2}"
        );
    }

    #[test]
    fn message_request_validates_and_encodes() {
        // 空 openid / 正文 / msg_id 一律拒绝（平台必回 50006 之类，提前拦截）。
        assert_eq!(
            send_message_request(false, "", "x", "m", 1).err(),
            Some(Error::MissingField("openid"))
        );
        assert_eq!(
            send_message_request(false, "u", "", "m", 1).err(),
            Some(Error::MissingField("content"))
        );
        assert_eq!(
            send_message_request(false, "u", "x", "", 1).err(),
            Some(Error::MissingField("msg_id"))
        );
        // openid 中的非 unreserved 字符做路径段编码，防路径注入。
        let request = send_message_request(false, "a/b?c", "x", "m", 1).unwrap();
        assert_eq!(
            request.url,
            "https://api.bot.qq.com/v2/users/a%2Fb%3Fc/messages"
        );
    }

    #[test]
    fn parses_send_success_and_business_error() {
        let sent = parse_send_response(
            200,
            r#"{"id":"ROBOT1.0_msg","timestamp":"2026-10-09T00:22:29+08:00"}"#,
        )
        .unwrap();
        assert_eq!(sent.id, "ROBOT1.0_msg");

        // err_code 非 0：HTTP 200 也算失败。
        assert_eq!(
            parse_send_response(200, r#"{"err_code":50006,"message":"empty"}"#).err(),
            Some(Error::Api(50006))
        );
        // code 变体（部分端点用 code）。
        assert_eq!(
            parse_send_response(200, r#"{"code":34006,"message":"limit"}"#).err(),
            Some(Error::Api(34006))
        );
        // 无业务码的 HTTP 错误 → 状态码兜底。
        assert_eq!(
            parse_send_response(404, "not found").err(),
            Some(Error::Api(404))
        );
        // 成功但缺 id。
        assert_eq!(
            parse_send_response(200, r#"{"timestamp":"t"}"#).err(),
            Some(Error::MissingField("id"))
        );
    }
}
