//! QQ 机器人 WebSocket 网关客户端（wtx 生态传输层）。
//!
//! 对应 README 的最后一个待办项，也是「no_std + wtx 生态」方针在传输层的具体落地：
//! 用 [`wtx::web_socket`] 的 no_std WebSocket 实现 + [`wtx::tls`]（Mozilla CCADB 根证书）
//! 直连官方网关，按 Discord 派生的标准网关协议（op 码 0/1/2/6/7/9/10/11）完成
//! Hello / Identify / Heartbeat / Dispatch / Reconnect 全流程。
//!
//! 设计要点（延续核心库的反模式规避）：
//!
//! - 协议与传输解耦：本模块只负责「连上网关并把每条 dispatch 的原始 JSON 交给调用方」，
//!   事件字段提取复用 [`crate::event`]（与 webhook 同构），不在此重复解析；
//! - 凭证不下放：传入的是已获取的 `access_token`，且 `token` 字段构造时统一加 `QQBot `
//!   前缀，库内不打印、不泄露；
//! - 失败上抛：TLS / 握手 / 解析错误一律返回 [`GatewayError`]，网关进程由调用方决定退出或重连。
//!
//! 本模块整体受 `gateway-wtx` feature 门控，未启用时不影响 no_std 核心构建与既有测试。

use crate::callback::{json_i64, json_str};
use alloc::format;
use alloc::string::{String, ToString};
use core::time::Duration;

#[cfg(feature = "gateway-wtx")]
mod live {
    use super::*;
    use wtx::{
        collections::Vector,
        net::Uri,
        rng::{ChaCha20, CryptoSeedableRng as _},
        sync::{Arc, AsyncMutex},
        tls::{TlsConfig, TlsConnectorBuilder},
        web_socket::{Frame, OpCode, WebSocketConnector, WebSocketPayloadOrigin},
    };

    /// 网关默认接入点（国内区，与 REST 基址同源）。
    pub(crate) const DEFAULT_GATEWAY_URL: &str = "wss://api.bot.qq.com/websocket";

    /// 网关协议 op 码（Discord 派生，QQ 机器人沿用）。
    ///
    /// 仅接收侧实际匹配的常量被代码引用；Identify/Heartbeat/Resume 由发送函数构造，
    /// 此处保留完整协议常量作为文档，故整体允许 dead_code。
    #[allow(dead_code)]
    pub(crate) mod op {
        pub const DISPATCH: i64 = 0;
        pub const HEARTBEAT: i64 = 1;
        pub const IDENTIFY: i64 = 2;
        pub const RESUME: i64 = 6;
        pub const RECONNECT: i64 = 7;
        pub const INVALID_SESSION: i64 = 9;
        pub const HELLO: i64 = 10;
        pub const HEARTBEAT_ACK: i64 = 11;
    }

    /// 网关连接配置。
    #[derive(Clone, Debug)]
    pub struct GatewayConfig {
        /// 网关 wss 接入点（默认 [`DEFAULT_GATEWAY_URL`]）。
        pub url: String,
        /// 已获取的 `access_token`（**不含** `QQBot ` 前缀，构造 Identify 时统一加）。
        pub token: String,
        /// 事件订阅意图位掩码，由 [`intents`] 按需按位或得到。
        pub intents: u32,
        /// 分片 `(shard_id, shard_count)`，单实例为 `(0, 1)`。
        pub shard: (u32, u32),
    }

    impl Default for GatewayConfig {
        fn default() -> Self {
            Self {
                url: String::from(DEFAULT_GATEWAY_URL),
                token: String::new(),
                intents: intents::GROUP_AT_MESSAGE_CREATE | intents::C2C_MESSAGE_CREATE,
                shard: (0, 1),
            }
        }
    }

    /// 一条 dispatch 事件的透传载体（原始 JSON 交给调用方，复用 [`crate::event`] 解析）。
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Dispatch {
        /// 顶层事件类型（`t`，如 `C2C_MESSAGE_CREATE`）。
        pub t: Option<String>,
        /// 序列号（`s`，用于心跳/续连）。
        pub s: Option<i64>,
        /// 整帧原始 JSON 文本（含 `op`/`d`/`t`/`s`，可直接喂给 [`crate::event::parse_message_event`]）。
        pub raw: String,
    }

    /// 网关客户端错误。
    #[derive(Debug)]
    pub enum GatewayError {
        /// wtx 传输层错误（TLS / 握手 / 帧编解码）。
        Wtx(wtx::Error),
        /// 核心库 JSON 解析错误（复用 [`crate::callback`] 提取字段时传播）。
        Core(crate::error::Error),
        /// 协议层错误：必备字段缺失或形态非法。
        Protocol(&'static str),
        /// 收到 op=7/9，应重建连接（外层 `run` 据此重连）。
        Reconnect,
    }

    impl core::fmt::Display for GatewayError {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match self {
                Self::Wtx(e) => write!(f, "wtx transport error: {e}"),
                Self::Core(e) => write!(f, "core parse error: {e}"),
                Self::Protocol(reason) => write!(f, "gateway protocol error: {reason}"),
                Self::Reconnect => f.write_str("gateway requested reconnect"),
            }
        }
    }

    impl core::error::Error for GatewayError {}

    impl From<wtx::Error> for GatewayError {
        fn from(e: wtx::Error) -> Self {
            Self::Wtx(e)
        }
    }

    impl From<crate::error::Error> for GatewayError {
        fn from(e: crate::error::Error) -> Self {
            Self::Core(e)
        }
    }

    /// 网关运行入口：连接 → 事件循环 → 断线按退避重连，仅在致命错误时返回。
    ///
    /// `on_dispatch` 在每次收到 dispatch 时被同步调用（借用当前帧缓冲，调用返回后即失效，
    /// 需长期持有请自行 clone `raw`）。
    pub async fn run<F>(config: &GatewayConfig, mut on_dispatch: F) -> Result<(), GatewayError>
    where
        F: FnMut(&Dispatch),
    {
        let mut backoff = Duration::from_secs(1);
        loop {
            match connect_once(config, &mut on_dispatch).await {
                Ok(()) => return Ok(()),
                Err(GatewayError::Reconnect) => {
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// 单次连接的生命周期：TLS 握手 → WebSocket 升级 → 读/写/桥接三线并发 → 退出。
    async fn connect_once<F>(
        config: &GatewayConfig,
        on_dispatch: &mut F,
    ) -> Result<(), GatewayError>
    where
        F: FnMut(&Dispatch),
    {
        let uri = Uri::new(config.url.clone());
        let tls = TlsConnectorBuilder::tokio(uri)
            .build(TlsConfig::from_ccadb()?, ChaCha20::from_getrandom()?)
            .await?;
        let ws = WebSocketConnector::default().connect(tls).await?;
        let (bridge, mut reader, writer) = ws.into_split()?;
        let writer = Arc::new(AsyncMutex::new(writer));

        // 跨读写共享的序列号（心跳读取、dispatch 写入）。
        let seq = Arc::new(AsyncMutex::new(None::<i64>));
        // 心跳间隔（收到 Hello 后由读线写入）。
        let interval = Arc::new(AsyncMutex::new(None::<u64>));

        // 桥接线：自动处理 Ping→Pong、Close 握手（并发模式下 read_frame 不自动处理）。
        let bridge_writer = writer.clone();
        let bridge_task = tokio::spawn(async move {
            loop {
                let data = bridge.listen().await;
                if bridge_writer.lock().await.manage_bridge_data(data).await? {
                    break;
                }
            }
            wtx::Result::Ok(())
        });

        // 心跳线：按 Hello 告知的间隔周期发送 op=1，序列号取最新 dispatch 的 `s`。
        let hb_writer = writer.clone();
        let hb_seq = seq.clone();
        let hb_interval = interval.clone();
        let hb_task = tokio::spawn(async move {
            let mut last = tokio::time::Instant::now();
            loop {
                tokio::time::sleep(Duration::from_millis(250)).await;
                let iv = *hb_interval.lock().await;
                if let Some(iv) = iv {
                    if last.elapsed() >= Duration::from_millis(iv) {
                        last = tokio::time::Instant::now();
                        let s = *hb_seq.lock().await;
                        let body = build_heartbeat(s);
                        // 心跳为尽力而为：构造或发送失败直接跳过本周期，不中断网关。
                        // 用 owned Vec<u8> 作为帧载荷，同时满足 new_fin 的 Lease 与
                        // write_frame 的 LeaseMut 约束（&[u8] 不满足 LeaseMut）。
                        let mut frame = match Frame::new_fin(OpCode::Text, body.into_bytes()) {
                            Ok(frame) => frame,
                            Err(_) => continue,
                        };
                        let _ = hb_writer.lock().await.write_frame(&mut frame).await;
                    }
                }
            }
        });

        let mut buffer = Vector::new();
        let mut result = Ok(());
        'session: loop {
            let frame = match reader
                .read_frame(&mut buffer, WebSocketPayloadOrigin::Adaptive)
                .await
            {
                Ok(frame) => frame,
                Err(e) => {
                    result = Err(GatewayError::Wtx(e));
                    break 'session;
                }
            };
            match frame.op_code() {
                // 桥接线已自动回 Close 握手，此处干净退出。
                OpCode::Close => break 'session,
                // 控制帧交给桥接线，读线不处理。
                OpCode::Ping | OpCode::Pong => continue,
                _ => {
                    let text = match frame.text_payload() {
                        Some(text) => text.to_string(),
                        None => continue,
                    };
                    let payload = match parse_payload(&text) {
                        Ok(payload) => payload,
                        Err(_) => continue,
                    };
                    match payload.op {
                        op::HELLO => {
                            let iv = match extract_heartbeat_interval(&text) {
                                Ok(iv) => iv,
                                Err(_) => {
                                    result = Err(GatewayError::Protocol("hello missing interval"));
                                    break 'session;
                                }
                            };
                            *interval.lock().await = Some(iv);
                            let identify =
                                build_identify(&config.token, config.intents, config.shard);
                            let mut frame = Frame::new_fin(OpCode::Text, identify.into_bytes())?;
                            if let Err(e) = writer.lock().await.write_frame(&mut frame).await {
                                result = Err(GatewayError::Wtx(e));
                                break 'session;
                            }
                        }
                        op::DISPATCH => {
                            if let Some(s) = payload.s {
                                *seq.lock().await = Some(s);
                            }
                            on_dispatch(&Dispatch {
                                t: payload.t.clone(),
                                s: payload.s,
                                raw: text,
                            });
                        }
                        op::HEARTBEAT_ACK => {}
                        // 服务端要求重连 / 会话失效 → 外层退避后重建。
                        op::RECONNECT | op::INVALID_SESSION => {
                            result = Err(GatewayError::Reconnect);
                            break 'session;
                        }
                        _ => {}
                    }
                }
            }
        }

        hb_task.abort();
        bridge_task.abort();
        result
    }

    /// 解析单帧 JSON 的基础字段（op / s / t）。
    fn parse_payload(text: &str) -> Result<Payload, GatewayError> {
        let bytes = text.as_bytes();
        let op = json_i64(bytes, b"op")?.ok_or(GatewayError::Protocol("frame missing op"))?;
        let s = json_i64(bytes, b"s")?;
        let t = json_str(bytes, b"t")?.map(String::from);
        Ok(Payload { op, s, t })
    }

    /// 从 Hello 帧提取 `heartbeat_interval`（毫秒）。
    fn extract_heartbeat_interval(text: &str) -> Result<u64, GatewayError> {
        json_i64(text.as_bytes(), b"heartbeat_interval")?
            .ok_or(GatewayError::Protocol("hello missing heartbeat_interval"))
            .map(|value| value.max(0) as u64)
    }

    /// 从 READY dispatch 提取 `session_id`（用于续连；本实现重连时直接重新 Identify，故仅记录）。
    #[allow(dead_code)]
    fn extract_session_id(text: &str) -> Option<String> {
        json_str(text.as_bytes(), b"session_id")
            .ok()
            .flatten()
            .map(String::from)
    }

    struct Payload {
        op: i64,
        s: Option<i64>,
        t: Option<String>,
    }

    /// 构造 Identify 帧（op=2）：统一加 `QQBot ` 前缀，附带意图与分片。
    pub fn build_identify(token: &str, intents: u32, shard: (u32, u32)) -> String {
        format!(
            "{{\"op\":2,\"d\":{{\"token\":\"QQBot {}\",\"intents\":{},\"shard\":[{},{}]}}}}",
            json_escape(token),
            intents,
            shard.0,
            shard.1
        )
    }

    /// 构造 Resume 帧（op=6）：重连时携带 session_id 与最新 seq。
    pub fn build_resume(token: &str, session_id: &str, seq: Option<i64>) -> String {
        let seq = match seq {
            Some(s) => s.to_string(),
            None => "null".to_string(),
        };
        format!(
            "{{\"op\":6,\"d\":{{\"token\":\"QQBot {}\",\"session_id\":\"{}\",\"seq\":{}}}}}",
            json_escape(token),
            json_escape(session_id),
            seq
        )
    }

    /// 构造 Heartbeat 帧（op=1）：未收到 dispatch 前 `d` 为 `null`。
    pub fn build_heartbeat(seq: Option<i64>) -> String {
        match seq {
            Some(s) => format!("{{\"op\":1,\"d\":{s}}}"),
            None => String::from("{\"op\":1,\"d\":null}"),
        }
    }

    /// JSON 字符串内容最小转义（token / session_id 内联用，防注入）。
    fn json_escape(text: &str) -> String {
        let mut out = String::with_capacity(text.len() + 8);
        for ch in text.chars() {
            match ch {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn builds_identify_with_prefix_and_shard() {
            let frame = build_identify("TOKEN123", 33_554_432, (0, 1));
            assert!(frame.contains("\"op\":2"));
            assert!(frame.contains("\"token\":\"QQBot TOKEN123\""));
            assert!(frame.contains("\"intents\":33554432"));
            assert!(frame.contains("\"shard\":[0,1]"));
        }

        #[test]
        fn builds_heartbeat_with_and_without_seq() {
            assert_eq!(build_heartbeat(None), "{\"op\":1,\"d\":null}");
            assert_eq!(build_heartbeat(Some(42)), "{\"op\":1,\"d\":42}");
        }

        #[test]
        fn builds_resume_with_session() {
            let frame = build_resume("TOKEN", "SES-1", Some(7));
            assert!(frame.contains("\"op\":6"));
            assert!(frame.contains("\"token\":\"QQBot TOKEN\""));
            assert!(frame.contains("\"session_id\":\"SES-1\""));
            assert!(frame.contains("\"seq\":7"));
            let frame = build_resume("TOKEN", "SES-1", None);
            assert!(frame.contains("\"seq\":null"));
        }

        #[test]
        fn parses_dispatch_payload() {
            let text = r#"{"op":0,"s":5,"t":"C2C_MESSAGE_CREATE","d":{"id":"m1"}}"#;
            let p = parse_payload(text).unwrap();
            assert_eq!(p.op, 0);
            assert_eq!(p.s, Some(5));
            assert_eq!(p.t.as_deref(), Some("C2C_MESSAGE_CREATE"));
        }

        #[test]
        fn extracts_hello_interval_and_ready_session() {
            let hello = r#"{"op":10,"d":{"heartbeat_interval":45000}}"#;
            assert_eq!(extract_heartbeat_interval(hello).unwrap(), 45000);
            assert!(extract_heartbeat_interval(r#"{"op":10}"#).is_err());

            let ready = r#"{"op":0,"t":"READY","d":{"session_id":"abc-123","shard":[0,1]}}"#;
            assert_eq!(extract_session_id(ready).as_deref(), Some("abc-123"));
            assert_eq!(extract_session_id(r#"{"op":0,"t":"X","d":{}}"#), None);
        }
    }
}

#[cfg(feature = "gateway-wtx")]
pub use live::{
    Dispatch, GatewayConfig, GatewayError, build_heartbeat, build_identify, build_resume, run,
};

/// 网关事件订阅意图位（见 QQ开放平台《接口权限 / Intents》文档）。
///
/// 实际生效值以官方文档为准；本库仅提供命名常量，调用方按需按位或。
/// 官方新接口中 `GROUP_AT_MESSAGE_CREATE` 与 `C2C_MESSAGE_CREATE` 共用 `1 << 25` 位，
/// 若你的应用权限模型不同，请按官方文档调整。
pub mod intents {
    /// 频道相关：GUILDS。
    pub const GUILDS: u32 = 1 << 0;
    /// 频道成员变更。
    pub const GUILD_MEMBERS: u32 = 1 << 1;
    /// 频道消息。
    pub const GUILD_MESSAGES: u32 = 1 << 9;
    /// 频道消息反应。
    pub const GUILD_MESSAGE_REACTIONS: u32 = 1 << 10;
    /// 私信消息。
    pub const DIRECT_MESSAGE: u32 = 1 << 12;
    /// 群 @ 机器人消息。
    pub const GROUP_AT_MESSAGE_CREATE: u32 = 1 << 25;
    /// 单聊（C2C）消息，与群 @ 共用 `1 << 25` 位。
    pub const C2C_MESSAGE_CREATE: u32 = 1 << 25;
    /// 互动事件（按钮等）。
    pub const INTERACTION: u32 = 1 << 26;
    /// 消息审核。
    pub const MESSAGE_AUDIT: u32 = 1 << 27;
    /// 论坛事件。
    pub const FORUM_EVENT: u32 = 1 << 28;
    /// 音频动作。
    pub const AUDIO_ACTION: u32 = 1 << 29;
    /// 频道公域消息。
    pub const PUBLIC_GUILD_MESSAGES: u32 = 1 << 30;
}
