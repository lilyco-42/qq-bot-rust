//! wtx WebSocket 网关客户端演示。
//!
//! 用法：
//! ```sh
//! # 先取一次 access_token（本示例不内置 REST 取 token，请用项目的 api 模块或官方工具获取）
//! export QQ_ACCESS_TOKEN="<your-access-token>"
//! # 可选：覆盖网关地址（默认 wss://api.bot.qq.com/websocket）
//! export QQ_GATEWAY_URL="wss://api.bot.qq.com/websocket"
//! cargo run --example gateway_wtx --features gateway-wtx
//! ```
//!
//! 演示重点：用 wtx 的 no_std WebSocket + TLS(CCADB) 直连网关，收到 dispatch 后复用
//! 核心库的 [`qq_bot_rust::event`] 解析消息事件——与 webhook 路径同构。

use qq_bot_rust::event::{is_message_event, parse_message_event};
use qq_bot_rust::gateway::intents;
use qq_bot_rust::gateway::{Dispatch, GatewayConfig, run};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let token = match std::env::var("QQ_ACCESS_TOKEN") {
        Ok(token) if !token.is_empty() => token,
        _ => {
            eprintln!(
                "缺少 QQ_ACCESS_TOKEN：请先获取 access_token 后 export 再运行 \
                 （本示例不内置 REST 取 token）。"
            );
            return Ok(());
        }
    };

    let mut config = GatewayConfig::default();
    config.token = token;
    // 订阅群 @ 与单聊消息（其余意图按需按位或，见 `intents` 模块）。
    config.intents = intents::GROUP_AT_MESSAGE_CREATE | intents::C2C_MESSAGE_CREATE;
    if let Ok(url) = std::env::var("QQ_GATEWAY_URL") {
        config.url = url;
    }

    println!(
        "[gateway] connecting to {} (intents={})",
        config.url, config.intents
    );

    run(&config, |dispatch: &Dispatch| {
        on_dispatch(dispatch);
    })
    .await
    .map_err(|err| -> Box<dyn std::error::Error> { Box::new(err) })?;

    Ok(())
}

/// 事件分发回调：复用核心库的事件解析，与 webhook 路径完全一致。
fn on_dispatch(dispatch: &Dispatch) {
    match dispatch.t.as_deref() {
        Some(t) if is_message_event(t) => match parse_message_event(dispatch.raw.as_bytes(), t) {
            Ok(event) => println!(
                "[event] {} from {:?} group={:?} content={:?}",
                event.event_type, event.user_openid, event.group_openid, event.content
            ),
            Err(err) => eprintln!("[event-parse-error] {}: {}", t, err),
        },
        Some("READY") => println!("[gateway] READY, session established"),
        Some(t) => println!("[dispatch] t={} s={:?}", t, dispatch.s),
        None => println!("[dispatch] untyped s={:?}", dispatch.s),
    }
}
