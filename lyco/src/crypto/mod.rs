//! 密码学原语。
//!
//! 目前包含 webhook 回调链路所需的 Ed25519 操作，算法与参数完全对齐官方文档：
//! - [安全和授权（签名算法）](https://bot.q.qq.com/wiki/develop/api-v2/dev-prepare/interface-framework/sign.html)
//! - [Webhook 方式（回调握手）](https://bot.q.qq.com/wiki/develop/api-v2/dev-prepare/event-emit/webhook.html)

pub mod webhook;
