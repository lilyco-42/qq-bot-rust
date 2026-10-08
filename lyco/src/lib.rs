//! `qq_bot_rust` —— QQ 机器人 OpenAPI SDK。
//!
//! # 设计基线
//!
//! - 核心为 `no_std + alloc`，传输层（HTTP/TLS/WebSocket）由 wtx 生态按 feature 渐进引入；
//! - 遵循 Linux 内核开发规范：小函数、无魔数、错误码语义清晰、零 `unsafe`、无隐藏全局状态；
//! - 针对 [tencent-connect/botgo issue #61](https://github.com/tencent-connect/botgo/issues/61)
//!   列举的五类反模式做结构性规避：
//!
//!   1. **凭证不进日志**：[`secret::SecretString`] 的 `Debug`/`Display` 恒定脱敏，
//!      取明文必须显式 [`expose`](secret::SecretString::expose)；
//!   2. **日志分级可控**：本库不自造 logger，不打印任何凭证；
//!   3. **库内零 panic**：所有失败路径返回 [`error::Result`]，不 `unwrap`/`expect`/`panic!`；
//!   4. **无数据竞争**：不设共享可变状态（如裸 `lastTraceID`），trace 标识随值传递；
//!   5. **错误不吞**：解析/验签失败必须上抛，禁止"打日志继续跑"。
#![cfg_attr(not(test), no_std)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

extern crate alloc;

pub mod api;
pub mod callback;
pub mod commands;
pub mod crypto;
pub mod error;
pub mod event;
pub mod secret;

pub use error::{Error, Result};
