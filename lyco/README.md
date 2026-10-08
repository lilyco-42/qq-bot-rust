# qq_bot_rust

QQ 机器人 OpenAPI SDK —— `no_std + alloc` 核心，wtx 生态传输层，cargo-xmake 加速开发构建。

## 设计基线（对照 botgo issue #61）

| issue #61 反模式 | 本库防线 |
| --- | --- |
| appsecret / access_token 明文进日志 | `secret::SecretString`：`Debug`/`Display` 恒脱敏，取明文必须 `expose()`（调用点即审计点） |
| 日志级别不可控、关不掉 | 库内不自造 logger、不打印任何凭证；分级交给使用方的 `log` facade |
| token 服务不可用即 panic | 全库零 panic：失败一律 `Result` 上抛，`#![deny(unsafe_code)]` |
| `lastTraceID` 无锁数据竞争 | 无共享可变状态：trace 标识随请求上下文/错误值按值传递 |
| 解析失败只打日志继续跑 | 解析/验签失败必须上抛，调用方拿不到结果就无法"继续跑" |

## 状态

- [x] 骨架 + webhook Ed25519 验签 / 回调握手签名（11 测试全绿：单测 10 + doctest 1；
  `cargo fmt` 与 `cargo clippy -- -D warnings` 干净）
- [ ] AppAccessToken 获取与自动续期（错误上抛、凭证脱敏）
- [ ] OpenAPI endpoint（消息收发起步）
- [ ] Webhook 服务端（wtx HTTP server + 事件分发）
- [ ] WebSocket 兼容链路（官方已宣布下线，仅作过渡）

## 预研结论（已验证的官方文档坑）

- **`sign.html` 验签 DEMO 的 `sig` 是占位值**：官方公钥对 `timestamp+body` 验不过、
  用官方 seed 重签也对不上——全生态已知（bofa-qqbot 用 vitest `it.fails` 标注该向量
  预期失败；tgmon 实测后注明"文档随手填的占位值"）。本库改为用官方 seed 自签自验
  锁定拼接顺序；公钥派生与 op=13 握手签名两个官方向量仍逐字节通过。
- **op=13 回调握手可能不带 `X-Signature-*` 头**，不应强制验签（tgmon 实测官方 SDK
  也放行）；op=0 事件推送必须验签，缺失/非法一律拒绝。
- **Bot Secret 就是 getAppAccessToken 的 clientSecret**：验签与取 token 是同一凭证，
  不存在第二个签名密钥。
- 回调地址仅允许端口 80/443/8080/8443 且需 HTTPS；OpenAPI 统一基址
  `https://api.bot.qq.com`，鉴权头 `Authorization: QQBot {ACCESS_TOKEN}`，
  失败响应以 `err_code` 判定（勿依赖 `message`），trace 从 `X-Tps-trace-ID`
  响应头或 `trace_id` 字段取——按请求携带，不做全局共享（issue61-④）。

## 工具链

- **nightly 必需**：wtx 使用 `#![feature(random, return_type_notation)]`，见 `rust-toolchain.toml`；
- **cargo-xmake**：`.cargo/config.toml` 中带 `# cargo-xmake` 标记的行由 `cargo xmake setup` 生成
  （debug 档 xmake 级构建速度，release 保持全静态派发），勿手工改动标记。
