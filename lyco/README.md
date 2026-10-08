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

- [x] 骨架 + webhook Ed25519 验签 / 回调握手签名
- [x] 回调报文最小解析 `callback.rs`（op/字段提取，严格失败；单测覆盖转义、
  字符串内同名文本、截断等边界）
- [x] Webhook 服务端 `src/bin/webhook_server.rs`（std 运行时；手搓 HTTP/1.1
  解析 = wtx `httparse` feature 同款解析器直依赖——wtx 未对外 re-export，
  且其 Cargo.toml 无 HTTP/1.1 服务端框架；每连接一线程、读写超时、
  零 panic、`QQ_BOT_SECRET` 只经环境变量注入 `SecretString`）
- [x] **真实平台端到端验收（2026-10-09）**：开放平台控制台切换 WebSocket→Webhook
  时 op=13 挑战签名被平台验证通过；用户私聊消息经公网隧道推送至 Radxa A7a，
  `event verified` + EVENT 日志打印（`C2C_MESSAGE_CREATE` / `GROUP_MEMBER_ADD`）
- [x] AppAccessToken 获取与自动续期（`api.rs` + bin 内 `Arc<Mutex>` 缓存，
  60s 刷新余量、锁不跨 IO、仅 401 强制刷新重试一次；凭证脱敏）
- [x] 消息收发：`event.rs` 解析 C2C/群消息事件 → `commands.rs` 指令分发 →
  OpenAPI 被动回复（`POST /v2/users|groups/{openid}/messages`）；
  webhook 200 先行 ACK、工作线程发送；`cargo test` 56 项全绿
- [ ] 问答与更多指令（zerostack 单发问答、`/` 指令前缀）
- [ ] WebSocket 兼容链路（官方已宣布下线，仅作过渡）

## Radxa 部署（aarch64，验收现场）

```sh
# 交叉编译（静态 musl）
cargo zigbuild --release --target aarch64-unknown-linux-musl
# 部署：scp target/aarch64-unknown-linux-musl/release/webhook_server radxa@192.168.10.165:qq_bot/
# 凭证注入（env.sh，chmod 600，绝不进 ps 命令行/仓库）：
#   export QQ_BOT_SECRET=...  export WEBHOOK_BIND=0.0.0.0:8080  export QQ_APPID=...
# 启动（fd 全脱离，ssh 会话不挂起）：
nohup sh -c 'cd ~/qq_bot && set -a && . ./env.sh && set +a && exec ./webhook_server >> server.log 2>&1' </dev/null >/dev/null 2>&1 &
# 公网回调（无公网 IP 时的 cloudflared 快速隧道，URL 每次重启变化，需回控制台重配）：
nohup sh -c 'cd ~/qq_bot && ./cloudflared tunnel --url http://127.0.0.1:8080 >> tunnel.log 2>&1' </dev/null >/dev/null 2>&1 &
```

- 回调地址：控制台 → 开发设置 → 事件订阅与回调 → 回调地址（HTTPS，仅 80/443/8080/8443）；
- 自测工具：`SIGN_SECRET=... SIGN_TS=... SIGN_BODY='...' cargo run --example sign_event`
  生成事件签名，可离线复验整条公网推送链。

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
