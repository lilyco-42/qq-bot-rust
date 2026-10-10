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
- [x] 斜杠指令 + AI 问答（`commands.rs`：仅 `/` 前缀识别指令（无点号）、未知指令
  与裸 `/` 回提示指向 `/帮助`、非指令正文 → `Reply::Ask`；bin 侧 spawn
  `ZEROSTACK_BIN --no-tools --no-context-files --no-session --no-color -p` 单发问答：
  双线程排空 stdout/stderr、50ms 轮询到超时 kill、ANSI/控制字符清洗、
  按字数截断（平台无公开上限，保守可配）；未启用/失败回显式兜底文案不装死；
  `cargo test` 61 项全绿）
- [x] 服务器状态查询 `/对局`（别名 `/状态`、`/服务器`）：只读公开 HTTP 接口，不改动
  游戏/大厅服务器——游戏 `/healthz` 给在线人数/对局数/房间数（出现 `matching`/`queued`
  字段时补报快速匹配队列，前向兼容 0.2.3），大厅 `/api/online_count` + `/api/active_rooms`
  给在线人数/房间数；三个请求相互独立，任一失败只少一行、全失败回显式兜底；
  地址经 `SP_STATUS_URL` / `LOBBY_BASE_URL` 可指向自建服；`cargo test` 66 项全绿）
- [x] 组队大厅房间查询 `/房间`（别名 `/组队`、`/大厅`）：机器人专用账号登录后只读
  `GET /lobby/api/rooms`，列出等待中的房间（名称/公开私密/人数/房主在线），
  access token 缓存、401 时先用 refresh token 换新（轮换式）或重登后有界重试一次；
  账号经 `LOBBY_USER` / `LOBBY_PASS` 注入（`SecretString`，永不进日志），
  `WEBHOOK_LOBBY=0` 关闭；`cargo test` 78 项全绿）
- [x] WebSocket 兼容链路（wtx 生态，feature `gateway-wtx`）：no_std WebSocket + TLS(CCADB 根证书)
  直连 `wss://api.bot.qq.com/websocket`，Hello/Identify/Heartbeat/Dispatch/Reconnect 全协议闭环；
  `cargo check --features gateway-wtx` 编译验收通过（零警告），真机端到端验收待 `QQ_ACCESS_TOKEN`
  实跑（官方已宣布下线，仅作过渡）

## WebSocket 网关（wtx 生态传输层）

README 末尾待办项的落地实现：用 [`wtx`](https://crates.io/crates/wtx) 0.52.1 的 no_std WebSocket
+ TLS（Mozilla CCADB 根证书）直连官方网关，按 Discord 派生标准协议完成全流程。

**启用方式**（启用后整库以 std 构建，核心协议层仍可独立 no_std 编译）：

```sh
cargo run --example gateway_wtx --features gateway-wtx
# 需先 export QQ_ACCESS_TOKEN="<token>"（本示例不内置 REST 取 token）
```

**设计要点（延续 issue #61 反模式防线）**：

- 协议/传输解耦：本模块只负责"连上网关并把每条 dispatch 的原始 JSON 交给调用方"，
  `Dispatch.raw` 直接喂给既有 `event::parse_message_event`，与 webhook 路径同构，不重复解析；
- 凭证不下放：传入已获取的 `access_token`，`token` 字段构造时统一加 `QQBot ` 前缀，库内不打印；
- 失败上抛：TLS/握手/解析错误一律返回 `GatewayError`，断线按指数退避重连，致命错才退出；
- 零 panic / 无共享可变状态：`seq` 按值传递，心跳与读取各跑独立 tokio task。

**feature 组成**（`gateway-wtx`）：`tokio` + `wtx/std` + `wtx/web-socket` + `wtx/tls` +
`wtx/crypto-ring` + `wtx/ccadb` + `wtx/getrandom` + `wtx/tokio`。

> 选型说明：wtx 锁定 0.52.1（crates.io，不追 main 分支——main 与 0.52.1 的 WebSocket/TLS API 差异显著）。
> wtx 的 `from_std_random` 需其 `nightly` cargo feature，本库改用 `getrandom` 后端取 CSPRNG 种子，
> 因此不引入额外 nightly 门槛（项目本身仍按 `rust-toolchain.toml` 用 nightly 通道）。

## Radxa 部署（aarch64，验收现场）

```sh
# 交叉编译（静态 musl）
#   memory = 记忆库（Turso）；tools = 资源调用（gh / 网页 / MC）。不启用则相应命令给出提示。
cargo zigbuild --release --target aarch64-unknown-linux-musl --features memory,tools
# 部署：scp target/aarch64-unknown-linux-musl/release/webhook_server radxa@192.168.10.165:qq_bot/
# 凭证注入（env.sh，chmod 600，绝不进 ps 命令行/仓库）：
#   export QQ_BOT_SECRET=...  export WEBHOOK_BIND=0.0.0.0:8080  export QQ_APPID=...
#   export NIM_API_KEY=...          # AI 问答免费模型 key（同上，不进仓库/日志）
#   export ZEROSTACK_BIN=~/.local/bin/zerostack   # 直连 NIM 推理接口（无需代理）
# 可选：WEBHOOK_QA=0 关问答；QA_TIMEOUT_SECS（默认120，5..=600）；QA_MAX_CHARS（默认1000，50..=4000）
#   QA_PROVIDER / QA_MODEL 覆盖 zerostack 的 provider/model（切 NIM/OpenRouter；留空沿用 config.toml）
# 可选：WEBHOOK_STATUS=0 关 /对局 状态查询；SP_STATUS_URL / LOBBY_BASE_URL 换自建服地址
# 可选：WEBHOOK_LOBBY=0 关 /房间 房间查询；LOBBY_USER / LOBBY_PASS = 大厅机器人专用账号
# 可选：MEMORY_DB（默认 memory.db）记忆库路径；BOT_TOPIC（默认「明日方舟卫戍协议」）群默认话题
# 可选：GH_REPO=owner/repo（/issue 检索、/提单 建单）；GH_WRITE=1 才允许 gh 写操作（默认关闭）
# 可选：MINECRAFT_API_URL（/mc 我的世界后台）；WEB_FETCH_ALLOW_PRIVATE=1 才允许 /网站 抓内网
# AI 问答（zerostack v1.8.4，aarch64-musl 静态单二进制 → ~/.local/bin/）：
#   ~/.config/zerostack/config.toml            # provider=nim，model=nvidia/nemotron-3-super-120b-a12b
#                                              #   2026-10 实测 Radxa 直连 ~3–6s、中文干净（旧
#                                              #   deepseek-v4.1-flash 直连 POST 挂起，已弃用）
#   ~/.local/share/zerostack/prompts/qqbot.md  # 回答风格 prompt（首行 %%mode=readonly）
#   切换后端：config.toml 内含 [custom_providers.openrouter]（openrouter.ai/api/v1，
#     api_key_env=OPENROUTER_API_KEY）；env.sh 设 OPENROUTER_API_KEY + QA_PROVIDER=openrouter
#     + QA_MODEL=<模型 id> 即可切到 OpenRouter，无需改代码
# 启动（fd 全脱离，ssh 会话不挂起）：
nohup sh -c 'cd ~/qq_bot && set -a && . ./env.sh && set +a && exec ./webhook_server >> server.log 2>&1' </dev/null >/dev/null 2>&1 &
# 公网回调（无公网 IP 时的 cloudflared 快速隧道，URL 每次重启变化，需回控制台重配）：
nohup sh -c 'cd ~/qq_bot && ./cloudflared tunnel --url http://127.0.0.1:8080 >> tunnel.log 2>&1' </dev/null >/dev/null 2>&1 &
```

- 回调地址：控制台 → 开发设置 → 事件订阅与回调 → 回调地址（HTTPS，仅 80/443/8080/8443）；
- 自测工具：`SIGN_SECRET=... SIGN_TS=... SIGN_BODY='...' cargo run --example sign_event`
  生成事件签名，可离线复验整条公网推送链。

## 记忆与资源调用（`memory` / `tools` feature）

### 记忆：像人一样会忘，也会越记越牢

存储用 **Turso**（SQLite 的 Rust 重写，纯 Rust、无 C 依赖，与 musl 静态交叉编译零摩擦）。
依赖刻意写 `default-features = false`：默认集里的 `fts` 模块在当前 nightly 下编译失败，
而记忆检索走 `LIKE` + 自研评分，**不需要 FTS**（顺带去掉 mimalloc 给静态二进制瘦身）。

- **遗忘**：`strength × 2^(-Δt / half_life)`，`half_life = 7 天 × importance²`
  —— 琐碎闲聊（0.3）半衰期约 0.6 天，隔夜就淡；重要事实（2.0）约 28 天。
  「忘记今天吃了什么、但记得重要的事」就靠这条平方关系拉开差距。
- **强化**：同一件事再次被问到或检索命中 → `freq += 1`、强度回补 0.4（上限 1.0）。
  反复出现的事自然沉淀为长期记忆（需求里的「记录出现频次」）。
- **排序**：`score = importance × ln(1+freq) × 有效强度`（`ln` 让频次边际收益递减，
  被提 100 次不会压过真正重要的事）。
- **自动沉淀**：群内一问一答自动写入 `issue` 记忆（含提问者 openid），
  于是「之前是不是有人问过 / 同一个人问过吗」可被直接回答（`/issue`）。
- 启动时做一次遗忘清理，剔除已衰减到阈值以下的条目。

### 资源调用

| 命令 | 能力 | 前提 |
|------|------|------|
| `/记 <内容>` | 记下重要事实（高重要度，不易忘） | `memory` |
| `/忆 [关键词]` | 回忆（不带词=重要记忆概览） | `memory` |
| `/issue <关键词>` | 本地记忆 + `gh issue list --search` 搜仓库 | `tools` + gh 已登录 |
| `/提单 <标题>` | `gh issue create` 建 issue | `tools` + `GH_WRITE=1` |
| `/网站 <url>` | 抓取网页正文（去标签 + 截断） | `tools` |
| `/mc` | 我的世界服务器后台状态 | `tools` + `MINECRAFT_API_URL` |
| `/话题` | 展示群默认话题（默认「明日方舟卫戍协议」） | — |

安全基线（沿用 botgo issue #61 的结构性规避）：

- **不执行任意命令**：只按白名单拼接固定子命令，用户参数作为独立 argv 传入、不经 shell；
- **gh 写操作默认关闭**：避免群成员随意在仓库建 issue；
- **防 SSRF**：网页抓取默认拒绝内网地址（bot 本身在局域网内，放任抓取等于暴露内网）；
- **超时 + 截断**：所有外部调用有界，不把巨量正文灌进群；失败一律显式回应，不装死。

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

- **工具链**：`rust-toolchain.toml` 锁定 nightly 通道（wtx 部分特性依赖未稳定 API）。
  本库所用 wtx feature 子集（WebSocket/TLS/CCADB/crypto-ring/getrandom/tokio，锁定 0.52.1）
  在 nightly 通道下编译通过；网关取 CSPRNG 种子走 `getrandom` 后端，**未**启用 wtx 的 `nightly`
  cargo feature（避免 `from_std_random` 的额外门槛）。
- **cargo-xmake**：`.cargo/config.toml` 中带 `# cargo-xmake` 标记的行由 `cargo xmake setup` 生成
  （debug 档 xmake 级构建速度，release 保持全静态派发），勿手工改动标记。
