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
# 首装（一次性，之后不再需要 ssh 上来）：systemd 常驻 + 自更新定时器
scp -r deploy radxa@192.168.10.165:~/qq_bot/
ssh radxa@192.168.10.165 'sudo bash ~/qq_bot/deploy/install.sh'
# 公网回调（无公网 IP 时的 cloudflared 快速隧道，URL 每次重启变化，需回控制台重配）：
nohup sh -c 'cd ~/qq_bot && ./cloudflared tunnel --url http://127.0.0.1:8080 >> tunnel.log 2>&1' </dev/null >/dev/null 2>&1 &
```

### ⚠️ `env.sh` 不要写 `export` 前缀（2026-10-10 实机踩坑）

systemd 的 `EnvironmentFile=` **不认 shell 语法**：`export QQ_BOT_SECRET=...` 这一行会被
当成非法赋值**整行忽略**（journal 里能看到 `Ignoring invalid environment assignment`），
后果是服务起来了却因为「没拿到 secret」立刻 exit 1，而且重启循环。

```sh
# ✅ 正确：裸 KEY=VALUE（systemd 自动注入子进程环境）
QQ_BOT_SECRET=...
# ❌ 错误：export 前缀会被 systemd 丢掉
export QQ_BOT_SECRET=...
```

需要手工 source 时用 `set -a` 补上导出语义：

```sh
set -a && . ./env.sh && set +a && ./webhook_server
```

⚠️ 附带教训：这个错误还会把**整行含密钥的内容原样写进 journal**。改完 `env.sh` 记得
`sudo journalctl --rotate && sudo journalctl --vacuum-time=1s`，并视情况轮换泄露过的
token（GH_TOKEN / 模型 API key）。

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

## 无人维护：自更新 / 自检 / 长期兼容

目标很直白：**服务器不需要人管**。你只改代码、推 tag，剩下的它自己做。

### 一条链：tag → 构建 → 自动换版

```
本机 git push --tags v1.2.3
   └─ .github/workflows/release.yml  先跑测试，再 zigbuild aarch64-musl
         └─ Release 资产：webhook_server + webhook_server.sha256
               └─ Radxa 上 qqbot-update.timer（每 10 分钟）
                     └─ update.sh：比版本 → 下载 → sha256 校验 → 装前试执行
                                    → 原子替换 → 重启 → 健康检查 → 失败回滚
```

`deploy/` 里的四件东西：

| 文件 | 作用 |
|------|------|
| `qqbot.service` | 常驻服务：`Restart=always`，崩溃 60s 内超 5 次则停下（不刷爆 QQ 接口） |
| `qqbot-update.timer` | 每 10 分钟（±60s 抖动）触发一次更新检查 |
| `update.sh` | 更新逻辑本体，幂等：版本没变就是 no-op |
| `install.sh` | 一次性安装：单元 + sudo 免密规则（只放行 `systemctl restart qqbot`） |

### update.sh 的四道闸门（都是被真实翻车方式逼出来的）

1. **sha256 对不上就不装**（fail closed）：拿不到校验文件直接放弃，拒绝安装未校验的二进制；
2. **装前先试着跑**：新二进制先执行一次 `--version`（**不读任何密钥**），架构不符/被截断/
   缺可执行位都在替换之前暴露，而不是替换之后；
3. **健康检查要认版本**：重启后必须能从 `/healthz` 读到**新版本号**才算成功——
   只探「端口通」会漏掉「重启了但还跑着旧二进制」这种最阴的情况；
4. **失败自动回滚**：留着最近 3 份备份，回滚后再验一次健康；回滚也失败就明确喊人介入。

另外：`flock` 兜住定时器与手动执行的并发；更新过程**从不写 `env.sh`**（凭证与配置永远由人掌握）；
**换二进制前先确认「有人能把它跑起来」**（不能重启就不动文件，免得白折腾一轮再回滚）。

> ⚠️ 改 `update.sh` 时注意 **pipefail 陷阱**：`systemctl list-unit-files | grep -q ...` 这类
> 「提前退出的读取器」会让上游吃 SIGPIPE（141），`set -o pipefail` 就把整条管道判失败，
> 症状是「明明装了 systemd 单元却报未发现、静默跳过重启」。脚本末尾有详细说明。

```sh
# 更新源默认走 GitHub Releases（私有库靠 GH_TOKEN，已注入 env.sh）
UPDATE_SOURCE=github UPDATE_REPO=lilyco-42/qq-bot-rust
# 也可以走自建静态目录：需要 latest.txt / webhook_server / webhook_server.sha256 三个文件
UPDATE_SOURCE=static UPDATE_BASE_URL=https://lain42.top/dl/qqbot
```

### 自检：机器人能自己说清哪里坏了

- `GET /healthz` → 纯文本 `ok` + `version=` + `build=`（**部署契约**，改格式等于改协议）；
- `--version` → 不读任何密钥即可回答，供更新脚本做装前预检；
- `/版本` → 构建版本、运行时长、后端候选链、记忆库状态、当前话题；
- `/自检` → 逐条接缝体检：记忆库 / 每个问答后端 / gh / gh 仓库 / 我的世界后台 / 网页抓取。
  **硬约束：永远返回一段文本，永不 Err、永不 panic** —— 「机器人不回话」本身就是最难查的
  故障，体检自己不能变成新的静默失败点。

### zerostack 的十年兼容：只留一个可换件

bot 与「模型生态」之间只有一份契约，就是 [`ask_one_backend`]：

> 一个可执行文件，收 `-p <问题>`，把回答打到 stdout。仅此而已。

守住这一条，任何后端都能直接顶上来：换厂商、换 CLI 名、换实现语言，都只改环境变量。

```sh
# 候选链：逗号分隔，前一个失败自动退到后一个（上游消亡时不必改代码）
export ZEROSTACK_BIN=/home/radxa/qq_bot/zerostack_wrap.sh,zerostack,/opt/llm-cli
```

回退时打 WARN 日志（只记后端名，不记问题正文）。设计意图很清楚：
**上游会死、会改名、会被更好的东西取代；死一个后端不该让机器人停止思考。**

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
