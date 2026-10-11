# QQ Bot Rust

Radxa ARM64 QQ bot, webhook gateway and public GitHub Actions releases.

## 最新客户端下载（群内自然语言）

群友真正 `@lyco` 后，发送「网盘链接」「哪里下载」「安卓APK下载链接」
或 `/下载`，机器人走确定性的 GitHub 客户端 Release 查询，
回复公开夸克网盘文件夹与当前正式版的 GitHub 链接，不靠模型猜网址。
公开文件夹：https://pan.quark.cn/s/eb08795d014c

普通的 ZeroStack AI 问答也可以读取运营方维护的**本地只读知识条目**。
Radxa 服务环境可设置：
`BOT_KNOWLEDGE_FILE=/home/radxa/qq_bot/knowledge.md`。
知识条目的上游存于
[卫戍知识库的客户端条目](https://github.com/lilyco-42/stronghold-knowledge/blob/main/downloads/client.md)；
建议从该仓库同步到上述本地路径（仅运营方有写权限），无需开放群友知识库写权限。
机器人每次普通问答读取前 1800 字，不在日志打印知识全文。
最新版本必须查询 GitHub，不可把知识条目的历史版本快照当作实时信息。


## QQ group images and OCR

The optional vision feature handles image attachments in QQ group and C2C
messages, and is enabled in production release builds. The input pipeline
validates the HTTPS QQ CDN hostname, disallows redirects, enforces 5 MiB and
14 MP bounds, checks format magic, and converts PNG/JPEG/WebP/GIF to JPEG.
A Base64 JPEG data URI is submitted to a multimodal model which performs both
image understanding and OCR (recognition of readable text in the image).

The public repository lilyco-42/lilyco currently contains lilyco-vision for
image manipulation, but no OCR module at the referenced path. This bot supplies
its own model-based OCR adapter; no separate Tesseract binary is required on Radxa.
Screenshots, Base64 payload and API credentials are not written to group memory.

Set on the server (never commit real tokens):
- VISION_API_KEY: optional, falls back to NIM_API_KEY
- VISION_API_URL: optional, defaults to https://integrate.api.nvidia.com/v1/chat/completions
- VISION_MODEL: optional, defaults to meta/llama-3.2-11b-vision-instruct

Image processing failure yields an explicit diagnostic, not a fabricated OCR
result. Images are transmitted to an external AI provider; avoid private
screenshots unless this transfer is acceptable. Screenshot text is untrusted
and never executed as instructions.


## Persistent QQ group knowledge

The /记 command or a direct message beginning with 记住 writes an important
fact to the current group's Turso database. The /忆 command only reads
and reinforces stored knowledge and never writes the message as a new fact.
On subsequent questions such as 0.2.3版本更新了什么, the bot first searches
saved version facts in the same group before calling the stateless AI model.
The answer is labelled as group-provided and not independently verified.
Generated AI answers never become authoritative facts.

An administrator can import one fact at the next process startup by writing
a UTF-8 file named .memory-import in the bot working directory. The first
line is the QQ group's hexadecimal openid; all remaining lines contain the
fact. On successful Turso write, the bot removes the import file. Do NOT
commit group IDs or import files to this public repository. Alternatively
set MEMORY_IMPORT_FILE to a file path controlled by the administrator.


## Stronghold Protocol game room directory

The new `/游戏房间` (aliases: `/卫戍房间`, `/sp房间`, `/gamerooms`) reads the actual Stronghold game waiting rooms; it is separate from `/房间`, which reads the online-platform lobby. The command is read-only and never joins a game.

On Radxa, configure `SP_ROOM_API_URL=https://sp.lain42.top/api/bot/v1/rooms?limit=10` and `SP_ROOM_API_TOKEN` in the bot's private service environment. The Bearer token must not be committed, logged, sent to a chat, or injected into an LLM prompt. Missing configuration or a service outage returns an explicit message rather than invented rooms.

The server adapter and protocol are in [lain42-stronghold-ops](https://github.com/lilyco-42/lain42-stronghold-ops/tree/main/extensions/sp-room-api). It requires authentication and only returns waiting-room codes, safe player display names, seat counts, difficulty and the optional AI-draft-order strategy. In-match selections and player credentials remain private. This adapter is opt-in at the Stronghold systemd layer and needs a planned game service restart before the endpoint becomes live.

## Quark Drive share transfer via QQ Bot

`/夸克转存 https://pan.quark.cn/s/abc123` (alias `/网盘转存`) uses the third-party [QuarkPan CLI](https://github.com/lich0821/QuarkPan) to copy a Quark share into the operator's own Quark Drive.

**Security by default:** transfer is a write operation and remains **disabled** unless `QUARK_SAVE_ENABLED=1` and the sender's exact QQ user OpenID is included in `QUARK_SAVE_ALLOWED_OPENIDS`. Do not use the QQ group OpenID for this allowlist. No group user can supply an executable name, destination directory or shell arguments. No command shell is used; at most one task runs at once with a 105 second watchdog. The CLI subprocess receives only a small whitelist of environment variables, not QQ or AI credentials. The reply contains no file contents, login cookies or API tokens.

On the always-on **QQ Bot device** (Radxa), install QuarkPan (e.g. into a dedicated virtual environment) and log in using that **same Linux service account** with `quarkpan auth login`. Set these in the bot's private systemd environment, not in Git:

- `QUARK_SAVE_ENABLED=1` (default: disabled)
- `QUARK_SAVE_ALLOWED_OPENIDS=<QQ user OpenID>[,other OpenID]`
- `QUARKPAN_BIN=/path/to/quarkpan` (default: `quarkpan`)
- `QUARK_SAVE_FOLDER=/来自QQ群/` (default, not user-selectable)

If the CLI returns success, the bot reports this outcome but asks you to verify the file in your drive. Login expiry, revoked links and capacity failures return a clear error. This code does **not** install QuarkPan, ask for a cookie in a QQ group, start any automatic scheduled task, or transfer any files until you configure the service and an administrator explicitly submits a share link. The bot works even when Windows is powered off.

Only transfer content you are authorized to access and store. The tool is unofficial and its dependencies and Quark session credentials should be reviewed and kept isolated from other server services.


## 群内 GitHub Issue 提单（Radxa / ZeroStack / gh）

真正使用 QQ 的 @ 成员选中 `lyco` 机器人，然后在群里发送：

```text
@lyco /提单 绝境模拟隐身敌人技能释放动画正常但没有伤害，待复现
@lyco bug记录 隐身怪会空放技能，主要是无伤害
```

默认仅 **管理员授权 QQ 用户 OpenID** 能执行。服务端设置
`GH_WRITE=1`、`GH_REPO=lilyco-42/Stronghold-Protocol`、
`GH_ALLOWED_OPENIDS=<author.member_openid>`（多个用逗号分隔）。

如需允许**普通群成员自助提单**，由管理员额外设置 `GH_GROUP_ISSUES=1` 并重启 Bot。
群友必须通过已验签的 QQ 群事件触发 `/提单`，私聊无法提交。
普通群友每 24 小时最多提交 2 次、两次间隔至少 15 分钟、所有群友
每 24 小时合计最多 20 次；失败的提单尝试也占用频率额度，以防止重试风暴。
限额记录默认写入 Bot 工作目录的 `issue-submissions.log`（0600）并在进程
重启后保留。白名单管理员不受这些限额影响。`GH_GROUP_ISSUES` 默认关闭。
`GH_TOKEN` 作为 QQ Bot **systemd 环境**内的机密变量提供；需要有目标仓库 Issue 写权限。
这些值存入 `/home/radxa/qq_bot/env.sh`（仅 `radxa` 可读），禁止提交 GitHub。

处理流程：QQ 校验签名 → 解析发送者 OpenID → 管理员白名单或群友自助权限及持久限额 →
ZeroStack (`--no-tools`) 把文本整理为待确认的描述 →
`gh issue create --repo <固定仓库> --title ... --body ...` →
QQ 回复真实 Issue URL。Issue 正文始终保留原始反馈，不接受模型产生的工具指令，
模型不可直接执行 gh。AI 无响应时自动退化为原始反馈直接建单，确保不因模型失败丢单；
`GH_ISSUE_AI=0` 可以禁用 AI 整理。

未经授权回复权限不足，不执行 gh；`GH_WRITE` 默认为关闭；
同一进程一次最多执行一个提单任务，超时受 gh/ZeroStack 配置限制。
指令只处理从 QQ Webhook 实际送达的 `GROUP_AT_MESSAGE_CREATE` 事件。
如果 QQ 没有下发群 @ 事件，再好的命令实现也不会被触发；排障时检查
`server.log` 中 `event verified` 和 `POST /qq/webhook` 的时间。
建议生产环境设置 `WEBHOOK_PRINT_EVENTS=0`，防止将 QQ 回调完整原文及附带认证元数据写入日志。
