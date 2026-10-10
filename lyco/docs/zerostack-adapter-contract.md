# 问答后端适配契约（bot ↔ 模型生态之间唯一的那一份约定）

> 写这份文档的原因：上游会死、会改名、会被更好的东西取代。
> 只要这个契约被守住，**换后端只改环境变量，bot 一行都不用动**。
> 十年后接手的人（可能是你自己）只读这一页就能把新后端接上去。

## 一句话契约

> **一个可执行文件，接受 `-p <问题>` 参数，把回答写进 stdout。**

就这一条。没有 SDK、没有协议版本、没有网络接口要求、不规定语言——shell 脚本、Rust 二进制、
Python 小工具都行，只要它满足上面这句。

## 调用侧的确切行为（`ask_one_backend`）

| 项 | 约定 |
|---|---|
| 参数 | `--no-tools --no-context-files --no-session --no-color [--provider X] [--model Y] -p <问题>` |
| 问题传递 | 作为**独立 argv** 传入（不经 shell），因此问题里可以有引号、换行、`;` 等任意字符 |
| stdin | `/dev/null`（后端不要指望交互输入） |
| stdout | 全部内容即回答（行尾空白会被裁掉） |
| stderr | 只用于日志，不进入回答；但**非零退出时会被当作失败原因** |
| 退出码 | `0` = 成功；非 0 = 失败（换下一个候选后端） |
| 超时 | `QA_TIMEOUT_SECS`（默认 120s，5..=600）；超时会 kill 子进程后再试下一个候选 |
| 空 stdout | 视为失败（不把空回答发给用户） |
| 长度 | 超过 `QA_MAX_CHARS`（默认 1000）截断 |

> 「不认识的参数要忽略而不是报错」是**强烈建议**：bot 会把上面那串参数固定传下去，
> 未来若调整了参数集合，新后端应当容忍多余/陌生的 flag。

## 候选链：一个挂了不等于全挂

```sh
# env.sh —— 按优先级从左到右尝试，第一个成功的生效
ZEROSTACK_BIN=/home/radxa/qq_bot/zerostack_wrap.sh,/opt/llm-cli,zerostack
```

- 前面失败会依次退到后面，成功时打一条 `WARN qa backend fell back to ...`（**只记后端名**，
  不记问题正文）；
- 全部失败才向用户回显式兜底文案（`AI 问答暂时不可用，请稍后再试`）并记 `WARN`；
- 空链（或 `WEBHOOK_QA=0`）＝关闭问答。

**因此：迁移新后端不需要停机窗口** —— 先把它追加到链尾，观察生效，再决定要不要删掉旧头。

## 接一个新后端的最小步骤

1. 准备可执行文件，确保 `./your-backend -p "你好"` 能在 stdout 打印一句回答；
2. `chmod +x`，放到任意路径（含路径分隔符时按路径解析，否则按 `PATH` 查找）；
3. 写进 `env.sh` 的 `ZEROSTACK_BIN`（追加到链尾最安全）；
4. `sudo systemctl restart qqbot`；
5. 群里发 `/自检` 确认那一行是 `问答后端 <你的后端>：ok`；
6. 群里随便说句话，确认真的答上来了。

> ⚠️ `env.sh` 里**不要写 `export` 前缀**（systemd `EnvironmentFile` 会把整行丢掉，见 README）。

## 不该做的事

- ❌ 不要把模型厂商的 SDK 直接嵌进 bot：那等于把「十年」缩短成「厂商 API 的生命周期」；
- ❌ 不要在 bot 里解析后端特有的日志格式来判断成败 —— 只认退出码与 stdout；
- ❌ 不要让契约依赖某个特定 CLI 的名字。名字属于环境变量，不属于代码。

## 相关位置

| 位置 | 作用 |
|---|---|
| `src/bin/webhook_server/main.rs` → `ask_one_backend` | 契约的唯一实现点 |
| `src/bin/webhook_server/main.rs` → `ask_zerostack` | 候选链与回退、留痕 |
| `src/bin/webhook_server/main.rs` → `qa_args` | 参数拼装（含 provider/model 覆盖） |
| `qa_provider` / `qa_model`（`QA_PROVIDER` / `QA_MODEL`） | 同一后端内换模型/供应商，不必写适配器 |
| `/自检` | 运维侧验证：不真的发问答，只探「存在且可执行」 |
