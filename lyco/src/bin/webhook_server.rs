//! QQ 机器人 webhook 接收端（std 运行时；库核心保持 no_std）。
//!
//! 职责（对应 botgo issue #61 的结构性规避）：
//!
//! - op=13 回调握手：应答 `{plain_token, signature}`，保存回调地址即通过校验；
//! - op=0 事件推送：`X-Signature-Ed25519` + `X-Signature-Timestamp` 验签通过才上抛
//!   （打印事件正文），失败回 403 并记录原因——不吞错、不 panic；
//! - 消息类事件验签通过后，先回 200 再异步被动回复（AppAccessToken 缓存 +
//!   OpenAPI 发送，协议层在 `qq_bot_rust::api`，指令层在 `qq_bot_rust::commands`）；
//! - 凭证只从环境变量 `QQ_BOT_SECRET` 读入 [`SecretString`]，永不进日志；
//!   token 仅在构造 `Authorization` 头的 `expose()` 审计点取明文。
//!
//! 环境变量：
//!
//! | 变量 | 默认值 | 说明 |
//! |------|--------|------|
//! | `QQ_BOT_SECRET` | （必填） | 机器人 secret（运行时注入，不入库） |
//! | `QQ_APPID` | — | 应用 AppID；缺省时只收事件、不回复（启动时告警） |
//! | `WEBHOOK_BIND` | `0.0.0.0:8080` | 监听地址 |
//! | `WEBHOOK_PRINT_EVENTS` | `1` | 是否打印已验签事件的原始报文 |
//! | `WEBHOOK_REPLY` | `1` | 是否启用被动回复（`0` 关闭） |

use qq_bot_rust::api;
use qq_bot_rust::callback::{self, OP_CHALLENGE, OP_EVENT};
use qq_bot_rust::commands::{self, Reply as CommandReply};
use qq_bot_rust::crypto::webhook::{derive_public_key, verify_callback};
use qq_bot_rust::error::Error as LibError;
use qq_bot_rust::event;
use qq_bot_rust::secret::SecretString;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 请求头缓冲上限（QQ 回调头远小于此值）。
const MAX_HEADER_BYTES: usize = 16 * 1024;
/// 请求体上限（群/私聊消息事件远小于此值）。
const MAX_BODY_BYTES: usize = 1024 * 1024;
/// 读/写超时：防止慢速连接占用线程（QQ 5 秒未收到响应会重试）。
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// 单条日志中事件正文的最大展示字节数。
const LOG_BODY_CAP: usize = 4096;
/// 签名头取值展示上限（验签失败排障用，非凭证）。
const LOG_SIG_CAP: usize = 32;

/// 事件验签头（官方文档《Webhook 方式》）。
const HEADER_SIG_ED25519: &str = "X-Signature-Ed25519";
/// 事件验签时间戳头。
const HEADER_SIG_TIMESTAMP: &str = "X-Signature-Timestamp";

/// token 缓存刷新提前量（官方：过期前 60s 内获取会签发新 token）。
const TOKEN_REFRESH_MARGIN_SECS: i64 = 60;

/// 服务配置（每连接克隆一份；token 缓存经 `Arc<Mutex<..>>` 共享）。
#[derive(Clone)]
struct Config {
    secret: SecretString,
    print_events: bool,
    /// 应用 AppID；`None` = 无回复能力（启动日志告警）。
    app_id: Option<String>,
    /// 是否启用被动回复（`WEBHOOK_REPLY`）。
    reply_enabled: bool,
    /// 出站 HTTP 客户端（连接池共享；`Agent` 内部为 `Arc`，克隆廉价）。
    agent: ureq::Agent,
    /// AppAccessToken 缓存（互斥锁内仅做指针级存取，网络 I/O 不持锁）。
    token: Arc<Mutex<Option<CachedToken>>>,
}

/// 缓存的 AppAccessToken 及其绝对过期时刻（unix 秒）。
struct CachedToken {
    token: SecretString,
    expires_at_unix: i64,
}

impl Config {
    /// 是否具备回复条件（开关打开且 AppID 存在）。
    fn can_reply(&self) -> bool {
        self.reply_enabled
            && self
                .app_id
                .as_deref()
                .is_some_and(|value| !value.is_empty())
    }
}

/// 一次被动回复的全部要素（[`plan_reply`] 的产物）。
struct ReplyJob {
    /// 目标是否为群聊（`true` 群 / `false` 单聊）。
    is_group: bool,
    /// 回复目标 openid（群 openid 或用户 openid）。
    openid: String,
    /// 被回复消息 id（`d.id`）。
    msg_id: String,
    /// 事件类型（日志标签）。
    event_type: String,
    /// 回复正文。
    text: String,
}

impl ReplyJob {
    /// 日志用目标标签。
    fn target_label(&self) -> &'static str {
        if self.is_group { "group" } else { "c2c" }
    }
}

/// 出站失败分类（排障日志 + 401 有界重试判定）。
enum SendError {
    /// 传输层失败（DNS/超时/TLS 连接）。
    Transport(String),
    /// 协议层错误（业务错误码、HTTP 状态兜底、应答解析失败）。
    Api(LibError),
    /// 运行时配置缺失（如未设置 `QQ_APPID`）。
    Config(String),
}

impl std::fmt::Display for SendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(reason) => write!(f, "transport error: {reason}"),
            Self::Api(err) => write!(f, "{err}"),
            Self::Config(reason) => write!(f, "config error: {reason}"),
        }
    }
}

impl From<LibError> for SendError {
    fn from(err: LibError) -> Self {
        Self::Api(err)
    }
}

/// 已解析的 HTTP 请求（拥有所需字段）。
struct HttpRequest {
    method: String,
    path: String,
    sig_ed25519: Option<String>,
    sig_timestamp: Option<String>,
    body: Vec<u8>,
}

/// HTTP 应答。
struct Reply {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: String,
}

impl Reply {
    fn json(status: u16, reason: &'static str, body: String) -> Self {
        Self {
            status,
            reason,
            content_type: "application/json; charset=utf-8",
            body,
        }
    }

    fn text(status: u16, reason: &'static str, body: String) -> Self {
        Self {
            status,
            reason,
            content_type: "text/plain; charset=utf-8",
            body,
        }
    }
}

/// 请求读取阶段的失败分类（决定是否还能回 400）。
enum ReadError {
    /// 传输层失败（超时/对端关闭）。
    Io(std::io::Error),
    /// 报文本身非法，可回 400。
    BadRequest(&'static str),
    /// 超限，回 413。
    TooLarge,
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("[FATAL] {err}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let secret_value =
        std::env::var("QQ_BOT_SECRET").map_err(|_| "QQ_BOT_SECRET 环境变量未设置")?;
    if secret_value.is_empty() {
        return Err("QQ_BOT_SECRET 环境变量为空".to_string());
    }
    let app_id = std::env::var("QQ_APPID")
        .ok()
        .filter(|value| !value.is_empty());
    let reply_enabled = std::env::var("WEBHOOK_REPLY")
        .map(|value| value != "0")
        .unwrap_or(true);
    let config = Config {
        secret: SecretString::new(secret_value),
        print_events: std::env::var("WEBHOOK_PRINT_EVENTS")
            .map(|value| value != "0")
            .unwrap_or(true),
        app_id,
        reply_enabled,
        agent: ureq::AgentBuilder::new()
            .timeout_connect(Duration::from_secs(5))
            .timeout_read(IO_TIMEOUT)
            .timeout_write(IO_TIMEOUT)
            .build(),
        token: Arc::new(Mutex::new(None)),
    };
    let bind = std::env::var("WEBHOOK_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    let listener = TcpListener::bind(&bind).map_err(|err| format!("bind {bind} 失败: {err}"))?;
    let local = listener
        .local_addr()
        .map_err(|err| format!("读取监听地址失败: {err}"))?;

    if config.reply_enabled && !config.can_reply() {
        logln(
            "WARN",
            "QQ_APPID 未设置：事件只打印，不发送被动回复（WEBHOOK_REPLY=0 可消除本告警）",
        );
    }

    // 公钥非机密：启动时打印，供与开放平台控制台展示的公钥比对。
    let pubkey = derive_public_key(config.secret.expose())
        .map_err(|err| format!("派生机器人公钥失败: {err}"))?;
    logln(
        "INFO",
        &format!(
            "webhook server listening on {local} appid={} pubkey={} print_events={} reply={}",
            config.app_id.as_deref().unwrap_or("-"),
            hex_encode(&pubkey),
            config.print_events,
            config.can_reply(),
        ),
    );

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let config = config.clone();
                std::thread::spawn(move || handle_client(stream, &config));
            }
            Err(err) => {
                // 瞬时 accept 错误（如 EMFILE）：记录并退避，避免忙等。
                logln("WARN", &format!("accept failed: {err}"));
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
    Ok(())
}

/// 处理单个连接：读请求 → 路由 → 写应答；任何失败只影响本连接。
fn handle_client(mut stream: TcpStream, config: &Config) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));

    match read_http_request(&mut stream) {
        Ok(request) => {
            let reply = process(config, &request);
            logln(
                "INFO",
                &format!(
                    "{} {} -> {}",
                    sanitize_text(request.method.as_bytes(), 16),
                    sanitize_text(request.path.as_bytes(), 128),
                    reply.status
                ),
            );
            if let Err(err) = write_reply(&mut stream, &reply) {
                logln("WARN", &format!("write reply failed: {err}"));
            }
        }
        Err(ReadError::Io(err)) => {
            logln("INFO", &format!("read request failed: {err}"));
        }
        Err(ReadError::TooLarge) => {
            let reply = Reply::json(413, "Payload Too Large", "{\"error\":\"too large\"}".into());
            let _ = write_reply(&mut stream, &reply);
            logln(
                "WARN",
                &format!("rejected oversized request -> {}", reply.status),
            );
        }
        Err(ReadError::BadRequest(reason)) => {
            let reply = Reply::json(400, "Bad Request", format!("{{\"error\":\"{reason}\"}}"));
            let _ = write_reply(&mut stream, &reply);
            logln("WARN", &format!("rejected bad request ({reason})"));
        }
    }
}

/// 读取并解析一个 HTTP/1.1 请求（header + 指定长度的 body）。
fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest, ReadError> {
    let mut buf: Vec<u8> = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 4096];

    // 1. 读到 header 结束符。
    let header_len = loop {
        if let Some(pos) = find_bytes(&buf, b"\r\n\r\n") {
            break pos + 4;
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(ReadError::TooLarge);
        }
        let read = stream.read(&mut chunk).map_err(ReadError::Io)?;
        if read == 0 {
            return Err(ReadError::BadRequest("connection closed before headers"));
        }
        buf.extend_from_slice(&chunk[..read]);
    };

    // 2. 解析 header，立即取出所需字段（owned），之后 buf 可继续扩容。
    let mut headers = [httparse::EMPTY_HEADER; 48];
    let mut parsed = httparse::Request::new(&mut headers);
    match parsed.parse(&buf) {
        Ok(httparse::Status::Complete(parsed_len)) if parsed_len == header_len => {}
        Ok(_) => return Err(ReadError::BadRequest("incomplete headers")),
        Err(_) => return Err(ReadError::BadRequest("malformed headers")),
    }
    let method = parsed.method.unwrap_or("").to_string();
    let path = parsed.path.unwrap_or("").to_string();
    let sig_ed25519 = header_value(&parsed, HEADER_SIG_ED25519).map(str::to_string);
    let sig_timestamp = header_value(&parsed, HEADER_SIG_TIMESTAMP).map(str::to_string);
    let transfer_encoding = header_value(&parsed, "transfer-encoding").map(str::to_string);
    let expect_continue = header_value(&parsed, "expect").map(str::to_string);
    let content_length_raw = header_value(&parsed, "content-length").map(str::to_string);

    // 3. 传输编码/长度/100-continue。
    if transfer_encoding
        .as_deref()
        .map(|value| !value.eq_ignore_ascii_case("identity"))
        .unwrap_or(false)
    {
        return Err(ReadError::BadRequest("chunked encoding unsupported"));
    }
    if expect_continue
        .as_deref()
        .map(|value| value.eq_ignore_ascii_case("100-continue"))
        .unwrap_or(false)
    {
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .and_then(|()| stream.flush())
            .map_err(ReadError::Io)?;
    }
    let content_length = match content_length_raw.as_deref() {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| ReadError::BadRequest("invalid content-length"))?,
        None if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") => 0,
        None => return Err(ReadError::BadRequest("missing content-length")),
    };
    if content_length > MAX_BODY_BYTES {
        return Err(ReadError::TooLarge);
    }

    // 4. 补齐 body。
    while buf.len() < header_len + content_length {
        let read = stream.read(&mut chunk).map_err(ReadError::Io)?;
        if read == 0 {
            return Err(ReadError::BadRequest("connection closed before body"));
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.len() > MAX_HEADER_BYTES + MAX_BODY_BYTES {
            return Err(ReadError::TooLarge);
        }
    }
    let body = buf[header_len..header_len + content_length].to_vec();

    Ok(HttpRequest {
        method,
        path,
        sig_ed25519,
        sig_timestamp,
        body,
    })
}

/// 路由并生成应答（纯函数，便于单测）。
fn process(config: &Config, request: &HttpRequest) -> Reply {
    let method = request.method.as_str();
    if method.eq_ignore_ascii_case("GET") && (request.path == "/healthz" || request.path == "/") {
        return Reply::text(200, "OK", "ok\n".to_string());
    }
    if method.eq_ignore_ascii_case("HEAD") {
        return Reply::text(200, "OK", String::new());
    }
    if method.eq_ignore_ascii_case("OPTIONS") {
        return Reply::text(204, "No Content", String::new());
    }
    if !method.eq_ignore_ascii_case("POST") {
        return Reply::json(
            405,
            "Method Not Allowed",
            "{\"error\":\"method not allowed\"}".into(),
        );
    }
    handle_webhook(config, request)
}

/// webhook 报文处理：op=13 握手 / op=0 验签 / 其他 op 确认。
fn handle_webhook(config: &Config, request: &HttpRequest) -> Reply {
    let op = match callback::json_i64(&request.body, b"op") {
        Ok(Some(op)) => op,
        Ok(None) => {
            logln("WARN", "webhook payload missing op field");
            return Reply::json(400, "Bad Request", "{\"error\":\"missing op\"}".into());
        }
        Err(err) => {
            logln(
                "WARN",
                &format!(
                    "webhook payload parse error: {err} body={}",
                    sanitize_text(&request.body, 256)
                ),
            );
            return Reply::json(
                400,
                "Bad Request",
                "{\"error\":\"malformed payload\"}".into(),
            );
        }
    };

    match op {
        OP_CHALLENGE => match callback::challenge_response(config.secret.expose(), &request.body) {
            Ok(response) => {
                logln(
                    "INFO",
                    &format!(
                        "challenge answered plain_token={} signature={}",
                        sanitize_text(response.plain_token.as_bytes(), 64),
                        &response.signature[..response.signature.len().min(LOG_SIG_CAP)]
                    ),
                );
                Reply::json(200, "OK", response.to_json())
            }
            Err(err) => {
                logln("WARN", &format!("challenge failed: {err}"));
                Reply::json(
                    400,
                    "Bad Request",
                    "{\"error\":\"challenge failed\"}".into(),
                )
            }
        },
        OP_EVENT => {
            let (Some(signature), Some(timestamp)) = (&request.sig_ed25519, &request.sig_timestamp)
            else {
                logln("WARN", "event rejected: missing signature headers");
                return Reply::json(403, "Forbidden", "{\"error\":\"missing signature\"}".into());
            };
            match verify_callback(config.secret.expose(), timestamp, &request.body, signature) {
                Ok(()) => {
                    logln(
                        "INFO",
                        &format!(
                            "event verified bytes={} ts={}",
                            request.body.len(),
                            sanitize_text(timestamp.as_bytes(), 32)
                        ),
                    );
                    if config.print_events {
                        logln("EVENT", &sanitize_text(&request.body, LOG_BODY_CAP));
                    }
                    // 消息类事件：先回 200（平台 5s 重试窗口），再异步被动回复。
                    // 工作线程内部自行分流：非消息事件/无可回正文直接退出。
                    if config.can_reply() {
                        spawn_reply(config.clone(), request.body.clone());
                    }
                    Reply::json(200, "OK", "{}".to_string())
                }
                Err(err) => {
                    // 验签失败：记录原因与签名片段（公开数据），不打印事件正文。
                    logln(
                        "WARN",
                        &format!(
                            "event rejected: {err} ts={} sig={}",
                            sanitize_text(timestamp.as_bytes(), 32),
                            sanitize_text(signature.as_bytes(), LOG_SIG_CAP)
                        ),
                    );
                    Reply::json(
                        403,
                        "Forbidden",
                        "{\"error\":\"signature verification failed\"}".into(),
                    )
                }
            }
        }
        other => {
            logln("INFO", &format!("acknowledging unhandled op={other}"));
            Reply::json(200, "OK", "{}".to_string())
        }
    }
}

// ——— 被动回复链路：先回 200，再异步发送 ————————————————————

/// 从已验签事件字节规划回复任务（纯函数，便于单测）。
///
/// - 无 `t` / 非消息类事件 → `Ok(None)`（正常分流，不是错误）；
/// - 消息事件但结构非法 → `Err`（上抛，由工作线程记 WARN，不吞）；
/// - 正文为空或指令返回 [`Reply::Skip`] → `Ok(None)`（无可回内容）。
fn plan_reply(body: &[u8], now_unix: i64, random: u64) -> Result<Option<ReplyJob>, LibError> {
    let Some(event_type) = event::event_type(body)? else {
        return Ok(None);
    };
    if !event::is_message_event(&event_type) {
        return Ok(None);
    }
    let parsed = event::parse_message_event(body, &event_type)?;
    let (is_group, openid) = match (&parsed.group_openid, &parsed.user_openid) {
        (Some(group), _) => (true, group.clone()),
        (None, Some(user)) => (false, user.clone()),
        // parse_message_event 已保证至少一个目标；此处保持严格，不 unwrap。
        (None, None) => return Err(LibError::NoReplyTarget),
    };
    let text = match commands::dispatch(&parsed.content, now_unix, random)? {
        CommandReply::Text(text) => text,
        CommandReply::Skip => return Ok(None),
    };
    Ok(Some(ReplyJob {
        is_group,
        openid,
        msg_id: parsed.msg_id,
        event_type: parsed.event_type,
        text,
    }))
}

/// 派生工作线程执行回复（spawn 失败仅告警，不影响已回的 200）。
fn spawn_reply(config: Config, body: Vec<u8>) {
    let spawned = std::thread::Builder::new()
        .name("reply-worker".to_string())
        .spawn(move || reply_worker(config, body));
    if let Err(err) = spawned {
        logln("WARN", &format!("spawn reply worker failed: {err}"));
    }
}

/// 回复工作线程：规划 → 发送（仅 401 强刷重试一次）→ 记录结果。
fn reply_worker(config: Config, body: Vec<u8>) {
    let job = match plan_reply(&body, unix_now(), mix_random()) {
        Ok(Some(job)) => job,
        Ok(None) => return,
        Err(err) => {
            logln("WARN", &format!("reply skipped, event parse failed: {err}"));
            return;
        }
    };
    let outcome = match send_reply(&config, &job, false) {
        Ok(reply_id) => Ok(reply_id),
        // 401 = 凭证失效/过期：强刷 token 后有界重试一次（绝不循环）。
        Err(err @ SendError::Api(LibError::Api(401))) => {
            logln(
                "INFO",
                &format!("reply got 401, refreshing token and retrying once: {err}"),
            );
            send_reply(&config, &job, true)
        }
        Err(err) => Err(err),
    };
    let label = sanitize_text(job.event_type.as_bytes(), 48);
    match outcome {
        Ok(reply_id) => logln(
            "INFO",
            &format!(
                "reply sent event={label} target={} reply_id={} text_bytes={}",
                job.target_label(),
                sanitize_text(reply_id.as_bytes(), 64),
                job.text.len(),
            ),
        ),
        Err(err) => logln(
            "WARN",
            &format!(
                "reply failed event={label} target={}: {err}",
                job.target_label()
            ),
        ),
    }
}

/// 发送一次回复：取 token → 构造请求 → POST → 解析回执。
fn send_reply(config: &Config, job: &ReplyJob, force_refresh: bool) -> Result<String, SendError> {
    let token = ensure_token(config, force_refresh)?;
    let request = api::send_message_request(job.is_group, &job.openid, &job.text, &job.msg_id, 1)?;
    let (status, body) = post_json(&config.agent, &request, Some(&token))?;
    Ok(api::parse_send_response(status, &body)?.id)
}

/// 取可用 AppAccessToken：命中缓存直接返回，否则向平台换取并写回。
///
/// 命中条件 `now + 60s < expires_at`（官方：过期前 60s 内获取会签发新
/// token）。网络 I/O 不持锁：并发未命中的线程可能重复换取，平台在有效期内
/// 返回同一 token，属良性重复，无共享状态竞争。
fn ensure_token(config: &Config, force_refresh: bool) -> Result<SecretString, SendError> {
    let now = unix_now();
    if !force_refresh && let Some(cached) = cached_token(config, now) {
        return Ok(cached);
    }
    let app_id = config
        .app_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| SendError::Config("QQ_APPID 未设置".to_string()))?;
    let request = api::app_token_request(app_id, config.secret.expose());
    let (status, body) = post_json(&config.agent, &request, None)?;
    let parsed = api::parse_app_token(status, &body)?;
    // saturating：恶意/异常 expires_in 不得溢出 panic；非正值等价于不缓存。
    let expires_at = now.saturating_add(parsed.expires_in.max(0));
    store_token(config, parsed.token.clone(), expires_at);
    // 只记有效期，不记 token 本体。
    logln(
        "INFO",
        &format!("access_token refreshed expires_in={}s", parsed.expires_in),
    );
    Ok(parsed.token)
}

/// 读 token 缓存（锁中毒时取回内部值继续，绝不 panic）。
fn cached_token(config: &Config, now: i64) -> Option<SecretString> {
    let guard = match config.token.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let cached = guard.as_ref()?;
    if now + TOKEN_REFRESH_MARGIN_SECS < cached.expires_at_unix {
        Some(cached.token.clone())
    } else {
        None
    }
}

/// 写 token 缓存（锁中毒时取回内部值继续，绝不 panic）。
fn store_token(config: &Config, token: SecretString, expires_at_unix: i64) {
    let mut guard = match config.token.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    *guard = Some(CachedToken {
        token,
        expires_at_unix,
    });
}

/// POST JSON（传输层）：返回 `(status, body)`；判定交给协议层。
///
/// - `token` 存在时附加 `Authorization: QQBot {token}`（`expose()` 审计点）；
/// - 非 2xx 在 ureq 中表现为 [`ureq::Error::Status`]，其 body 仍是应答
///   内容，照常交协议层按 `err_code`/`code` 判定（不因非 2xx 丢信息）。
fn post_json(
    agent: &ureq::Agent,
    request: &api::ApiRequest,
    token: Option<&SecretString>,
) -> Result<(u16, String), SendError> {
    let mut builder = agent
        .post(&request.url)
        .set("Content-Type", "application/json; charset=utf-8");
    if let Some(token) = token {
        builder = builder.set("Authorization", &format!("QQBot {}", token.expose()));
    }
    match builder.send_string(&request.body) {
        Ok(response) => {
            let status = response.status();
            let text = response
                .into_string()
                .map_err(|err| SendError::Transport(format!("read response body: {err}")))?;
            Ok((status, text))
        }
        Err(ureq::Error::Status(status, response)) => {
            let text = response.into_string().unwrap_or_default();
            Ok((status, text))
        }
        Err(other) => Err(SendError::Transport(other.to_string())),
    }
}

/// 当前 unix 秒（时钟异常回退 0，不 panic）。
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 混合随机源：时间纳秒 ^ 原子计数器，经 splitmix64 扩散（无全局可变状态风险）。
fn mix_random() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut mixed = nanos ^ seq.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    mixed ^ (mixed >> 31)
}

/// 写出 HTTP 应答（短连接：`Connection: close`）。
fn write_reply(stream: &mut TcpStream, reply: &Reply) -> std::io::Result<()> {
    let payload = reply.body.as_bytes();
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        reply.status,
        reply.reason,
        reply.content_type,
        payload.len()
    )?;
    stream.write_all(payload)?;
    stream.flush()
}

/// 大小写不敏感地取 header 值。
fn header_value<'a>(request: &httparse::Request<'_, 'a>, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .and_then(|header| std::str::from_utf8(header.value).ok())
        .map(str::trim)
}

/// 在字节序列中查找子串位置。
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// 日志用文本清洗：控制字符替换 + 长度截断（防日志注入/刷屏）。
fn sanitize_text(bytes: &[u8], cap: usize) -> String {
    let taken = &bytes[..bytes.len().min(cap)];
    String::from_utf8_lossy(taken)
        .chars()
        .map(|c| if c.is_control() { '·' } else { c })
        .collect()
}

/// 小写 hex 编码。
fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0F) as usize] as char);
    }
    out
}

/// 单行日志：`[unix LEVEL] message`（stdout，随重定向落盘）。
fn logln(level: &str, message: &str) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();
    let _ = writeln!(handle, "[{ts} {level}] {message}");
}

#[cfg(test)]
mod tests {
    use super::{
        Config, HttpRequest, cached_token, handle_client, plan_reply, process, store_token,
    };
    use qq_bot_rust::crypto::webhook::{derive_seed, sign_challenge};
    use qq_bot_rust::error::Error as LibError;
    use qq_bot_rust::secret::SecretString;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{Arc, Mutex};

    /// 官方《Webhook 方式》演示 secret。
    const DOC_SECRET: &str = "DG5g3B4j9X2KOErG";

    fn config() -> Config {
        Config {
            secret: SecretString::new(DOC_SECRET),
            print_events: true,
            // 测试配置不触发网络：无 AppID → can_reply() == false。
            app_id: None,
            reply_enabled: true,
            agent: ureq::AgentBuilder::new().build(),
            token: Arc::new(Mutex::new(None)),
        }
    }

    fn request(method: &str, path: &str, sig: Option<(&str, &str)>, body: &[u8]) -> HttpRequest {
        let (sig_ed25519, sig_timestamp) = match sig {
            Some((signature, timestamp)) => {
                (Some(signature.to_string()), Some(timestamp.to_string()))
            }
            None => (None, None),
        };
        HttpRequest {
            method: method.to_string(),
            path: path.to_string(),
            sig_ed25519,
            sig_timestamp,
            body: body.to_vec(),
        }
    }

    #[test]
    fn health_endpoint_answers_200() {
        let reply = process(&config(), &request("GET", "/healthz", None, b""));
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, "ok\n");
    }

    #[test]
    fn challenge_roundtrip_matches_library_vector() {
        let body =
            br#"{"op":13,"d":{"event_ts":"1725442341","plain_token":"Arq0D5A61EgUu4OxUvOp"}}"#;
        let reply = process(&config(), &request("POST", "/qq/webhook", None, body));
        assert_eq!(reply.status, 200);
        let expected = sign_challenge(DOC_SECRET, "1725442341", "Arq0D5A61EgUu4OxUvOp").unwrap();
        assert!(
            reply
                .body
                .contains(&format!("\"signature\":\"{expected}\""))
        );
        assert!(
            reply
                .body
                .contains("\"plain_token\":\"Arq0D5A61EgUu4OxUvOp\"")
        );
    }

    fn sign_event(secret: &str, timestamp: &str, body: &[u8]) -> String {
        use ed25519_dalek::{Signer, SigningKey};
        let key = SigningKey::from_bytes(&derive_seed(secret.as_bytes()).unwrap());
        let mut msg = timestamp.as_bytes().to_vec();
        msg.extend_from_slice(body);
        hex_encode_test(&key.sign(&msg).to_bytes())
    }

    fn hex_encode_test(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn valid_event_signature_is_accepted() {
        let timestamp = "1725442341";
        let body = br#"{"op":0,"d":{"s":2},"t":"GROUP_AT_MESSAGE_CREATE","seq":1}"#;
        let signature = sign_event(DOC_SECRET, timestamp, body);
        let reply = process(
            &config(),
            &request("POST", "/qq/webhook", Some((&signature, timestamp)), body),
        );
        assert_eq!(reply.status, 200, "body={}", reply.body);
        assert_eq!(reply.body, "{}");
    }

    #[test]
    fn invalid_or_missing_signature_is_rejected() {
        let timestamp = "1725442341";
        let body = br#"{"op":0,"d":{"s":2},"t":"GROUP_AT_MESSAGE_CREATE","seq":1}"#;
        // 缺头。
        let reply = process(&config(), &request("POST", "/qq/webhook", None, body));
        assert_eq!(reply.status, 403);
        // 错签名。
        let good = sign_event(DOC_SECRET, timestamp, body);
        let bad = format!("{}00", &good[2..]);
        let reply = process(
            &config(),
            &request("POST", "/qq/webhook", Some((bad.as_str(), timestamp)), body),
        );
        assert_eq!(reply.status, 403);
        // 错时间戳（签名体不匹配）。
        let reply = process(
            &config(),
            &request(
                "POST",
                "/qq/webhook",
                Some((good.as_str(), "1725442342")),
                body,
            ),
        );
        assert_eq!(reply.status, 403);
    }

    #[test]
    fn malformed_payload_and_unknown_ops_are_handled() {
        let reply = process(&config(), &request("POST", "/x", None, b""));
        assert_eq!(reply.status, 400);
        let reply = process(&config(), &request("POST", "/x", None, b"{not json"));
        assert_eq!(reply.status, 400);
        // 未知 op：确认（200）避免平台无限重试，但不产生事件日志。
        let reply = process(&config(), &request("POST", "/x", None, br#"{"op":99}"#));
        assert_eq!(reply.status, 200);
        let reply = process(&config(), &request("DELETE", "/x", None, b""));
        assert_eq!(reply.status, 405);
    }

    /// 真实 socket 往返：challenge 经过读请求/写应答全链路。
    #[test]
    fn socket_roundtrip_serves_challenge() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle_client(stream, &config());
        });

        let body =
            br#"{"op":13,"d":{"event_ts":"1725442341","plain_token":"Arq0D5A61EgUu4OxUvOp"}}"#;
        let mut client = TcpStream::connect(addr).unwrap();
        write!(
            client,
            "POST /cb HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        client.write_all(body).unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        server.join().unwrap();

        let expected = sign_challenge(DOC_SECRET, "1725442341", "Arq0D5A61EgUu4OxUvOp").unwrap();
        assert!(response.starts_with("HTTP/1.1 200 OK"), "resp={response}");
        assert!(response.contains(&expected), "resp={response}");
    }

    /// 真实单聊事件报文（Radxa 抓取；中文按 UTF-8 字节转义）。
    const C2C_HELP_EVENT: &[u8] = b"{\"op\":0,\"id\":\"C2C_MESSAGE_CREATE:sfyoo42bh\",\"d\":{\"id\":\"ROBOT1.0_oC3JDEal\",\"content\":\"\xe5\xb8\xae\xe5\x8a\xa9\",\"timestamp\":\"2026-10-09T00:22:29+08:00\",\"author\":{\"id\":\"DE8C8AEC\",\"username\":\"\",\"bot\":false,\"user_openid\":\"DE8C8AECAF13F8D144240291E8D7B0A7\",\"union_openid\":\"\"},\"message_type\":0},\"t\":\"C2C_MESSAGE_CREATE\",\"seq\":1}";

    /// 真实群事件报文（成员进群；无正文、无消息 id → 不属于消息事件）。
    const GROUP_MEMBER_ADD: &[u8] = b"{\"op\":0,\"id\":\"GROUP_MEMBER_ADD:x\",\"d\":{\"timestamp\":\"2026-10-09T00:19:16+08:00\",\"group_openid\":\"3D54AA8E\",\"member_openid\":\"095AF6EF\"},\"t\":\"GROUP_MEMBER_ADD\",\"seq\":3}";

    #[test]
    fn plan_reply_targets_c2c_for_help_command() {
        let job = plan_reply(C2C_HELP_EVENT, 1_791_476_549, 0)
            .unwrap()
            .expect("帮助 must plan a reply");
        assert!(!job.is_group);
        assert_eq!(job.openid, "DE8C8AECAF13F8D144240291E8D7B0A7");
        assert_eq!(job.msg_id, "ROBOT1.0_oC3JDEal");
        assert_eq!(job.event_type, "C2C_MESSAGE_CREATE");
        assert!(job.text.contains("可用指令"), "text={}", job.text);
    }

    #[test]
    fn plan_reply_targets_group_and_answers_unknown_command() {
        let body = b"{\"op\":0,\"id\":\"GROUP_AT_MESSAGE_CREATE:g\",\"d\":{\"author\":{\"id\":\"79BE\",\"user_openid\":\"79BE66EF\"},\"content\":\"123\",\"group_openid\":\"3D54AA8E\",\"id\":\"ROBOT1.0_grp\",\"message_type\":0},\"t\":\"GROUP_AT_MESSAGE_CREATE\",\"seq\":1}";
        let job = plan_reply(body, 0, 0)
            .unwrap()
            .expect("group @ message must plan a reply");
        assert!(job.is_group);
        assert_eq!(job.openid, "3D54AA8E");
        assert_eq!(job.msg_id, "ROBOT1.0_grp");
        // 未知指令不装死。
        assert!(job.text.contains("帮助"), "text={}", job.text);
    }

    #[test]
    fn plan_reply_skips_non_message_and_empty_content() {
        // 非消息事件（群成员进群）：正常分流，不是错误。
        assert!(plan_reply(GROUP_MEMBER_ADD, 0, 0).unwrap().is_none());
        // 无 t（如握手报文）：同样不回复。
        assert!(plan_reply(br#"{"op":13,"d":{}}"#, 0, 0).unwrap().is_none());
        // 空正文（媒体消息）：无文本可回。
        let body = b"{\"d\":{\"id\":\"m\",\"content\":\"\",\"author\":{\"user_openid\":\"u\"}},\"t\":\"C2C_MESSAGE_CREATE\"}";
        assert!(plan_reply(body, 0, 0).unwrap().is_none());
    }

    #[test]
    fn plan_reply_propagates_structural_errors() {
        // 消息事件缺 d.id → 错误上抛（由工作线程记 WARN，不吞）。
        let body =
            b"{\"d\":{\"content\":\"\xe5\xb8\xae\xe5\x8a\xa9\"},\"t\":\"C2C_MESSAGE_CREATE\"}";
        assert_eq!(
            plan_reply(body, 0, 0).err(),
            Some(LibError::MissingField("d.id"))
        );
        // 无回复目标。
        let body = b"{\"d\":{\"id\":\"m\",\"content\":\"hi\"},\"t\":\"C2C_MESSAGE_CREATE\"}";
        assert_eq!(plan_reply(body, 0, 0).err(), Some(LibError::NoReplyTarget));
    }

    #[test]
    fn token_cache_enforces_refresh_margin() {
        let config = config();
        // 空缓存。
        assert!(cached_token(&config, 1_000).is_none());
        // 有效期内命中明文。
        store_token(&config, SecretString::new("tok".to_string()), 8_200);
        assert_eq!(
            cached_token(&config, 1_000).map(|token| token.expose().to_string()),
            Some("tok".to_string())
        );
        // 进入 60s 刷新窗口 → 视为过期，触发重取。
        assert!(cached_token(&config, 8_200 - 60).is_none());
        assert!(cached_token(&config, 8_200).is_none());
        // 非正值有效期 → 永不命中。
        store_token(&config, SecretString::new("tok".to_string()), 1_000);
        assert!(cached_token(&config, 1_000).is_none());
    }

    #[test]
    fn reply_requires_appid_and_switch() {
        let mut config = config();
        // 测试配置无 AppID → 不派生线程、不发网络请求。
        assert!(!config.can_reply());
        config.app_id = Some("1903680813".to_string());
        assert!(config.can_reply());
        config.reply_enabled = false;
        assert!(!config.can_reply());
        config.reply_enabled = true;
        config.app_id = Some(String::new());
        assert!(!config.can_reply());
    }
}
