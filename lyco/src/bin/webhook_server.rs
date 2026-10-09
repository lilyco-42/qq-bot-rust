//! QQ 机器人 webhook 接收端（std 运行时；库核心保持 no_std）。
//!
//! 职责（对应 botgo issue #61 的结构性规避）：
//!
//! - op=13 回调握手：应答 `{plain_token, signature}`，保存回调地址即通过校验；
//! - op=0 事件推送：`X-Signature-Ed25519` + `X-Signature-Timestamp` 验签通过才上抛
//!   （打印事件正文），失败回 403 并记录原因——不吞错、不 panic；
//! - 消息类事件验签通过后，先回 200 再异步被动回复（AppAccessToken 缓存 +
//!   OpenAPI 发送，协议层在 `qq_bot_rust::api`，指令层在 `qq_bot_rust::commands`）；
//! - `/` 前缀 → 指令；其余正文 → AI 问答（spawn zerostack 单次问答，超时
//!   kill、失败回显式兜底文案，绝不静默丢消息）；
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
//! | `WEBHOOK_QA` | `1` | 是否启用 AI 问答（`0` 关闭；非 `/` 指令的普通消息） |
//! | `ZEROSTACK_BIN` | `zerostack` | zerostack 可执行文件（空串等价于关闭问答） |
//! | `QA_TIMEOUT_SECS` | `120` | 单次问答超时（5..=600 秒，超时回兜底文案） |
//! | `QA_MAX_CHARS` | `1000` | 回答截断字数（50..=4000；平台无公开上限，保守截断） |
//! | `WEBHOOK_STATUS` | `1` | 是否启用 `/对局` 服务器状态查询（`0` 关闭） |
//! | `SP_STATUS_URL` | `https://sp.lain42.top/healthz` | 游戏服务器状态地址 |
//! | `LOBBY_BASE_URL` | `https://sp.lain42.top/lobby` | 组队大厅基地址（读其公开计数） |
//! | `WEBHOOK_LOBBY` | `1` | 是否启用 `/房间` 组队大厅房间查询（`0` 关闭） |
//! | `LOBBY_USER` | — | 大厅机器人专用账号（与 `LOBBY_PASS` 同时设置才启用） |
//! | `LOBBY_PASS` | — | 大厅机器人专用密码（运行时注入，永不进日志） |

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
    /// AI 问答配置（zerostack 单次问答）。
    qa: QaConfig,
    /// 服务器状态查询配置（`/对局`）。
    status: StatusConfig,
    /// 组队大厅房间查询配置（`/房间`）。
    lobby: LobbyConfig,
    /// 大厅登录会话缓存（access/refresh token；锁内仅指针级存取，网络 I/O 不持锁）。
    lobby_session: Arc<Mutex<Option<LobbySession>>>,
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
    /// 回复内容（指令文本，或待 AI 问答的问题）。
    body: ReplyBody,
}

/// 回复内容形态。
enum ReplyBody {
    /// 直接发送的指令回复文本。
    Text(String),
    /// 需要先经 AI（zerostack 单次问答）求解的问题。
    Ask(String),
    /// 需要查询服务器状态（`/对局`），由接收端发 HTTP 请求后成文。
    ServerStatus,
    /// 需要查询组队大厅房间列表（`/房间`），由接收端带 token 请求后成文。
    LobbyRooms,
}

impl ReplyJob {
    /// 日志用目标标签。
    fn target_label(&self) -> &'static str {
        if self.is_group { "group" } else { "c2c" }
    }
}

#[derive(Clone)]
/// AI 问答配置（`WEBHOOK_QA` / `ZEROSTACK_BIN` / `QA_TIMEOUT_SECS` / `QA_MAX_CHARS`）。
struct QaConfig {
    /// 是否启用问答（`WEBHOOK_QA=0` 关闭）。
    enabled: bool,
    /// zerostack 可执行文件（空串等价于关闭）。
    bin: String,
    /// 单次问答超时（超时杀进程，回复显式兜底文案）。
    timeout: Duration,
    /// 回答截断上限（字数；平台无公开上限，保守截断）。
    max_chars: usize,
}

/// 服务器状态查询配置（`/对局`：`WEBHOOK_STATUS` / `SP_STATUS_URL` / `LOBBY_BASE_URL`）。
///
/// 只读公开 HTTP 接口，不改动游戏/大厅服务器：游戏 `/healthz` 给聚合
/// 对局/人数（0.2.3 起可能含 `matching`/`queued` 快速匹配队列），大厅
/// `/api/online_count`、`/api/active_rooms` 给在线人数与房间数。
#[derive(Clone)]
struct StatusConfig {
    /// 是否启用状态查询（`WEBHOOK_STATUS=0` 关闭）。
    enabled: bool,
    /// 游戏服务器 `/healthz` 地址。
    game_url: String,
    /// 组队大厅基地址（其 `/api/*` 与网页入口）。
    lobby_base: String,
}

/// 组队大厅房间查询配置（`/房间`：`WEBHOOK_LOBBY` / `LOBBY_USER` / `LOBBY_PASS`）。
///
/// 需要机器人专用账号：`POST {base}/api/login` 取 access token，再以
/// `Authorization: Bearer <token>` 读 `GET {base}/api/rooms`——只读接口，
/// 不改动大厅/游戏服务器。
#[derive(Clone)]
struct LobbyConfig {
    /// 是否启用（`WEBHOOK_LOBBY=0` 或账号/密码缺失时为关闭）。
    enabled: bool,
    /// 机器人专用账号。
    user: String,
    /// 机器人专用密码（`SecretString`：结构上不可能进日志）。
    pass: SecretString,
}

/// 大厅登录会话（access/refresh token 均为凭证，按 `SecretString` 脱敏）。
#[derive(Clone)]
struct LobbySession {
    /// 短期访问令牌（`Authorization: Bearer`）。
    access: SecretString,
    /// 长期续期令牌（轮换式；换新后需回写缓存）。
    refresh: SecretString,
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
    // AI 问答：默认开启；`WEBHOOK_QA=0` 或空 `ZEROSTACK_BIN` 关闭。
    let qa_enabled = std::env::var("WEBHOOK_QA")
        .map(|value| value != "0")
        .unwrap_or(true);
    let qa_bin = std::env::var("ZEROSTACK_BIN").unwrap_or_else(|_| "zerostack".to_string());
    let qa_timeout_secs = std::env::var("QA_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(120);
    let qa_max_chars = std::env::var("QA_MAX_CHARS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1_000);
    let qa = QaConfig {
        enabled: qa_enabled && !qa_bin.is_empty(),
        bin: qa_bin,
        timeout: Duration::from_secs(qa_timeout_secs.clamp(5, 600)),
        max_chars: qa_max_chars.clamp(50, 4_000),
    };
    // 服务器状态查询：默认开启；`WEBHOOK_STATUS=0` 关闭。地址可换成自建服。
    let status = StatusConfig {
        enabled: std::env::var("WEBHOOK_STATUS")
            .map(|value| value != "0")
            .unwrap_or(true),
        game_url: std::env::var("SP_STATUS_URL")
            .unwrap_or_else(|_| "https://sp.lain42.top/healthz".to_string()),
        lobby_base: std::env::var("LOBBY_BASE_URL")
            .unwrap_or_else(|_| "https://sp.lain42.top/lobby".to_string()),
    };
    // 组队大厅房间查询：默认开启；`WEBHOOK_LOBBY=0` 或账号/密码缺失时关闭。
    let lobby_user = std::env::var("LOBBY_USER").unwrap_or_default();
    let lobby_pass = std::env::var("LOBBY_PASS").unwrap_or_default();
    let lobby = LobbyConfig {
        enabled: std::env::var("WEBHOOK_LOBBY")
            .map(|value| value != "0")
            .unwrap_or(true)
            && !lobby_user.is_empty()
            && !lobby_pass.is_empty(),
        user: lobby_user,
        pass: SecretString::new(lobby_pass),
    };
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
        qa,
        status,
        lobby,
        lobby_session: Arc::new(Mutex::new(None)),
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
            "webhook server listening on {local} appid={} pubkey={} print_events={} reply={} qa={} status={} lobby={}",
            config.app_id.as_deref().unwrap_or("-"),
            hex_encode(&pubkey),
            config.print_events,
            config.can_reply(),
            if config.qa.enabled { "on" } else { "off" },
            if config.status.enabled { "on" } else { "off" },
            if config.lobby.enabled { "on" } else { "off" },
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
/// - 正文为空或指令返回 [`Reply::Skip`] → `Ok(None)`（无可回内容）；
/// - [`Reply::Ask`] → 携带问题，由工作线程跑 AI 问答后发送。
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
    let reply_body = match commands::dispatch(&parsed.content, now_unix, random)? {
        CommandReply::Text(text) => ReplyBody::Text(text),
        CommandReply::Ask(question) => ReplyBody::Ask(question),
        CommandReply::ServerStatus => ReplyBody::ServerStatus,
        CommandReply::LobbyRooms => ReplyBody::LobbyRooms,
        CommandReply::Skip => return Ok(None),
    };
    Ok(Some(ReplyJob {
        is_group,
        openid,
        msg_id: parsed.msg_id,
        event_type: parsed.event_type,
        body: reply_body,
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

/// 回复工作线程：规划 → 解析正文（Ask 则跑 AI 问答）→ 发送（仅 401 强刷重试一次）→ 记录结果。
fn reply_worker(config: Config, body: Vec<u8>) {
    let job = match plan_reply(&body, unix_now(), mix_random()) {
        Ok(Some(job)) => job,
        Ok(None) => return,
        Err(err) => {
            logln("WARN", &format!("reply skipped, event parse failed: {err}"));
            return;
        }
    };
    let label = sanitize_text(job.event_type.as_bytes(), 48);
    // Ask：先跑 zerostack 单次问答得到回答正文（有界超时；失败回显式兜底文案，
    // 不吞错——错误已记日志）。Text：直接用指令回复。
    let text = match &job.body {
        ReplyBody::Text(text) => text.clone(),
        ReplyBody::Ask(question) => answer_question(&config, &label, question),
        ReplyBody::ServerStatus => server_status(&config, &label),
        ReplyBody::LobbyRooms => lobby_rooms(&config, &label),
    };
    let outcome = match send_reply(&config, &job, &text, false) {
        Ok(reply_id) => Ok(reply_id),
        // 401 = 凭证失效/过期：强刷 token 后有界重试一次（绝不循环）。
        Err(err @ SendError::Api(LibError::Api(401))) => {
            logln(
                "INFO",
                &format!("reply got 401, refreshing token and retrying once: {err}"),
            );
            send_reply(&config, &job, &text, true)
        }
        Err(err) => Err(err),
    };
    match outcome {
        Ok(reply_id) => logln(
            "INFO",
            &format!(
                "reply sent event={label} target={} reply_id={} text_bytes={}",
                job.target_label(),
                sanitize_text(reply_id.as_bytes(), 64),
                text.len(),
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
fn send_reply(
    config: &Config,
    job: &ReplyJob,
    text: &str,
    force_refresh: bool,
) -> Result<String, SendError> {
    let token = ensure_token(config, force_refresh)?;
    let request = api::send_message_request(job.is_group, &job.openid, text, &job.msg_id, 1)?;
    let (status, body) = post_json(&config.agent, &request, Some(&token))?;
    Ok(api::parse_send_response(status, &body)?.id)
}

/// AI 问答：调用 zerostack 单次问答，返回可发送的回答正文。
///
/// 失败（未启用/启动失败/超时/非零退出/空回答）→ 记 WARN 并返回显式兜底
/// 文案：错误不吞（日志留痕），机器人不装死（用户得到明确回应）。
fn answer_question(config: &Config, label: &str, question: &str) -> String {
    let started = std::time::Instant::now();
    match ask_zerostack(config, question) {
        Ok(answer) => {
            logln(
                "INFO",
                &format!(
                    "qa answered event={label} q_bytes={} a_chars={} ms={}",
                    question.len(),
                    answer.chars().count(),
                    started.elapsed().as_millis(),
                ),
            );
            answer
        }
        Err(err) => {
            logln(
                "WARN",
                &format!("qa failed event={label} q_bytes={}: {err}", question.len()),
            );
            String::from("AI 问答暂时不可用，请稍后再试")
        }
    }
}

/// 服务器状态：只读查询游戏 `/healthz` 与大厅公开计数，成文返回。
///
/// 三个请求相互独立：任一失败只少一行，绝不让整条回复变成错误；全失败
/// 才回显式兜底文案。失败原因逐条记 WARN（不吞错）。
fn server_status(config: &Config, label: &str) -> String {
    if !config.status.enabled {
        return String::from("服务器状态查询未启用（/帮助 查看指令）");
    }
    let started = std::time::Instant::now();
    let game = http_get_text(&config.agent, &config.status.game_url);
    let base = config.status.lobby_base.trim_end_matches('/');
    let online = http_get_text(&config.agent, &format!("{base}/api/online_count"));
    let active = http_get_text(&config.agent, &format!("{base}/api/active_rooms"));
    if let Err(err) = &game {
        logln("WARN", &format!("status game fetch failed: {err}"));
    }
    if let Err(err) = &online {
        logln("WARN", &format!("status lobby online fetch failed: {err}"));
    }
    if let Err(err) = &active {
        logln("WARN", &format!("status lobby rooms fetch failed: {err}"));
    }
    let text = compose_status(
        game.as_deref().ok(),
        online.as_deref().ok(),
        active.as_deref().ok(),
        base,
    );
    logln(
        "INFO",
        &format!(
            "status queried event={label} game={} lobby_online={} lobby_rooms={} ms={}",
            if game.is_ok() { "ok" } else { "err" },
            online.is_ok(),
            active.is_ok(),
            started.elapsed().as_millis(),
        ),
    );
    text
}

/// GET 一个文本响应；非 2xx 也取回 body 供排障（不丢信息）。
fn http_get_text(agent: &ureq::Agent, url: &str) -> Result<String, String> {
    match agent.get(url).call() {
        Ok(response) => response
            .into_string()
            .map_err(|err| format!("read body: {err}")),
        Err(ureq::Error::Status(status, response)) => {
            let body = response.into_string().unwrap_or_default();
            Err(format!(
                "status {status}: {}",
                sanitize_text(body.as_bytes(), 120)
            ))
        }
        Err(other) => Err(other.to_string()),
    }
}

/// 纯函数：把三份可选的应答正文拼成回复文本（无 IO，便于单测）。
fn compose_status(
    game: Option<&str>,
    online: Option<&str>,
    active: Option<&str>,
    link: &str,
) -> String {
    let mut lines: Vec<String> = vec![String::from("🎮 卫戍协议 · 服务器状态")];
    let mut any = false;
    if let Some(body) = game {
        let humans = json_int(body, "humans");
        let matches = json_int(body, "matches");
        let rooms = json_int(body, "rooms");
        if humans.is_some() || matches.is_some() || rooms.is_some() {
            lines.push(format!(
                "游戏服：{} 人在线 · {} 场对局 · {} 房间 · 观战 {}",
                humans.unwrap_or(0),
                matches.unwrap_or(0),
                rooms.unwrap_or(0),
                json_int(body, "spectators").unwrap_or(0),
            ));
            // 快速匹配队列（0.2.3 起 /healthz 可能带这两个字段）。
            if let Some(matching) = json_int(body, "matching") {
                lines.push(format!(
                    "快速匹配：{} 队 / {} 人等待",
                    matching,
                    json_int(body, "queued").unwrap_or(0),
                ));
            }
            any = true;
        }
    }
    if let Some(count) = online.and_then(|body| json_int(body, "online_count")) {
        match active.and_then(|body| json_int(body, "active_room_count")) {
            Some(rooms) => lines.push(format!("组队大厅：{count} 人在线 · {rooms} 个房间")),
            None => lines.push(format!("组队大厅：{count} 人在线")),
        }
        any = true;
    }
    if !any {
        return String::from("服务器状态暂时不可用，请稍后再试");
    }
    if !link.is_empty() {
        lines.push(format!("一起玩：{link}"));
    }
    lines.join("\n")
}

/// 从扁平 JSON 文本里读一个整数字段（键后必须跟 `:`；无 serde 依赖）。
///
/// 只服务本用例的 `/healthz`、`/api/online_count` 等扁平对象：找 `"key"`，
/// 跳过冒号与空白后取连续数字。找不到/非整数 → `None`。
fn json_int(body: &str, key: &str) -> Option<i64> {
    let needle = format!("\"{key}\"");
    let mut from = 0;
    while let Some(offset) = body[from..].find(&needle) {
        let after = from + offset + needle.len();
        let rest = body[after..].trim_start();
        if let Some(rest) = rest.strip_prefix(':') {
            let digits: String = rest
                .trim_start()
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '-')
                .collect();
            if !digits.is_empty()
                && digits != "-"
                && let Ok(value) = digits.parse::<i64>()
            {
                return Some(value);
            }
        }
        from = after;
    }
    None
}

/// 单条回复里最多列出的等待房间数。
const MAX_ROOM_LINES: usize = 8;

/// 组队大厅房间列表：用机器人专用账号登录取 token，只读 `GET /api/rooms` 后成文。
///
/// token 命中缓存直接复用；`/api/rooms` 返回 401（token 失效）时先用
/// refresh_token 换新（轮换式）或重新登录，再有界重试一次。任一环节失败都
/// 记 WARN 并回显式兜底文案（不吞错，不装死）。
fn lobby_rooms(config: &Config, label: &str) -> String {
    if !config.lobby.enabled {
        return String::from("组队大厅房间查询未启用（/帮助 查看指令）");
    }
    let started = std::time::Instant::now();
    let base = config.status.lobby_base.trim_end_matches('/');
    let url = format!("{base}/api/rooms");
    let mut session = match lobby_session(config) {
        Ok(session) => session,
        Err(err) => {
            logln("WARN", &format!("lobby login failed: {err}"));
            return String::from("组队大厅暂时不可用，请稍后再试");
        }
    };
    let mut fetched = http_get_status(&config.agent, &url, Some(&session.access));
    if let Ok((401, _)) = &fetched {
        logln("INFO", "lobby token expired, renewing and retrying once");
        match lobby_renew(config, &session) {
            Ok(renewed) => {
                store_lobby_session(config, &renewed);
                session = renewed;
                fetched = http_get_status(&config.agent, &url, Some(&session.access));
            }
            Err(err) => {
                logln("WARN", &format!("lobby session renew failed: {err}"));
                fetched = Err(err);
            }
        }
    }
    let text = match fetched {
        Ok((200, body)) => match compose_rooms(&body, base) {
            Ok(text) => text,
            Err(err) => {
                logln("WARN", &format!("lobby rooms parse failed: {err}"));
                String::from("组队大厅房间数据解析失败，请稍后再试")
            }
        },
        Ok((status, body)) => {
            logln(
                "WARN",
                &format!(
                    "lobby rooms status {status}: {}",
                    sanitize_text(body.as_bytes(), 120)
                ),
            );
            String::from("组队大厅暂时不可用，请稍后再试")
        }
        Err(err) => {
            logln("WARN", &format!("lobby rooms fetch failed: {err}"));
            String::from("组队大厅暂时不可用，请稍后再试")
        }
    };
    logln(
        "INFO",
        &format!(
            "lobby rooms queried event={label} ms={}",
            started.elapsed().as_millis()
        ),
    );
    text
}

/// 取大厅会话：命中缓存直接用，否则登录取新并写缓存。
fn lobby_session(config: &Config) -> Result<LobbySession, String> {
    if let Some(session) = cached_lobby_session(config) {
        return Ok(session);
    }
    let session = lobby_login(config)?;
    store_lobby_session(config, &session);
    Ok(session)
}

/// 续期大厅会话：优先用 refresh_token 换新，失败则重新登录（有界，不循环）。
fn lobby_renew(config: &Config, session: &LobbySession) -> Result<LobbySession, String> {
    if !session.refresh.is_empty() {
        match lobby_refresh(config, session.refresh.expose()) {
            Ok(renewed) => return Ok(renewed),
            Err(err) => logln("WARN", &format!("lobby refresh failed, re-login: {err}")),
        }
    }
    lobby_login(config)
}

/// `POST {base}/api/login` → 解析 access/refresh token。
fn lobby_login(config: &Config) -> Result<LobbySession, String> {
    let base = config.status.lobby_base.trim_end_matches('/');
    let payload = format!(
        "{{\"username\":\"{}\",\"password\":\"{}\"}}",
        json_escape(&config.lobby.user),
        json_escape(config.lobby.pass.expose()),
    );
    let (status, body) = http_post_status(&config.agent, &format!("{base}/api/login"), &payload)?;
    if status != 200 {
        return Err(format!(
            "login status {status}: {}",
            sanitize_text(body.as_bytes(), 120)
        ));
    }
    parse_lobby_session(&body)
}

/// `POST {base}/api/refresh` → 解析轮换后的 access/refresh token。
fn lobby_refresh(config: &Config, refresh_token: &str) -> Result<LobbySession, String> {
    let base = config.status.lobby_base.trim_end_matches('/');
    let payload = format!("{{\"refresh_token\":\"{}\"}}", json_escape(refresh_token));
    let (status, body) = http_post_status(&config.agent, &format!("{base}/api/refresh"), &payload)?;
    if status != 200 {
        return Err(format!(
            "refresh status {status}: {}",
            sanitize_text(body.as_bytes(), 120)
        ));
    }
    parse_lobby_session(&body)
}

/// 从登录/续期应答里取 token（缺 access_token 视为失败，不降级）。
fn parse_lobby_session(body: &str) -> Result<LobbySession, String> {
    let access = callback::json_top_text(body.as_bytes(), b"access_token")
        .map_err(|err| format!("parse access_token: {err}"))?
        .ok_or_else(|| "login response missing access_token".to_string())?;
    let refresh = callback::json_top_text(body.as_bytes(), b"refresh_token")
        .map_err(|err| format!("parse refresh_token: {err}"))?
        .unwrap_or_default();
    Ok(LobbySession {
        access: SecretString::new(access),
        refresh: SecretString::new(refresh),
    })
}

/// 读会话缓存（锁中毒时取回内部值继续，绝不 panic）。
fn cached_lobby_session(config: &Config) -> Option<LobbySession> {
    let guard = match config.lobby_session.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.clone()
}

/// 写会话缓存（锁中毒时取回内部值继续，绝不 panic）。
fn store_lobby_session(config: &Config, session: &LobbySession) {
    let mut guard = match config.lobby_session.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    *guard = Some(session.clone());
}

/// 带可选 Bearer token 的 GET：返回 `(status, body)`；非 2xx 也取回 body（不丢信息）。
fn http_get_status(
    agent: &ureq::Agent,
    url: &str,
    token: Option<&SecretString>,
) -> Result<(u16, String), String> {
    let mut builder = agent.get(url);
    if let Some(token) = token {
        builder = builder.set("Authorization", &format!("Bearer {}", token.expose()));
    }
    match builder.call() {
        Ok(response) => Ok((
            response.status(),
            response
                .into_string()
                .map_err(|err| format!("read body: {err}"))?,
        )),
        Err(ureq::Error::Status(status, response)) => {
            Ok((status, response.into_string().unwrap_or_default()))
        }
        Err(other) => Err(other.to_string()),
    }
}

/// POST JSON：返回 `(status, body)`；非 2xx 也取回 body（不丢信息）。
fn http_post_status(
    agent: &ureq::Agent,
    url: &str,
    payload: &str,
) -> Result<(u16, String), String> {
    match agent
        .post(url)
        .set("Content-Type", "application/json; charset=utf-8")
        .send_string(payload)
    {
        Ok(response) => Ok((
            response.status(),
            response
                .into_string()
                .map_err(|err| format!("read body: {err}"))?,
        )),
        Err(ureq::Error::Status(status, response)) => {
            Ok((status, response.into_string().unwrap_or_default()))
        }
        Err(other) => Err(other.to_string()),
    }
}

/// JSON 字符串内容转义（不含包裹引号）：防登录/续期请求体注入。
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 8);
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// 一轮房间的展示字段（`/api/rooms` 顶层数组项）。
struct LobbyRoom {
    name: String,
    room_type: String,
    game_status: String,
    creator: String,
    owner_online: bool,
    member_count: i64,
    max_players: i64,
}

/// 解析 `/api/rooms` 应答并渲染为回复文本（纯函数，无 IO，便于单测）。
fn compose_rooms(body: &str, link_base: &str) -> Result<String, String> {
    let objects = json_array_objects(body, "rooms")?
        .ok_or_else(|| "response missing rooms array".to_string())?;
    let mut rooms = Vec::with_capacity(objects.len());
    for object in objects {
        rooms.push(parse_room(object)?);
    }
    Ok(render_rooms(&rooms, link_base))
}

/// 从单个房间对象取展示字段（字符串经库内 `json_top_text` 解码转义）。
fn parse_room(object: &str) -> Result<LobbyRoom, String> {
    Ok(LobbyRoom {
        name: json_text(object, "name")?.unwrap_or_default(),
        room_type: json_text(object, "room_type")?.unwrap_or_default(),
        game_status: json_text(object, "game_status")?.unwrap_or_default(),
        creator: json_text(object, "creator_nickname")?.unwrap_or_else(|| String::from("未知")),
        owner_online: json_bool(object, "is_owner_online").unwrap_or(false),
        member_count: json_int(object, "member_count").unwrap_or(0),
        max_players: json_int(object, "max_players").unwrap_or(0),
    })
}

/// 渲染房间列表：突出「等待中」的房间，附带进行中数量与大厅入口。
fn render_rooms(rooms: &[LobbyRoom], link_base: &str) -> String {
    let waiting: Vec<&LobbyRoom> = rooms
        .iter()
        .filter(|room| room.game_status == "waiting")
        .collect();
    let playing = rooms
        .iter()
        .filter(|room| room.game_status == "playing")
        .count();
    let mut lines: Vec<String> = vec![String::from("🏠 组队大厅 · 等待中的房间")];
    if waiting.is_empty() {
        lines.push(String::from("当前没有等待中的房间，快去开一个吧"));
    } else {
        for room in waiting.iter().take(MAX_ROOM_LINES) {
            lines.push(format_room(room));
        }
        if waiting.len() > MAX_ROOM_LINES {
            lines.push(format!("…… 还有 {} 个房间", waiting.len() - MAX_ROOM_LINES));
        }
    }
    if playing > 0 {
        lines.push(format!("进行中：{playing} 个房间"));
    }
    if !link_base.is_empty() {
        lines.push(format!("前往大厅：{link_base}/"));
    }
    lines.join("\n")
}

/// 单个房间一行：名称、公开/私密、人数、房主与在线状态。
fn format_room(room: &LobbyRoom) -> String {
    let kind = if room.room_type == "private" {
        "私密"
    } else {
        "公开"
    };
    let owner = if room.owner_online {
        "在线"
    } else {
        "离线"
    };
    format!(
        "· {} [{kind}] {}/{} 人 · 房主 {}（{owner}）",
        room.name, room.member_count, room.max_players, room.creator
    )
}

/// 取 `"key":[...]` 顶层数组里的对象切片（字符串感知，容忍对象内嵌套）。
///
/// key 不存在 → `Ok(None)`；值不是数组、或数组项不是对象 → 报错（严格模式：
/// 宁可拒绝也不猜结构）。
fn json_array_objects<'a>(body: &'a str, key: &str) -> Result<Option<Vec<&'a str>>, String> {
    let bytes = body.as_bytes();
    let needle = format!("\"{key}\"");
    let Some(offset) = body.find(&needle) else {
        return Ok(None);
    };
    let mut i = skip_ws(bytes, offset + needle.len());
    if bytes.get(i) != Some(&b':') {
        return Err(format!("{key}: missing ':'"));
    }
    i = skip_ws(bytes, i + 1);
    if bytes.get(i) != Some(&b'[') {
        return Err(format!("{key}: not an array"));
    }
    i += 1;
    let mut objects = Vec::new();
    loop {
        i = skip_array_sep(bytes, i);
        match bytes.get(i) {
            None | Some(&b']') => break,
            Some(&b'{') => {
                let end = scan_object_end(bytes, i)
                    .ok_or_else(|| format!("{key}: unterminated object"))?;
                objects.push(&body[i..=end]);
                i = end + 1;
            }
            Some(_) => return Err(format!("{key}: array item is not an object")),
        }
    }
    Ok(Some(objects))
}

/// 跳过空白（不含逗号）。
fn skip_ws(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r') {
        i += 1;
    }
    i
}

/// 跳过数组项之间的空白与逗号。
fn skip_array_sep(bytes: &[u8], mut i: usize) -> usize {
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r' | b',') {
        i += 1;
    }
    i
}

/// 返回与 `bytes[start]`（`{`）匹配的 `}` 下标；字符串内的花括号不计。
fn scan_object_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0usize;
    let mut i = start;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = skip_string(bytes, i)?,
            b'{' | b'[' => {
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(i);
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    None
}

/// 跳过 `bytes[quote]`（开引号）处的字符串，返回闭引号后的下标。
fn skip_string(bytes: &[u8], quote: usize) -> Option<usize> {
    let mut i = quote + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i + 1),
            _ => i += 1,
        }
    }
    None
}

/// 取字符串字段值（`null` 视作缺省；其余交库内 `json_top_text` 严格解码转义）。
fn json_text(object: &str, key: &str) -> Result<Option<String>, String> {
    if json_value_is_null(object, key) {
        return Ok(None);
    }
    callback::json_top_text(object.as_bytes(), key.as_bytes())
        .map_err(|err| format!("parse {key}: {err}"))
}

/// 判定 `"key"` 的值是否为 `null`（`json_top_text` 会把 null 当形态错误）。
fn json_value_is_null(object: &str, key: &str) -> bool {
    let needle = format!("\"{key}\"");
    let Some(offset) = object.find(&needle) else {
        return false;
    };
    match object[offset + needle.len()..]
        .trim_start()
        .strip_prefix(':')
    {
        Some(value) => value.trim_start().starts_with("null"),
        None => false,
    }
}

/// 从扁平 JSON 文本里读一个布尔字段（键后必须跟 `:`；无 serde 依赖）。
fn json_bool(object: &str, key: &str) -> Option<bool> {
    let needle = format!("\"{key}\"");
    let mut from = 0;
    while let Some(offset) = object[from..].find(&needle) {
        let after = from + offset + needle.len();
        if let Some(rest) = object[after..].trim_start().strip_prefix(':') {
            let rest = rest.trim_start();
            if rest.starts_with("true") {
                return Some(true);
            }
            if rest.starts_with("false") {
                return Some(false);
            }
        }
        from = after;
    }
    None
}

/// 执行 zerostack 单次问答（`-p` 打印回答到 stdout；`--no-tools` 单轮纯问答）。
///
/// - 问答未启用 → Err（由 [`answer_question`] 转为提示文案）；
/// - 超时 → kill 子进程后 Err（绝不无限等待占住工作线程）；
/// - stdout/stderr 由独立线程排空（避免管道写满死锁），退出后回收；
/// - 回答经控制字符清洗 + 字数截断（平台未公开文本长度上限，保守截断）。
fn ask_zerostack(config: &Config, question: &str) -> Result<String, String> {
    if !config.qa.enabled {
        return Err("qa disabled".to_string());
    }
    let args = [
        "--no-tools".to_string(),
        "--no-context-files".to_string(),
        // 临时模式：不落会话文件（问答为一次性调用，避免数据目录无限增长）。
        "--no-session".to_string(),
        "--no-color".to_string(),
        "-p".to_string(),
        question.to_string(),
    ];
    let raw = run_capture(&config.qa.bin, &args, config.qa.timeout)?;
    let answer = clean_answer(&raw);
    if answer.is_empty() {
        return Err("empty answer on stdout".to_string());
    }
    Ok(truncate_answer(&answer, config.qa.max_chars))
}

/// 启动子进程并在超时内收集 stdout；非零退出/超时/启动失败 → Err。
///
/// stdout/stderr 由读取线程排空；超时 kill 后同样回收线程，不留孤儿。
fn run_capture(bin: &str, args: &[String], timeout: Duration) -> Result<String, String> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("spawn {bin}: {err}"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "stdout pipe missing".to_string())?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| "stderr pipe missing".to_string())?;
    let out_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout.read_to_end(&mut buf);
        buf
    });
    let err_reader = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        buf
    });
    let deadline = std::time::Instant::now() + timeout;
    let status: std::process::ExitStatus = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_reader.join();
                let _ = err_reader.join();
                return Err(format!("timeout after {}s", timeout.as_secs()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_reader.join();
                let _ = err_reader.join();
                return Err(format!("wait: {err}"));
            }
        }
    };
    let out = out_reader
        .join()
        .map_err(|_| "stdout reader panicked".to_string())?;
    let err_bytes = err_reader
        .join()
        .map_err(|_| "stderr reader panicked".to_string())?;
    if !status.success() {
        return Err(format!("exit {status}: {}", sanitize_text(&err_bytes, 300)));
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// 清洗回答：剥离 ANSI 转义序列与控制字符（保留换行）并 trim。
fn clean_answer(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    // 状态机：0 正文 / 1 ESC 之后 / 2 CSI|OSC 序列中。
    let mut state = 0u8;
    for c in raw.chars() {
        match state {
            1 => state = if c == '[' || c == ']' { 2 } else { 0 },
            // 序列被换行打断（防跑飞）：结束序列并保留换行。
            2 if c == '\n' => {
                state = 0;
                out.push('\n');
            }
            // CSI 最终字节（0x40..=0x7E）→ 序列结束。
            2 if ('\u{40}'..='\u{7e}').contains(&c) => state = 0,
            // 参数/中间字节：丢弃。
            2 => {}
            _ => {
                if c == '\u{1b}' {
                    state = 1;
                } else if c == '\n' || !c.is_control() {
                    out.push(c);
                }
            }
        }
    }
    out.trim().to_string()
}

/// 按字数截断（char 边界安全；超长加省略号）。
fn truncate_answer(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars).collect();
    out.push('…');
    out
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
            // 问答默认关闭：单测不 spawn 进程。
            qa: super::QaConfig {
                enabled: false,
                bin: String::new(),
                timeout: std::time::Duration::from_secs(1),
                max_chars: 100,
            },
            // 状态查询默认关闭：单测不发网络请求。
            status: super::StatusConfig {
                enabled: false,
                game_url: "http://127.0.0.1:1/healthz".to_string(),
                lobby_base: "http://127.0.0.1:1/lobby".to_string(),
            },
            // 房间查询默认关闭：单测不发网络请求。
            lobby: super::LobbyConfig {
                enabled: false,
                user: String::new(),
                pass: SecretString::new(String::new()),
            },
            lobby_session: Arc::new(Mutex::new(None)),
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

    /// 真实单聊事件报文（Radxa 抓取；中文按 UTF-8 字节转义，`/帮助` 带指令前缀）。
    const C2C_HELP_EVENT: &[u8] = b"{\"op\":0,\"id\":\"C2C_MESSAGE_CREATE:sfyoo42bh\",\"d\":{\"id\":\"ROBOT1.0_oC3JDEal\",\"content\":\"/\xe5\xb8\xae\xe5\x8a\xa9\",\"timestamp\":\"2026-10-09T00:22:29+08:00\",\"author\":{\"id\":\"DE8C8AEC\",\"username\":\"\",\"bot\":false,\"user_openid\":\"DE8C8AECAF13F8D144240291E8D7B0A7\",\"union_openid\":\"\"},\"message_type\":0},\"t\":\"C2C_MESSAGE_CREATE\",\"seq\":1}";

    /// 真实群事件报文（成员进群；无正文、无消息 id → 不属于消息事件）。
    const GROUP_MEMBER_ADD: &[u8] = b"{\"op\":0,\"id\":\"GROUP_MEMBER_ADD:x\",\"d\":{\"timestamp\":\"2026-10-09T00:19:16+08:00\",\"group_openid\":\"3D54AA8E\",\"member_openid\":\"095AF6EF\"},\"t\":\"GROUP_MEMBER_ADD\",\"seq\":3}";

    /// 取指令回复文本（非 Text 断言失败）。
    fn text_of(job: &super::ReplyJob) -> &str {
        match &job.body {
            super::ReplyBody::Text(text) => text,
            super::ReplyBody::Ask(question) => panic!("expected Text, got Ask({question})"),
            super::ReplyBody::ServerStatus => panic!("expected Text, got ServerStatus"),
            super::ReplyBody::LobbyRooms => panic!("expected Text, got LobbyRooms"),
        }
    }

    #[test]
    fn plan_reply_targets_c2c_for_help_command() {
        let job = plan_reply(C2C_HELP_EVENT, 1_791_476_549, 0)
            .unwrap()
            .expect("/帮助 must plan a reply");
        assert!(!job.is_group);
        assert_eq!(job.openid, "DE8C8AECAF13F8D144240291E8D7B0A7");
        assert_eq!(job.msg_id, "ROBOT1.0_oC3JDEal");
        assert_eq!(job.event_type, "C2C_MESSAGE_CREATE");
        assert!(text_of(&job).contains("可用指令"), "text={}", text_of(&job));
    }

    #[test]
    fn plan_reply_targets_group_and_answers_unknown_command() {
        let body = b"{\"op\":0,\"id\":\"GROUP_AT_MESSAGE_CREATE:g\",\"d\":{\"author\":{\"id\":\"79BE\",\"user_openid\":\"79BE66EF\"},\"content\":\"/123\",\"group_openid\":\"3D54AA8E\",\"id\":\"ROBOT1.0_grp\",\"message_type\":0},\"t\":\"GROUP_AT_MESSAGE_CREATE\",\"seq\":1}";
        let job = plan_reply(body, 0, 0)
            .unwrap()
            .expect("group @ message must plan a reply");
        assert!(job.is_group);
        assert_eq!(job.openid, "3D54AA8E");
        assert_eq!(job.msg_id, "ROBOT1.0_grp");
        // 未知指令不装死。
        assert!(text_of(&job).contains("帮助"), "text={}", text_of(&job));
    }

    #[test]
    fn plan_reply_routes_plain_text_to_ai_ask() {
        // 无 `/` 前缀的群消息 → Ask，问题原样携带、目标仍为群。
        let body = b"{\"op\":0,\"id\":\"GROUP_AT_MESSAGE_CREATE:g\",\"d\":{\"author\":{\"id\":\"79BE\",\"user_openid\":\"79BE66EF\"},\"content\":\"Rust is fun\",\"group_openid\":\"3D54AA8E\",\"id\":\"ROBOT1.0_grp\",\"message_type\":0},\"t\":\"GROUP_AT_MESSAGE_CREATE\",\"seq\":1}";
        let job = plan_reply(body, 0, 0)
            .unwrap()
            .expect("plain text must plan an ask");
        assert!(job.is_group);
        let super::ReplyBody::Ask(question) = &job.body else {
            panic!("expected Ask, got Text");
        };
        assert_eq!(question, "Rust is fun");
    }

    #[test]
    fn plan_reply_routes_status_command() {
        // `/对局`（UTF-8）→ ServerStatus，目标仍为单聊。
        let body = b"{\"op\":0,\"id\":\"C2C_MESSAGE_CREATE:g\",\"d\":{\"author\":{\"id\":\"79BE\",\"user_openid\":\"79BE66EF\"},\"content\":\"/\xe5\xaf\xb9\xe5\xb1\x80\",\"id\":\"ROBOT1.0_grp\",\"message_type\":0},\"t\":\"C2C_MESSAGE_CREATE\",\"seq\":1}";
        let job = plan_reply(body, 0, 0)
            .unwrap()
            .expect("/对局 must plan a reply");
        assert!(matches!(job.body, super::ReplyBody::ServerStatus));
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
    fn clean_answer_strips_controls_and_trims() {
        // 控制字符（含 ANSI ESC）被移除，换行保留。
        assert_eq!(
            super::clean_answer("\u{1b}[31m红色\u{1b}[0m\n第二行\n"),
            "红色\n第二行"
        );
        // 全控制字符 + 空白 → 空串（调用方按空回答处理）。
        assert_eq!(super::clean_answer(" \n\t "), "");
    }

    #[test]
    fn truncate_answer_caps_by_chars_with_ellipsis() {
        assert_eq!(super::truncate_answer("短回答", 100), "短回答");
        let long = "问".repeat(50);
        let out = super::truncate_answer(&long, 10);
        assert_eq!(out.chars().count(), 11, "10 字 + 省略号");
        assert!(out.ends_with('…'));
        // 中英混排按 char 截断，不 panic（char 边界安全）。
        assert!(super::truncate_answer("abc中文def", 4).ends_with('…'));
    }

    #[test]
    fn json_int_reads_flat_fields() {
        let body = r#"{"ok":true,"version":1,"rooms":98,"matches":96,"humans":108,"bots":25,"spectators":0}"#;
        assert_eq!(super::json_int(body, "humans"), Some(108));
        assert_eq!(super::json_int(body, "matches"), Some(96));
        assert_eq!(super::json_int(body, "rooms"), Some(98));
        // 字段不存在 → None（键必须后跟冒号）。
        assert_eq!(super::json_int(body, "matching"), None);
        assert_eq!(super::json_int(body, "spectators"), Some(0));
        // 快速匹配字段（0.2.3 起可能出现在 /healthz）。
        assert_eq!(
            super::json_int(r#"{"matching":2,"queued":5}"#, "queued"),
            Some(5)
        );
        // 值里出现同名键不误读。
        assert_eq!(
            super::json_int(r#"{"a":"humans:9","humans":3}"#, "humans"),
            Some(3)
        );
    }

    #[test]
    fn compose_status_formats_game_and_lobby() {
        let game = r#"{"humans":108,"matches":96,"rooms":98,"spectators":0}"#;
        let online = r#"{"online_count":0}"#;
        let active = r#"{"active_room_count":1}"#;
        let text = super::compose_status(
            Some(game),
            Some(online),
            Some(active),
            "https://sp.lain42.top/lobby",
        );
        assert!(text.contains("108 人在线"), "text={text}");
        assert!(text.contains("96 场对局"), "text={text}");
        assert!(text.contains("组队大厅"), "text={text}");
        assert!(text.contains("https://sp.lain42.top/lobby"), "text={text}");
        // 队列字段存在时多一行。
        let queued = r#"{"humans":3,"matches":1,"rooms":2,"spectators":0,"matching":1,"queued":2}"#;
        let text = super::compose_status(Some(queued), None, None, "L");
        assert!(text.contains("快速匹配"), "text={text}");
        assert!(text.contains("2 人等待"), "text={text}");
        // 三份全失败 → 显式兜底，不是空串。
        assert!(
            super::compose_status(None, None, None, "L").contains("暂时不可用"),
            "must fall back"
        );
    }

    #[test]
    fn server_status_disabled_returns_hint_without_network() {
        // 单测配置 status.enabled=false → 不触网，直接给提示。
        let text = super::server_status(&config(), "TEST");
        assert!(text.contains("未启用"), "text={text}");
    }

    #[test]
    fn lobby_rooms_disabled_returns_hint_without_network() {
        // 单测配置 lobby.enabled=false → 不触网，直接给提示。
        let text = super::lobby_rooms(&config(), "TEST");
        assert!(text.contains("未启用"), "text={text}");
    }

    /// 读取一条完整的 HTTP 请求（头 + 按 Content-Length 读完请求体）。
    fn read_full_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut buf = Vec::new();
        let mut tmp = [0u8; 2048];
        let mut header_end = None;
        while header_end.is_none() {
            match stream.read(&mut tmp) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = super::find_bytes(&buf, b"\r\n\r\n") {
                        header_end = Some(pos + 4);
                    }
                }
            }
        }
        if let Some(header_end) = header_end {
            let head = String::from_utf8_lossy(&buf[..header_end]).to_lowercase();
            let clen = head
                .split("content-length:")
                .nth(1)
                .and_then(|rest| {
                    rest.split(|c: char| !c.is_ascii_digit())
                        .find(|s| !s.is_empty())
                })
                .and_then(|digits| digits.parse::<usize>().ok())
                .unwrap_or(0);
            while buf.len() < header_end + clen {
                match stream.read(&mut tmp) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => buf.extend_from_slice(&tmp[..n]),
                }
            }
        }
        buf
    }

    /// 假登录/续期应答（带 access/refresh token）。
    const MOCK_LOGIN: &str =
        r#"{"access_token":"mock-access","refresh_token":"mock-refresh","expires_in":1800}"#;
    /// 假房间列表（一个等待中的房间）。
    const MOCK_ROOMS: &str = r#"{"rooms":[{"id":7,"name":"waitroom","creator_nickname":"bot","member_count":1,"max_players":4,"room_type":"public","game_status":"waiting","is_owner_online":true}]}"#;

    /// 起一个最小 HTTP 假服务，返回其 `/lobby` 基地址。
    ///
    /// `/api/login`、`/api/refresh` → 200 + 伪造 token；`/api/rooms` → 当
    /// `unauthorized_first` 时首次 401、其后 200 + 一个等待房间。
    fn spawn_mock(unauthorized_first: bool) -> String {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let rooms_calls = AtomicUsize::new(0);
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let buf = read_full_request(&mut stream);
                let line_end = super::find_bytes(&buf, b"\r\n").unwrap_or(buf.len());
                let request_line = String::from_utf8_lossy(&buf[..line_end]).to_string();
                let (status, reason, body) = if request_line.contains("/api/login")
                    || request_line.contains("/api/refresh")
                {
                    (200u16, "OK", MOCK_LOGIN)
                } else if request_line.contains("/api/rooms") {
                    if unauthorized_first && rooms_calls.fetch_add(1, Ordering::Relaxed) == 0 {
                        (401, "Unauthorized", "{}")
                    } else {
                        (200, "OK", MOCK_ROOMS)
                    }
                } else {
                    (404, "Not Found", "{}")
                };
                let response = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.flush();
            }
        });
        format!("http://{addr}/lobby")
    }

    fn lobby_config(base: String) -> Config {
        let mut config = config();
        config.lobby = super::LobbyConfig {
            enabled: true,
            user: "qqbot".to_string(),
            pass: SecretString::new("pw".to_string()),
        };
        config.status.lobby_base = base;
        config
    }

    #[test]
    fn lobby_rooms_logs_in_and_lists_rooms() {
        // 全链路：登录取 token → 带 Bearer 读房间 → 成文（走真实 ureq + 假服务）。
        let config = lobby_config(spawn_mock(false));
        let text = super::lobby_rooms(&config, "TEST");
        assert!(text.contains("waitroom"), "text={text}");
        assert!(text.contains("房主 bot（在线）"), "text={text}");
        assert!(text.contains("1/4 人"), "text={text}");
    }

    #[test]
    fn lobby_rooms_renews_and_retries_on_401() {
        // 首次房间请求 401 → refresh_token 换新 → 重试一次成功。
        let config = lobby_config(spawn_mock(true));
        let text = super::lobby_rooms(&config, "TEST");
        assert!(text.contains("waitroom"), "text={text}");
    }

    #[test]
    fn plan_reply_routes_lobby_command() {
        // `/房间`（UTF-8）→ LobbyRooms，目标仍为单聊。
        let body = b"{\"op\":0,\"id\":\"C2C_MESSAGE_CREATE:g\",\"d\":{\"author\":{\"id\":\"79BE\",\"user_openid\":\"79BE66EF\"},\"content\":\"/\xe6\x88\xbf\xe9\x97\xb4\",\"id\":\"ROBOT1.0_grp\",\"message_type\":0},\"t\":\"C2C_MESSAGE_CREATE\",\"seq\":1}";
        let job = plan_reply(body, 0, 0)
            .unwrap()
            .expect("/房间 must plan a reply");
        assert!(matches!(job.body, super::ReplyBody::LobbyRooms));
    }

    #[test]
    fn json_escape_escapes_quotes_and_controls() {
        assert_eq!(super::json_escape("a\"b\\c"), "a\\\"b\\\\c");
        assert_eq!(super::json_escape("行1\n行2\t"), "行1\\n行2\\t");
        assert_eq!(super::json_escape("\u{1}"), "\\u0001");
    }

    #[test]
    fn compose_rooms_lists_waiting_and_hides_finished() {
        // 中文按 Flask 默认 ensure_ascii 转义为 \uXXXX；null 昵称 → 未知。
        let body = r#"{"rooms":[{"id":1,"name":"已结束房","creator_nickname":"z","created_at":"2026-10-05T14:36:32.122779","member_count":1,"max_players":4,"room_type":"public","game_status":"finished","is_owner_online":false},{"id":2,"name":"\u4e0a\u5206\u8f66\u961f","creator_nickname":null,"member_count":2,"max_players":4,"room_type":"private","game_status":"waiting","is_owner_online":true},{"id":3,"name":"playing","creator_nickname":"a","member_count":4,"max_players":4,"room_type":"public","game_status":"playing","is_owner_online":true}]}"#;
        let text = super::compose_rooms(body, "https://sp.lain42.top/lobby").unwrap();
        assert!(text.contains("上分车队"), "unicode name missing: {text}");
        assert!(text.contains("[私密]"), "room_type missing: {text}");
        assert!(text.contains("2/4 人"), "member count missing: {text}");
        assert!(
            text.contains("房主 未知（在线）"),
            "null creator missing: {text}"
        );
        assert!(
            text.contains("进行中：1 个房间"),
            "playing line missing: {text}"
        );
        assert!(
            text.contains("https://sp.lain42.top/lobby"),
            "link missing: {text}"
        );
        // 已结束的房间不出现在等待列表里。
        assert!(!text.contains("已结束房"), "finished room leaked: {text}");
    }

    #[test]
    fn compose_rooms_handles_empty_and_empty_link() {
        let text = super::compose_rooms(r#"{"rooms":[]}"#, "").unwrap();
        assert!(text.contains("没有等待中的房间"), "text={text}");
        assert!(
            !text.contains("前往大厅"),
            "empty link must be omitted: {text}"
        );
    }

    #[test]
    fn json_array_objects_is_string_and_nesting_aware() {
        // 对象内含嵌套数组 + 字符串里的花括号，不应截断对象。
        let body = r#"{"rooms":[{"name":"a}b","members":[{"id":1}]},{"name":"c"}]}"#;
        let objects = super::json_array_objects(body, "rooms").unwrap().unwrap();
        assert_eq!(objects.len(), 2);
        assert!(objects[0].contains("\"members\""));
        assert!(objects[0].ends_with('}'));
        // 键不存在 → None；值非法形态 → 报错（严格模式）。
        assert!(super::json_array_objects("{}", "rooms").unwrap().is_none());
        assert!(super::json_array_objects(r#"{"rooms":5}"#, "rooms").is_err());
        assert!(super::json_array_objects(r#"{"rooms":[1]}"#, "rooms").is_err());
    }

    #[test]
    fn json_bool_reads_flat_fields() {
        assert_eq!(
            super::json_bool(r#"{"is_owner_online":true}"#, "is_owner_online"),
            Some(true)
        );
        assert_eq!(
            super::json_bool(r#"{"is_owner_online": false}"#, "is_owner_online"),
            Some(false)
        );
        assert_eq!(
            super::json_bool(r#"{"is_owner_online":null}"#, "is_owner_online"),
            None
        );
        assert_eq!(super::json_bool("{}", "is_owner_online"), None);
    }

    #[test]
    fn answer_question_disabled_returns_fallback() {
        // 问答未启用（单测配置）→ 显式兜底文案，不 spawn 进程。
        let text = super::answer_question(&config(), "TEST", "任意问题");
        assert!(text.contains("AI 问答"), "text={text}");
        assert!(super::ask_zerostack(&config(), "q").is_err());
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
