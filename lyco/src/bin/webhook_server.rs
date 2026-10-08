//! QQ 机器人 webhook 接收端（std 运行时；库核心保持 no_std）。
//!
//! 职责（对应 botgo issue #61 的结构性规避）：
//!
//! - op=13 回调握手：应答 `{plain_token, signature}`，保存回调地址即通过校验；
//! - op=0 事件推送：`X-Signature-Ed25519` + `X-Signature-Timestamp` 验签通过才上抛
//!   （打印事件正文），失败回 403 并记录原因——不吞错、不 panic；
//! - 凭证只从环境变量 `QQ_BOT_SECRET` 读入 [`SecretString`]，永不进日志。
//!
//! 环境变量：
//!
//! | 变量 | 默认值 | 说明 |
//! |------|--------|------|
//! | `QQ_BOT_SECRET` | （必填） | 机器人 secret（运行时注入，不入库） |
//! | `QQ_APPID` | — | 仅用于启动日志展示 |
//! | `WEBHOOK_BIND` | `0.0.0.0:8080` | 监听地址 |
//! | `WEBHOOK_PRINT_EVENTS` | `1` | 是否打印已验签事件的原始报文 |

use qq_bot_rust::callback::{self, OP_CHALLENGE, OP_EVENT};
use qq_bot_rust::crypto::webhook::{derive_public_key, verify_callback};
use qq_bot_rust::secret::SecretString;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
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

/// 服务配置（每连接克隆一份，无共享可变状态）。
#[derive(Clone)]
struct Config {
    secret: SecretString,
    print_events: bool,
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
    let config = Config {
        secret: SecretString::new(secret_value),
        print_events: std::env::var("WEBHOOK_PRINT_EVENTS")
            .map(|value| value != "0")
            .unwrap_or(true),
    };
    let bind = std::env::var("WEBHOOK_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());

    let listener = TcpListener::bind(&bind).map_err(|err| format!("bind {bind} 失败: {err}"))?;
    let local = listener
        .local_addr()
        .map_err(|err| format!("读取监听地址失败: {err}"))?;

    // 公钥非机密：启动时打印，供与开放平台控制台展示的公钥比对。
    let pubkey = derive_public_key(config.secret.expose())
        .map_err(|err| format!("派生机器人公钥失败: {err}"))?;
    logln(
        "INFO",
        &format!(
            "webhook server listening on {local} appid={} pubkey={} print_events={}",
            std::env::var("QQ_APPID").unwrap_or_else(|_| "-".to_string()),
            hex_encode(&pubkey),
            config.print_events,
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
    use super::{Config, HttpRequest, handle_client, process};
    use qq_bot_rust::crypto::webhook::{derive_seed, sign_challenge};
    use qq_bot_rust::secret::SecretString;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    /// 官方《Webhook 方式》演示 secret。
    const DOC_SECRET: &str = "DG5g3B4j9X2KOErG";

    fn config() -> Config {
        Config {
            secret: SecretString::new(DOC_SECRET),
            print_events: true,
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
}
