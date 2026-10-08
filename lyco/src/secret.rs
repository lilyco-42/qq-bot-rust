//! 凭证脱敏包装。
//!
//! 对应 botgo issue #61 反模式①（appsecret/access_token 被完整打进日志）
//! 与反模式②（调试日志不可关）：**结构上**不可能通过常规格式化泄露明文，
//! 无论使用方的日志级别如何配置都安全。

use alloc::string::String;
use core::fmt;

/// 不可打印的字符串凭证（bot secret / access token 等）。
///
/// - `Debug`、`Display` 永远只输出 [`REDACTED`](Self::REDACTED)，
///   即使被 `{:?}` / `{}` 误格式化、或被日志框架整对象序列化，也不会泄露明文；
/// - 取回明文必须显式调用 [`expose`](Self::expose)——该调用点即代码审计点。
///
/// ```
/// use qq_bot_rust::secret::SecretString;
///
/// let secret = SecretString::new("s3cr3t-value");
/// assert_eq!(format!("{secret}"), "[REDACTED]");
/// assert_eq!(format!("{secret:?}"), "SecretString([REDACTED])");
/// assert_eq!(secret.expose(), "s3cr3t-value");
/// ```
#[derive(Clone)]
pub struct SecretString {
    inner: String,
}

impl SecretString {
    /// 脱敏占位符。
    pub const REDACTED: &'static str = "[REDACTED]";

    /// 包装一份明文凭证。
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            inner: value.into(),
        }
    }

    /// 显式取回明文。
    ///
    /// 审计原则：库内部（日志、错误信息、panic 消息）禁止调用本方法。
    pub fn expose(&self) -> &str {
        &self.inner
    }

    /// 凭证长度（长度非敏感信息，可用于空值检查）。
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// 凭证是否为空串。
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::REDACTED)
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString({})", Self::REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::SecretString;
    use alloc::format;

    #[test]
    fn display_and_debug_never_leak() {
        let secret = SecretString::new("super-secret-token");
        for rendered in [format!("{secret}"), format!("{secret:?}")] {
            assert!(
                !rendered.contains("super-secret-token"),
                "leaked: {rendered}"
            );
        }
        assert_eq!(format!("{secret}"), SecretString::REDACTED);
    }

    #[test]
    fn expose_returns_plaintext() {
        let secret = SecretString::new("super-secret-token");
        assert_eq!(secret.expose(), "super-secret-token");
        assert_eq!(secret.len(), "super-secret-token".len());
        assert!(SecretString::new("").is_empty());
    }
}
