//! 统一错误类型。
//!
//! 对应 botgo issue #61 反模式③（token 服务不可用即 panic）与⑤（解析失败吞错继续跑）：
//! 库内任何失败都以 [`Result`] 上抛，绝不 panic。

use core::fmt;

/// SDK 统一错误。
///
/// 标记 `#[non_exhaustive]`：后续新增错误种类不破坏下游 `match`（须带通配臂）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// 十六进制解码失败（如 webhook 签名 header 非法：奇数长度或非法字符）。
    InvalidHex,
    /// Ed25519 签名验证未通过（签名与消息不匹配）。
    SignatureInvalid,
    /// 签名结构非法：字节数 ≠ 64，或 S 值高 3 位未清零（文档要求的延展性检查）。
    MalformedSignature,
    /// bot secret 为空，无法派生 Ed25519 密钥。
    EmptySecret,
    /// 底层密码学运算失败，携带静态原因描述。
    Crypto(&'static str),
    /// 回调报文 JSON 形态非法（截断、值类型不符、含转义、非 UTF-8）。
    MalformedJson,
    /// 回调报文缺少必需字段，携带字段名。
    MissingField(&'static str),
    /// 回调 op 与预期不符（如对非 13 的报文执行握手处理）。
    UnexpectedOp(i64),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHex => f.write_str("invalid hex encoding"),
            Self::SignatureInvalid => f.write_str("ed25519 signature verification failed"),
            Self::MalformedSignature => f.write_str("malformed ed25519 signature"),
            Self::EmptySecret => f.write_str("bot secret must not be empty"),
            Self::Crypto(reason) => write!(f, "cryptographic error: {reason}"),
            Self::MalformedJson => f.write_str("malformed webhook payload JSON"),
            Self::MissingField(field) => write!(f, "webhook payload missing field: {field}"),
            Self::UnexpectedOp(op) => write!(f, "unexpected webhook op: {op}"),
        }
    }
}

impl core::error::Error for Error {}

/// SDK 统一返回类型。
pub type Result<T> = core::result::Result<T, Error>;
