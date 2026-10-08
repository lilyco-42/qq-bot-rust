//! Webhook 回调的 Ed25519 验签与握手签名。
//!
//! 两条链路（均对齐官方文档，测试使用文档给出的已知向量）：
//!
//! 1. **回调验签**：header `X-Signature-Ed25519`（64 字节签名的 hex）+
//!    `X-Signature-Timestamp`，签名体为 `timestamp || body`；
//! 2. **回调地址握手（op=13）**：签名体为 `event_ts || plain_token`，
//!    返回 `{plain_token, signature}`。

use crate::error::{Error, Result};
use alloc::string::String;
use alloc::vec::Vec;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};

/// Ed25519 seed 长度（字节）。
const SEED_LEN: usize = 32;
/// Ed25519 签名长度（字节）。
const SIGNATURE_LEN: usize = 64;
/// 官方文档要求：签名 S 值高 3 位必须为零（防延展性）。
const SIGNATURE_S_HIGH_BITS_MASK: u8 = 0xE0;

/// 由 bot secret 派生 Ed25519 seed。
///
/// 规则（与官方 Go 示例一致）：secret 不足 32 字节时不断与自身拼接加倍，
/// 直到长度 ≥ 32，再截断为前 32 字节。空 secret 直接报错（官方 Go 示例
/// 在空串时会死循环拼接，此处显式拒绝）。
pub fn derive_seed(secret: &[u8]) -> Result<[u8; SEED_LEN]> {
    if secret.is_empty() {
        return Err(Error::EmptySecret);
    }

    let mut buf = Vec::from(secret);
    while buf.len() < SEED_LEN {
        let mut doubled = Vec::with_capacity(buf.len() * 2);
        doubled.extend_from_slice(&buf);
        doubled.extend_from_slice(&buf);
        buf = doubled;
    }

    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&buf[..SEED_LEN]);
    Ok(seed)
}

/// 由 bot secret 派生公钥（32 字节）。
pub fn derive_public_key(secret: &str) -> Result<[u8; SEED_LEN]> {
    let key = SigningKey::from_bytes(&derive_seed(secret.as_bytes())?);
    Ok(*key.verifying_key().as_bytes())
}

/// 校验 webhook 回调签名。
///
/// - 签名体：`timestamp || body`（原始字节拼接，body 不做任何解析假设）；
/// - `signature_hex` 必须是偶数长度的合法 hex，解码后恰为 64 字节；
/// - 第 64 字节（S 值末字节）高 3 位必须为 0。
///
/// 任何一步失败都返回错误——对应 botgo issue #61 反模式⑤"解析失败只打日志继续跑"。
pub fn verify_callback(
    secret: &str,
    timestamp: &str,
    body: &[u8],
    signature_hex: &str,
) -> Result<()> {
    let signature = decode_hex(signature_hex)?;
    if signature.len() != SIGNATURE_LEN
        || signature[SIGNATURE_LEN - 1] & SIGNATURE_S_HIGH_BITS_MASK != 0
    {
        return Err(Error::MalformedSignature);
    }
    let signature = Signature::from_slice(&signature).map_err(|_| Error::MalformedSignature)?;

    let mut msg = Vec::with_capacity(timestamp.len() + body.len());
    msg.extend_from_slice(timestamp.as_bytes());
    msg.extend_from_slice(body);

    let verifying_key = SigningKey::from_bytes(&derive_seed(secret.as_bytes())?).verifying_key();
    verifying_key
        .verify(&msg, &signature)
        .map_err(|_| Error::SignatureInvalid)
}

/// 生成回调地址握手（op=13）的应答签名。
///
/// 签名体为 `event_ts || plain_token`，返回小写 hex 编码的 64 字节签名。
pub fn sign_challenge(secret: &str, event_ts: &str, plain_token: &str) -> Result<String> {
    let mut msg = Vec::with_capacity(event_ts.len() + plain_token.len());
    msg.extend_from_slice(event_ts.as_bytes());
    msg.extend_from_slice(plain_token.as_bytes());
    sign_message(secret, &msg)
}

/// 对任意消息体签名，返回小写 hex（内部原语，握手与自检共用）。
fn sign_message(secret: &str, msg: &[u8]) -> Result<String> {
    let key = SigningKey::from_bytes(&derive_seed(secret.as_bytes())?);
    let signature = key.sign(msg);
    Ok(encode_hex(&signature.to_bytes()))
}

/// 十六进制解码；奇数长度或非法字符返回 [`Error::InvalidHex`]（绝不 panic）。
fn decode_hex(input: &str) -> Result<Vec<u8>> {
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(Error::InvalidHex);
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = hex_value(pair[0])?;
        let lo = hex_value(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// 单个 hex 字符转数值。
fn hex_value(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::InvalidHex),
    }
}

/// 十六进制编码（小写）。
fn encode_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0F) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{decode_hex, derive_public_key, sign_challenge, sign_message, verify_callback};
    use crate::error::Error;

    /// 文档《安全和授权》演示向量的 secret。
    const DOC_SECRET: &str = "naOC0ocQE3shWLAfffVLB1rhYPG7";
    /// 上述 secret 派生的公钥（文档 DEMO 输出，32 字节十进制）。
    const DOC_PUBLIC_KEY: [u8; 32] = [
        215, 195, 98, 254, 120, 174, 248, 31, 242, 50, 135, 180, 147, 98, 139, 93, 176, 42, 60, 79,
        227, 11, 33, 94, 77, 25, 96, 155, 93, 118, 103, 58,
    ];

    #[test]
    fn derives_documented_public_key() {
        assert_eq!(derive_public_key(DOC_SECRET).unwrap(), DOC_PUBLIC_KEY);
    }

    #[test]
    fn rejects_empty_secret() {
        assert_eq!(derive_public_key(""), Err(Error::EmptySecret));
    }

    /// 官方 sign.html 的验签 DEMO sig 是**占位值**，连文档自己给的 body 都验不过：
    /// 全生态已知问题——Embers-of-the-Fire/bofa-qqbot 用 vitest `it.fails` 标注该
    /// 向量预期失败，znjhahaha/tgmon 实测后注明"文档随手填的占位值，不是真实签名"。
    /// 因此不拿它当向量；改用官方 seed 自签自验，锁定「签名体 = timestamp || body」
    /// 的拼接顺序与完整验签链路（公钥派生另有官方向量覆盖）。
    #[test]
    fn roundtrips_timestamp_then_body_concatenation() {
        let body = br#"{ "op": 0,"d": {}, "t": "GATEWAY_EVENT_NAME"}"#;
        let timestamp = "1725442341";

        let signature = sign_message(DOC_SECRET, &[timestamp.as_bytes(), body].concat()).unwrap();
        verify_callback(DOC_SECRET, timestamp, body, &signature).unwrap();

        // 同一签名换 body 必须拒绝（验签链路不是恒真）。
        assert_eq!(
            verify_callback(DOC_SECRET, timestamp, br#"{"op":0}"#, &signature),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_tampered_body() {
        let timestamp = "1725442341";
        let signature = "865ad13a61752ca65e26bde6676459cd36cf1be609375b37bd62af366e1dc25a8dc789ba7f14e017ada3d554c671a911bfdf075ba54835b23391d509579ed002";
        let body = br#"{ "op": 0,"d": {}, "t": "TAMPERED_EVENT"}"#;
        assert_eq!(
            verify_callback(DOC_SECRET, timestamp, body, signature),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_tampered_timestamp() {
        let body = br#"{ "op": 0,"d": {}, "t": "GATEWAY_EVENT_NAME"}"#;
        let signature = "865ad13a61752ca65e26bde6676459cd36cf1be609375b37bd62af366e1dc25a8dc789ba7f14e017ada3d554c671a911bfdf075ba54835b23391d509579ed002";
        assert_eq!(
            verify_callback(DOC_SECRET, "1725442342", body, signature),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn rejects_malformed_signature_hex() {
        let body: &[u8] = b"{}";
        // 奇数长度。
        assert_eq!(
            verify_callback(DOC_SECRET, "1", body, "abc"),
            Err(Error::InvalidHex)
        );
        // 非法字符。
        assert_eq!(
            verify_callback(DOC_SECRET, "1", body, "zz"),
            Err(Error::InvalidHex)
        );
        // 长度不是 64 字节。
        assert_eq!(
            verify_callback(DOC_SECRET, "1", body, "abcd"),
            Err(Error::MalformedSignature)
        );
    }

    #[test]
    fn signs_official_challenge_vector() {
        // 文档《Webhook 方式》演示向量：secret + 回调验证请求。
        let signature =
            sign_challenge("DG5g3B4j9X2KOErG", "1725442341", "Arq0D5A61EgUu4OxUvOp").unwrap();
        assert_eq!(
            signature,
            "87befc99c42c651b3aac0278e71ada338433ae26fcb24307bdc5ad38c1adc2d01bcfcadc0842edac85e85205028a1132afe09280305f13aa6909ffc2d652c706"
        );
    }

    #[test]
    fn hex_decode_edge_cases() {
        assert_eq!(decode_hex("").unwrap(), Vec::<u8>::new());
        assert_eq!(decode_hex("0aFF").unwrap(), vec![0x0A, 0xFF]);
        assert_eq!(decode_hex("0"), Err(Error::InvalidHex));
        assert_eq!(decode_hex("0g"), Err(Error::InvalidHex));
    }
}
