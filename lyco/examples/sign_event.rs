//! E2E 自测工具：为 op=0 事件报文生成 `X-Signature-Ed25519` 签名。
//!
//! 用法（secret 只经环境变量传入，不落命令行历史）：
//!
//! ```sh
//! SIGN_SECRET=xxx SIGN_TS=1725442341 SIGN_BODY='{"op":0}' \
//!   cargo run --example sign_event
//! ```

use qq_bot_rust::crypto::webhook::derive_seed;

fn main() {
    let secret = std::env::var("SIGN_SECRET").expect("SIGN_SECRET is required");
    let timestamp = std::env::var("SIGN_TS").expect("SIGN_TS is required");
    let body = std::env::var("SIGN_BODY").expect("SIGN_BODY is required");

    let seed = derive_seed(secret.as_bytes()).expect("derive_seed failed");
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let mut message = timestamp.into_bytes();
    message.extend_from_slice(body.as_bytes());
    let signature = ed25519_dalek::Signer::sign(&key, &message);

    let hex: String = signature
        .to_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!("{hex}");
}
