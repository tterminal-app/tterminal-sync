//! RustDesk 式配對字串:`TTERMSYNC1:` + base64url(json)。
//! 一段字串攜帶 server 位置、vault id、認證 token 與 E2E vault key,
//! 複製到其他 client 貼上即完成同步設定。

use anyhow::Result;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::KEY_LEN;

pub const PREFIX: &str = "TTERMSYNC1:";
pub const TOKEN_LEN: usize = 32;

/// 配對字串解不開的原因。使用者是貼上來的,UI 要能分辨給出看得懂的提示
/// (見 tterm-ffi 的 error.rs)。
#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    #[error("not a tterminal pairing string (missing TTERMSYNC1: prefix)")]
    MissingPrefix,
    #[error("pairing string version {0} is not supported (this build only reads v1)")]
    UnsupportedVersion(u32),
    #[error("malformed pairing string: {0}")]
    Malformed(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Pairing {
    pub server: String,
    pub vault_id: Uuid,
    pub token: [u8; TOKEN_LEN],
    pub key: [u8; KEY_LEN],
}

#[derive(Serialize, Deserialize)]
struct PairingJson {
    v: u32,
    server: String,
    vault: Uuid,
    token: String,
    key: String,
}

impl Pairing {
    pub fn encode(&self) -> String {
        let json = PairingJson {
            v: 1,
            server: self.server.clone(),
            vault: self.vault_id,
            token: STANDARD.encode(self.token),
            key: STANDARD.encode(self.key),
        };
        let payload = serde_json::to_vec(&json).expect("pairing json");
        format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(payload))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let s = s.trim();
        let Some(b64) = s.strip_prefix(PREFIX) else {
            return Err(PairingError::MissingPrefix.into());
        };
        // 濾掉字串內所有空白:pairing 常經郵件/備忘錄/聊天等會自動折行的通道
        // 傳遞,中間夾進 \n / 空格。只做 trim() 清不掉中間的換行,會 decode 失敗。
        let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        let malformed = |what: &str| PairingError::Malformed(what.to_string());
        let payload = URL_SAFE_NO_PAD
            .decode(&cleaned)
            .map_err(|e| malformed(&format!("base64: {e}")))?;
        let json: PairingJson = serde_json::from_slice(&payload)
            .map_err(|e| malformed(&format!("json: {e}")))?;
        if json.v != 1 {
            return Err(PairingError::UnsupportedVersion(json.v).into());
        }
        if json.server.is_empty() {
            return Err(malformed("missing server address").into());
        }
        let token_vec = STANDARD
            .decode(&json.token)
            .map_err(|e| malformed(&format!("token: {e}")))?;
        let key_vec = STANDARD
            .decode(&json.key)
            .map_err(|e| malformed(&format!("key: {e}")))?;
        let token: [u8; TOKEN_LEN] = token_vec
            .try_into()
            .map_err(|_| malformed("wrong token length"))?;
        let key: [u8; KEY_LEN] = key_vec
            .try_into()
            .map_err(|_| malformed("wrong key length"))?;
        Ok(Self {
            server: json.server,
            vault_id: json.vault,
            token,
            key,
        })
    }
}
