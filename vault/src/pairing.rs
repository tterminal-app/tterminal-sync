//! RustDesk 式配對字串:`TTERMSYNC1:` + base64url(json)。
//! 一段字串攜帶 server 位置、vault id、認證 token 與 E2E vault key,
//! 複製到其他 client 貼上即完成同步設定。

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto::KEY_LEN;

pub const PREFIX: &str = "TTERMSYNC1:";
pub const TOKEN_LEN: usize = 32;

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
            bail!("不是 tterminal 配對字串(缺少 {PREFIX} 前綴)");
        };
        // 濾掉字串內所有空白:pairing 常經郵件/備忘錄/聊天等會自動折行的通道
        // 傳遞,中間夾進 \n / 空格。只做 trim() 清不掉中間的換行,會 decode 失敗。
        let cleaned: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
        let payload = URL_SAFE_NO_PAD
            .decode(&cleaned)
            .context("配對字串 base64 解碼失敗")?;
        let json: PairingJson =
            serde_json::from_slice(&payload).context("配對字串內容格式錯誤")?;
        if json.v != 1 {
            bail!("配對字串版本 {} 不支援(此版本只支援 v1)", json.v);
        }
        if json.server.is_empty() {
            bail!("配對字串缺少 server 位置");
        }
        let token_vec = STANDARD.decode(&json.token).context("token 解碼失敗")?;
        let key_vec = STANDARD.decode(&json.key).context("key 解碼失敗")?;
        let token: [u8; TOKEN_LEN] = token_vec
            .try_into()
            .map_err(|_| anyhow::anyhow!("token 長度錯誤"))?;
        let key: [u8; KEY_LEN] = key_vec
            .try_into()
            .map_err(|_| anyhow::anyhow!("key 長度錯誤"))?;
        Ok(Self {
            server: json.server,
            vault_id: json.vault,
            token,
            key,
        })
    }
}
