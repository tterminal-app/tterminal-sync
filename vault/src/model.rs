//! Record 模型與 HLC。
//!
//! server 可見欄位:id / hlc / device / deleted(+ server 自配的 seq)。
//! body(kind/name/data)一律在加密 blob 內,server 不可見。

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// 加密 blob 內的內容(server 不可見)。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordBody {
    pub kind: String,
    pub name: String,
    pub data: serde_json::Value,
}

/// 一筆 vault record。tombstone(deleted=true)不保留 body。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub id: Uuid,
    pub hlc: u64,
    pub device: String,
    pub deleted: bool,
    pub body: Option<RecordBody>,
}

impl Record {
    /// LWW 排序鍵:先比 hlc,平手比 device(字典序)。
    pub fn version_key(&self) -> (u64, &str) {
        (self.hlc, self.device.as_str())
    }
}

/// 同步 wire 格式(密文)。與 server 的 JSON 欄位一一對應。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireRecord {
    pub id: Uuid,
    pub hlc: u64,
    pub device: String,
    pub deleted: bool,
    /// base64(nonce || ciphertext);tombstone 為空字串。
    pub blob: String,
    /// server 端變更序號;push 上行時不帶(None)。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

/// 混合邏輯時鐘:hlc = ms * 1000 + counter,單調遞增。
/// 同一毫秒內的連續變更以 +1 遞增;收到遠端 hlc 時往前推進,
/// 讓時鐘漂移的裝置不會用「舊時間」蓋掉新資料。
pub fn next_hlc(last: &mut u64) -> u64 {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let candidate = now_ms * 1000;
    *last = candidate.max(*last + 1);
    *last
}

pub fn observe_hlc(last: &mut u64, remote: u64) {
    if remote > *last {
        *last = remote;
    }
}
