//! tterm-vault:Vault 核心(模型、加密、合併、配對字串、本地儲存)。
//!
//! 設計依據:docs/vault-sync-design.md。
//! 分層原則:金鑰與密文只存在這裡;上層(FFI/Dart)只搬運已加密的
//! wire payload 與已解密的 UI snapshot,拿不到 vault key 本體。

pub mod crypto;
pub mod model;
pub mod pairing;
pub mod store;

pub use model::{Record, RecordBody, WireRecord};
pub use crypto::DecryptError;
pub use pairing::{Pairing, PairingError};
pub use store::{ApplySummary, JoinSummary, SyncConfig, VaultStore};
