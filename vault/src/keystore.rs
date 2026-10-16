//! vault key 的保管處(KeyStore)。
//!
//! VaultStore 不管 key 實際放在哪:檔案模式(Windows/Linux、測試)用
//! [`FileKeyStore`];Apple 平台由 tterm-ffi 提供 Keychain 版。
//!
//! 一個 key store 平常只放一把 key。換 key(import_pairing)途中會暫時放新舊兩把,
//! 不論在哪一步斷電,裡面都有一把解得開磁碟上那份 vault.tv(見 VaultStore)。

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

use crate::crypto::KEY_LEN;
use crate::store::atomic_write;

pub type VaultKey = [u8; KEY_LEN];

pub trait KeyStore: Send {
    /// 讀出保管中的 key(平常一把,換 key 途中兩把)。
    ///
    /// 空 Vec 只代表「確定沒有」。讀不到(裝置鎖定、使用者拒絕存取…)一律回
    /// Err——VaultStore 會把「沒有」當成可以另開新 vault。
    fn load(&self) -> Result<Vec<VaultKey>>;

    /// 整組取代保管中的 key(至少一把)。回 Ok 前必須已經持久化。
    fn store(&self, keys: &[VaultKey]) -> Result<()>;
}

/// key 存成檔案:base64(key₁ ‖ key₂ ‖ …)。只有一把時就是舊版 `vault.key` 的格式。
pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl KeyStore for FileKeyStore {
    fn load(&self) -> Result<Vec<VaultKey>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e).context("failed to read vault.key"),
        };
        let bytes = STANDARD.decode(text.trim()).context("failed to decode vault.key")?;
        split_keys(&bytes).context("vault.key has the wrong length")
    }

    fn store(&self, keys: &[VaultKey]) -> Result<()> {
        atomic_write(&self.path, STANDARD.encode(join_keys(keys)?).as_bytes())
    }
}

/// key store 內容的共同格式:一把以上的 key 首尾相接。
pub fn join_keys(keys: &[VaultKey]) -> Result<Vec<u8>> {
    if keys.is_empty() {
        bail!("at least one vault key is required");
    }
    Ok(keys.concat())
}

/// [`join_keys`] 的反向。空的或長度不是 key 整數倍都算壞資料(不是「沒有 key」)。
pub fn split_keys(bytes: &[u8]) -> Result<Vec<VaultKey>> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(KEY_LEN) {
        bail!("vault key data length {} is not a multiple of {KEY_LEN}", bytes.len());
    }
    Ok(bytes.as_chunks::<KEY_LEN>().0.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_split_roundtrip() {
        let a = [1u8; KEY_LEN];
        let b = [2u8; KEY_LEN];
        assert_eq!(
            split_keys(&join_keys(&[a, b]).unwrap()).unwrap(),
            vec![a, b]
        );
        assert!(join_keys(&[]).is_err());
        assert!(split_keys(&[]).is_err());
        assert!(split_keys(&[0u8; KEY_LEN + 1]).is_err());
    }

    #[test]
    fn file_store_missing_is_empty_not_error() {
        let dir = tempfile::TempDir::new().unwrap();
        let fs = FileKeyStore::new(dir.path().join("vault.key"));
        assert!(fs.load().unwrap().is_empty());
        fs.store(&[[7u8; KEY_LEN]]).unwrap();
        assert_eq!(fs.load().unwrap(), vec![[7u8; KEY_LEN]]);
    }

    #[test]
    fn file_store_single_key_matches_legacy_format() {
        // 舊版 vault.key = base64(32B);新舊版本互相讀得懂
        let dir = tempfile::TempDir::new().unwrap();
        let fs = FileKeyStore::new(dir.path().join("vault.key"));
        let key = [9u8; KEY_LEN];
        fs.store(&[key]).unwrap();
        let text = std::fs::read_to_string(fs.path()).unwrap();
        assert_eq!(STANDARD.decode(text.trim()).unwrap(), key.to_vec());
    }
}
