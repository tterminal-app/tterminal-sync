//! 外部 key store(Keychain 模式)測試:新 vault、舊版 vault.key 遷移、
//! 遷移中途失敗、重裝 app、備份還原到新裝置、換 key(import_pairing)中斷。
//!
//! 用記憶體版 key store 模擬 Keychain,可以注入讀/寫失敗,在 host 上就能跑。

use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::json;
use tempfile::TempDir;
use tterm_vault::{KeyStore, VaultKey, VaultStore};

#[derive(Default)]
struct Inner {
    keys: Vec<VaultKey>,
    fail_load: bool,
    fail_store: bool,
    /// store 回 Ok 但其實沒寫進去(讀回驗證要抓得到)
    lose_writes: bool,
    stores: usize,
}

/// 記憶體版 key store;clone 出來的是同一份(模擬同一台裝置的 Keychain)。
#[derive(Clone, Default)]
struct MemKeyStore(Arc<Mutex<Inner>>);

impl MemKeyStore {
    fn with_keys(keys: &[VaultKey]) -> Self {
        let s = Self::default();
        s.0.lock().unwrap().keys = keys.to_vec();
        s
    }
    fn keys(&self) -> Vec<VaultKey> {
        self.0.lock().unwrap().keys.clone()
    }
    fn set(&self, f: impl FnOnce(&mut Inner)) {
        f(&mut self.0.lock().unwrap());
    }
    fn stores(&self) -> usize {
        self.0.lock().unwrap().stores
    }
    fn boxed(&self) -> Box<dyn KeyStore> {
        Box::new(self.clone())
    }
}

impl KeyStore for MemKeyStore {
    fn load(&self) -> anyhow::Result<Vec<VaultKey>> {
        let inner = self.0.lock().unwrap();
        if inner.fail_load {
            anyhow::bail!("模擬:裝置鎖定中");
        }
        Ok(inner.keys.clone())
    }
    fn store(&self, keys: &[VaultKey]) -> anyhow::Result<()> {
        let mut inner = self.0.lock().unwrap();
        if inner.fail_store {
            anyhow::bail!("模擬:Keychain 寫入失敗");
        }
        inner.stores += 1;
        if !inner.lose_writes {
            inner.keys = keys.to_vec();
        }
        Ok(())
    }
}

fn key_file(dir: &TempDir) -> std::path::PathBuf {
    dir.path().join("vault.key")
}

fn state_file(dir: &TempDir) -> std::path::PathBuf {
    dir.path().join("vault.tv")
}

/// 舊版(檔案模式)的 vault.key 內容。
fn file_key(dir: &TempDir) -> VaultKey {
    use base64::Engine;
    let text = std::fs::read_to_string(key_file(dir)).unwrap();
    base64::engine::general_purpose::STANDARD
        .decode(text.trim())
        .unwrap()
        .try_into()
        .unwrap()
}

fn names(v: &VaultStore) -> Vec<String> {
    v.snapshot_json()["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_string())
        .collect()
}

fn unreadable_files(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with("vault.tv.unreadable-"))
        .collect()
}

/// 舊版安裝:檔案模式建 vault、存一筆 host。
fn legacy_install(dir: &TempDir) -> VaultKey {
    let mut v = VaultStore::open(dir.path()).unwrap();
    v.upsert(None, "host", "web1", json!({"address": "10.0.0.1"}))
        .unwrap();
    file_key(dir)
}

// ---- 新安裝 ----

#[test]
fn new_vault_key_lives_only_in_key_store() {
    let dir = TempDir::new().unwrap();
    let ks = MemKeyStore::default();
    {
        let mut v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
        v.upsert(None, "host", "web1", json!({})).unwrap();
    }
    assert!(!key_file(&dir).exists(), "Keychain 模式不得留下 vault.key");
    assert_eq!(ks.keys().len(), 1);

    let v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    assert_eq!(names(&v), ["web1"]);
}

#[test]
fn new_vault_aborts_when_key_store_cannot_write() {
    let dir = TempDir::new().unwrap();
    let ks = MemKeyStore::default();
    ks.set(|i| i.fail_store = true);
    assert!(VaultStore::open_with_key_store(dir.path(), ks.boxed()).is_err());
    // 不能留下一份沒有 key 解得開的 vault.tv,也不能退回寫檔
    assert!(!state_file(&dir).exists());
    assert!(!key_file(&dir).exists());
}

#[test]
fn load_error_aborts_without_touching_anything() {
    let dir = TempDir::new().unwrap();
    legacy_install(&dir);
    let tv = std::fs::read(state_file(&dir)).unwrap();
    let key = std::fs::read(key_file(&dir)).unwrap();

    let ks = MemKeyStore::default();
    ks.set(|i| i.fail_load = true);
    assert!(VaultStore::open_with_key_store(dir.path(), ks.boxed()).is_err());
    assert_eq!(std::fs::read(state_file(&dir)).unwrap(), tv);
    assert_eq!(std::fs::read(key_file(&dir)).unwrap(), key);
    assert!(unreadable_files(dir.path()).is_empty());
}

// ---- 舊版升級:vault.key 搬進 key store ----

#[test]
fn legacy_key_file_migrates_into_key_store() {
    let dir = TempDir::new().unwrap();
    let old_key = legacy_install(&dir);
    let tv = std::fs::read(state_file(&dir)).unwrap();

    let ks = MemKeyStore::default();
    let v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    assert_eq!(names(&v), ["web1"], "資料都要還在");
    assert_eq!(ks.keys(), vec![old_key], "沿用原本那把 key,不重新加密");
    assert!(!key_file(&dir).exists(), "搬完要刪 vault.key");
    assert_eq!(
        std::fs::read(state_file(&dir)).unwrap(),
        tv,
        "vault.tv 不用重寫"
    );
    drop(v);

    let v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    assert_eq!(names(&v), ["web1"]);
}

#[test]
fn migration_write_failure_keeps_file_and_retries_next_launch() {
    let dir = TempDir::new().unwrap();
    let old_key = legacy_install(&dir);

    let ks = MemKeyStore::default();
    ks.set(|i| i.fail_store = true);
    let v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    assert_eq!(names(&v), ["web1"], "key store 壞了也要打得開");
    assert!(key_file(&dir).exists(), "沒搬成功不能刪檔");
    drop(v);

    ks.set(|i| i.fail_store = false);
    let v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    assert_eq!(names(&v), ["web1"]);
    assert_eq!(ks.keys(), vec![old_key]);
    assert!(!key_file(&dir).exists());
}

#[test]
fn migration_unverified_write_keeps_file() {
    // store 回 Ok 但讀回來沒有:不能刪檔
    let dir = TempDir::new().unwrap();
    legacy_install(&dir);
    let ks = MemKeyStore::default();
    ks.set(|i| i.lose_writes = true);
    let v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    assert_eq!(names(&v), ["web1"]);
    assert!(key_file(&dir).exists());
}

#[test]
fn migration_interrupted_before_delete_finishes_next_launch() {
    // 上次寫進 key store 後、刪檔前中斷:兩邊都有同一把 key
    let dir = TempDir::new().unwrap();
    let old_key = legacy_install(&dir);
    let ks = MemKeyStore::with_keys(&[old_key]);
    let v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    assert_eq!(names(&v), ["web1"]);
    assert!(!key_file(&dir).exists());
    assert_eq!(ks.stores(), 0, "已經在了,不用再寫");
}

#[test]
fn stale_key_from_previous_install_is_replaced_by_legacy_file() {
    // iOS 刪 app 不會清 Keychain:上一次安裝留下的 key 解不開現在這份 vault.tv
    let dir = TempDir::new().unwrap();
    let old_key = legacy_install(&dir);
    let ks = MemKeyStore::with_keys(&[[0xAB; 32]]);
    let v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    assert_eq!(names(&v), ["web1"]);
    assert_eq!(ks.keys(), vec![old_key]);
    assert!(!key_file(&dir).exists());
}

#[test]
fn unrelated_legacy_file_is_left_alone() {
    // key store 的 key 解得開;旁邊那個 vault.key 對不上 → 不是我們能判斷的,不刪
    let dir = TempDir::new().unwrap();
    let ks = MemKeyStore::default();
    drop(VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap());
    let stray = TempDir::new().unwrap();
    legacy_install(&stray);
    std::fs::copy(key_file(&stray), key_file(&dir)).unwrap();

    VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    assert!(key_file(&dir).exists());
}

// ---- 重裝、備份還原 ----

#[test]
fn reinstall_reuses_key_left_in_key_store() {
    // 重裝:沙盒清空、Keychain 還在 → 新 vault 沿用那把 key,不覆蓋
    let ks = MemKeyStore::with_keys(&[[0x11; 32]]);
    let dir = TempDir::new().unwrap();
    VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    assert_eq!(ks.keys(), vec![[0x11; 32]]);
    assert_eq!(ks.stores(), 0);
}

#[test]
fn backup_restore_with_keychain_opens() {
    // 加密備份(iCloud 備份一律加密)還原到新手機:vault.tv 與 Keychain 項目都跟過來
    let old = TempDir::new().unwrap();
    let ks = MemKeyStore::default();
    {
        let mut v = VaultStore::open_with_key_store(old.path(), ks.boxed()).unwrap();
        v.upsert(None, "host", "web1", json!({})).unwrap();
    }
    let new = TempDir::new().unwrap();
    std::fs::copy(old.path().join("vault.tv"), new.path().join("vault.tv")).unwrap();
    let restored = MemKeyStore::with_keys(&ks.keys());
    let v = VaultStore::open_with_key_store(new.path(), restored.boxed()).unwrap();
    assert_eq!(names(&v), ["web1"]);
}

#[test]
fn restore_without_key_sets_state_aside_and_starts_fresh() {
    // 未加密備份還原到另一台:vault.tv 回來了、key 沒有 → 原檔保留在旁邊,開新 vault
    let old = TempDir::new().unwrap();
    {
        let mut v =
            VaultStore::open_with_key_store(old.path(), MemKeyStore::default().boxed()).unwrap();
        v.upsert(None, "host", "web1", json!({})).unwrap();
    }
    let tv = std::fs::read(old.path().join("vault.tv")).unwrap();
    let new = TempDir::new().unwrap();
    std::fs::write(new.path().join("vault.tv"), &tv).unwrap();

    let ks = MemKeyStore::default();
    let mut v = VaultStore::open_with_key_store(new.path(), ks.boxed()).unwrap();
    assert!(names(&v).is_empty());
    let aside = unreadable_files(new.path());
    assert_eq!(aside.len(), 1);
    assert_eq!(
        std::fs::read(new.path().join(&aside[0])).unwrap(),
        tv,
        "原檔一個 byte 都不能動"
    );
    assert_eq!(v.snapshot_json()["setAside"], json!(aside[0]));

    // 新 vault 可以正常用,重開也不會再被移開
    v.upsert(None, "host", "fresh", json!({})).unwrap();
    drop(v);
    let v = VaultStore::open_with_key_store(new.path(), ks.boxed()).unwrap();
    assert_eq!(names(&v), ["fresh"]);
    assert_eq!(v.snapshot_json()["setAside"], json!(null));
    assert_eq!(unreadable_files(new.path()).len(), 1);
}

#[test]
fn file_mode_missing_key_sets_aside_instead_of_overwriting() {
    // 舊行為:vault.key 不見就產生新 key 直接蓋掉 vault.tv。現在改成移到旁邊。
    let dir = TempDir::new().unwrap();
    legacy_install(&dir);
    let tv = std::fs::read(state_file(&dir)).unwrap();
    std::fs::remove_file(key_file(&dir)).unwrap();

    let v = VaultStore::open(dir.path()).unwrap();
    assert!(names(&v).is_empty());
    let aside = unreadable_files(dir.path());
    assert_eq!(std::fs::read(dir.path().join(&aside[0])).unwrap(), tv);
}

// ---- 換 key(import_pairing) ----

/// 建一個已啟用同步的 vault,回傳它的配對字串與 vault key 所在的 key store。
fn other_vault_pairing() -> (TempDir, MemKeyStore, String) {
    let dir = TempDir::new().unwrap();
    let ks = MemKeyStore::default();
    let mut v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    v.sync_enable("http://sync.example:8722").unwrap();
    let pairing = v.export_pairing().unwrap();
    (dir, ks, pairing)
}

#[test]
fn import_pairing_rotates_key_in_key_store() {
    let (_other, other_ks, pairing) = other_vault_pairing();
    let new_key = other_ks.keys()[0];

    let dir = TempDir::new().unwrap();
    let ks = MemKeyStore::default();
    {
        let mut v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
        v.upsert(None, "host", "mine", json!({})).unwrap();
        v.import_pairing(&pairing).unwrap();
    }
    assert_eq!(ks.keys(), vec![new_key], "換完只留新 key");
    assert!(!key_file(&dir).exists());
    let v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    assert_eq!(names(&v), ["mine"], "本地資料併入新 vault");
}

#[test]
fn import_pairing_key_store_failure_changes_nothing() {
    let (_other, _, pairing) = other_vault_pairing();
    let dir = TempDir::new().unwrap();
    let ks = MemKeyStore::default();
    let mut v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    v.upsert(None, "host", "mine", json!({})).unwrap();
    let vault_id = v.vault_id();
    let tv = std::fs::read(state_file(&dir)).unwrap();

    ks.set(|i| i.fail_store = true);
    assert!(v.import_pairing(&pairing).is_err());
    assert_eq!(v.vault_id(), vault_id);
    assert!(v.sync_config().is_none());
    assert_eq!(std::fs::read(state_file(&dir)).unwrap(), tv);

    // 失敗後照常可用、重開也沒事
    ks.set(|i| i.fail_store = false);
    v.upsert(None, "host", "after", json!({})).unwrap();
    drop(v);
    let v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    assert_eq!(names(&v), ["after", "mine"]);
}

#[test]
fn rotation_interrupted_before_state_write_keeps_old_vault() {
    // key store 已是「新、舊」、vault.tv 還是舊 key 封的 → 用舊 key 開,收成只剩舊的
    let dir = TempDir::new().unwrap();
    let ks = MemKeyStore::default();
    {
        let mut v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
        v.upsert(None, "host", "mine", json!({})).unwrap();
    }
    let old_key = ks.keys()[0];
    ks.set(|i| i.keys = vec![[0x22; 32], old_key]);

    let v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    assert_eq!(names(&v), ["mine"]);
    assert_eq!(ks.keys(), vec![old_key]);
}

#[test]
fn rotation_interrupted_after_state_write_keeps_new_vault() {
    // vault.tv 已換新 key、最後「只留新 key」那步沒做到 → 用新 key 開,收成只剩新的
    let (_other, other_ks, pairing) = other_vault_pairing();
    let new_key = other_ks.keys()[0];
    let dir = TempDir::new().unwrap();
    let ks = MemKeyStore::default();
    {
        let mut v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
        let old_key = ks.keys()[0];
        v.import_pairing(&pairing).unwrap();
        ks.set(|i| i.keys = vec![new_key, old_key]);
    }
    let v = VaultStore::open_with_key_store(dir.path(), ks.boxed()).unwrap();
    assert!(v.sync_config().is_some(), "配對已生效");
    assert_eq!(ks.keys(), vec![new_key]);
}

#[test]
fn file_mode_import_pairing_leaves_single_key_file() {
    let (_other, other_ks, pairing) = other_vault_pairing();
    let dir = TempDir::new().unwrap();
    let mut v = VaultStore::open(dir.path()).unwrap();
    v.import_pairing(&pairing).unwrap();
    drop(v);
    assert_eq!(
        file_key(&dir),
        other_ks.keys()[0],
        "舊版讀得懂的單一 key 格式"
    );
    let v = VaultStore::open(dir.path()).unwrap();
    assert!(v.sync_config().is_some());
}
