//! VaultStore:本地儲存、CRUD、dirty 追蹤、同步 payload 與合併。
//!
//! 檔案佈局(dir 內):
//!   vault.tv   b"TTV1" + seal(key, aad="vault-state", json(PersistState))
//!   vault.key  檔案模式的 vault key(base64);Keychain 模式下不存在
//!              (舊版留下的會在開啟時搬進 key store,見 open_with_key_store)
//!   vault.tv.unreadable-<ms>  沒有任何 key 解得開時移到旁邊的原檔(只搬不刪)
//!
//! vault key 由 KeyStore 保管(keystore.rs)。寫入一律原子(tmp + rename),
//! 斷電不會留下半份檔案。

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::crypto::{self, KEY_LEN};
use crate::keystore::{FileKeyStore, KeyStore, VaultKey};
use crate::model::{next_hlc, observe_hlc, Record, RecordBody, WireRecord};
use crate::pairing::{Pairing, TOKEN_LEN};

const MAGIC: &[u8; 4] = b"TTV1";
const STATE_AAD: &[u8] = b"vault-state";
const KEY_FILE: &str = "vault.key";
const STATE_FILE: &str = "vault.tv";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    pub server: String,
    /// bearer token 原文(server 只存其 SHA-256)。
    pub token: String, // base64
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistState {
    vault_id: Uuid,
    device_id: String,
    last_hlc: u64,
    cursor: u64,
    sync: Option<SyncConfig>,
    /// 停用同步時保留的舊設定:重新啟用同一台 server 時重用 token,
    /// server 端註冊才會是冪等(否則同 vault id 換 token 會 409)。
    #[serde(default)]
    last_sync: Option<SyncConfig>,
    records: Vec<Record>,
    dirty: Vec<Uuid>,
}

/// apply_pull 的結果摘要。
#[derive(Debug, Default, Serialize)]
pub struct ApplySummary {
    pub applied: usize,
    pub ignored: usize,
    pub conflicts: usize,
    pub cursor: u64,
}

/// import_pairing 的結果摘要。
#[derive(Debug, Serialize)]
pub struct JoinSummary {
    pub server: String,
    pub vault_id: Uuid,
    /// 併入新 vault、待上傳的本地 records 數。
    pub carried: usize,
}

pub struct VaultStore {
    dir: PathBuf,
    key: [u8; KEY_LEN],
    vault_id: Uuid,
    device_id: String,
    last_hlc: u64,
    cursor: u64,
    sync: Option<SyncConfig>,
    last_sync: Option<SyncConfig>,
    records: HashMap<Uuid, Record>,
    dirty: HashSet<Uuid>,
    key_store: Box<dyn KeyStore>,
    /// 這次開啟時因為沒有 key 解得開而移到旁邊的舊 vault.tv。
    set_aside: Option<PathBuf>,
    /// 衝突副本的名稱樣板,見 [`VaultStore::set_conflict_name_template`]。
    conflict_name_template: String,
}

/// 預設的衝突副本名稱(UI 會換成使用者語系的樣板)。
const DEFAULT_CONFLICT_NAME_TEMPLATE: &str = "{name} (conflicted copy {device} @{time})";

impl VaultStore {
    /// 檔案模式:vault key 存在 dir/vault.key(Windows/Linux、測試)。
    /// 第一次開啟會產生 vault key / vault id / device id。
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref();
        let key_store = Box::new(FileKeyStore::new(dir.join(KEY_FILE)));
        Self::open_inner(dir, key_store, false)
    }

    /// vault key 交給外部的 key store 保管(Apple Keychain 等),dir 裡只剩 vault.tv。
    ///
    /// 舊版留在 dir 的 vault.key 會搬進 key store:寫進去、讀回來確認是同一把之後
    /// 才刪檔。寫不進去就照舊用檔案開啟,下次開啟再搬——key store 出問題時
    /// 既有資料照樣打得開,也不會有哪一步把唯一一份 key 弄丟。
    pub fn open_with_key_store(dir: impl AsRef<Path>, key_store: Box<dyn KeyStore>) -> Result<Self> {
        Self::open_inner(dir.as_ref(), key_store, true)
    }

    fn open_inner(dir: &Path, key_store: Box<dyn KeyStore>, migrate_legacy: bool) -> Result<Self> {
        std::fs::create_dir_all(dir).context("failed to create the vault directory")?;
        let legacy = migrate_legacy.then(|| FileKeyStore::new(dir.join(KEY_FILE)));
        // 讀不到(鎖定、拒絕存取)就到此為止:當成「沒有 key」會把現有 vault 移開
        let stored = key_store.load().context("failed to read the vault key")?;
        let state_path = dir.join(STATE_FILE);
        let mut set_aside = None;

        if state_path.exists() {
            let raw = std::fs::read(&state_path).context("failed to read vault.tv")?;
            if let Some((key, state)) = open_state(&raw, &stored)? {
                if stored.len() > 1 {
                    // 換 key 途中斷掉:只留解得開的那把(失敗無妨,下次開啟再收)
                    let _ = key_store.store(&[key]);
                }
                if let Some(legacy) = &legacy {
                    // 上次搬完 key 還沒刪檔就中斷了
                    retire_legacy_key(legacy, key_store.as_ref());
                }
                return Ok(Self::from_state(dir, key, state, key_store, None));
            }
            if let Some(legacy) = &legacy {
                // 檔案讀不到就不能斷定解不開,不往下走到「移開」
                let legacy_keys = legacy.load()?;
                if let Some((key, state)) = open_state(&raw, &legacy_keys)? {
                    if key_store.store(&[key]).is_ok() {
                        retire_legacy_key(legacy, key_store.as_ref());
                    }
                    return Ok(Self::from_state(dir, key, state, key_store, None));
                }
            }
            // 沒有任何 key 解得開(例:未加密備份還原到另一台裝置,Keychain 沒跟過來)。
            // 原檔移到旁邊保留、開新 vault:卡在打不開的話,連重新配對拿回同步資料都做不到。
            let aside = dir.join(format!("{STATE_FILE}.unreadable-{}", now_ms()));
            std::fs::rename(&state_path, &aside)
                .with_context(|| format!("vault.tv could not be opened, and moving it to {} failed", aside.display()))?;
            set_aside = Some(aside);
        }

        // 新 vault:沿用 key store 既有的 key(例:iOS 重裝 app,Keychain 還留著),
        // 其次是舊版 vault.key,都沒有才產生新的。
        let legacy_key = legacy
            .as_ref()
            .and_then(|l| l.load().ok())
            .and_then(|keys| keys.first().copied());
        let key = stored
            .first()
            .copied()
            .or(legacy_key)
            .unwrap_or_else(crypto::random_bytes);
        if stored != [key] {
            // key 存不進去就不建 vault:寫出去的 vault.tv 會沒有 key 解得開
            key_store.store(&[key]).context("failed to store the vault key")?;
        }
        let device: [u8; 4] = crypto::random_bytes();
        let state = PersistState {
            vault_id: Uuid::new_v4(),
            device_id: hex(&device),
            last_hlc: 0,
            cursor: 0,
            sync: None,
            last_sync: None,
            records: Vec::new(),
            dirty: Vec::new(),
        };
        let store = Self::from_state(dir, key, state, key_store, set_aside);
        store.save()?;
        if let Some(legacy) = &legacy {
            retire_legacy_key(legacy, store.key_store.as_ref());
        }
        Ok(store)
    }

    fn from_state(
        dir: &Path,
        key: VaultKey,
        state: PersistState,
        key_store: Box<dyn KeyStore>,
        set_aside: Option<PathBuf>,
    ) -> Self {
        Self {
            dir: dir.to_path_buf(),
            key,
            vault_id: state.vault_id,
            device_id: state.device_id,
            last_hlc: state.last_hlc,
            cursor: state.cursor,
            sync: state.sync,
            last_sync: state.last_sync,
            records: state.records.into_iter().map(|r| (r.id, r)).collect(),
            dirty: state.dirty.into_iter().collect(),
            key_store,
            set_aside,
            conflict_name_template: DEFAULT_CONFLICT_NAME_TEMPLATE.to_string(),
        }
    }

    fn persist_state(&self) -> PersistState {
        PersistState {
            vault_id: self.vault_id,
            device_id: self.device_id.clone(),
            last_hlc: self.last_hlc,
            cursor: self.cursor,
            sync: self.sync.clone(),
            last_sync: self.last_sync.clone(),
            records: self.records.values().cloned().collect(),
            dirty: self.dirty.iter().copied().collect(),
        }
    }

    fn restore(&mut self, state: PersistState) {
        self.vault_id = state.vault_id;
        self.device_id = state.device_id;
        self.last_hlc = state.last_hlc;
        self.cursor = state.cursor;
        self.sync = state.sync;
        self.last_sync = state.last_sync;
        self.records = state.records.into_iter().map(|r| (r.id, r)).collect();
        self.dirty = state.dirty.into_iter().collect();
    }

    pub fn save(&self) -> Result<()> {
        let plain = serde_json::to_vec(&self.persist_state())?;
        let sealed = crypto::seal(&self.key, STATE_AAD, &plain)?;
        let mut out = Vec::with_capacity(MAGIC.len() + sealed.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&sealed);
        atomic_write(&self.dir.join(STATE_FILE), &out)
    }

    // ---- 查詢 ----

    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    pub fn sync_config(&self) -> Option<&SyncConfig> {
        self.sync.as_ref()
    }

    pub fn records(&self) -> impl Iterator<Item = &Record> {
        self.records.values()
    }

    pub fn dirty_count(&self) -> usize {
        self.dirty.len()
    }

    /// 這次開啟時解不開、移到旁邊的舊 vault.tv 檔名(UI 用來提示使用者)。
    pub fn set_aside_name(&self) -> Option<String> {
        self.set_aside
            .as_ref()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
    }

    /// UI snapshot(明文;不含 key/token)。
    pub fn snapshot_json(&self) -> serde_json::Value {
        let mut list: Vec<&Record> = self
            .records
            .values()
            .filter(|r| !r.deleted)
            .collect();
        list.sort_by(|a, b| {
            let an = a.body.as_ref().map(|b| b.name.as_str()).unwrap_or("");
            let bn = b.body.as_ref().map(|b| b.name.as_str()).unwrap_or("");
            an.cmp(bn).then(a.id.cmp(&b.id))
        });
        serde_json::json!({
            "vaultId": self.vault_id,
            "deviceId": self.device_id,
            "dirty": self.dirty.len(),
            "sync": self.sync.as_ref().map(|s| serde_json::json!({ "server": s.server })),
            "setAside": self.set_aside_name(),
            "records": list.iter().map(|r| {
                let body = r.body.as_ref().expect("非 tombstone 必有 body");
                serde_json::json!({
                    "id": r.id,
                    "kind": body.kind,
                    "name": body.name,
                    "data": body.data,
                })
            }).collect::<Vec<_>>(),
        })
    }

    // ---- CRUD ----

    pub fn upsert(
        &mut self,
        id: Option<Uuid>,
        kind: &str,
        name: &str,
        data: serde_json::Value,
    ) -> Result<Record> {
        let id = id.unwrap_or_else(Uuid::new_v4);
        if let Some(existing) = self.records.get(&id) {
            if existing.deleted {
                bail!("record has been deleted");
            }
        }
        let record = Record {
            id,
            hlc: next_hlc(&mut self.last_hlc),
            device: self.device_id.clone(),
            deleted: false,
            body: Some(RecordBody {
                kind: kind.to_string(),
                name: name.to_string(),
                data,
            }),
        };
        self.records.insert(id, record.clone());
        self.dirty.insert(id);
        self.save()?;
        Ok(record)
    }

    pub fn delete(&mut self, id: Uuid) -> Result<bool> {
        let Some(existing) = self.records.get_mut(&id) else {
            return Ok(false);
        };
        if existing.deleted {
            return Ok(false);
        }
        existing.deleted = true;
        existing.body = None;
        existing.hlc = next_hlc(&mut self.last_hlc);
        existing.device = self.device_id.clone();
        self.dirty.insert(id);
        self.save()?;
        Ok(true)
    }

    // ---- 同步設定 ----

    /// 在指定 server 上啟用同步:產生 token,回傳註冊用資料
    /// (vault_id + auth hash;由上層負責呼叫 server 的 POST /v1/vaults)。
    pub fn sync_enable(&mut self, server: &str) -> Result<(Uuid, String)> {
        if self.sync.is_some() {
            bail!("sync is already set up; turn it off before switching servers");
        }
        let server = server.trim().trim_end_matches('/').to_string();
        if server.is_empty() {
            bail!("server address is empty");
        }
        // 之前在同一台 server 啟用過 → 重用舊 token,server 端註冊冪等回 200;
        // 產新 token 會因同 vault id 不同 auth 而 409,把使用者鎖在外面。
        let token = match &self.last_sync {
            Some(prev) if prev.server == server => prev.token.clone(),
            _ => {
                let t: [u8; TOKEN_LEN] = crypto::random_bytes();
                STANDARD.encode(t)
            }
        };
        self.sync = Some(SyncConfig { server, token });
        // 啟用同步後,既有資料都要推上去
        let ids: Vec<Uuid> = self.records.keys().copied().collect();
        self.dirty.extend(ids);
        self.cursor = 0;
        self.save()?;
        Ok((self.vault_id, self.auth_hash_b64()?))
    }

    pub fn sync_disable(&mut self) -> Result<()> {
        // 保留設定供之後重新啟用同一台 server 時重用 token(見 sync_enable)
        if let Some(prev) = self.sync.take() {
            self.last_sync = Some(prev);
        }
        self.cursor = 0;
        self.save()
    }

    /// bearer token 的 SHA-256(base64)——server 註冊與驗證用。
    pub fn auth_hash_b64(&self) -> Result<String> {
        let Some(sync) = &self.sync else {
            bail!("sync is not set up");
        };
        let token = STANDARD.decode(&sync.token).context("failed to decode token")?;
        Ok(STANDARD.encode(Sha256::digest(&token)))
    }

    pub fn export_pairing(&self) -> Result<String> {
        let Some(sync) = &self.sync else {
            bail!("sync is not set up, so there is no pairing string to export");
        };
        let token_vec = STANDARD.decode(&sync.token)?;
        let token: [u8; TOKEN_LEN] = token_vec
            .try_into()
            .map_err(|_| anyhow::anyhow!("token has the wrong length"))?;
        Ok(Pairing {
            server: sync.server.clone(),
            vault_id: self.vault_id,
            token,
            key: self.key,
        }
        .encode())
    }

    /// 貼上配對字串加入既有 vault:採用其身分(server/vault/token/key),
    /// 本地既有 records 換新 id、標 dirty 併入(兩邊資料合流,不丟任何一邊)。
    ///
    /// 換 key 的順序:key store 先收「新、舊」兩把 → 用新 key 寫 vault.tv
    /// (原子 rename,真正的切換點)→ key store 只留新的。任何一步中斷,
    /// key store 裡都有一把解得開磁碟上的 vault.tv,下次開啟自動收尾。
    pub fn import_pairing(&mut self, s: &str) -> Result<JoinSummary> {
        let pairing = Pairing::decode(s)?;
        let old_key = self.key;
        let rotating = pairing.key != old_key;
        if rotating {
            self.key_store
                .store(&[pairing.key, old_key])
                .context("failed to store the vault key")?;
        }
        let before = self.persist_state();
        let carried: Vec<Record> = self
            .records
            .values()
            .filter(|r| !r.deleted)
            .cloned()
            .collect();

        self.key = pairing.key;
        self.vault_id = pairing.vault_id;
        self.sync = Some(SyncConfig {
            server: pairing.server.clone(),
            token: STANDARD.encode(pairing.token),
        });
        self.cursor = 0;
        self.records.clear();
        self.dirty.clear();
        for mut r in carried {
            r.id = Uuid::new_v4();
            r.hlc = next_hlc(&mut self.last_hlc);
            r.device = self.device_id.clone();
            self.dirty.insert(r.id);
            self.records.insert(r.id, r);
        }
        let carried_count = self.dirty.len();
        if let Err(e) = self.save() {
            // vault.tv 還是舊 key 封的那份;記憶體也退回去,key store 裡新舊都在
            self.key = old_key;
            self.restore(before);
            return Err(e);
        }
        if rotating {
            // 失敗無妨:兩把都在,下次開啟會只留解得開的那把
            let _ = self.key_store.store(&[self.key]);
        }
        Ok(JoinSummary {
            server: pairing.server,
            vault_id: pairing.vault_id,
            carried: carried_count,
        })
    }

    // ---- 同步資料通道 ----

    /// 收集 dirty records,加密成 wire 格式(push 上行 payload)。
    pub fn build_push(&self) -> Result<Vec<WireRecord>> {
        let mut out = Vec::with_capacity(self.dirty.len());
        for id in &self.dirty {
            let Some(r) = self.records.get(id) else {
                continue;
            };
            let blob = match &r.body {
                Some(body) => {
                    let plain = serde_json::to_vec(body)?;
                    let sealed =
                        crypto::seal(&self.key, r.id.to_string().as_bytes(), &plain)?;
                    STANDARD.encode(sealed)
                }
                None => String::new(), // tombstone
            };
            out.push(WireRecord {
                id: r.id,
                hlc: r.hlc,
                device: r.device.clone(),
                deleted: r.deleted,
                blob,
                seq: None,
            });
        }
        Ok(out)
    }

    /// push 成功後清 dirty 標記(只清當時送出的那批)。
    pub fn ack_push(&mut self, ids: &[Uuid]) -> Result<()> {
        for id in ids {
            self.dirty.remove(id);
        }
        self.save()
    }

    /// 衝突副本的名稱樣板:`{name}` 原名、`{device}` 改它的裝置、`{time}`
    /// 改的時間(unix 秒)。名稱會同步到所有裝置,UI 用建立副本那台的語系。
    pub fn set_conflict_name_template(&mut self, template: &str) {
        self.conflict_name_template = template.to_string();
    }

    /// 套用 pull 下來的遠端變更(LWW;雙方都改過時保留衝突副本)。
    pub fn apply_pull(&mut self, incoming: &[WireRecord], next_cursor: u64) -> Result<ApplySummary> {
        let mut summary = ApplySummary::default();
        for wire in incoming {
            observe_hlc(&mut self.last_hlc, wire.hlc);
            let incoming_key = (wire.hlc, wire.device.as_str());
            let local = self.records.get(&wire.id);
            let incoming_wins = match local {
                None => true,
                Some(l) => incoming_key > l.version_key(),
            };
            if !incoming_wins {
                summary.ignored += 1;
                continue;
            }

            // 本地也改過且尚未推送 → 遠端成為正式版,本地版本另存衝突副本
            if let Some(l) = local {
                if self.dirty.contains(&wire.id) && !l.deleted {
                    if let Some(body) = &l.body {
                        let mut copy_body = body.clone();
                        // 名稱最後才填:使用者取的名字裡剛好有 {device} 之類也不會被換掉
                        copy_body.name = self
                            .conflict_name_template
                            .replace("{device}", &l.device)
                            .replace("{time}", &(l.hlc / 1000).to_string())
                            .replace("{name}", &copy_body.name);
                        let copy = Record {
                            id: Uuid::new_v4(),
                            hlc: next_hlc(&mut self.last_hlc),
                            device: self.device_id.clone(),
                            deleted: false,
                            body: Some(copy_body),
                        };
                        self.dirty.insert(copy.id);
                        self.records.insert(copy.id, copy);
                        summary.conflicts += 1;
                    }
                }
            }

            let body = if wire.deleted {
                None
            } else {
                let sealed = STANDARD.decode(&wire.blob).context("failed to decode blob")?;
                let plain =
                    crypto::open(&self.key, wire.id.to_string().as_bytes(), &sealed)?;
                Some(serde_json::from_slice::<RecordBody>(&plain)?)
            };
            self.records.insert(
                wire.id,
                Record {
                    id: wire.id,
                    hlc: wire.hlc,
                    device: wire.device.clone(),
                    deleted: wire.deleted,
                    body,
                },
            );
            // 遠端版本成為正式版;此筆本地的 dirty(若有)已由衝突副本代表
            self.dirty.remove(&wire.id);
            summary.applied += 1;
        }
        if next_cursor > self.cursor {
            self.cursor = next_cursor;
        }
        summary.cursor = self.cursor;
        self.save()?;
        Ok(summary)
    }
}

/// 依序用每把 key 試開 vault.tv。`Ok(None)` = 都解不開;格式錯誤(magic 不符、
/// 解開後不是合法狀態)與 key 無關,直接回 Err,不讓呼叫端把檔案移開。
fn open_state(raw: &[u8], keys: &[VaultKey]) -> Result<Option<(VaultKey, PersistState)>> {
    if raw.len() < MAGIC.len() || &raw[..MAGIC.len()] != MAGIC {
        bail!("vault.tv is not a vault file (bad magic)");
    }
    for key in keys {
        let Ok(plain) = crypto::open(key, STATE_AAD, &raw[MAGIC.len()..]) else {
            continue;
        };
        let state = serde_json::from_slice(&plain).context("failed to parse the vault state")?;
        return Ok(Some((*key, state)));
    }
    Ok(None)
}

/// 舊版 vault.key:key store 讀回來確實有同一把才刪。讀不到、對不上都不動它。
fn retire_legacy_key(legacy: &FileKeyStore, key_store: &dyn KeyStore) {
    let Ok(file_keys) = legacy.load() else { return };
    if file_keys.is_empty() {
        return;
    }
    let Ok(kept) = key_store.load() else { return };
    if file_keys.iter().all(|k| kept.contains(k)) {
        let _ = std::fs::remove_file(legacy.path());
    }
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data).with_context(|| format!("failed to write {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("failed to rename to {}", path.display()))?;
    Ok(())
}
