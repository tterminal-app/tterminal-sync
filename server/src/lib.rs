//! tterm-server:自架同步伺服器(axum)。
//!
//! zero-knowledge:只存密文 blob 與同步 metadata(id/hlc/device/deleted/seq),
//! 認證只存 token 的 SHA-256。API 見 docs/vault-sync-design.md §4。

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::extract::{Path as AxPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use uuid::Uuid;

// ---- 儲存 ----

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRecord {
    pub id: Uuid,
    pub hlc: u64,
    pub device: String,
    pub deleted: bool,
    pub blob: String,
    pub seq: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct VaultData {
    auth_hash: String,
    next_seq: u64,
    records: HashMap<Uuid, StoredRecord>,
}

impl VaultData {
    fn latest_seq(&self) -> u64 {
        self.next_seq
    }
}

pub struct AppState {
    data_dir: PathBuf,
    vaults: Mutex<HashMap<Uuid, Arc<Mutex<VaultData>>>>,
}

impl AppState {
    pub fn new(data_dir: impl Into<PathBuf>) -> anyhow::Result<Arc<Self>> {
        let data_dir = data_dir.into();
        std::fs::create_dir_all(&data_dir)?;
        Ok(Arc::new(Self {
            data_dir,
            vaults: Mutex::new(HashMap::new()),
        }))
    }

    fn vault_path(&self, id: Uuid) -> PathBuf {
        self.data_dir.join(format!("{id}.json"))
    }

    /// 取得 vault(記憶體快取;miss 時從磁碟載入)。
    async fn vault(&self, id: Uuid) -> Option<Arc<Mutex<VaultData>>> {
        let mut vaults = self.vaults.lock().await;
        if let Some(v) = vaults.get(&id) {
            return Some(v.clone());
        }
        let path = self.vault_path(id);
        let data = std::fs::read(&path).ok()?;
        let parsed: VaultData = serde_json::from_slice(&data).ok()?;
        let arc = Arc::new(Mutex::new(parsed));
        vaults.insert(id, arc.clone());
        Some(arc)
    }

    fn persist(&self, id: Uuid, data: &VaultData) -> anyhow::Result<()> {
        let path = self.vault_path(id);
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(data)?)?;
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }
}

// ---- API 型別 ----

#[derive(Deserialize)]
struct CreateVaultReq {
    vault_id: Uuid,
    /// base64(sha256(token))
    auth: String,
}

#[derive(Deserialize, Serialize)]
struct WireRecord {
    id: Uuid,
    hlc: u64,
    device: String,
    deleted: bool,
    blob: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    seq: Option<u64>,
}

#[derive(Deserialize)]
struct PullQuery {
    #[serde(default)]
    since: u64,
}

// ---- 錯誤 ----

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({"error": self.1}))).into_response()
    }
}

fn err(code: StatusCode, msg: impl Into<String>) -> ApiError {
    ApiError(code, msg.into())
}

// ---- 認證 ----

fn bearer_token(headers: &HeaderMap) -> Result<String, ApiError> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "缺少 Authorization"))?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "Authorization 格式錯誤"))?;
    Ok(token.trim().to_string())
}

fn auth_hash_of(token_b64: &str) -> Result<String, ApiError> {
    let raw = STANDARD
        .decode(token_b64)
        .map_err(|_| err(StatusCode::UNAUTHORIZED, "token 解碼失敗"))?;
    Ok(STANDARD.encode(Sha256::digest(&raw)))
}

// ---- Handlers ----

async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true, "version": env!("CARGO_PKG_VERSION")}))
}

async fn create_vault(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateVaultReq>,
) -> Result<Response, ApiError> {
    if req.auth.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "auth 不可為空"));
    }
    if let Some(existing) = state.vault(req.vault_id).await {
        let data = existing.lock().await;
        return if data.auth_hash == req.auth {
            // 幂等重註冊(client 重試)
            Ok((StatusCode::OK, Json(serde_json::json!({}))).into_response())
        } else {
            Err(err(StatusCode::CONFLICT, "vault 已存在"))
        };
    }
    let data = VaultData {
        auth_hash: req.auth,
        next_seq: 0,
        records: HashMap::new(),
    };
    state
        .persist(req.vault_id, &data)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state
        .vaults
        .lock()
        .await
        .insert(req.vault_id, Arc::new(Mutex::new(data)));
    Ok((StatusCode::CREATED, Json(serde_json::json!({}))).into_response())
}

async fn authed_vault(
    state: &AppState,
    id: Uuid,
    headers: &HeaderMap,
) -> Result<Arc<Mutex<VaultData>>, ApiError> {
    let token = bearer_token(headers)?;
    let vault = state
        .vault(id)
        .await
        .ok_or_else(|| err(StatusCode::NOT_FOUND, "vault 不存在"))?;
    let hash = auth_hash_of(&token)?;
    let data = vault.lock().await;
    if data.auth_hash != hash {
        return Err(err(StatusCode::UNAUTHORIZED, "token 不正確"));
    }
    drop(data);
    Ok(vault)
}

/// push:LWW(舊版本靜默丟棄,幂等);接受者 assign 遞增 seq。
async fn push_records(
    State(state): State<Arc<AppState>>,
    AxPath(id): AxPath<Uuid>,
    headers: HeaderMap,
    Json(incoming): Json<Vec<WireRecord>>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let vault = authed_vault(&state, id, &headers).await?;
    let mut data = vault.lock().await;
    for wire in incoming {
        let accept = match data.records.get(&wire.id) {
            None => true,
            Some(existing) => {
                (wire.hlc, wire.device.as_str()) > (existing.hlc, existing.device.as_str())
            }
        };
        if !accept {
            continue;
        }
        data.next_seq += 1;
        let seq = data.next_seq;
        data.records.insert(
            wire.id,
            StoredRecord {
                id: wire.id,
                hlc: wire.hlc,
                device: wire.device,
                deleted: wire.deleted,
                blob: wire.blob,
                seq,
            },
        );
    }
    state
        .persist(id, &data)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({"seq": data.latest_seq()})))
}

/// pull:回傳 seq > since 的變更(依 seq 排序)+ 最新 cursor。
async fn pull_records(
    State(state): State<Arc<AppState>>,
    AxPath(id): AxPath<Uuid>,
    headers: HeaderMap,
    Query(q): Query<PullQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let vault = authed_vault(&state, id, &headers).await?;
    let data = vault.lock().await;
    let mut records: Vec<&StoredRecord> =
        data.records.values().filter(|r| r.seq > q.since).collect();
    records.sort_by_key(|r| r.seq);
    let out: Vec<WireRecord> = records
        .iter()
        .map(|r| WireRecord {
            id: r.id,
            hlc: r.hlc,
            device: r.device.clone(),
            deleted: r.deleted,
            blob: r.blob.clone(),
            seq: Some(r.seq),
        })
        .collect();
    Ok(Json(serde_json::json!({
        "records": out,
        "next": data.latest_seq(),
    })))
}

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/health", get(health))
        .route("/v1/vaults", post(create_vault))
        .route(
            "/v1/vaults/{id}/records",
            post(push_records).get(pull_records),
        )
        .with_state(state)
}

/// 啟動時把磁碟上既有的 vault 載進快取(可選;lazy load 也會撈)。
pub fn preload(state: &Arc<AppState>) -> anyhow::Result<usize> {
    let mut n = 0;
    for entry in std::fs::read_dir(&state.data_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(stem) = name.strip_suffix(".json") {
            if Uuid::parse_str(stem).is_ok() {
                n += 1;
            }
        }
    }
    Ok(n)
}

pub async fn serve(listen: &str, data_dir: &Path) -> anyhow::Result<()> {
    let state = AppState::new(data_dir)?;
    let existing = preload(&state)?;
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(listen).await?;
    eprintln!(
        "tterm-server v{} listening on {listen}  (data: {}, vaults: {existing})",
        env!("CARGO_PKG_VERSION"),
        data_dir.display()
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
