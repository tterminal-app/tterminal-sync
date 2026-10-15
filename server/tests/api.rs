//! tterm-server API 測試(tower oneshot,不開真實 port)+
//! 端對端:兩個 VaultStore 透過 server handler 互推互拉收斂一致。

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tower::ServiceExt;
use tterm_server::AppState;
use tterm_vault::{VaultStore, WireRecord};
use uuid::Uuid;

fn app(dir: &TempDir) -> Router {
    tterm_server::router(AppState::new(dir.path()).unwrap())
}

async fn call(app: &Router, req: Request<Body>) -> (StatusCode, Value) {
    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, body)
}

fn post_json(uri: &str, token: Option<&str>, body: &Value) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::from(serde_json::to_vec(body).unwrap())).unwrap()
}

fn get_req(uri: &str, token: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().method("GET").uri(uri);
    if let Some(t) = token {
        b = b.header("authorization", format!("Bearer {t}"));
    }
    b.body(Body::empty()).unwrap()
}

fn auth_of(token_b64: &str) -> String {
    STANDARD.encode(Sha256::digest(STANDARD.decode(token_b64).unwrap()))
}

#[tokio::test]
async fn health() {
    let dir = TempDir::new().unwrap();
    let (status, body) = call(&app(&dir), get_req("/v1/health", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ok"], json!(true));
}

#[tokio::test]
async fn create_push_pull_flow() {
    let dir = TempDir::new().unwrap();
    let app = app(&dir);
    let vault_id = Uuid::new_v4();
    let token = STANDARD.encode([1u8; 32]);

    // 建立
    let (status, _) = call(
        &app,
        post_json("/v1/vaults", None, &json!({"vault_id": vault_id, "auth": auth_of(&token)})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // 幂等重註冊(同 auth)→ 200;不同 auth → 409
    let (status, _) = call(
        &app,
        post_json("/v1/vaults", None, &json!({"vault_id": vault_id, "auth": auth_of(&token)})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let other = STANDARD.encode(Sha256::digest([9u8; 32]));
    let (status, _) = call(
        &app,
        post_json("/v1/vaults", None, &json!({"vault_id": vault_id, "auth": other})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    // 沒 token / 錯 token
    let uri = format!("/v1/vaults/{vault_id}/records");
    let (status, _) = call(&app, get_req(&format!("{uri}?since=0"), None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let bad = STANDARD.encode([2u8; 32]);
    let (status, _) = call(&app, get_req(&format!("{uri}?since=0"), Some(&bad))).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // 不存在的 vault → 404
    let ghost = format!("/v1/vaults/{}/records?since=0", Uuid::new_v4());
    let (status, _) = call(&app, get_req(&ghost, Some(&token))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    // push 兩筆
    let ra = Uuid::new_v4();
    let rb = Uuid::new_v4();
    let push = json!([
        {"id": ra, "hlc": 100, "device": "aaaa", "deleted": false, "blob": "QQ=="},
        {"id": rb, "hlc": 200, "device": "aaaa", "deleted": false, "blob": "Qg=="},
    ]);
    let (status, body) = call(&app, post_json(&uri, Some(&token), &push)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["seq"], json!(2));

    // pull since=0 → 兩筆、有 seq、next=2
    let (status, body) = call(&app, get_req(&format!("{uri}?since=0"), Some(&token))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["records"].as_array().unwrap().len(), 2);
    assert_eq!(body["next"], json!(2));

    // LWW:舊 hlc 蓋不掉(靜默丟棄,seq 不動)
    let stale = json!([
        {"id": ra, "hlc": 50, "device": "bbbb", "deleted": false, "blob": "WA=="},
    ]);
    let (status, body) = call(&app, post_json(&uri, Some(&token), &stale)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["seq"], json!(2));

    // 新 hlc 蓋得掉 → seq=3;pull since=2 只回這筆
    let newer = json!([
        {"id": ra, "hlc": 300, "device": "bbbb", "deleted": true, "blob": ""},
    ]);
    let (status, body) = call(&app, post_json(&uri, Some(&token), &newer)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["seq"], json!(3));
    let (_, body) = call(&app, get_req(&format!("{uri}?since=2"), Some(&token))).await;
    let records = body["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["id"], json!(ra));
    assert_eq!(records[0]["deleted"], json!(true));
    assert_eq!(records[0]["seq"], json!(3));
}

#[tokio::test]
async fn persistence_across_restart() {
    let dir = TempDir::new().unwrap();
    let vault_id = Uuid::new_v4();
    let token = STANDARD.encode([3u8; 32]);
    {
        let app = app(&dir);
        call(
            &app,
            post_json("/v1/vaults", None, &json!({"vault_id": vault_id, "auth": auth_of(&token)})),
        )
        .await;
        let uri = format!("/v1/vaults/{vault_id}/records");
        let push = json!([
            {"id": Uuid::new_v4(), "hlc": 1, "device": "d", "deleted": false, "blob": "QQ=="},
        ]);
        let (status, _) = call(&app, post_json(&uri, Some(&token), &push)).await;
        assert_eq!(status, StatusCode::OK);
    }
    // 重新建 state(模擬重啟)→ 從磁碟載回
    let app = app(&dir);
    let uri = format!("/v1/vaults/{vault_id}/records?since=0");
    let (status, body) = call(&app, get_req(&uri, Some(&token))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["records"].as_array().unwrap().len(), 1);
}

/// 端對端:兩個真實 VaultStore 經 server 收斂。
#[tokio::test]
async fn two_clients_converge() {
    let server_dir = TempDir::new().unwrap();
    let app = app(&server_dir);

    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let mut a = VaultStore::open(dir_a.path()).unwrap();
    let mut b = VaultStore::open(dir_b.path()).unwrap();

    // A 啟用同步 + 在 server 註冊
    let (vault_id, auth) = a.sync_enable("http://in-proc").unwrap();
    let (status, _) = call(
        &app,
        post_json("/v1/vaults", None, &json!({"vault_id": vault_id, "auth": auth})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    // B 由配對字串加入
    b.import_pairing(&a.export_pairing().unwrap()).unwrap();

    let token_a = a.sync_config().unwrap().token.clone();
    let token_b = b.sync_config().unwrap().token.clone();
    assert_eq!(token_a, token_b, "配對字串帶同一個 token");

    // A 建 host、B 建 key,各自 push,互相 pull
    a.upsert(None, "host", "prod", json!({"address": "1.1.1.1"})).unwrap();
    b.upsert(None, "ssh_key", "deploy", json!({"privateKey": "K"})).unwrap();
    let uri = format!("/v1/vaults/{vault_id}/records");

    async fn sync(
        app: &Router,
        uri: &str,
        token: &str,
        store: &mut VaultStore,
    ) -> (StatusCode, usize) {
        // push
        let push = store.build_push().unwrap();
        let ids: Vec<Uuid> = push.iter().map(|w| w.id).collect();
        if !push.is_empty() {
            let body = serde_json::to_value(&push).unwrap();
            let (status, _) = call(app, post_json(uri, Some(token), &body)).await;
            assert_eq!(status, StatusCode::OK);
            store.ack_push(&ids).unwrap();
        }
        // pull
        let (status, body) = call(
            app,
            get_req(&format!("{uri}?since={}", store.cursor()), Some(token)),
        )
        .await;
        let records: Vec<WireRecord> =
            serde_json::from_value(body["records"].clone()).unwrap();
        let next = body["next"].as_u64().unwrap();
        let summary = store.apply_pull(&records, next).unwrap();
        (status, summary.applied)
    }

    sync(&app, &uri, &token_a, &mut a).await; // A push host、pull(拿到自己的)
    sync(&app, &uri, &token_b, &mut b).await; // B push key、pull(拿到 host)
    sync(&app, &uri, &token_a, &mut a).await; // A pull(拿到 key)

    let names = |v: &VaultStore| -> Vec<String> {
        let snap = v.snapshot_json();
        snap["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| r["name"].as_str().unwrap().to_string())
            .collect()
    };
    let mut na = names(&a);
    let mut nb = names(&b);
    na.sort();
    nb.sort();
    assert_eq!(na, vec!["deploy".to_string(), "prod".to_string()]);
    assert_eq!(na, nb, "兩端收斂一致");
    assert_eq!(a.dirty_count(), 0);
    assert_eq!(b.dirty_count(), 0);
}
