//! tterm-vault 單元/整合測試:儲存 roundtrip、加密、配對、LWW 合併、衝突副本。

use serde_json::json;
use tempfile::TempDir;
use tterm_vault::{Pairing, PairingError, VaultStore, WireRecord};
use uuid::Uuid;

fn open(dir: &TempDir) -> VaultStore {
    VaultStore::open(dir.path()).expect("open vault")
}

#[test]
fn persist_roundtrip() {
    let dir = TempDir::new().unwrap();
    let id;
    {
        let mut v = open(&dir);
        let r = v
            .upsert(None, "host", "web1", json!({"address": "10.0.0.1", "port": 22}))
            .unwrap();
        id = r.id;
    }
    let v = open(&dir);
    let snap = v.snapshot_json();
    let records = snap["records"].as_array().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["id"], json!(id));
    assert_eq!(records[0]["name"], "web1");
    assert_eq!(records[0]["data"]["address"], "10.0.0.1");
}

#[test]
fn state_file_is_encrypted() {
    let dir = TempDir::new().unwrap();
    {
        let mut v = open(&dir);
        v.upsert(None, "host", "secret-name-abc", json!({"password": "p@ss"}))
            .unwrap();
    }
    let raw = std::fs::read(dir.path().join("vault.tv")).unwrap();
    let hay = String::from_utf8_lossy(&raw);
    assert!(!hay.contains("secret-name-abc"), "名稱不得以明文落地");
    assert!(!hay.contains("p@ss"), "密碼不得以明文落地");
}

#[test]
fn delete_becomes_tombstone() {
    let dir = TempDir::new().unwrap();
    let mut v = open(&dir);
    let r = v.upsert(None, "host", "gone", json!({})).unwrap();
    assert!(v.delete(r.id).unwrap());
    assert!(!v.delete(r.id).unwrap(), "重複刪除回 false");
    assert_eq!(v.snapshot_json()["records"].as_array().unwrap().len(), 0);
    // tombstone 仍會進 push payload
    let push = v.build_push().unwrap();
    let t = push.iter().find(|w| w.id == r.id).unwrap();
    assert!(t.deleted);
    assert!(t.blob.is_empty());
}

#[test]
fn pairing_roundtrip_and_reject() {
    let p = Pairing {
        server: "http://192.168.1.9:8722".into(),
        vault_id: Uuid::new_v4(),
        token: [7u8; 32],
        key: [9u8; 32],
    };
    let s = p.encode();
    assert!(s.starts_with("TTERMSYNC1:"));
    assert_eq!(Pairing::decode(&s).unwrap(), p);
    assert_eq!(Pairing::decode(&format!("  {s}  ")).unwrap(), p, "容忍前後空白");
    // 傳遞通道折行:字串中間夾換行(或空格)也要能解(真實回報:mac 貼上時
    // base64 第 82 字元被折成 \n,decode 失敗)
    let wrapped = format!("{}\n{}", &s[..40], &s[40..]);
    assert_eq!(Pairing::decode(&wrapped).unwrap(), p, "容忍中間換行(折行)");
    let spaced = format!("{}\r\n {}", &s[..60], &s[60..]);
    assert_eq!(Pairing::decode(&spaced).unwrap(), p, "容忍中間 CRLF + 空格");
    // UI 依錯誤型別給提示,型別要對
    let kind = |s: &str| {
        let err = Pairing::decode(s).unwrap_err();
        match err.downcast_ref::<PairingError>() {
            Some(PairingError::MissingPrefix) => "prefix",
            Some(PairingError::UnsupportedVersion(_)) => "version",
            Some(PairingError::Malformed(_)) => "malformed",
            None => "untyped",
        }
    };
    assert_eq!(kind("TTERMSYNC1:!!!"), "malformed");
    assert_eq!(kind("hello"), "prefix");
}

#[test]
fn sync_disable_keeps_token_for_reenable() {
    let dir = TempDir::new().unwrap();
    let (auth1, token1);
    {
        let mut v = open(&dir);
        let (_, a) = v.sync_enable("http://s:1").unwrap();
        auth1 = a;
        token1 = v.sync_config().unwrap().token.clone();

        // 停用後重新啟用同一台 server → 重用 token(server 端註冊才會冪等,
        // 產新 token 會因同 vault id 不同 auth 而 409)
        v.sync_disable().unwrap();
        assert!(v.sync_config().is_none());
        let (_, auth2) = v.sync_enable("http://s:1/").unwrap();
        assert_eq!(v.sync_config().unwrap().token, token1);
        assert_eq!(auth1, auth2);
        v.sync_disable().unwrap();
    }

    // 落地重載後 last_sync 仍在,重啟 app 一樣能重用
    let mut v = open(&dir);
    v.sync_enable("http://s:1").unwrap();
    assert_eq!(v.sync_config().unwrap().token, token1);

    // 換一台 server → 產新 token
    v.sync_disable().unwrap();
    v.sync_enable("http://other").unwrap();
    assert_ne!(v.sync_config().unwrap().token, token1);
}

#[test]
fn sync_enable_then_export_import() {
    let dir_a = TempDir::new().unwrap();
    let mut a = open(&dir_a);
    a.upsert(None, "host", "a-host", json!({"address": "a"})).unwrap();
    let (vault_id, auth) = a.sync_enable("http://s:1/").unwrap();
    assert_eq!(vault_id, a.vault_id());
    assert!(!auth.is_empty());
    assert_eq!(a.sync_config().unwrap().server, "http://s:1", "去掉尾端斜線");
    assert!(a.sync_enable("http://other").is_err(), "已設定不可重複啟用");

    let pairing = a.export_pairing().unwrap();

    // B 本地已有一筆資料,加入 A 的 vault → 合流且標 dirty
    let dir_b = TempDir::new().unwrap();
    let mut b = open(&dir_b);
    b.upsert(None, "ssh_key", "b-key", json!({"privateKey": "K"})).unwrap();
    let summary = b.import_pairing(&pairing).unwrap();
    assert_eq!(summary.vault_id, vault_id);
    assert_eq!(summary.carried, 1);
    assert_eq!(b.vault_id(), a.vault_id());
    assert_eq!(b.dirty_count(), 1);
    assert_eq!(b.cursor(), 0);

    // B 的 push payload 可被 A 解密(同一把 key)
    let push = b.build_push().unwrap();
    assert_eq!(push.len(), 1);
    let summary = a.apply_pull(&push_with_seq(&push, 1), 1).unwrap();
    assert_eq!(summary.applied, 1);
    let snap = a.snapshot_json();
    let names: Vec<&str> = snap["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"b-key"));
}

#[test]
fn lww_merge_and_conflict_copy() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let mut a = open(&dir_a);
    let mut b = open(&dir_b);
    // 讓兩邊共用同一把 key/身分(模擬配對完成)
    a.sync_enable("http://s").unwrap();
    let pairing = a.export_pairing().unwrap();
    b.import_pairing(&pairing).unwrap();

    // A 建立 host 並「推送成功」
    let r = a.upsert(None, "host", "prod", json!({"address": "1.1.1.1"})).unwrap();
    let push_a = a.build_push().unwrap();
    let ids: Vec<Uuid> = push_a.iter().map(|w| w.id).collect();
    a.ack_push(&ids).unwrap();

    // B 拉到 A 的版本
    b.apply_pull(&push_with_seq(&push_a, 1), push_a.len() as u64).unwrap();

    // 兩邊同時修改同一筆:B 先改(hlc 較舊),A 後改(hlc 較新)
    b.upsert(Some(r.id), "host", "prod-by-B", json!({"address": "2.2.2.2"})).unwrap();
    std::thread::sleep(std::time::Duration::from_millis(3));
    a.upsert(Some(r.id), "host", "prod-by-A", json!({"address": "3.3.3.3"})).unwrap();
    let push_a2 = a.build_push().unwrap();

    // B 還掛著未推送的修改,拉到 A 的新版 → LWW 由 A 勝,B 的版本變衝突副本
    // (副本名稱樣板由 UI 依語系給)
    b.set_conflict_name_template("{name}(衝突副本 {device} @{time})");
    let summary = b.apply_pull(&push_with_seq(&push_a2, 10), 10).unwrap();
    assert_eq!(summary.applied, 1);
    assert_eq!(summary.conflicts, 1);
    let snap = b.snapshot_json();
    let names: Vec<String> = snap["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["name"].as_str().unwrap().to_string())
        .collect();
    assert!(names.contains(&"prod-by-A".to_string()), "正式版是 A 的新版:{names:?}");
    assert!(
        names.iter().any(|n| n.starts_with("prod-by-B(衝突副本")),
        "B 的版本保留為衝突副本:{names:?}"
    );

    // 反向:落後的版本拉進來要被忽略
    let push_b = b.build_push().unwrap();
    let old = push_b.iter().find(|w| w.id == r.id);
    assert!(old.is_none(), "B 的該筆 dirty 已被正式版取代,只剩衝突副本待推");

    // A 再收到自己的舊版本(模擬重放)→ ignored
    let summary = a.apply_pull(&push_with_seq(&push_a2, 10), 10).unwrap();
    assert_eq!(summary.applied, 0);
    assert_eq!(summary.ignored, 1);
}

#[test]
fn tombstone_wins_when_newer() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let mut a = open(&dir_a);
    let mut b = open(&dir_b);
    a.sync_enable("http://s").unwrap();
    b.import_pairing(&a.export_pairing().unwrap()).unwrap();

    let r = a.upsert(None, "host", "temp", json!({})).unwrap();
    let push = a.build_push().unwrap();
    b.apply_pull(&push_with_seq(&push, 1), 1).unwrap();
    assert_eq!(b.snapshot_json()["records"].as_array().unwrap().len(), 1);

    a.delete(r.id).unwrap();
    let push = a.build_push().unwrap();
    b.apply_pull(&push_with_seq(&push, 2), 2).unwrap();
    assert_eq!(b.snapshot_json()["records"].as_array().unwrap().len(), 0);
}

#[test]
fn wrong_key_cannot_decrypt() {
    let dir_a = TempDir::new().unwrap();
    let dir_b = TempDir::new().unwrap();
    let mut a = open(&dir_a);
    let mut b = open(&dir_b); // 不同 key
    a.upsert(None, "host", "x", json!({"password": "s3cret"})).unwrap();
    let push = a.build_push().unwrap();
    assert!(b.apply_pull(&push_with_seq(&push, 1), 1).is_err());
}

fn push_with_seq(records: &[WireRecord], start_seq: u64) -> Vec<WireRecord> {
    records
        .iter()
        .enumerate()
        .map(|(i, w)| {
            let mut w = w.clone();
            w.seq = Some(start_seq + i as u64);
            w
        })
        .collect()
}
