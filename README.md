# tterminal-sync

[![ci](https://github.com/tterminal-app/tterminal-sync/actions/workflows/ci.yml/badge.svg)](https://github.com/tterminal-app/tterminal-sync/actions/workflows/ci.yml)
[![docker](https://github.com/tterminal-app/tterminal-sync/actions/workflows/docker.yml/badge.svg)](https://github.com/tterminal-app/tterminal-sync/pkgs/container/tterminal-sync)

Self-hosted sync server for [tterminal](https://tterminal-app.github.io/tterminal-sync/), the SSH terminal for iPhone and iPad.

It keeps your hosts and SSH keys in sync across devices without an account and without trusting the server. Everything is encrypted on your device before it's sent; the server only ever stores ciphertext and the bare minimum it needs to order updates.

[中文說明在下面](#中文)

## Quick start

```sh
docker run -d --name tterm-sync \
  -p 8722:8722 -v tterm-data:/data \
  --restart unless-stopped \
  ghcr.io/tterminal-app/tterminal-sync:latest
```

Check it's up:

```sh
curl http://localhost:8722/v1/health
# {"ok":true,"version":"..."}
```

Then in the app:

1. **Settings → Sync**, enter `http://<your-server>:8722`, tap **Create sync**
2. Tap **Export pairing string** and copy it
3. On your other device: **Settings → Sync → Paste pairing string**

That's it. Changes sync when the app starts, a couple of seconds after you edit something, and whenever you tap **Sync now**.

## Over the internet: put TLS in front

The server speaks plain HTTP. Your data is end-to-end encrypted either way, but the bearer token travels with every request, so on an untrusted network you want HTTPS. The included Caddy setup gets a certificate automatically:

```sh
# 1. point sync.example.com at this machine
# 2. edit Caddyfile
docker compose -f compose.caddy.yml up -d
```

Use `https://sync.example.com` in the app.

On a home LAN or over a VPN (Tailscale, WireGuard), plain `docker-compose.yml` is fine.

## Without Docker

```sh
cargo build --release -p tterm-server
./target/release/tterm-server --listen 0.0.0.0:8722 --data ./data
```

`TTERM_LISTEN` and `TTERM_DATA` work too; command-line flags win.

## Backups

Copy the data directory. Each vault is a single JSON file, written atomically, so a plain `cp` or `rsync` while the server runs is safe.

```sh
docker run --rm -v tterm-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/tterm-sync-$(date +%F).tgz -C /data .
```

If you bind-mount a host directory instead of a named volume, make it writable by UID 10001 (the container's user).

## What the server can and can't see

It can see: vault IDs, record IDs, timestamps (a hybrid logical clock), device IDs, whether a record is deleted, and the SHA-256 of your token.

It can't see: anything inside a record. Host names, addresses, usernames, passwords, private keys, even whether a record is a host or a key, all live inside an XChaCha20-Poly1305 blob that only your devices hold the key for.

A few things worth knowing:

- **The pairing string is the keys to the kingdom.** It contains the server address, the token and the encryption key. Share it only between your own devices.
- **Anyone who can reach the server can create a vault.** They can't touch yours, but they can use your disk. If you expose it publicly, consider putting it behind a VPN or an authenticating proxy.
- **Someone with your token (e.g. sniffed over plain HTTP) still can't read anything**, but they could push bogus updates to your vault. Another reason to use TLS outside your LAN.
- On the device, the vault key currently lives in a file next to the vault inside the app's sandbox. Moving it into the iOS Keychain is planned; the file format won't change.

The wire format, crypto and sync rules are described in [PROTOCOL.md](PROTOCOL.md).

## Repository layout

```
server/   tterm-server: HTTP API (axum), stores ciphertext on disk
vault/    tterm-vault: the client-side crypto, merge and pairing logic
          used by the app (included here so you can audit it)
```

```sh
cargo test --workspace   # includes an end-to-end test with two clients converging
```

## License

[AGPL-3.0](LICENSE). If you run a modified version as a service for others, you need to publish your changes.

---

## 中文

tterminal 的自架同步伺服器。tterminal 是 iPhone / iPad 上的 SSH 終端機。

不用註冊帳號,也不用信任伺服器:主機和金鑰在你的裝置上就先加密,伺服器只存密文,以及排序更新所需的最少資訊。

### 快速開始

```sh
docker run -d --name tterm-sync \
  -p 8722:8722 -v tterm-data:/data \
  --restart unless-stopped \
  ghcr.io/tterminal-app/tterminal-sync:latest
```

確認有跑起來:`curl http://localhost:8722/v1/health`

接著在 app 裡:

1. **設定 → 同步**,輸入 `http://<你的伺服器>:8722`,按「建立同步」
2. 按「匯出配對字串」,複製起來
3. 在另一台裝置:**設定 → 同步 → 貼上配對字串加入**

之後 app 啟動時、修改後兩秒、按「立即同步」時都會同步。

### 要放到公網:前面加 TLS

伺服器本身只講 HTTP。資料本來就是端對端加密,但每個請求都帶著 token,在不信任的網路上請走 HTTPS。附的 Caddy 設定會自動申請憑證:

```sh
# 1. 把 sync.example.com 指到這台機器
# 2. 改 Caddyfile 裡的網域
docker compose -f compose.caddy.yml up -d
```

app 裡改填 `https://sync.example.com`。在家裡的區網或 VPN(Tailscale、WireGuard)裡,直接用 `docker-compose.yml` 就好。

### 不用 Docker

```sh
cargo build --release -p tterm-server
./target/release/tterm-server --listen 0.0.0.0:8722 --data ./data
```

也可以用環境變數 `TTERM_LISTEN`、`TTERM_DATA`,命令列參數優先。

### 備份

複製資料夾就好。每個 vault 是一個 JSON 檔,寫入是原子操作,伺服器跑著直接 `cp`、`rsync` 也沒問題。用 bind mount 掛主機目錄的話,要讓 UID 10001(容器裡的使用者)可以寫入。

### 伺服器看得到、看不到什麼

看得到:vault ID、紀錄 ID、時間戳(混合邏輯時鐘)、裝置 ID、紀錄是否已刪除,以及 token 的 SHA-256。

看不到:紀錄裡的任何內容。主機名稱、位址、帳號、密碼、私鑰,甚至這筆是主機還是金鑰,都包在 XChaCha20-Poly1305 加密的 blob 裡,金鑰只在你的裝置上。

幾件要知道的事:

- **配對字串就是全部的鑰匙**:裡面有伺服器位址、token 和加密金鑰,只在自己的裝置之間傳。
- **連得到伺服器的人都能建立新的 vault**:動不到你的資料,但會佔你的硬碟。放公網的話,建議放在 VPN 或有驗證的反向代理後面。
- **token 被拿到(例如走明文 HTTP 被側錄)也讀不到內容**,但對方可以往你的 vault 推假的更新。這也是公網要上 TLS 的原因。
- 目前裝置上的 vault 金鑰是存在 app 沙盒裡、跟 vault 放在一起的檔案,之後會移進 iOS 鑰匙圈,檔案格式不會變。

傳輸格式、加密方式和同步規則見 [PROTOCOL.md](PROTOCOL.md)。

### 授權

[AGPL-3.0](LICENSE)。如果你改了程式並拿來對外提供服務,修改的部分也要公開。
