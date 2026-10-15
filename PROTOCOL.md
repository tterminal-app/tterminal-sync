# Sync protocol

How tterminal devices sync a vault through `tterm-server`. The client side lives in [`vault/`](vault/), the server in [`server/`](server/).

## Goals

- **No accounts.** The server is a single binary you run yourself.
- **Zero knowledge.** The server stores ciphertext plus the minimum metadata needed to order updates. A full copy of its data directory reveals nothing about your hosts or keys.
- **Offline first.** The vault works entirely locally; sync is optional.
- **Pairing, not passwords.** The first device creates a pairing string; other devices paste it. (A master-password flow could be added later by wrapping the vault key; it wouldn't require re-encrypting anything.)

## Records

A vault is a set of records. A record is the unit of sync:

```
Record {
  id:      UUID     # plaintext, used for addressing
  hlc:     u64      # plaintext, hybrid logical clock for ordering
  device:  string   # plaintext, device that produced this version (HLC tie-breaker)
  deleted: bool     # plaintext, tombstone
  body: {           # encrypted, the server never sees any of this
    kind: "host" | "ssh_key" | ...
    name: string
    data: JSON      # kind-specific fields; the core doesn't interpret them
  }
}
```

Even `kind` is inside the ciphertext, so the server only learns that "some record changed".

### Hybrid logical clock

`hlc = max(wall_clock_ms, last_hlc / 1000 + 1) * 1000 + counter`, strictly increasing per device. Ordering compares `hlc` first, then `device` lexicographically. When a device receives a remote record it advances its own clock past it, so clock drift between devices can't let an old edit overwrite a newer one.

## Encryption

- Algorithm: XChaCha20-Poly1305 (RustCrypto `chacha20poly1305`).
- Vault key: 32 random bytes, generated locally the first time the vault opens.
- On the wire, each record body is sealed separately:
  `blob = nonce(24) || seal(key, nonce, plaintext = json(body), aad = record_id)`.
  Binding the record ID as associated data stops the server from moving one record's ciphertext onto another.
- At rest on the device, the whole vault state is serialized and sealed into `vault.tv`. The key currently sits next to it in `vault.key` inside the app sandbox; moving it into the OS keychain is planned and won't change the file format.

## Pairing string

```
TTERMSYNC1:<base64url(json)>

{
  "v": 1,
  "server": "https://sync.example.com",
  "vault":  "<uuid>",
  "token":  "<base64, 32 bytes>",   # bearer token for the server
  "key":    "<base64, 32 bytes>"    # vault key; the server never has this
}
```

The token authenticates to the server, which stores only `SHA-256(token)`. The key decrypts records. They're deliberately separate: someone with the server's data has neither.

Leaking the pairing string leaks the whole vault. The app warns about this when exporting it.

## Server API

Data lives on disk under the data directory, one JSON file per vault, written atomically.

```
GET  /v1/health
     200 {"ok": true, "version": "..."}

POST /v1/vaults
     {"vault_id": "<uuid>", "auth": "<base64 sha256(token)>"}
     201 {}          # the client generates both the vault ID and the token
     409             # already exists
```

Everything below requires `Authorization: Bearer <token>`.

```
POST /v1/vaults/:id/records            # push
     [{"id", "hlc", "device", "deleted", "blob": "<base64>"}, ...]
     200 {"seq": <server seq of the last accepted record>}

GET  /v1/vaults/:id/records?since=<seq>  # pull
     200 {"records": [{... same fields ..., "seq"}], "next": <current max seq>}
```

- For each pushed record the server compares `hlc` (then `device`) with what it has and silently drops older versions, so pushes are idempotent.
- Every accepted record gets a new, per-vault, monotonically increasing `seq`. Clients keep `next` as a cursor and only pull what changed since.
- Creating a vault is open to anyone who can reach the server.

## Client sync

```
sync():
  1. push: collect dirty records (created / edited / deleted locally, not yet pushed)
           encrypt bodies → POST /records → clear the dirty flags on success
  2. pull: GET /records?since=<cursor>
           decrypt each record, merge last-writer-wins → cursor = next
  3. any network error: keep dirty flags and cursor, retry next time
```

The app syncs on launch, about two seconds after a local change, and when you tap Sync now.

### Conflicts

- Normally last-writer-wins by HLC.
- If a newer remote version arrives for a record that also has unpushed local edits, the remote version wins and the local one is kept as a **conflict copy** (new ID, name annotated with the device and time, marked dirty so it gets pushed). A password or private key is never silently lost to sync; you decide which to keep.
- Deletes are tombstones and follow the same rules.

### Joining an existing vault

- Empty local vault: adopt the pairing string's vault ID, token and key, then pull everything.
- Local vault already has records: re-encrypt them under the new key with fresh IDs, mark them dirty, and merge them into the joined vault. Nothing on either side is lost.
