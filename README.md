# ⏳ TimeLock Vault

Server-side time-lock file encryption. Files are sealed with AES-256-GCM.
The decryption key lives on the server and is **released only after the unlock date**.

---

## Quickstart

### curl

```bash
# encrypt
curl -T file.txt en.rt0.me/1year -o file.txt.tlp

# decrypt  (just the subdomain, no path needed)
curl -T file.txt.tlp de.rt0.me -o file.txt
```

### CLI

```bash
python enc.py file.txt           # 1month default
python enc.py file.txt 1year
python enc.py file.txt 2weeks --server https://en.yourdomain.com

python dec.py file.txt.tlp
python dec.py file.txt.tlp --server https://de.yourdomain.com
```

---

## Available Durations

★ Default when no duration specified

| Token     | Duration    |
|-----------|-------------|
| `1h`      | 1 hour      |
| `2h`      | 2 hours     |
| `6h`      | 6 hours     |
| `12h`     | 12 hours    |
| `1d`      | 1 day       |
| `3d`      | 3 days      |
| `1week`   | 1 week      |
| `2weeks`  | 2 weeks     |
| `1month`  | 30 days ★   |
| `3months` | 90 days     |
| `6months` | 180 days    |
| `1year`   | 365 days    |

---

## Deploy Self-Host

### 1. Clone & configure

Edit `.env` - set a long random `SERVER_SECRET`:
```bash
cp .env.example .env
```

Edit server name in `nginx.conf`:
```nginx
server_name en.yourdomain.com;

...

server_name de.yourdomain.com;
```

Edit html files `enctypt.html` and `dectypt.html`

Ctrl+F in files for `yourdomain.com` and replace to your FQDN

Example:
```html
<span>TimeLock Vault — de.yourdomain.com</span>
```

### 2. Point your DNS

```
en.yourdomain.com  →  your server IP
de.yourdomain.com  →  your server IP
```

### 3. Run

```bash
docker compose up -d
```

That's it. Nginx routes by subdomain:

```
GET  en.yourdomain.com/        →  encrypt instruction page
PUT  en.yourdomain.com/1year   →  FastApi /1year  (encrypt)

GET  de.yourdomain.com/        →  decrypt instruction page
PUT  de.yourdomain.com/        →  FastApi /decrypt  (nginx rewrites internally)
```

---

## API Reference

### `POST /encrypt[/<duration>]`

Encrypt a file and store its key in the vault.

**Request:**
- Body: raw file bytes
- Header `X-Filename`: original filename (optional, default: `"file"`)
- Header `Content-Type`: `application/octet-stream`

**Response:** `.tlp` file (JSON, saved to disk)

**Response headers:**
- `X-Unlock-At`: unix timestamp
- `X-Unlock-ISO`: ISO 8601 datetime
- `X-Lock-Duration`: duration token used

---

### `POST /decrypt`

Attempt to decrypt a `.tlp` file.

**Request:**
- Body: `.tlp` file bytes

**Responses:**

| Code | Meaning |
|------|---------|
| `200` | Decrypted — body is original file bytes |
| `423` | Locked — body is JSON countdown |
| `400` | Malformed .tlp file |
| `403` | Integrity check failed (tampered file) |
| `404` | Key not found (server reset?) |

**423 JSON body:**
```json
{
  "error": "🔒 Locked",
  "message": "This file unlocks in 47d 3h 22m",
  "unlock_at": 1798761600,
  "unlock_iso": "2027-01-01T00:00:00+00:00",
  "remaining_seconds": 4079340,
  "remaining_human": "47d 3h 22m"
}
```

---

## .tlp File Format

```json
{
  "v": 1,
  "id": "key_id_on_server",
  "unlock_at": 1798761600,
  "unlock_iso": "2027-01-01T00:00:00+00:00",
  "original": "secret.pdf",
  "nonce": "<base64 AES-GCM nonce>",
  "ct": "<base64 ciphertext>",
  "_sig": "<32-char integrity hash>"
}
```

The `.tlp` file contains **only the ciphertext** and a key reference.
The actual AES key lives only on the server.

---

## Security Notes

- Keys are stored in SQLite on the server. Back it up.
- `SERVER_SECRET` must be kept secret and stable — it signs all .tlp files.
- The server sees plaintext briefly during encryption (over HTTPS).
- For ultra-high security, run your own server so you control the key vault.
- Keys are stored indefinitely — do not delete `vault.db` before files are unlocked.