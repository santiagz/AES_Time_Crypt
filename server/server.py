"""
TimeLock Vault — Server (FastAPI)
==================================
PUT /<duration>   encrypt — body=raw file bytes, header X-Filename: name.txt
PUT /decrypt      decrypt — body=.tlp JSON blob
GET /health       → {"ok": true}
GET /docs         → Swagger UI

Duration tokens: 1h 2h 6h 12h 1d 3d 1week 2weeks 1month 3months 6months 1year
"""

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import FastAPI, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# ── Config ────────────────────────────────────────────────────────────────────

DB_PATH   = os.environ.get("DB_PATH", "vault.db")
MAX_BYTES = int(os.environ.get("MAX_MB", "100")) * 1024 * 1024
SECRET    = os.environ.get("SERVER_SECRET", secrets.token_hex(32))

DURATIONS: dict[str, int] = {
    "1h":       3_600,
    "2h":       7_200,
    "6h":      21_600,
    "12h":     43_200,
    "1d":      86_400,
    "1day":    86_400,
    "3d":     259_200,
    "3days":  259_200,
    "1week":  604_800,
    "2weeks": 1_209_600,
    "1month": 2_592_000,
    "3months":7_776_000,
    "6months":15_552_000,
    "1year":  31_536_000,
}

# ── DB ────────────────────────────────────────────────────────────────────────

def get_db() -> sqlite3.Connection:
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db

def init_db() -> None:
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS vault (
                id          TEXT PRIMARY KEY,
                aes_key     BLOB NOT NULL,
                unlock_at   INTEGER NOT NULL,
                created_at  INTEGER NOT NULL,
                original    TEXT NOT NULL
            )
        """)
        db.commit()

# ── Helpers ───────────────────────────────────────────────────────────────────

def fmt_countdown(seconds_left: float) -> str:
    s = int(seconds_left)
    parts = []
    if s // 86400:          parts.append(f"{s // 86400}d")
    if (s % 86400) // 3600: parts.append(f"{(s % 86400) // 3600}h")
    if (s % 3600) // 60:    parts.append(f"{(s % 3600) // 60}m")
    if s % 60 or not parts: parts.append(f"{s % 60}s")
    return " ".join(parts)

def sign(payload: dict) -> str:
    msg = f"{payload['id']}:{payload['unlock_at']}".encode()
    return hashlib.sha256(SECRET.encode() + msg).hexdigest()[:32]

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="TimeLock Vault",
    description="Time-lock file encryption. Keys released only after the unlock date.",
    docs_url=None,
    openapi_url=None,
    redoc_url=None,
    version="1.0.0",
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
init_db()

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"ok": True, "ts": int(time.time())}


@app.put("/{path}")
async def router(path: str, request: Request, x_filename: str = Header(default="file")):
    """Single PUT handler — routes to encrypt or decrypt based on path."""
    if path == "decrypt":
        return await _decrypt(request)
    return await _encrypt(path, request, x_filename)


# ── Encrypt ───────────────────────────────────────────────────────────────────

async def _encrypt(duration: str, request: Request, filename: str) -> Response:
    raw = await request.body()
    if not raw:
        return JSONResponse({"error": "No file data in request body"}, status_code=400)
    if len(raw) > MAX_BYTES:
        return JSONResponse({"error": f"File too large (max {MAX_BYTES // 1024 // 1024} MB)"}, status_code=413)

    secs = DURATIONS.get(duration.lower())
    if secs is None:
        return JSONResponse(
            {"error": f"Unknown duration '{duration}'. Valid: {', '.join(DURATIONS)}"},
            status_code=400
        )

    unlock_at  = int(time.time()) + secs
    unlock_iso = datetime.fromtimestamp(unlock_at, tz=timezone.utc).isoformat()
    key        = secrets.token_bytes(32)
    nonce      = secrets.token_bytes(12)
    ct         = AESGCM(key).encrypt(nonce, raw, None)
    key_id     = secrets.token_urlsafe(16)

    with get_db() as db:
        db.execute("INSERT INTO vault VALUES (?,?,?,?,?)",
                   (key_id, key, unlock_at, int(time.time()), filename))
        db.commit()

    payload = {
        "v": 1, "id": key_id,
        "unlock_at": unlock_at, "unlock_iso": unlock_iso,
        "original": filename,
        "nonce": base64.b64encode(nonce).decode(),
        "ct":    base64.b64encode(ct).decode(),
    }
    payload["_sig"] = sign(payload)

    return Response(
        content=json.dumps(payload).encode(),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}.tlp"',
            "X-Unlock-At":  str(unlock_at),
            "X-Unlock-ISO": unlock_iso,
            "X-Duration":   duration,
        },
    )


# ── Decrypt ───────────────────────────────────────────────────────────────────

async def _decrypt(request: Request) -> Response:
    raw = await request.body()
    if not raw:
        return JSONResponse({"error": "No .tlp data in request body"}, status_code=400)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return JSONResponse({"error": "Invalid .tlp file (not valid JSON)"}, status_code=400)

    key_id    = payload.get("id")
    unlock_at = payload.get("unlock_at")
    original  = payload.get("original", "decrypted_file")
    nonce_b64 = payload.get("nonce")
    ct_b64    = payload.get("ct")

    if not all([key_id, unlock_at, nonce_b64, ct_b64]):
        return JSONResponse({"error": "Malformed .tlp — missing fields"}, status_code=400)

    if payload.get("_sig") != sign(payload):
        return JSONResponse({"error": "Integrity check failed — file may be tampered"}, status_code=403)

    now = time.time()
    if now < unlock_at:
        remaining  = unlock_at - now
        unlock_iso = datetime.fromtimestamp(unlock_at, tz=timezone.utc).isoformat()
        return JSONResponse({
            "error":             "🔒 Locked",
            "message":           f"This file unlocks in {fmt_countdown(remaining)}",
            "unlock_at":         unlock_at,
            "unlock_iso":        unlock_iso,
            "remaining_seconds": int(remaining),
            "remaining_human":   fmt_countdown(remaining),
        }, status_code=423)

    with get_db() as db:
        row = db.execute("SELECT aes_key FROM vault WHERE id=?", (key_id,)).fetchone()

    if not row:
        return JSONResponse({"error": "Key not found — was this server reset?"}, status_code=404)

    try:
        pt = AESGCM(bytes(row["aes_key"])).decrypt(
            base64.b64decode(nonce_b64), base64.b64decode(ct_b64), None
        )
    except Exception as e:
        return JSONResponse({"error": f"Decryption failed: {e}"}, status_code=500)

    return Response(
        content=pt,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{original}"'},
    )


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)