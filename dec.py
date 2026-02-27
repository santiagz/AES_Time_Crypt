"""
dec.py — TimeLock Vault CLI Decryptor
======================================
Usage:
    python dec.py <file.tlp> [--server URL] [--output PATH]

Examples:
    python dec.py secret.pdf.tlp
    python dec.py secret.pdf.tlp --output /tmp/secret.pdf
    python dec.py secret.pdf.tlp --server https://de.yourdomain.com
"""

import sys
import json
import argparse
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime, timezone


DEFAULT_SERVER = "https://de.rt0.me"


def decrypt(tlp_path: str, server: str, output: str | None) -> str:
    path = Path(tlp_path)
    if not path.exists():
        print(f"✗  File not found: {tlp_path}", file=sys.stderr)
        sys.exit(1)

    raw = path.read_bytes()

    # Peek at the .tlp for info
    try:
        meta = json.loads(raw)
        original = meta.get("original", "decrypted_file")
        unlock_at = meta.get("unlock_at", 0)
        unlock_dt = datetime.fromtimestamp(unlock_at, tz=timezone.utc)
        remaining = unlock_at - datetime.now(tz=timezone.utc).timestamp()
    except Exception:
        original, unlock_dt, remaining = "decrypted_file", None, 0

    if output:
        out_path = output
    else:
        # Strip .tlp extension
        out_path = str(path.with_suffix("")) if path.suffix == ".tlp" else str(path) + ".dec"

    print(f"  file       →  {path.name}")
    if unlock_dt:
        print(f"  unlocks at →  {unlock_dt.strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"  server     →  {server}")
    print()

    if remaining > 60:
        days  = int(remaining // 86400)
        hours = int((remaining % 86400) // 3600)
        mins  = int((remaining % 3600) // 60)
        parts = []
        if days:  parts.append(f"{days}d")
        if hours: parts.append(f"{hours}h")
        if mins:  parts.append(f"{mins}m")
        print(f"⚠  Still locked for  ~{' '.join(parts)}")
        print("   Sending to server anyway — it will refuse to decrypt.")
        print()

    url = f"{server.rstrip('/')}"
    req = urllib.request.Request(
        url,
        data=raw,
        method="POST",
        headers={"Content-Type": "application/octet-stream"}
    )

    try:
        with urllib.request.urlopen(req) as resp:
            decrypted = resp.read()
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        # Pretty-print JSON error from server
        try:
            err = json.loads(body)
            print(f"✗  {err.get('error', 'Error')}", file=sys.stderr)
            if "message" in err:
                print(f"   {err['message']}", file=sys.stderr)
            if "unlock_iso" in err:
                print(f"   Unlocks: {err['unlock_iso']}", file=sys.stderr)
        except Exception:
            print(f"✗  Server {e.code}: {body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"✗  Cannot reach server: {e.reason}", file=sys.stderr)
        sys.exit(1)

    Path(out_path).write_bytes(decrypted)
    print(f"✓  Decrypted  →  {out_path}")
    return out_path


def main():
    p = argparse.ArgumentParser(
        description="Decrypt a time-locked file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    p.add_argument("file",             help=".tlp file to decrypt")
    p.add_argument("--output", "-o",   help="Output path (default: strips .tlp extension)")
    p.add_argument("--server", "-s",
                   default=DEFAULT_SERVER, help="Decrypt server URL")

    args = p.parse_args()
    decrypt(args.file, args.server, args.output)


if __name__ == "__main__":
    main()