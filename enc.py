"""
enc.py — TimeLock Vault CLI Encryptor
======================================
Usage:
    python enc.py <file> [duration] [--server URL]

Duration (default: 1month):
    1h  2h  6h  12h  1d  3d  1week  2weeks  1month  3months  6months  1year

Examples:
    python enc.py secret.pdf
    python enc.py secret.pdf 1year
    python enc.py secret.pdf 2weeks --server https://en.yourdomain.com
"""

import sys
import os
import argparse
import urllib.request
import urllib.error
from pathlib import Path


DEFAULT_SERVER  = "https://de.rt0.me"
DEFAULT_DURATION = "1month"


def encrypt(filepath: str, duration: str, server: str) -> str:
    path = Path(filepath)
    if not path.exists():
        print(f"✗  File not found: {filepath}", file=sys.stderr)
        sys.exit(1)

    raw = path.read_bytes()
    url = f"{server.rstrip('/')}/{duration}"
    out_path = str(path) + ".tlp"

    print(f"  file     →  {path.name}  ({len(raw):,} bytes)")
    print(f"  lock for →  {duration}")
    print(f"  server   →  {server}")
    print()

    req = urllib.request.Request(
        url,
        data=raw,
        method="PUT",
        headers={
            "Content-Type": "application/octet-stream",
            "X-Filename":   path.name,
        }
    )

    try:
        with urllib.request.urlopen(req) as resp:
            tlp_bytes = resp.read()
            unlock_iso = resp.headers.get("X-Unlock-ISO", "?")
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")
        print(f"✗  Server error {e.code}: {body}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"✗  Cannot reach server: {e.reason}", file=sys.stderr)
        sys.exit(1)

    Path(out_path).write_bytes(tlp_bytes)

    print(f"✓  Encrypted  →  {out_path}")
    print(f"   Unlocks at →  {unlock_iso}")
    return out_path


def main():
    p = argparse.ArgumentParser(
        description="Encrypt a file with a time-lock",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    p.add_argument("file",                    help="File to encrypt")
    p.add_argument("duration", nargs="?",
                   default=DEFAULT_DURATION,  help="Lock duration (default: 1month)")
    p.add_argument("--server", "-s",
                   default=DEFAULT_SERVER,    help="Encrypt server URL")

    args = p.parse_args()
    encrypt(args.file, args.duration, args.server)


if __name__ == "__main__":
    main()