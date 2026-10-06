#!/usr/bin/env python3
"""
wazuh_enroll_token.py

Builds the `wazuh-enroll+jwt` bearer token required by the Wazuh 5.x remoted
HTTPS endpoint (port 1517) for POST /wazuh-manager/enroll.

Derivation, per src/shared_modules/utils/jwt/jwtEnrollProfileV1.hpp (5.0.0):

    key = HKDF-SHA256(
        IKM  = enrollment password (contents of etc/authd.pass),
        salt = 32 x 0x00,
        info = b"WAZUH-ENROLL-JWT-KEY" + 0x01,
        L    = 32 bytes)

    header = {"alg": "HS256", "typ": "wazuh-enroll+jwt"}      (no kid)
    claims = {"exp", "iat", "jti", "nbf"}                     (no iss/sub)
    exp    = iat + 60          (kLifetimeSec, fixed by the profile)
    jti    = 16 CSPRNG bytes, base64url, unpadded (22 chars)

Tokens are short-lived by design: the verifier requires exp - iat <= 60 and
now - iat <= maxAge + skew (defaults 60 s and 30 s). Generate a fresh one per
enrollment attempt rather than caching.

Usage:
    python3 wazuh_enroll_token.py --password-file /var/wazuh-manager/etc/authd.pass
    python3 wazuh_enroll_token.py --password 'literal-password'

    # emit a ready-to-run curl command instead of the bare token
    python3 wazuh_enroll_token.py --password-file ... --curl \
        --manager 127.0.0.1 --name macos-demo
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
from pathlib import Path

# Profile constants. These are fixed by the wazuh-enroll+jwt profile, not knobs.
HKDF_INFO_LABEL = b"WAZUH-ENROLL-JWT-KEY"
HKDF_INFO_VERSION = b"\x01"
HKDF_SALT = b"\x00" * 32
KEY_BYTES = 32
LIFETIME_SEC = 60
JTI_BYTES = 16
TYP = "wazuh-enroll+jwt"
ALG = "HS256"


def b64url(raw: bytes) -> str:
    """base64url without padding, as the JWT spec requires."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 extract-and-expand. Implemented directly so the script has no
    dependency beyond the standard library."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def derive_enroll_key(password: str) -> bytes:
    return hkdf_sha256(
        ikm=password.encode("utf-8"),
        salt=HKDF_SALT,
        info=HKDF_INFO_LABEL + HKDF_INFO_VERSION,
        length=KEY_BYTES,
    )


def make_token(password: str, now: int | None = None) -> str:
    key = derive_enroll_key(password)
    iat = int(time.time()) if now is None else now

    header = {"alg": ALG, "typ": TYP}
    claims = {
        "exp": iat + LIFETIME_SEC,
        "iat": iat,
        "jti": b64url(secrets.token_bytes(JTI_BYTES)),
        "nbf": iat,
    }

    # separators=(",", ":") keeps the JSON compact; the profile describes a
    # compact grammar and any extra whitespace changes the signed bytes.
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
        + "."
        + b64url(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    )
    sig = hmac.new(key, signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{b64url(sig)}"


def read_password(args) -> str:
    if args.password:
        return args.password.strip()
    path = Path(args.password_file)
    try:
        return path.read_text(encoding="utf-8").strip()
    except PermissionError:
        sys.exit(f"Cannot read {path} (try sudo)")
    except FileNotFoundError:
        sys.exit(f"No such file: {path}")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--password", help="Enrollment password as a literal string")
    src.add_argument("--password-file",
                     default="/var/wazuh-manager/etc/authd.pass",
                     help="File holding the enrollment password "
                          "(default: %(default)s)")
    ap.add_argument("--show-key", action="store_true",
                    help="Also print the derived key in hex, for debugging")
    ap.add_argument("--curl", action="store_true",
                    help="Print a complete curl command for POST /enroll")
    ap.add_argument("--manager", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1517)
    ap.add_argument("--prefix", default="/wazuh-manager")
    ap.add_argument("--name", default="simulated-agent")
    ap.add_argument("--agent-version", default="v5.0.0")
    ap.add_argument("--ip", default="any")
    ap.add_argument("--groups", default=None,
                    help="Comma-separated group names, e.g. 'default,simulated'. "
                         "Omitted from the request when unset.")
    args = ap.parse_args()

    password = read_password(args)
    if not password:
        sys.exit("Enrollment password is empty")

    token = make_token(password)

    if args.show_key:
        print(f"derived key (hex): {derive_enroll_key(password).hex()}",
              file=sys.stderr)

    if not args.curl:
        print(token)
        return 0

    # The endpoint validates `groups` as a STRING (comma-separated), not an
    # array, and treats `ip`, `groups` and `key_hash` as optional. Sending an
    # empty array returns "Invalid field: groups", so omit anything unset
    # rather than sending a placeholder.
    payload = {
        "name": args.name,
        "version": args.agent_version,
    }
    if args.ip:
        payload["ip"] = args.ip
    if args.groups:
        payload["groups"] = args.groups
    body = json.dumps(payload, separators=(",", ":"))

    print(
        f"curl -sk -X POST \\\n"
        f"  -H 'Content-Type: application/json' \\\n"
        f"  -H 'protocol-version: 1' \\\n"
        f"  -H 'Authorization: Bearer {token}' \\\n"
        f"  -d '{body}' \\\n"
        f"  https://{args.manager}:{args.port}{args.prefix}/enroll"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
