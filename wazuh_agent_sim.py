#!/usr/bin/env python3
"""
wazuh_agent_sim.py

A minimal Wazuh 5.x agent that enrolls and sends keepalives over the remoted
HTTPS endpoint (port 1517), and does nothing else. The manager treats it as a
genuinely connected agent, so the dashboard shows it as active -- the status is
real, not faked, because the agent really is talking to the manager.

Pair with wazuh_fixture_player.py, which supplies the inventory and
vulnerability documents this agent would otherwise have collected.

Protocol, from wazuh/wazuh @ 5.0.0:

  POST {prefix}/enroll
    Authorization: Bearer <wazuh-enroll+jwt>
      key    = HKDF-SHA256(password, salt=32x00, info="WAZUH-ENROLL-JWT-KEY"|0x01, L=32)
      header {"alg":"HS256","typ":"wazuh-enroll+jwt"}        (no kid)
      claims {exp, iat, jti, nbf}                            (no iss/sub)
    body   {"name", "version", "ip"?, "groups"?, "key_hash"?}
           NOTE: groups is a comma-separated STRING, not an array.
    -> {"id","ip","key","name"}   key = 64 lowercase hex chars

  POST {prefix}/control
    Authorization: Bearer <wazuh-agent+jwt>
      key    = the enrollment key, hex-DECODED to 32 raw bytes
      header {"alg":"HS256","typ":"wazuh-agent+jwt","kid":"<agent id>"}
      claims {exp, iat, jti, nbf, iss:"wazuh-agent/<id>", sub:"<id>"}
    body   {"type":"startup"|"notify"|"shutdown", ...}
      startup: {"type":"startup","version":"v5.0.0"}
      notify:  {"type":"notify","agent":{"version":...},
                "host":{"hostname","architecture","ip",
                        "os":{"name","version","platform","type"}}}

  Both require the header `protocol-version: 1`.
  Tokens live 60 s (kLifetimeSec) and are regenerated per request.

Usage:
  # enroll a simulated macOS endpoint and keep it alive
  python3 wazuh_agent_sim.py --manager 127.0.0.1 \
      --name macos-demo --profile macos --state ./agents/macos-demo.json

  # reuse an existing id/key instead of enrolling again
  python3 wazuh_agent_sim.py --manager 127.0.0.1 \
      --agent-id 005 --agent-key de63... --profile macos

  # clean shutdown (marks the agent disconnected deliberately)
  python3 wazuh_agent_sim.py --manager 127.0.0.1 --state ./agents/macos-demo.json --shutdown
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import secrets
import signal
import sys
import time
import urllib3
from pathlib import Path

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- profile constants (jwtProfileV1.hpp / jwtEnrollProfileV1.hpp) -----------
ENROLL_TYP = "wazuh-enroll+jwt"
AGENT_TYP = "wazuh-agent+jwt"
ISSUER_PREFIX = "wazuh-agent/"
ALG = "HS256"
LIFETIME_SEC = 60
JTI_BYTES = 16
HKDF_INFO = b"WAZUH-ENROLL-JWT-KEY" + b"\x01"
HKDF_SALT = b"\x00" * 32
KEY_BYTES = 32
PROTOCOL_VERSION = "1"

# Host profiles. These populate the /control notify body, which is what the
# manager records as the agent's reported host. This is why a simulator beats a
# stripped-down real agent: we declare the platform rather than inheriting it.
PROFILES = {
    "macos": {
        "hostname": "MAC-demo-MacBook-Air.local",
        "architecture": "arm64",
        "os": {
            "name": "macOS",
            "version": "26.7",
            "platform": "darwin",
            "type": "darwin",
        },
    },
    "windows": {
        "hostname": "WIN-DEMO",
        "architecture": "x86_64",
        "os": {
            "name": "Microsoft Windows 11 Pro",
            "version": "10.0.26200.9445",
            "platform": "windows",
            "type": "windows",
        },
    },
    "linux": {
        "hostname": "amazonlinux-demo",
        "architecture": "x86_64",
        "os": {
            "name": "Amazon Linux",
            "version": "2023",
            "platform": "amzn",
            "type": "linux",
        },
    },
}


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def jwt_sign(key: bytes, header: dict, claims: dict) -> str:
    """Compact JWT. Key order is fixed and separators are compact because the
    signature covers the exact bytes of both segments."""
    seg = (
        b64url(json.dumps(header, separators=(",", ":")).encode("ascii"))
        + "."
        + b64url(json.dumps(claims, separators=(",", ":")).encode("ascii"))
    )
    sig = hmac.new(key, seg.encode("ascii"), hashlib.sha256).digest()
    return f"{seg}.{b64url(sig)}"


def enroll_token(password: str) -> str:
    key = hkdf_sha256(password.encode("utf-8"), HKDF_SALT, HKDF_INFO, KEY_BYTES)
    iat = int(time.time())
    return jwt_sign(
        key,
        {"alg": ALG, "typ": ENROLL_TYP},
        {"exp": iat + LIFETIME_SEC, "iat": iat,
         "jti": b64url(secrets.token_bytes(JTI_BYTES)), "nbf": iat},
    )


def agent_token(agent_id: str, agent_key_hex: str) -> str:
    """The client key is stored as 64 hex chars but signs as 32 raw bytes:
    authMiddleware rejects any key that does not decode to exactly 32."""
    try:
        key = bytes.fromhex(agent_key_hex)
    except ValueError:
        sys.exit("Agent key is not valid hex")
    if len(key) != KEY_BYTES:
        sys.exit(f"Agent key decodes to {len(key)} bytes, expected {KEY_BYTES}")

    iat = int(time.time())
    return jwt_sign(
        key,
        {"alg": ALG, "typ": AGENT_TYP, "kid": agent_id},
        {
            "exp": iat + LIFETIME_SEC,
            "iat": iat,
            "iss": f"{ISSUER_PREFIX}{agent_id}",
            "jti": b64url(secrets.token_bytes(JTI_BYTES)),
            "nbf": iat,
            "sub": agent_id,
        },
    )


class Remoted:
    def __init__(self, manager: str, port: int, prefix: str, verify=False, timeout=15):
        self.base = f"https://{manager}:{port}{prefix.rstrip('/')}"
        self.s = requests.Session()
        self.s.verify = verify
        self.timeout = timeout

    def post(self, path: str, token: str, body: dict) -> requests.Response:
        return self.s.post(
            f"{self.base}{path}",
            headers={
                "Content-Type": "application/json",
                "protocol-version": PROTOCOL_VERSION,
                "Authorization": f"Bearer {token}",
            },
            data=json.dumps(body, separators=(",", ":")),
            timeout=self.timeout,
        )


def do_enroll(rem: Remoted, password: str, name: str, version: str,
              ip: str | None, groups: str | None) -> dict:
    body = {"name": name, "version": version}
    if ip:
        body["ip"] = ip
    if groups:
        body["groups"] = groups  # comma-separated string, never an array

    r = rem.post("/enroll", enroll_token(password), body)
    if r.status_code != 200:
        sys.exit(f"Enrollment failed ({r.status_code}): {r.text}")
    data = r.json()
    print(f"Enrolled '{data['name']}' as agent {data['id']}")
    return data


def control(rem: Remoted, agent_id: str, key: str, body: dict) -> requests.Response:
    return rem.post("/control", agent_token(agent_id, key), body)


def apply_identity(profile: dict, identity_path: Path | None) -> dict:
    """Overlay an identity file onto a built-in profile.

    The file (written by wazuh_identity.py) says what machine this agent should
    claim to be: the one its inventory was recorded on. Anything it does not
    set keeps the profile's value. A missing or unreadable file changes nothing.
    """
    out = dict(profile)
    out["os"] = dict(profile["os"])
    if not identity_path or not Path(identity_path).is_file():
        return out
    try:
        ident = json.loads(Path(identity_path).read_text())
    except (OSError, ValueError):
        return out
    for key in ("hostname", "architecture"):
        if ident.get(key):
            out[key] = ident[key]
    for key, val in (ident.get("os") or {}).items():
        if val not in (None, ""):
            out["os"][key] = val
    return out


def notify_body(version: str, profile: dict, ip: str) -> dict:
    return {
        "type": "notify",
        "agent": {"version": version},
        "host": {
            "hostname": profile["hostname"],
            "architecture": profile["architecture"],
            "ip": ip,
            "os": profile["os"],
        },
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manager", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1517)
    ap.add_argument("--prefix", default="/wazuh-manager")
    ap.add_argument("--password-file", default="/var/wazuh-manager/etc/authd.pass")
    ap.add_argument("--password")
    ap.add_argument("--name", help="Agent name to enroll as")
    ap.add_argument("--agent-id", help="Skip enrollment, use this id")
    ap.add_argument("--agent-key", help="Skip enrollment, use this key")
    ap.add_argument("--state", type=Path,
                    help="JSON file holding id/key. Reused if present, written "
                         "after enrollment. Avoids re-enrolling on restart.")
    ap.add_argument("--profile", choices=sorted(PROFILES), default="linux")
    ap.add_argument("--hostname", help="Override the profile hostname")
    ap.add_argument("--identity", type=Path, metavar="FILE",
                    help="JSON from wazuh_identity.py: report the OS, version and "
                         "architecture of the recorded machine this agent's inventory "
                         "comes from, instead of the built-in profile")
    ap.add_argument("--reported-ip", default="10.0.44.200",
                    help="IP this agent claims in its notify body")
    ap.add_argument("--agent-version", default="v5.0.0")
    ap.add_argument("--groups", help="Comma-separated groups, enrollment only")
    ap.add_argument("--interval", type=int, default=10,
                    help="Keepalive interval; matches notify_time (default 10)")
    ap.add_argument("--once", action="store_true", help="Single notify, then exit")
    ap.add_argument("--shutdown", action="store_true",
                    help="Send a shutdown control message and exit")
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    rem = Remoted(args.manager, args.port, args.prefix, verify=args.verify_tls)

    agent_id, agent_key = args.agent_id, args.agent_key
    if args.state and args.state.exists() and not agent_id:
        saved = json.loads(args.state.read_text())
        agent_id, agent_key = saved["id"], saved["key"]
        print(f"Reusing agent {agent_id} from {args.state}")

    if not (agent_id and agent_key):
        if not args.name:
            sys.exit("Need --name to enroll, or --agent-id/--agent-key to reuse")
        password = args.password or Path(args.password_file).read_text().strip()
        data = do_enroll(rem, password, args.name, args.agent_version,
                         "any", args.groups)
        agent_id, agent_key = data["id"], data["key"]
        if args.state:
            args.state.parent.mkdir(parents=True, exist_ok=True)
            args.state.write_text(json.dumps(data, indent=2))
            args.state.chmod(0o600)  # the key is a credential
            print(f"Saved credentials to {args.state}")

    # --identity, or failing that the file next to the state file (agents/<name>.identity)
    ident_path = args.identity or (args.state.with_suffix(".identity") if args.state else None)
    profile = apply_identity(PROFILES[args.profile], ident_path)
    if args.hostname:
        profile["hostname"] = args.hostname

    if args.shutdown:
        r = control(rem, agent_id, agent_key, {"type": "shutdown"})
        print(f"shutdown -> {r.status_code} {r.text.strip()}")
        return 0 if r.ok else 1

    r = control(rem, agent_id, agent_key,
                {"type": "startup", "version": args.agent_version})
    print(f"startup -> {r.status_code} {r.text.strip()}")
    if not r.ok:
        return 1

    body = notify_body(args.agent_version, profile, args.reported_ip)

    if args.once:
        r = control(rem, agent_id, agent_key, body)
        print(f"notify -> {r.status_code} {r.text.strip()}")
        return 0 if r.ok else 1

    stop = {"now": False}

    def handle(signum, frame):
        stop["now"] = True

    signal.signal(signal.SIGINT, handle)
    signal.signal(signal.SIGTERM, handle)

    print(f"Agent {agent_id} ({profile['hostname']}, {profile['os']['name']} "
          f"{profile['os']['version']}, {profile['architecture']}) "
          f"keepalive every {args.interval}s. Ctrl-C to stop.")
    sent = failed = 0
    while not stop["now"]:
        try:
            r = control(rem, agent_id, agent_key, body)
            if r.ok:
                sent += 1
            else:
                failed += 1
                print(f"  notify {r.status_code}: {r.text.strip()[:120]}")
        except requests.RequestException as exc:
            failed += 1
            print(f"  notify error: {exc}")

        if sent and sent % 30 == 0:
            print(f"  {sent} keepalives sent"
                  + (f", {failed} failed" if failed else ""))

        for _ in range(args.interval):
            if stop["now"]:
                break
            time.sleep(1)

    print(f"\nStopping. Sent {sent} keepalives, {failed} failures.")
    print("Agent will go disconnected after the manager's timeout. "
          "Use --shutdown to mark it disconnected immediately.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
