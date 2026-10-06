#!/usr/bin/env python3
"""
wazuh_identity.py

Make a simulated agent REPORT the machine its inventory was recorded on.

A simulated agent's dashboard shows data from two unrelated places. The header,
and the OS stamped on every event and finding, come from what the agent reports
to the manager in its keepalive. The inventory, SCA and FIM come from a recorded
real machine. Left alone the two disagree: the simulator's built-in profile says
"Windows 11 Pro 10.0.26200.9445" while the inventory it replays belongs to a
"Windows 11 Home Single Language 10.0.26200.9457", a Mac reports macOS 26.7
arm64 while its inventory is macOS 15.0.1 on Intel, and Ubuntu data sits under
an "Amazon Linux" header.

This builds an identity file from the recorded machine's own system-inventory
record. wazuh_agent_sim.py reads it with --identity and reports that instead of
its built-in profile.

  python3 wazuh_identity.py --fixtures fixtures/docs --source 004 \\
      --profile windows --hostname WIN-DEMO --out agents/win-demo.identity

Used by `democtl agent map` and by the web UI's Inventory button, so both paths
produce the same result.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# The `type` the manager records, by simulated platform, when the recorded
# machine's own record does not say.
OS_TYPE = {"windows": "windows", "macos": "darwin", "linux": "linux"}


def read_system_doc(docs_dir: Path, source: str) -> dict | None:
    f = Path(docs_dir) / "wazuh-states-inventory-system.jsonl"
    if not f.exists():
        return None
    with f.open() as fh:
        for line in fh:
            try:
                src = json.loads(line)["_source"]
            except (ValueError, KeyError, TypeError):
                continue
            aid = ((src.get("wazuh") or {}).get("agent") or {}).get("id")
            if str(aid) == str(source):
                return src
    return None


def identity_for(docs_dir: Path, source: str, profile: str,
                 hostname: str | None = None) -> dict | None:
    """The identity to report for `source`, or None if it has no OS record."""
    src = read_system_doc(docs_dir, source)
    if not src:
        return None
    host = src.get("host") or {}
    os_ = host.get("os") or {}
    if not os_.get("name"):
        return None
    ident: dict = {
        "architecture": host.get("architecture") or "x86_64",
        "os": {
            "name": os_["name"],
            "version": os_.get("version") or "",
            "platform": os_.get("platform") or OS_TYPE.get(profile, "linux"),
            "type": os_.get("type") or OS_TYPE.get(profile, "linux"),
        },
    }
    if hostname:
        ident["hostname"] = hostname
    return ident


def overlay_platform(plat: dict, state_path) -> dict:
    """Lay an agent's identity file over a player's built-in platform entry.

    The players (events, FIM state) each carry their own table of what a "macOS" or "Windows"
    machine looks like, and stamp it on everything they send. For an agent with an identity
    file those would disagree with what the agent itself registered. The file is found from
    the state path the player is already given: agents/<name>.json -> agents/<name>.identity.

    Only the hostname, architecture and the OS name/version/platform are replaced. The queue,
    location, timezone and the OS `type` the manager already expects are left as they are.
    The built-in table is never modified, and a missing or unreadable file changes nothing.
    """
    out = dict(plat)
    out["os"] = dict(plat["os"])
    try:
        ident = json.loads(Path(state_path).with_suffix(".identity").read_text())
    except (OSError, ValueError, TypeError):
        return out
    for key in ("hostname", "architecture"):
        if ident.get(key):
            out[key] = ident[key]
    for key in ("name", "version", "platform"):
        val = (ident.get("os") or {}).get(key)
        if val:
            out["os"][key] = val
    return out


def describe(ident: dict) -> str:
    o = ident["os"]
    return (f"{o['name']} {o['version']}".strip()
            + f", {ident['architecture']}"
            + (f", host {ident['hostname']}" if ident.get("hostname") else ""))


def write_identity(docs_dir: Path, source: str, profile: str, hostname: str | None,
                   out: Path) -> str | None:
    """Write the identity file. Returns a one-line description, or None when the
    source has no OS record; in that case any stale file is removed so the agent
    falls back to its built-in profile rather than reporting an old machine."""
    ident = identity_for(docs_dir, source, profile, hostname)
    out = Path(out)
    if ident is None:
        out.unlink(missing_ok=True)
        return None
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(ident, indent=2))
    return describe(ident)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--fixtures", type=Path, required=True,
                    help="the fixtures/docs directory")
    ap.add_argument("--source", required=True, help="recorded agent id, e.g. 004")
    ap.add_argument("--profile", choices=sorted(OS_TYPE), required=True)
    ap.add_argument("--hostname")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    got = write_identity(args.fixtures, args.source, args.profile, args.hostname, args.out)
    if got is None:
        print(f"  no OS record for source {args.source} in {args.fixtures}; "
              f"the agent keeps its built-in profile")
        return 4
    print(f"  reports as: {got}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
