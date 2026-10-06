#!/usr/bin/env python3
"""
wazuh_event_seed.py

Writes a SYNTHETIC corpus of log lines for a platform, in the same format the
harvester produces, so wazuh_event_player.py can replay them.

Why this exists: harvesting only works if the behaviour actually happened. An
idle Mac produces no authentication failures, no sudo activity and no brute
force, so there is nothing to record. This generates lines shaped exactly like
the ones that platform emits, which Wazuh's decoders then parse normally.

What is and is not real:
  - The ALERT is real. The decoder chain, the field extraction, the rule match,
    the MITRE mapping and the compliance tags all come from the manager.
  - The LOG LINE is fabricated, though its grammar is taken from the patterns
    decoder/system-auth/0 actually parses, and its content (TTY names, home
    directory layout, command paths) matches the target platform.

Prefer harvested lines wherever they exist. Use this only to fill a gap, and
say so when demoing.

Usage:
  python3 wazuh_event_seed.py --outdir ./events-seed --platform macos
  python3 wazuh_event_player.py --state agents/macos-demo.json \
      --events ./events-seed --profile macos --scenario security-alerts --once
"""

from __future__ import annotations

import argparse
import json
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

# Bodies are written to match the grammars in decoder/system-auth/0. The
# envelope (timestamp and hostname) is added by the player at send time, so
# only the "process[pid]: message" part is generated here.

USERS_MAC = ["dmartin", "jlee", "aroberts", "ops"]
USERS_NIX = ["ubuntu", "deploy", "svc-backup", "ops"]
ATTACK_USERS = ["admin", "root", "test", "oracle", "postgres", "ubnt"]
# RFC 5737 / RFC 3849 documentation ranges: safe to show, obviously not real.
ATTACK_IPS = ["203.0.113.45", "203.0.113.7", "198.51.100.23", "192.0.2.88"]

MAC_CMDS = [
    "/usr/bin/security find-generic-password -ga AirPort",
    "/bin/launchctl load -w /Library/LaunchDaemons/com.demo.agent.plist",
    "/usr/sbin/softwareupdate --install --all",
    "/usr/bin/defaults write com.apple.screensaver askForPassword -int 0",
]
NIX_CMDS = [
    "/usr/bin/apt-get install -y netcat",
    "/bin/systemctl restart sshd",
    "/usr/bin/cat /etc/shadow",
    "/usr/sbin/useradd -m -G sudo backdoor",
]

PLATFORM = {
    "macos": {"tty": "ttys000", "home": "/Users", "users": USERS_MAC,
              "cmds": MAC_CMDS},
    "linux": {"tty": "pts/0", "home": "/home", "users": USERS_NIX,
              "cmds": NIX_CMDS},
    "windows": {},   # handled separately: EventChannel XML, not text lines
}

USERS_WIN = ["a.morgan", "svc_backup", "jdoe", "helpdesk"]
WIN_DOMAIN = "CORP"

# Windows events are raw EventChannel XML. The player rewrites TimeCreated,
# Computer and EventRecordID at send time, so placeholders are fine here.
#
# Why seed these when real ones were harvested: the recorded 4625s are
# LogonType 2 (interactive) from 127.0.0.1 -- someone mistyping at the keyboard.
# These use LogonType 3 (network) from routable addresses, which is what a
# remote brute force actually looks like.
WIN_EVENT_TMPL = """<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>\
<System><Provider Name='Microsoft-Windows-Security-Auditing' \
Guid='{{54849625-5478-4994-a5ba-3e3b0328c30d}}'/><EventID>{eid}</EventID><Version>0</Version>\
<Level>0</Level><Task>{task}</Task><Opcode>0</Opcode><Keywords>{keywords}</Keywords>\
<TimeCreated SystemTime='2026-01-01T00:00:00.0000000Z'/>\
<EventRecordID>1000000000</EventRecordID>\
<Correlation/><Execution ProcessID='{procid}' ThreadID='{threadid}'/>\
<Channel>Security</Channel><Computer>SEED</Computer><Security/></System>\
<EventData>{data}</EventData></Event>"""


def _d(name: str, value: str) -> str:
    return f"<Data Name='{name}'>{value}</Data>"


def win_failed_logon(rnd) -> str:
    user = rnd.choice(ATTACK_USERS)
    ip = rnd.choice(ATTACK_IPS)
    data = "".join([
        _d("SubjectUserSid", "S-1-0-0"), _d("SubjectUserName", "-"),
        _d("SubjectDomainName", "-"), _d("SubjectLogonId", "0x0"),
        _d("TargetUserSid", "S-1-0-0"), _d("TargetUserName", user),
        _d("TargetDomainName", WIN_DOMAIN),
        _d("Status", "0xc000006d"), _d("FailureReason", "%%2313"),
        _d("SubStatus", "0xc000006a"),          # bad password
        _d("LogonType", "3"),                    # network, not interactive
        _d("LogonProcessName", "NtLmSsp "),
        _d("AuthenticationPackageName", "NTLM"),
        _d("WorkstationName", "-"), _d("TransmittedServices", "-"),
        _d("LmPackageName", "-"), _d("KeyLength", "0"),
        _d("ProcessId", "0x0"), _d("ProcessName", "-"),
        _d("IpAddress", ip), _d("IpPort", str(rnd.randint(30000, 65000))),
    ])
    return WIN_EVENT_TMPL.format(eid=4625, task=12544,
                                 keywords="0x8010000000000000",
                                 procid=rnd.randint(600, 2000),
                                 threadid=rnd.randint(1000, 20000), data=data)


def win_success_logon(rnd) -> str:
    user = rnd.choice(USERS_WIN)
    ip = rnd.choice(ATTACK_IPS)
    data = "".join([
        _d("SubjectUserSid", "S-1-0-0"), _d("SubjectUserName", "-"),
        _d("SubjectDomainName", "-"), _d("SubjectLogonId", "0x0"),
        _d("TargetUserSid", f"S-1-5-21-780672331-3256254420-2915116740-"
                            f"{rnd.randint(1001, 1999)}"),
        _d("TargetUserName", user), _d("TargetDomainName", WIN_DOMAIN),
        _d("TargetLogonId", f"0x{rnd.randint(0x100000, 0xffffff):x}"),
        _d("LogonType", "3"), _d("LogonProcessName", "NtLmSsp "),
        _d("AuthenticationPackageName", "NTLM"),
        _d("WorkstationName", "-"), _d("LogonGuid", "{00000000-0000-0000-0000-000000000000}"),
        _d("TransmittedServices", "-"), _d("LmPackageName", "NTLM V2"),
        _d("KeyLength", "128"), _d("ProcessId", "0x0"), _d("ProcessName", "-"),
        _d("IpAddress", ip), _d("IpPort", str(rnd.randint(30000, 65000))),
    ])
    return WIN_EVENT_TMPL.format(eid=4624, task=12544,
                                 keywords="0x8020000000000000",
                                 procid=rnd.randint(600, 2000),
                                 threadid=rnd.randint(1000, 20000), data=data)


def win_special_privileges(rnd) -> str:
    user = rnd.choice(USERS_WIN + ["Administrator"])
    data = "".join([
        _d("SubjectUserSid", f"S-1-5-21-780672331-3256254420-2915116740-"
                             f"{rnd.randint(1001, 1999)}"),
        _d("SubjectUserName", user), _d("SubjectDomainName", WIN_DOMAIN),
        _d("SubjectLogonId", f"0x{rnd.randint(0x100000, 0xffffff):x}"),
        _d("PrivilegeList", "SeSecurityPrivilege\n\t\t\tSeTakeOwnershipPrivilege"
                            "\n\t\t\tSeDebugPrivilege\n\t\t\tSeBackupPrivilege"),
    ])
    return WIN_EVENT_TMPL.format(eid=4672, task=12548,
                                 keywords="0x8020000000000000",
                                 procid=rnd.randint(600, 2000),
                                 threadid=rnd.randint(1000, 20000), data=data)


def win_user_added(rnd) -> str:
    user = rnd.choice(["backdoor", "svc_temp", "helpdesk2"])
    data = "".join([
        _d("TargetUserName", user), _d("TargetDomainName", WIN_DOMAIN),
        _d("TargetSid", f"S-1-5-21-780672331-3256254420-2915116740-"
                        f"{rnd.randint(2000, 2999)}"),
        _d("SubjectUserSid", "S-1-5-18"), _d("SubjectUserName", "Administrator"),
        _d("SubjectDomainName", WIN_DOMAIN),
        _d("SubjectLogonId", f"0x{rnd.randint(0x100000, 0xffffff):x}"),
        _d("PrivilegeList", "-"), _d("SamAccountName", user),
    ])
    return WIN_EVENT_TMPL.format(eid=4720, task=13824,
                                 keywords="0x8020000000000000",
                                 procid=rnd.randint(600, 2000),
                                 threadid=rnd.randint(1000, 20000), data=data)


def win_logoff(rnd) -> str:
    """4634 - an account was logged off. Pairs with 4624 so session activity
    looks balanced rather than showing logons that never end."""
    user = rnd.choice(USERS_WIN)
    data = "".join([
        _d("TargetUserSid", f"S-1-5-21-780672331-3256254420-2915116740-"
                            f"{rnd.randint(1001, 1099)}"),
        _d("TargetUserName", user), _d("TargetDomainName", WIN_DOMAIN),
        _d("TargetLogonId", f"0x{rnd.randint(0x100000, 0xffffff):x}"),
        _d("LogonType", str(rnd.choice([3, 10]))),
    ])
    return WIN_EVENT_TMPL.format(eid=4634, task=12545,
                                 keywords="0x8020000000000000",
                                 procid=rnd.randint(600, 2000),
                                 threadid=rnd.randint(1000, 20000), data=data)


def gen_windows(n_per_group: int) -> dict[str, list[str]]:
    rnd = random.Random(4321)
    return {
        "windows-authentication-failure": [win_failed_logon(rnd)
                                           for _ in range(n_per_group)],
        "windows-logged-in": [win_success_logon(rnd) for _ in range(n_per_group)],
        "windows-special-privileges-assigned": [win_special_privileges(rnd)
                                                for _ in range(n_per_group)],
        "windows-user-modified": [win_user_added(rnd)
                                  for _ in range(max(2, n_per_group // 4))],
        "windows-logged-out": [win_logoff(rnd)
                               for _ in range(max(2, n_per_group // 2))],
    }


def gen(platform: str, n_per_group: int) -> dict[str, list[str]]:
    if platform == "windows":
        return gen_windows(n_per_group)
    p = PLATFORM[platform]
    rnd = random.Random(1234)  # deterministic: same seed, same corpus
    out: dict[str, list[str]] = {}

    def pid() -> int:
        return rnd.randint(400, 99999)

    # --- authentication failures -------------------------------------
    fails = []
    for _ in range(n_per_group):
        u, ip, port = rnd.choice(ATTACK_USERS), rnd.choice(ATTACK_IPS), rnd.randint(30000, 65000)
        fails.append(rnd.choice([
            f"sshd[{pid()}]: Failed password for invalid user {u} from {ip} port {port} ssh2",
            f"sshd[{pid()}]: Failed password for {u} from {ip} port {port} ssh2",
            f"sshd[{pid()}]: Invalid user {u} from {ip} port {port}",
            f"sshd[{pid()}]: error: maximum authentication attempts exceeded for "
            f"invalid user {u} from {ip} port {port} ssh2 [preauth]",
            f"sshd[{pid()}]: Disconnecting invalid user {u} {ip} port {port}: "
            f"Too many authentication failures [preauth]",
        ]))
    out[f"{platform}-authentication-failure"] = fails

    # --- sudo, successful and failed ---------------------------------
    sudos = []
    for _ in range(n_per_group):
        u, cmd = rnd.choice(p["users"]), rnd.choice(p["cmds"])
        sudos.append(rnd.choice([
            f"sudo[{pid()}]:  {u} : TTY={p['tty']} ; PWD={p['home']}/{u} ; "
            f"USER=root ; COMMAND={cmd}",
            f"sudo[{pid()}]:  {u} : 1 incorrect password attempt ; TTY={p['tty']} ; "
            f"PWD={p['home']}/{u} ; USER=root ; COMMAND={cmd}",
            f"sudo[{pid()}]:  {u} : 3 incorrect password attempts ; TTY={p['tty']} ; "
            f"PWD={p['home']}/{u} ; USER=root ; COMMAND={cmd}",
        ]))
    out[f"{platform}-sudo"] = sudos

    # --- successful logins -------------------------------------------
    ins = []
    for _ in range(n_per_group):
        u, ip, port = rnd.choice(p["users"]), rnd.choice(ATTACK_IPS), rnd.randint(30000, 65000)
        ins.append(rnd.choice([
            f"sshd[{pid()}]: Accepted password for {u} from {ip} port {port} ssh2",
            f"sshd[{pid()}]: Accepted publickey for {u} from {ip} port {port} ssh2: "
            f"RSA SHA256:{''.join(rnd.choice('abcdef0123456789') for _ in range(20))}",
        ]))
    out[f"{platform}-logged-in"] = ins

    outs = [f"sshd[{pid()}]: Received disconnect from "
            f"{rnd.choice(ATTACK_IPS)} port {rnd.randint(30000, 65000)}:11: "
            f"disconnected by user" for _ in range(n_per_group)]
    out[f"{platform}-logged-out"] = outs

    # --- account manipulation ----------------------------------------
    mods = []
    for _ in range(max(2, n_per_group // 4)):
        u = rnd.choice(["backdoor", "svc-temp", "helpdesk"])
        mods.append(rnd.choice([
            f"useradd[{pid()}]: new user: name={u}, UID={rnd.randint(1001, 1999)}, "
            f"GID=20, home={p['home']}/{u}, shell=/bin/zsh",
            f"usermod[{pid()}]: add '{u}' to group 'admin'",
        ]))
    out[f"{platform}-user-modified"] = mods

    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--outdir", type=Path, required=True)
    ap.add_argument("--platform", choices=sorted(PLATFORM), default="macos")
    ap.add_argument("--count", type=int, default=40,
                    help="Lines per group (default: %(default)s)")
    ap.add_argument("--merge", action="store_true",
                    help="Add to an existing corpus instead of refusing")
    args = ap.parse_args()

    evdir = args.outdir / "events"
    if evdir.exists() and not args.merge:
        existing = list(evdir.glob(f"{args.platform}-*.jsonl"))
        if existing:
            sys.exit(f"{evdir} already has {args.platform} groups. "
                     f"Use --merge, or pick a different --outdir.")
    evdir.mkdir(parents=True, exist_ok=True)

    groups = gen(args.platform, args.count)
    total = 0
    for group, bodies in sorted(groups.items()):
        action = group.split("-", 1)[1]
        path = evdir / f"{group}.jsonl"
        with path.open("a" if args.merge else "w", encoding="utf-8") as fh:
            for body in bodies:
                # Player strips the envelope and rebuilds it per platform, so a
                # placeholder timestamp and host are fine here.
                original = body if args.platform == "windows" \
                    else f"Jan  1 00:00:00 seed {body}"
                fh.write(json.dumps({
                    "original": original,
                    "action": action,
                    "platform": args.platform,
                    "synthetic": True,
                }) + "\n")
        total += len(bodies)
        print(f"  {group:<40} {len(bodies):>4} lines")

    mf = args.outdir / "manifest.json"
    meta = {}
    if mf.exists():
        try:
            meta = json.loads(mf.read_text())
        except Exception:
            meta = {}
    meta.setdefault("synthetic", {})[args.platform] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "groups": {g: len(v) for g, v in groups.items()},
        "note": "Fabricated log lines. The alerts they produce are real; the "
                "lines themselves were not recorded from a host.",
    }
    mf.write_text(json.dumps(meta, indent=2))

    print(f"\nWrote {total} synthetic {args.platform} lines to {evdir}")
    print("These are FABRICATED lines. The alerts they raise are genuine, but "
          "the log lines were not recorded from a real host -- say so if anyone "
          "asks during a demo.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
