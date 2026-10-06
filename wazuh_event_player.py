#!/usr/bin/env python3
"""
wazuh_event_player.py

Replays harvested log lines through the manager's POST /stateless endpoint, so
Wazuh's own decoder chain processes them and produces real alerts for
simulated agents.

The alerts are genuine: field extraction, classification and rule metadata all
come from the manager. Only the input line is recycled, and it was real.

Wire format (from remoted_module/src/endpoints/statelessEndpoint.cpp):

    Content-Type: application/x-ndjson
    protocol-version: 1
    Authorization: Bearer <wazuh-agent+jwt>

    H {"wazuh":{"agent":{"id":"015",...},"protocol":{"queue":49,"location":"macos"}}}
    E 1:macos:<raw log line>
    E 1:macos:<raw log line>

The "1:<location>:" prefix on each E line is REQUIRED. Without it analysisd
rejects the batch with "event must be at least 5 bytes". The endpoint returns
202 either way — it only acknowledges receipt — so check
/var/wazuh-manager/logs/wazuh-manager.log when debugging.

The H-line's /wazuh/agent/id must equal the token's agent, or the request is
rejected as a payload mismatch.

Usage:
  # ambient background activity, one small batch every 30s
  python3 wazuh_event_player.py --state agents/macos-demo.json \
      --events ./events --profile macos --loop 30

  # one batch and exit, to check it works
  python3 wazuh_event_player.py --state agents/macos-demo.json \
      --events ./events --profile macos --once

  # a named scenario, on demand
  python3 wazuh_event_player.py --state agents/macos-demo.json \
      --events ./events --profile macos --scenario brute-force
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import signal
import sys
import time
import urllib3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROTOCOL_VERSION = "1"

# 56 ("8") is syscheck's own queue, distinct from 49 used by logcollector. FIM
# change events are JSON, sent as one E-line whose payload after the prefix is
# the document itself rather than a text log line. This is what
# decoder/wazuh-fim/0 consumes; confirmed against a real agent's own alert,
# which carries wazuh.protocol.location == "syscheck", queue == 56.
FIM_QUEUE = 56
FIM_LOCATION = "syscheck"

# The queue number is part of the wire format: the E-line is prefixed with
# "<chr(queue)>:<location>:". macOS and Linux logcollector use 49 ("1"),
# Windows EventChannel uses 102 ("f"). Sending the wrong one means the event
# is routed to the wrong decoder set and silently dropped.

try:
    from wazuh_identity import overlay_platform
except ImportError:      # an older install without the module: built-in identity only
    def overlay_platform(plat, state_path):
        return plat


# Envelope per platform: the location string used in the E-line prefix and in
# the H-line, plus how a timestamp is rendered for that platform's format.
PLATFORMS = {
    "macos": {
        "queue": 49,
        "location": "macos",
        "hostname": "MAC-demo-MacBook-Air.local",
        "architecture": "arm64",
        "tz_offset": 5.5,          # emit +0530 like the real Mac does
        "os": {"name": "macOS", "platform": "darwin",
               "type": "macos", "version": "26.7"},
    },
    "linux": {
        "queue": 49,
        "location": "journald",
        "hostname": "amazonlinux-demo",
        "architecture": "x86_64",
        "tz_offset": 0.0,
        "os": {"name": "Amazon Linux", "platform": "amzn",
               "type": "linux", "version": "2023"},
    },
    "windows": {
        "queue": 102,
        "location": "EventChannel",
        "hostname": "WIN-DEMO",
        "architecture": "x86_64",
        "tz_offset": 0.0,
        "os": {"name": "Microsoft Windows 11 Pro", "platform": "windows",
               "type": "windows", "version": "10.0.26200.9445"},
    },
}

# Content that betrays the source platform. A line replayed as macOS must not
# contain Linux-isms: an audience that knows macOS spots "pts/7", "/home/x" or
# "pam_unix(cron:session)" immediately, and Linux hosts emit CRON session
# messages that macOS simply does not produce.
IMPLAUSIBLE = {
    "macos": [
        re.compile(r"\bCRON\b"),
        re.compile(r"pam_unix\(cron:"),
        re.compile(r"TTY=pts/"),
        re.compile(r"/home/"),
        re.compile(r"systemd|journald|dbus-daemon", re.I),
        re.compile(r"\.service\b"),
        re.compile(r"/opt/wazuh-demo"),      # our own scaffolding
    ],
    "linux": [
        re.compile(r"TTY=ttys\d"),
        re.compile(r"/Users/"),
        re.compile(r"com\.apple\."),
        re.compile(r"\bloginwindow\b|\bsecurityd\b|\btccd\b"),
    ],
    "windows": [],
}


def plausible_on(body: str, platform: str) -> bool:
    """Would this log body credibly appear on the target platform?"""
    return not any(rx.search(body) for rx in IMPLAUSIBLE.get(platform, []))

# Scenarios pick from harvested groups in order. Missing groups are skipped,
# so a scenario degrades gracefully rather than failing.
# "ambient" is special-cased in build_batch: rather than demanding specific
# actions, it draws from whatever the corpus holds for the platform. A corpus
# harvested from an idle Mac has service and connection events but no logins,
# and an ambient scenario that produces nothing is worse than one that
# produces whatever is real.
SCENARIOS = {
    "ambient": [("*", 5)],
    # A distinct scenario: FIM changes are JSON sent on the syscheck queue,
    # not text lines on the platform's normal logcollector queue, so they
    # cannot be mixed into the pattern-based scenarios below.
    "fim-changes": None,
    "brute-force": [("*-authentication-failure", 8), ("*-logged-in", 1)],
    "privilege-escalation": [("*-authentication-failure", 3), ("*-sudo", 2),
                             ("*-special-privileges-assigned", 2)],
    "session-activity": [("*-logged-in", 3), ("*-logged-out", 3)],
    # Actions the ruleset actually raises findings on. Ambient traffic decodes
    # into events but usually matches no rule, so it never reaches the alerts
    # view -- this scenario exists to produce visible alerts on demand.
    "security-alerts": [
        ("*-authentication-failure", 2), ("*-sudo", 2),
        ("*-malware-detected", 2), ("*-user-modified", 1),
        ("*-special-privileges-assigned", 1), ("*-secret-accessed", 1),
        ("*-vulnerability-detected", 1), ("*-service-installed", 1),
        ("*-package-installed", 1),
    ],
}

# macOS ULS:  2026-09-18 14:27:39.303133+0530  localhost sudo[20754]: msg
ULS_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+[+-]\d{4}\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$", re.S)
# syslog:     Sep 18 10:36:36 host sshd[301470]: msg
SYSLOG_RE = re.compile(
    r"^[A-Z][a-z]{2} [ \d]?\d \d{2}:\d{2}:\d{2}\s+"
    r"(?P<host>\S+)\s+(?P<rest>.*)$", re.S)


# Windows EventChannel events are raw XML, not a prefixed text line.
WIN_XML_RE = re.compile(r"^\s*<Event\b", re.I)
WIN_TIME_RE = re.compile(r"(<TimeCreated\s+SystemTime=')([^']+)(')")
WIN_COMPUTER_RE = re.compile(r"(<Computer>)([^<]*)(</Computer>)")
WIN_RECID_RE = re.compile(r"(<EventRecordID>)(\d+)(</EventRecordID>)")


def is_windows_xml(line: str) -> bool:
    return bool(WIN_XML_RE.match(line))


def reformat_windows(line: str, hostname: str, when: datetime) -> str:
    """Retime and re-host a Windows EventChannel XML event.

    Three fields identify when and where: TimeCreated/@SystemTime (UTC with a
    7-digit fraction), <Computer>, and <EventRecordID>. The record id is
    bumped so replayed events do not collide with the originals in anything
    that de-duplicates on it.
    """
    stamp = when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") \
        + f"{when.microsecond:06d}0Z"
    out = WIN_TIME_RE.sub(lambda m: m.group(1) + stamp + m.group(3), line)
    out = WIN_COMPUTER_RE.sub(lambda m: m.group(1) + hostname + m.group(3), out)
    out = WIN_RECID_RE.sub(
        lambda m: m.group(1) + str(random.randint(10**9, 2 * 10**9)) + m.group(3),
        out)
    return out


def split_line(line: str) -> tuple[str, str] | None:
    """Split a log line into (hostname, everything-after-hostname).

    The body -- "sshd[4411]: Failed password for ..." -- is what the body
    decoders (system-auth and friends) actually parse. The leading timestamp
    and hostname belong to the transport envelope, which differs per platform.
    """
    for rx in (ULS_RE, SYSLOG_RE):
        m = rx.match(line)
        if m:
            return m.group("host"), m.group("rest")
    return None


def reformat(line: str, platform: str, hostname: str, when: datetime,
             tz_offset: float = 0.0) -> str | None:
    """Re-wrap a harvested line in the target platform's envelope.

    Retiming alone is not enough. A Linux syslog line sent with
    location=macos is handed to decoder/macos-uls/0, which expects the ULS
    timestamp shape; it fails to parse, the event becomes unclassified, and
    the policy drops it (index_unclassified_events: false). So the envelope
    has to be rebuilt, not just the clock moved.

    The body is preserved verbatim -- that is the part the auth decoders read,
    and it is identical across platforms because decoder/system-auth/0 has
    both decoder/syslog/0 and decoder/macos-uls/0 as parents.
    """
    if is_windows_xml(line):
        # XML events only make sense on Windows; there is no way to re-wrap
        # them as a Unix log line.
        if platform != "windows":
            return None
        return reformat_windows(line, hostname, when)

    if platform == "windows":
        # Conversely, a Unix text line cannot be presented as an EventChannel
        # event: decoder/windows-event/0 expects XML.
        return None

    parts = split_line(line)
    if not parts:
        return None
    _, body = parts

    if not plausible_on(body, platform):
        return None

    if platform == "macos":
        # 2026-09-18 16:09:35.545569+0530  localhost sshd[4411]: msg
        # Two spaces after the timestamp, as real ULS output has.
        tz = timezone(timedelta(hours=tz_offset))
        stamp = when.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S.%f%z")
        return f"{stamp}  {hostname} {body}"

    # Linux and Windows agents ship through decoder/syslog/0.
    tz = timezone(timedelta(hours=tz_offset))
    stamp = when.astimezone(tz).strftime("%b %e %H:%M:%S").replace("  ", " ")
    return f"{stamp} {hostname} {body}"


class Sender:
    def __init__(self, manager, port, prefix, state_path: Path, verify=False):
        self.base = f"https://{manager}:{port}{prefix.rstrip('/')}"
        self.state = json.loads(state_path.read_text())
        self.agent_id = self.state["id"]
        self.key = self.state["key"]
        self.s = requests.Session()
        self.s.verify = verify

        # Reuse the simulator's token builder so there is one implementation.
        import importlib.util
        sim = Path(__file__).resolve().parent / "wazuh_agent_sim.py"
        spec = importlib.util.spec_from_file_location("sim", sim)
        self.sim = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.sim)

    def header_line(self, plat: dict, name: str) -> str:
        return "H " + json.dumps({
            "wazuh": {
                "agent": {
                    "id": self.agent_id, "name": name, "version": "v5.0.0",
                    "groups": ["default"],
                    "host": {"architecture": plat["architecture"],
                             "hostname": plat["hostname"], "os": plat["os"]},
                },
                "cluster": {"name": "wazuh", "node": "node01"},
                "protocol": {"queue": plat["queue"],
                             "location": plat["location"]},
            }
        }, separators=(",", ":"))

    def send(self, plat: dict, name: str, lines: list[str],
             queue: int | None = None, location: str | None = None
             ) -> tuple[int, str]:
        q = queue if queue is not None else plat["queue"]
        loc = location if location is not None else plat["location"]
        body = self.header_line(plat, name) + "\n"
        for ln in lines:
            body += f"E {chr(q)}:{loc}:{ln}\n"
        try:
            r = self.s.post(
                f"{self.base}/stateless",
                data=body.encode("utf-8"),
                headers={
                    "Content-Type": "application/x-ndjson",
                    "protocol-version": PROTOCOL_VERSION,
                    "Authorization": f"Bearer "
                                     f"{self.sim.agent_token(self.agent_id, self.key)}",
                },
                timeout=20)
            return r.status_code, r.text[:200]
        except requests.RequestException as exc:
            return 0, str(exc)


def load_corpus(events_dir: Path) -> dict[str, list[dict]]:
    d = events_dir / "events"
    if not d.is_dir():
        raise SystemExit(f"No events/ directory under {events_dir}. "
                         "Run wazuh_event_harvester.py first.")
    corpus = {}
    for p in sorted(d.glob("*.jsonl")):
        rows = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
        if rows:
            corpus[p.stem] = rows
    return corpus


def pick(corpus: dict[str, list[dict]], pattern: str, n: int,
         platform: str, cross_platform: bool = False) -> list[dict]:
    """Resolve a scenario pattern against the corpus.

    Only groups harvested FROM the requested platform are used. Borrowing
    another platform's lines is off by default: a Linux sudo line replayed as
    macOS carries pam_unix(), TTY=pts/N and /home paths, which is obvious to
    anyone who knows the platform. Enable --cross-platform if you would rather
    have volume than fidelity.
    """
    if pattern == "*":
        # Rule-driven groups (wazuh_event_harvester.py --rule) hold events that
        # fire detections ON PURPOSE. Ambient traffic is meant to be quiet, so
        # they are only ever sent by name, with --scenario rule:<text>.
        groups = [g for g in corpus
                  if g.startswith(f"{platform}-") and "-rule-" not in g]
        if not groups and cross_platform:
            groups = [g for g in corpus if "-rule-" not in g]
    else:
        suffix = pattern.lstrip("*-")
        groups = [g for g in corpus if g == f"{platform}-{suffix}"]
        if not groups and cross_platform:
            groups = [g for g in corpus if g.endswith(f"-{suffix}")]

    pool: list[dict] = []
    for g in groups:
        pool.extend(corpus[g])
    return [random.choice(pool) for _ in range(n)] if pool else []


def is_fim_json(original: str) -> dict | None:
    """Harvested FIM documents are JSON, not text log lines: {"collector":
    "file"|"registry_key"|"registry_value", "module":"fim", "data": {...}}."""
    try:
        doc = json.loads(original)
    except (json.JSONDecodeError, TypeError):
        return None
    if isinstance(doc, dict) and doc.get("module") == "fim":
        return doc
    return None


def rehost_fim(doc: dict, when: datetime, tz_offset: float = 0.0,
              platform: str = "linux", rewrite_path: bool = True) -> dict:
    """Move the change timestamp forward, and rewrite the path so it looks
    native to the target platform.

    Harvested documents carry whatever path existed on the machine they were
    recorded from -- typically /opt/wazuh-demo/... from the Ubuntu manager.
    Replayed onto a Windows or macOS agent unchanged, that Unix path is an
    immediate tell that the file is not real. `file.previous` and
    `event.changed_fields` are left alone, since that detail is exactly what
    the rule needs to describe the change.
    """
    doc = json.loads(json.dumps(doc))
    tz = timezone(timedelta(hours=tz_offset))
    stamp = when.astimezone(tz).strftime("%Y-%m-%dT%H:%M:%S.") \
        + f"{when.microsecond // 1000:03d}Z"
    ev = (doc.get("data") or {}).get("event")
    if isinstance(ev, dict):
        ev["created"] = stamp

    file_ = (doc.get("data") or {}).get("file")
    if rewrite_path and isinstance(file_, dict) and file_.get("path"):
        file_["path"] = rehost_path(file_["path"], platform)
    return doc


# Filename kept as-is; only the directory convention changes per platform.
FIM_DIR = {
    "windows": r"C:\ProgramData\wazuh-demo",
    "macos": "/usr/local/wazuh-demo",
    "linux": "/opt/wazuh-demo",
}


def rehost_path(path: str, platform: str) -> str:
    """Replace a Unix directory prefix with the target platform's own
    convention, keeping the filename. A path already native to the target
    (e.g. already under C:\\ for windows) is left untouched."""
    target_dir = FIM_DIR.get(platform, "/opt/wazuh-demo")
    if platform == "windows" and "\\" in path:
        return path  # already Windows-shaped (e.g. a registry-adjacent path)
    if platform != "windows" and path.startswith(target_dir):
        return path  # already native to this platform

    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    sep = "\\" if platform == "windows" else "/"
    return f"{target_dir}{sep}{name}"


def build_fim_batch(corpus, platform: str, count: int,
                    spread_seconds: int, tz_offset: float = 0.0
                    ) -> list[str]:
    """FIM change events for security-alerts / fim-changes. Returns raw JSON
    strings ready to be queue-prefixed and sent -- these do not go through
    plausibility filtering or reformat(), since they are not text log lines.

    Collector names give away the platform outright: registry_key and
    registry_value only exist on Windows, so sending one onto a macOS or Linux
    agent is an immediate tell. Filtered here rather than relying on the
    harvested group's platform prefix, since a corpus can be merged from
    several sources.
    """
    collector_platforms = {
        "registry_key": {"windows"}, "registry_value": {"windows"},
    }

    pool = []
    for gname, rows in corpus.items():
        if "-rule-" in gname:
            continue  # rule-driven groups are only ever sent by name
        for rec in rows:
            doc = is_fim_json(rec.get("original", ""))
            if doc is None:
                continue
            allowed = collector_platforms.get(doc.get("collector"))
            if allowed and platform not in allowed:
                continue
            pool.append(doc)
    if not pool:
        return []

    now = datetime.now(timezone.utc)
    n = min(count, len(pool))
    picked = random.sample(pool, n) if n <= len(pool) else \
        [random.choice(pool) for _ in range(count)]
    out = []
    for i, doc in enumerate(picked):
        when = now - timedelta(seconds=spread_seconds * (len(picked) - i)
                               / max(1, len(picked)))
        out.append(json.dumps(rehost_fim(doc, when, tz_offset, platform),
                              separators=(",", ":")))
    return out


def build_batch(corpus, scenario: str, platform: str, hostname: str,
                spread_seconds: int, tz_offset: float = 0.0,
                cross_platform: bool = False) -> tuple[list[str], int]:
    steps = SCENARIOS.get(scenario)
    if steps is None:
        raise SystemExit(f"Unknown scenario '{scenario}'. "
                         f"Known: {', '.join(sorted(SCENARIOS))}")
    now = datetime.now(timezone.utc)
    out: list[str] = []
    picked: list[dict] = []
    # Over-pick: plausibility filtering rejects some candidates, and a batch
    # that silently shrinks to nothing looks like a broken pipeline.
    for pattern, count in steps:
        picked.extend(pick(corpus, pattern, count * 4, platform,
                           cross_platform))

    # Spread timestamps backwards so a burst looks like it happened over a
    # few seconds rather than all in the same microsecond.
    wanted = sum(c for _, c in steps)
    n = max(1, len(picked))
    dropped = 0
    for i, rec in enumerate(picked):
        if len(out) >= wanted:
            break
        when = now - timedelta(seconds=spread_seconds * (n - i) / n)
        line = reformat(rec["original"], platform, hostname, when, tz_offset)
        if line is None:
            dropped += 1
            continue
        out.append(line)
    return out, dropped


def rule_groups(corpus, text: str, platform: str,
                cross_platform: bool = False) -> list[str]:
    """Rule-driven groups, <platform>-rule-<slug>, whose slug contains `text`.

    These come from wazuh_event_harvester.py --rule. An empty `text` selects
    every rule group for the platform.
    """
    mine = [g for g in corpus if g.startswith(f"{platform}-rule-")]
    if not mine and cross_platform:
        mine = [g for g in corpus if "-rule-" in g]
    needle = text.strip().lower()
    if needle:
        mine = [g for g in mine if needle in g.split("-rule-", 1)[1].lower()]
    return sorted(mine)


def build_rule_batch(corpus, text: str, platform: str, hostname: str,
                     spread_seconds: int, tz_offset: float = 0.0,
                     count: int = 3, cross_platform: bool = False
                     ) -> tuple[list[str], list[str], int]:
    """Events harvested for a detection, ready to send.

    Returns (text_lines, fim_lines, dropped). A rule can fire on a log line OR
    on a FIM change, and the two travel differently: text goes out on the
    platform's logcollector queue, FIM JSON on the syscheck queue. So they are
    returned separately and the caller sends each its own way.

    Unlike the generic scenarios, nothing here is picked at random with
    replacement: every harvested line is a distinct trigger, so each is sent at
    most once per batch.
    """
    pool = [r for g in rule_groups(corpus, text, platform, cross_platform)
            for r in corpus[g]]
    if not pool:
        return [], [], 0
    random.shuffle(pool)

    now = datetime.now(timezone.utc)
    want = min(count, len(pool))
    registry_only = {"registry_key": {"windows"}, "registry_value": {"windows"}}
    text_lines: list[str] = []
    fim_lines: list[str] = []
    dropped = 0

    for rec in pool:
        done = len(text_lines) + len(fim_lines)
        if done >= want:
            break
        when = now - timedelta(seconds=spread_seconds * (want - done) / want)

        fim_doc = is_fim_json(rec.get("original", ""))
        if fim_doc is not None:
            allowed = registry_only.get(fim_doc.get("collector"))
            if allowed and platform not in allowed:
                dropped += 1
                continue
            # A custom FIM rule typically keys on the path itself. The group
            # was harvested from this platform, so the path is already native
            # and must reach the manager untouched; rewriting it would stop the
            # rule matching. Only a line borrowed from ANOTHER platform
            # (--cross-platform) needs its path translated.
            native = rec.get("platform") in (None, platform)
            fim_lines.append(json.dumps(
                rehost_fim(fim_doc, when, tz_offset, platform,
                           rewrite_path=not native),
                separators=(",", ":")))
            continue

        line = reformat(rec["original"], platform, hostname, when, tz_offset)
        if line is None:
            dropped += 1
            continue
        text_lines.append(line)
    return text_lines, fim_lines, dropped


# --------------------------------------------------------------- mirror ---
class IndexerTail:
    """Reads new events from a real agent as they arrive.

    Mirror mode exists because a simulated agent cannot produce a real alert:
    an alert belongs to whichever agent generated the event, and a simulated
    agent has no machine. What it can do is replay, continuously, whatever a
    real agent is producing right now -- so the simulated endpoints stay as
    active as the real ones instead of being a one-off burst.
    """

    def __init__(self, url: str, user: str, password: str, verify=False):
        self.url = url.rstrip("/")
        self.s = requests.Session()
        self.s.auth = (user, password)
        self.s.verify = verify
        self.last_ts: str | None = None

    def new_events(self, agent_id: str, lookback_min: int,
                   limit: int = 50) -> list[dict]:
        rng: dict = ({"gt": self.last_ts} if self.last_ts
                     else {"gte": f"now-{lookback_min}m"})
        body = {
            "size": limit,
            "query": {"bool": {"must": [
                {"term": {"wazuh.agent.id": agent_id}},
                {"range": {"@timestamp": rng}},
            ]}},
            "sort": [{"@timestamp": "asc"}],
            "_source": ["event.original", "event.action", "@timestamp",
                        "wazuh.integration.decoders"],
        }
        try:
            r = self.s.post(f"{self.url}/wazuh-events-v5-*/_search",
                            json=body, timeout=30)
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("hits", [])
        except requests.RequestException as exc:
            print(f"  indexer read failed: {exc}")
            return []
        if hits:
            self.last_ts = hits[-1]["_source"]["@timestamp"]
        out = []
        for h in hits:
            src = h.get("_source", {})
            original = (src.get("event") or {}).get("original")
            if original:
                out.append({"original": original,
                            "action": (src.get("event") or {}).get("action")})
        return out


def run_mirror(sender: "Sender", plat: dict, name: str, args) -> int:
    """Follow a real agent and replay its events onto the simulated one."""
    url = args.indexer_url or os.environ.get("WAZUH_INDEXER_URL")
    pw = args.indexer_pass or os.environ.get("WAZUH_INDEXER_PASS")
    user = args.indexer_user or os.environ.get("WAZUH_INDEXER_USER", "admin")
    if not (url and pw):
        sys.exit("Mirror mode needs indexer credentials: set WAZUH_INDEXER_URL "
                 "and WAZUH_INDEXER_PASS, or pass --indexer-url/--indexer-pass")

    tail = IndexerTail(url, user, pw, verify=args.verify_tls)
    print(f"mirroring agent {args.mirror} -> {sender.agent_id} ({name}), "
          f"polling every {args.loop or 60}s")

    stop = {"now": False}
    signal.signal(signal.SIGINT, lambda *a: stop.update(now=True))
    signal.signal(signal.SIGTERM, lambda *a: stop.update(now=True))

    interval = args.loop or 60
    sent = skipped = fim_sent = 0
    while not stop["now"]:
        rows = tail.new_events(args.mirror, args.mirror_lookback,
                               args.mirror_batch)
        if rows:
            now = datetime.now(timezone.utc)

            # Mirrored rows are a mix: ordinary log lines that go through
            # reformat() onto the platform's normal queue, and FIM state-change
            # JSON that reformat() can never parse -- it isn't a text line, so
            # every one of these was previously counted as "not portable" and
            # silently dropped every single poll. They need the syscheck queue
            # and rehost_fim() instead.
            lines, fim_lines = [], []
            for i, rec in enumerate(rows):
                when = now - timedelta(
                    seconds=args.spread * (len(rows) - i) / max(1, len(rows)))
                fim_doc = is_fim_json(rec["original"])
                if fim_doc is not None:
                    allowed = {"registry_key": {"windows"},
                              "registry_value": {"windows"}}.get(
                        fim_doc.get("collector"))
                    if allowed and args.profile not in allowed:
                        skipped += 1
                        continue
                    fim_lines.append(json.dumps(
                        rehost_fim(fim_doc, when, plat.get("tz_offset", 0.0),
                                  args.profile),
                        separators=(",", ":")))
                    continue
                ln = reformat(rec["original"], args.profile, plat["hostname"],
                              when, plat.get("tz_offset", 0.0))
                if ln is None:
                    skipped += 1
                else:
                    lines.append(ln)

            if lines:
                code, body = sender.send(plat, name, lines)
                if code == 202:
                    sent += len(lines)
                else:
                    print(f"  HTTP {code}: {body}")
            if fim_lines:
                code, body = sender.send(plat, name, fim_lines,
                                         queue=FIM_QUEUE, location=FIM_LOCATION)
                if code == 202:
                    fim_sent += len(fim_lines)
                else:
                    print(f"  HTTP {code} (fim): {body}")
            if lines or fim_lines:
                print(f"  mirrored {len(lines)} event(s) + {len(fim_lines)} "
                      f"FIM change(s) of {len(rows)} "
                      f"(totals: {sent} events, {fim_sent} fim, "
                      f"{skipped} not portable)")
        for _ in range(interval):
            if stop["now"]:
                break
            time.sleep(1)

    print(f"\nstopped. mirrored {sent} events, {fim_sent} FIM changes, "
          f"skipped {skipped}.")
    return 0


def scenario_arg(value: str) -> str:
    """A named scenario, or rule:<text> for events harvested for a detection."""
    if value in SCENARIOS or value.startswith("rule:"):
        return value
    raise argparse.ArgumentTypeError(
        f"invalid scenario '{value}' (choose from "
        f"{', '.join(sorted(SCENARIOS))}, or rule:<text>)")


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manager", default="10.0.44.61")
    ap.add_argument("--port", type=int, default=1517)
    ap.add_argument("--prefix", default="/wazuh-manager")
    ap.add_argument("--state", type=Path,
                    help="Agent state file, e.g. agents/macos-demo.json "
                         "(not needed with --list)")
    ap.add_argument("--events", type=Path, default=Path("./events"))
    ap.add_argument("--profile", choices=sorted(PLATFORMS), default="linux")
    ap.add_argument("--name", default=None, help="Agent name for the H-line")
    ap.add_argument("--scenario", default="ambient", type=scenario_arg,
                    metavar="SCENARIO",
                    help="One of: " + ", ".join(sorted(SCENARIOS)) + ". Or "
                         "rule:<text> to replay events harvested for a "
                         "detection (wazuh_event_harvester.py --rule); <text> "
                         "is any part of the group name, and an empty text "
                         "means every rule group for the platform.")
    ap.add_argument("--rule-count", type=int, default=3,
                    help="Events per batch for --scenario rule:<text> "
                         "(default: 3)")
    ap.add_argument("--fim-count", type=int, default=3,
                    help="FIM changes per batch for --scenario fim-changes "
                         "(default: 3)")
    ap.add_argument("--loop", type=int, default=0, metavar="SECONDS",
                    help="Repeat every N seconds. 0 = single batch.")
    ap.add_argument("--once", action="store_true", help="Same as --loop 0")
    ap.add_argument("--spread", type=int, default=20,
                    help="Spread a batch's timestamps over this many seconds")
    ap.add_argument("--mirror", metavar="AGENT_ID",
                    help="Continuously replay a REAL agent's incoming events "
                         "onto this simulated agent, so it stays as active as "
                         "the real one. Needs indexer credentials.")
    ap.add_argument("--mirror-lookback", type=int, default=15, metavar="MIN",
                    help="On the first poll, how far back to read (default 15)")
    ap.add_argument("--mirror-batch", type=int, default=50,
                    help="Max events to carry per poll (default 50)")
    ap.add_argument("--indexer-url", default=None)
    ap.add_argument("--indexer-user", default=None)
    ap.add_argument("--indexer-pass", default=None)
    ap.add_argument("--cross-platform", action="store_true",
                    help="Allow replaying another platform's harvested lines "
                         "when this platform has none. Off by default: the "
                         "content usually gives itself away.")
    ap.add_argument("--verify-tls", action="store_true")
    ap.add_argument("--list", action="store_true",
                    help="Show the harvested corpus and exit")
    args = ap.parse_args()

    corpus = load_corpus(args.events)

    if args.list:
        print("Harvested groups:")
        for g, rows in sorted(corpus.items()):
            print(f"  {g:<40} {len(rows):>5}")
        fim_total = sum(1 for g, rows in corpus.items() if "-rule-" not in g
                        for r in rows if is_fim_json(r.get("original", "")))
        print(f"\nFIM change documents (scenario 'fim-changes'): {fim_total}")
        rule_total = sum(1 for g in corpus if "-rule-" in g)
        print(f"Rule-driven groups (scenario 'rule:<text>'): {rule_total}")
        print("\nScenarios:")
        for s, steps in sorted(SCENARIOS.items()):
            shown = steps if steps is not None else "(FIM change events, see above)"
            print(f"  {s:<24} {shown}")
        return 0

    if not args.state or not args.state.exists():
        sys.exit(f"No state file: {args.state}")

    # An agent with an identity file stamps its events with THAT machine's OS, not the table's.
    plat = overlay_platform(PLATFORMS[args.profile], args.state)
    name = args.name or args.state.stem
    sender = Sender(args.manager, args.port, args.prefix, args.state,
                    verify=args.verify_tls)

    if args.mirror:
        return run_mirror(sender, plat, name, args)

    print(f"agent {sender.agent_id} ({name}, {args.profile}) "
          f"scenario '{args.scenario}'")

    stop = {"now": False}
    signal.signal(signal.SIGINT, lambda *a: stop.update(now=True))
    signal.signal(signal.SIGTERM, lambda *a: stop.update(now=True))

    sent = failed = 0
    while True:
        if args.scenario == "fim-changes":
            fim_lines = build_fim_batch(corpus, args.profile, args.fim_count,
                                        args.spread, plat.get("tz_offset", 0.0))
            if not fim_lines:
                print("  nothing to send — no FIM change documents in the "
                      "corpus. Harvest from an agent with FIM enabled.")
                return 1
            code, body = sender.send(plat, name, fim_lines,
                                     queue=FIM_QUEUE, location=FIM_LOCATION)
            if code == 202:
                sent += len(fim_lines)
                print(f"  {len(fim_lines)} FIM change(s) accepted "
                      f"(total {sent})")
            else:
                failed += 1
                print(f"  HTTP {code}: {body}")
            if args.once or not args.loop or stop["now"]:
                break
            for _ in range(args.loop):
                if stop["now"]:
                    break
                time.sleep(1)
            if stop["now"]:
                break
            continue

        if args.scenario.startswith("rule:"):
            text_lines, fim_lines, dropped = build_rule_batch(
                corpus, args.scenario[len("rule:"):], args.profile,
                plat["hostname"], args.spread, plat.get("tz_offset", 0.0),
                args.rule_count, args.cross_platform)
            if dropped:
                print(f"  {dropped} candidate(s) rejected as implausible for "
                      f"{args.profile}")
            if not text_lines and not fim_lines:
                have = rule_groups(corpus, "", args.profile,
                                   args.cross_platform)
                print(f"  nothing to send for '{args.scenario}' on "
                      f"{args.profile}.")
                if have:
                    print("  rule groups for this platform: "
                          + ", ".join(g.split("-rule-", 1)[1] for g in have))
                else:
                    print(f"  no rule groups for {args.profile}. Harvest some "
                          f"from a real {args.profile} agent that has "
                          f"triggered the rule:")
                    print('    python3 wazuh_event_harvester.py --rule "<title '
                          'prefix>" --agents <real agent id>')
                return 1
            if text_lines:
                code, body = sender.send(plat, name, text_lines)
                if code == 202:
                    sent += len(text_lines)
                    print(f"  {len(text_lines)} rule event(s) accepted")
                else:
                    failed += 1
                    print(f"  HTTP {code}: {body}")
            if fim_lines:
                code, body = sender.send(plat, name, fim_lines,
                                         queue=FIM_QUEUE, location=FIM_LOCATION)
                if code == 202:
                    sent += len(fim_lines)
                    print(f"  {len(fim_lines)} rule FIM change(s) accepted")
                else:
                    failed += 1
                    print(f"  HTTP {code}: {body}")
            if args.once or not args.loop or stop["now"]:
                break
            for _ in range(args.loop):
                if stop["now"]:
                    break
                time.sleep(1)
            if stop["now"]:
                break
            continue

        lines, dropped = build_batch(corpus, args.scenario, args.profile,
                                     plat["hostname"], args.spread,
                                     plat.get("tz_offset", 0.0),
                                     args.cross_platform)
        if dropped:
            print(f"  {dropped} candidate(s) rejected as implausible for "
                  f"{args.profile} or unparseable")
        if not lines:
            print(f"  nothing to send for scenario '{args.scenario}' on "
                  f"{args.profile}.")
            groups = sorted(g for g in corpus if g.startswith(f"{args.profile}-"))
            if groups:
                print("  this corpus holds: " + ", ".join(
                    f"{g} ({len(corpus[g])})" for g in groups))
                print("  try --scenario ambient, which uses any of them.")
            else:
                print(f"  no {args.profile} lines at all. Harvest from a real "
                      f"{args.profile} host: "
                      f"wazuh_event_harvester.py --agents <id> --decoder ''")
            return 1
        code, body = sender.send(plat, name, lines)
        if code == 202:
            sent += len(lines)
            print(f"  {len(lines)} lines accepted  (total {sent})")
        else:
            failed += 1
            print(f"  HTTP {code}: {body}")

        if not args.loop or args.once or stop["now"]:
            break
        for _ in range(args.loop):
            if stop["now"]:
                break
            time.sleep(1)
        if stop["now"]:
            break

    if sent:
        print(f"\n{sent} lines sent. 202 means accepted, not decoded — "
              f"check the manager log and the events index to confirm.")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
