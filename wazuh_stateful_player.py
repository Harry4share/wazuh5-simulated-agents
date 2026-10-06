#!/usr/bin/env python3
"""
wazuh_stateful_player.py

Replays module state documents (FIM file and registry changes, syscollector
deltas) to the manager's POST /wazuh-manager/stateful endpoint, so the manager
applies them and raises real alerts.

Why a separate player: the manager takes two kinds of input through two
different doors.

  /stateless  things that HAPPENED   plain log lines   -> wazuh_event_player.py
  /stateful   things that ARE        FlatBuffer state  -> this script

FIM change events are state, not log lines, which is why replaying them through
/stateless silently drops them. The body is a Message{FullSession} FlatBuffer
described by inventorySync.fbs; wazuh_syncschema.py builds it.

The harvested corpus already contains these documents. They look like:

    {"collector":"file","module":"fim","data":{"event":{"type":"modified"},...}}
    {"collector":"registry_value","module":"fim","data":{...}}
    {"collector":"dbsync_packages","data":{...}}

Usage:
  # what is replayable in the corpus, and where each group would be sent
  python3 wazuh_stateful_player.py --events ./events --list

  # one FIM batch for a simulated agent
  python3 wazuh_stateful_player.py --state agents/macos-demo.json \
      --events ./events --profile macos --module fim --once

  # keep file activity flowing
  python3 wazuh_stateful_player.py --state agents/macos-demo.json \
      --events ./events --profile macos --module fim --loop 120

Note the manager's response IS the session result — unlike /stateless, a
non-2xx here tells you the session was rejected, so failures are visible.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import random
import re
import signal
import sys
import time
import urllib3
from datetime import datetime, timezone
from pathlib import Path

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HERE = Path(__file__).resolve().parent

_spec = importlib.util.spec_from_file_location(
    "syncschema", HERE / "wazuh_syncschema.py")
fbs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fbs)

PROTOCOL_VERSION = "1"

# Which index a document belongs in, by its declared collector. The Start table
# has to name the indices the session touches, and each DataValue names its own.
COLLECTOR_INDEX = {
    "file": "wazuh-states-fim-files",
    "registry_key": "wazuh-states-fim-registry-keys",
    "registry_value": "wazuh-states-fim-registry-values",
    "dbsync_packages": "wazuh-states-inventory-packages",
    "dbsync_processes": "wazuh-states-inventory-processes",
    "dbsync_ports": "wazuh-states-inventory-ports",
    "dbsync_users": "wazuh-states-inventory-users",
    "dbsync_groups": "wazuh-states-inventory-groups",
    "dbsync_services": "wazuh-states-inventory-services",
    "dbsync_hotfixes": "wazuh-states-inventory-hotfixes",
    "dbsync_network_iface": "wazuh-states-inventory-interfaces",
    "dbsync_network_address": "wazuh-states-inventory-networks",
    "dbsync_network_protocol": "wazuh-states-inventory-protocols",
    "dbsync_browser_extensions": "wazuh-states-inventory-browser-extensions",
    "dbsync_osinfo": "wazuh-states-inventory-system",
    "dbsync_hwinfo": "wazuh-states-inventory-hardware",
}

try:
    from wazuh_identity import overlay_platform
except ImportError:      # an older install without the module: built-in identity only
    def overlay_platform(plat, state_path):
        return plat


PLATFORMS = {
    "macos": {"hostname": "MAC-demo-MacBook-Air.local", "architecture": "arm64",
              "os": {"name": "macOS", "platform": "darwin",
                     "type": "macos", "version": "26.7"}},
    "linux": {"hostname": "amazonlinux-demo", "architecture": "x86_64",
              "os": {"name": "Amazon Linux", "platform": "amzn",
                     "type": "linux", "version": "2023"}},
    "windows": {"hostname": "WIN-DEMO", "architecture": "x86_64",
                "os": {"name": "Microsoft Windows 11 Pro",
                       "platform": "windows", "type": "windows",
                       "version": "10.0.26200.9445"}},
}

# Collectors that only exist on one platform. Windows registry monitoring has
# no equivalent on macOS or Linux, so replaying a registry document onto a Mac
# is immediately wrong to anyone reading the alert.
COLLECTOR_PLATFORM = {
    "registry_key": {"windows"},
    "registry_value": {"windows"},
    "dbsync_hotfixes": {"windows"},
}

# Which module owns each collector, for the Start table. A session declares one
# module, so batches are built per module rather than mixed.
COLLECTOR_MODULE = {
    "file": "fim", "registry_key": "fim", "registry_value": "fim",
}

# Paths that would look wrong on the target platform, same principle as the
# stateless player's plausibility filter.
IMPLAUSIBLE_PATH = {
    "macos": re.compile(r"^/(home|proc|sys)/|/systemd/|\.service$|\.deb$|"
                        r"^/var/log/(syslog|dpkg)|C:\\\\", re.I),
    "linux": re.compile(r"^/(Users|System|Library|Applications)/|"
                        r"C:\\\\|com\.apple\.", re.I),
    "windows": re.compile(r"^/(home|Users|etc|var)/", re.I),
}


def load_json_corpus(events_dir: Path) -> dict[str, list[dict]]:
    """Corpus entries whose event.original is a module state document."""
    d = events_dir / "events"
    if not d.is_dir():
        raise SystemExit(f"No events/ under {events_dir}. Harvest first.")
    out: dict[str, list[dict]] = {}
    for path in sorted(d.glob("*.jsonl")):
        if "-rule-" in path.stem:
            continue  # rule-driven groups are only ever sent by name
        rows = []
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
                doc = json.loads(rec["original"])
            except (json.JSONDecodeError, KeyError, TypeError):
                continue  # a log line, not a state document
            if not isinstance(doc, dict) or "collector" not in doc:
                continue
            rec["doc"] = doc
            rows.append(rec)
        if rows:
            out[path.stem] = rows
    return out


def doc_path(doc: dict) -> str:
    data = doc.get("data") or {}
    for key in ("file", "registry", "package", "process"):
        node = data.get(key)
        if isinstance(node, dict):
            for field in ("path", "name", "key"):
                if node.get(field):
                    return str(node[field])
    return ""


def module_of(doc: dict) -> str:
    return doc.get("module") or COLLECTOR_MODULE.get(
        doc.get("collector", ""), "syscollector")


def plausible(doc: dict, platform: str) -> bool:
    collector = doc.get("collector", "")
    allowed = COLLECTOR_PLATFORM.get(collector)
    if allowed and platform not in allowed:
        return False
    rx = IMPLAUSIBLE_PATH.get(platform)
    p = doc_path(doc)
    return not (rx and p and rx.search(p))


def mutate(doc: dict) -> dict:
    """Make the document differ from whatever is already stored.

    FIM raises an alert on a *change*: the manager compares incoming state with
    what it holds and reports the difference. Replaying an identical document
    is a no-op, so a file that should look modified needs a new size, mtime and
    hashes — exactly what a real edit would produce.
    """
    data = doc.get("data")
    if not isinstance(data, dict):
        return doc
    for key in ("file", "registry", "registry_value"):
        node = data.get(key)
        if not isinstance(node, dict):
            continue
        if isinstance(node.get("size"), int):
            node["size"] = max(1, node["size"] + random.randint(-64, 256))
        if node.get("mtime"):
            node["mtime"] = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z")
        h = node.get("hash")
        if isinstance(h, dict):
            seed = f"{node.get('path','')}{time.time()}{random.random()}".encode()
            if "md5" in h:
                h["md5"] = hashlib.md5(seed).hexdigest()
            if "sha1" in h:
                h["sha1"] = hashlib.sha1(seed).hexdigest()
            if "sha256" in h:
                h["sha256"] = hashlib.sha256(seed).hexdigest()
        ck = data.get("checksum")
        if isinstance(ck, dict) and isinstance(ck.get("hash"), dict):
            ck["hash"]["sha1"] = hashlib.sha1(seed).hexdigest()
    return doc


# Filename kept as-is; only the directory convention changes per platform.
# Shared convention with wazuh_event_player.py's rehost_path, so a file's
# baseline (here) and its later "modified" alert (there) name the same path.
FIM_DIR = {
    "windows": r"C:\ProgramData\wazuh-demo",
    "macos": "/usr/local/wazuh-demo",
    "linux": "/opt/wazuh-demo",
}


def rehost_path(path: str, platform: str) -> str:
    target_dir = FIM_DIR.get(platform, "/opt/wazuh-demo")
    if platform == "windows" and "\\" in path:
        return path
    if platform != "windows" and path.startswith(target_dir):
        return path
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    sep = "\\" if platform == "windows" else "/"
    return f"{target_dir}{sep}{name}"


def retime(doc: dict, when: datetime, platform: str = "linux") -> dict:
    """Move the document's observation times to now, and rewrite the file path
    to match the target platform's own filesystem convention.

    Only the observation timestamp is rewritten -- an mtime or a package
    install date is part of the observed data and is left alone. The path
    IS rewritten: a harvested document carries whatever path it had on the
    machine it was recorded from (typically /opt/wazuh-demo/... from the
    Ubuntu manager), and left unchanged that is an immediate tell on a
    Windows or macOS agent.
    """
    stamp = when.strftime("%Y-%m-%dT%H:%M:%S.") + f"{when.microsecond // 1000:03d}Z"
    data = doc.get("data")
    if isinstance(data, dict):
        ev = data.get("event")
        if isinstance(ev, dict) and "created" in ev:
            ev["created"] = stamp
        st = data.get("state")
        if isinstance(st, dict) and "modified_at" in st:
            st["modified_at"] = stamp
        file_ = data.get("file")
        if isinstance(file_, dict) and file_.get("path"):
            file_["path"] = rehost_path(file_["path"], platform)
    return doc


def doc_id_for(doc: dict) -> str:
    """Deterministic id so replaying the same item updates it in place.

    NOT prefixed with wazuh_<agent>_: the manager adds that itself from the
    authenticated identity. Prefixing here produces ids like
    wazuh_016_wazuh_016_<sha1>.
    """
    basis = f"{doc.get('collector','')}|{doc_path(doc)}".encode("utf-8")
    return hashlib.sha1(basis).hexdigest()


class StatefulSender:
    def __init__(self, manager: str, port: int, prefix: str, state_path: Path,
                 verify=False):
        self.base = f"https://{manager}:{port}{prefix.rstrip('/')}"
        st = json.loads(state_path.read_text())
        self.agent_id, self.key = st["id"], st["key"]
        self.s = requests.Session()
        self.s.verify = verify

        spec = importlib.util.spec_from_file_location(
            "sim", HERE / "wazuh_agent_sim.py")
        self.sim = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.sim)

    def send(self, buf: bytes) -> tuple[int, str]:
        try:
            r = self.s.post(
                f"{self.base}/stateful",
                data=buf,
                headers={
                    "Content-Type": "application/octet-stream",
                    "protocol-version": PROTOCOL_VERSION,
                    "Authorization":
                        f"Bearer {self.sim.agent_token(self.agent_id, self.key)}",
                },
                timeout=60)
            return r.status_code, r.text[:300]
        except requests.RequestException as exc:
            return 0, str(exc)


# The state indices use strict dynamic mapping: a single field the mapping does
# not define rejects the whole bulk operation, and the session fails with a bare
# HTTP 500. So rather than removing known-bad fields, keep only known-good ones.
#
# These lists are the field sets of documents the manager itself indexed,
# obtained from a live index:
#
#   GET wazuh-states-fim-files/_mapping
#
# `wazuh.*` is deliberately absent: the manager fills it in from the
# authenticated identity, and an agent cannot set it.
ALLOWED_FIELDS = {
    "wazuh-states-fim-files": {
        "checksum": {"hash"},
        "file": {"device", "gid", "group", "hash", "inode", "mtime", "owner",
                 "path", "permissions", "size", "uid"},
        "state": {"document_version", "modified_at"},
    },
    "wazuh-states-fim-registry-keys": {
        "checksum": {"hash"},
        "registry": {"architecture", "gid", "group", "hive", "key", "mtime",
                     "owner", "path", "permissions", "uid"},
        "state": {"document_version", "modified_at"},
    },
    "wazuh-states-fim-registry-values": {
        "checksum": {"hash"},
        "registry": {"architecture", "data", "hive", "key", "path", "value"},
        "state": {"document_version", "modified_at"},
    },
}


def prune_to_mapping(inner: dict, index: str) -> dict:
    """Keep only fields the index mapping defines.

    Unknown indices are passed through unchanged, so adding a collector does
    not require updating this table first — it will simply fail loudly the
    first time, with the manager naming the offending field.
    """
    allowed = ALLOWED_FIELDS.get(index)
    if not allowed:
        return inner

    out: dict = {}
    for top, value in inner.items():
        if top not in allowed:
            continue
        if isinstance(value, dict):
            kept = {k: v for k, v in value.items() if k in allowed[top]}
            if kept:
                out[top] = kept
        else:
            out[top] = value
    return out


def payload_for(doc: dict, style: str, index: str) -> dict:
    """What goes into DataValue.data.

    The harvested event.original is the agent's whole message, including the
    collector/module envelope and change-only detail such as the previous
    state of a modified file. Only the inner document, pruned to the fields the
    index actually defines, is accepted.
    """
    if style == "full":
        return doc
    inner = doc.get("data")
    if not isinstance(inner, dict):
        return doc
    if style == "raw":
        return inner
    return prune_to_mapping(inner, index)


def baseline_path(events_dir: Path, agent_id: str) -> Path:
    return events_dir / f".baseline-{agent_id}.json"


def load_baseline(events_dir: Path, agent_id: str) -> list[str]:
    f = baseline_path(events_dir, agent_id)
    if not f.exists():
        return []
    try:
        return json.loads(f.read_text())
    except Exception:
        return []


def save_baseline(events_dir: Path, agent_id: str, keys: list[str]) -> None:
    try:
        baseline_path(events_dir, agent_id).write_text(json.dumps(keys))
    except OSError:
        pass


def doc_key(doc: dict) -> str:
    return f"{doc.get('collector','')}|{doc_path(doc)}"


def build_batch(corpus, module: str, platform: str, agent: dict,
                count: int, cluster: str, payload_style: str = "inner",
                change: bool = False,
                events_dir: Path | None = None) -> tuple[bytes | None, dict]:
    pool = []
    for rows in corpus.values():
        for rec in rows:
            doc = rec["doc"]
            if module != "all" and module_of(doc) != module:
                continue
            if doc.get("collector") not in COLLECTOR_INDEX:
                continue
            if not plausible(doc, platform):
                continue
            pool.append(doc)

    stats = {"available": len(pool), "sent": 0, "indices": [], "module": module}
    if not pool:
        return None, stats

    # A FullSession declares a single module in Start, so never mix them.
    if module == "all":
        by_module: dict[str, list[dict]] = {}
        for d in pool:
            by_module.setdefault(module_of(d), []).append(d)
        chosen = max(by_module.items(), key=lambda kv: len(kv[1]))
        session_module, pool = chosen[0], chosen[1]
    else:
        session_module = module
        pool = [d for d in pool if module_of(d) == session_module]
    if not pool:
        return None, stats
    stats["module"] = session_module

    now = datetime.now(timezone.utc)

    # A FIM alert is raised on a DIFFERENCE between stored and incoming state.
    # Sending a file the manager has never seen creates state and raises
    # nothing, so --change has to revisit files this agent already sent rather
    # than picking fresh ones at random.
    if change and events_dir is not None:
        wanted = set(load_baseline(events_dir, agent["id"]))
        known = [d for d in pool if doc_key(d) in wanted]
        if known:
            pool = known
        else:
            stats["note"] = ("no baseline for this agent yet — send a batch "
                             "without --change first, then repeat with it")

    picked = [random.choice(pool) for _ in range(min(count, max(1, len(pool))))]
    # de-duplicate: the same file twice in one session is pointless
    seen_keys, unique = set(), []
    for d in picked:
        k = doc_key(d)
        if k not in seen_keys:
            seen_keys.add(k)
            unique.append(d)
    picked = unique

    if events_dir is not None and not change:
        save_baseline(events_dir, agent["id"], sorted(seen_keys))

    documents, indices = [], set()
    for doc in picked:
        stable_id = doc_id_for(doc)  # from the ORIGINAL path, before rehosting
        doc = retime(json.loads(json.dumps(doc)), now, platform)
        if change:
            doc = mutate(doc)
        index = COLLECTOR_INDEX[doc["collector"]]
        indices.add(index)
        documents.append({
            "id": stable_id,
            "index": index,
            "version": 1,
            "data": payload_for(doc, payload_style, index),
        })

    stats["sent"] = len(documents)
    stats["indices"] = sorted(indices)

    buf = fbs.build_session(
        module=session_module,
        indices=sorted(indices),
        agent=agent,
        documents=documents,
        mode=fbs.Mode.ModuleDelta,
        option=fbs.Option.Sync,
        cluster_name=cluster,
    )
    return buf, stats


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--manager", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=1517)
    ap.add_argument("--prefix", default="/wazuh-manager")
    ap.add_argument("--state", type=Path, help="Agent state file")
    ap.add_argument("--events", type=Path, default=Path("./events"))
    ap.add_argument("--profile", choices=sorted(PLATFORMS), default="linux")
    ap.add_argument("--name", default=None)
    ap.add_argument("--module", default="fim",
                    help="Module to replay: fim, or 'all' (default: fim)")
    ap.add_argument("--count", type=int, default=5,
                    help="Documents per batch (default: 5)")
    ap.add_argument("--cluster", default="wazuh")
    ap.add_argument("--loop", type=int, default=0, metavar="SECONDS")
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--change", action="store_true",
                    help="Alter size, mtime and hashes so the document differs "
                         "from what is stored. Without this a replay is a no-op "
                         "and raises no FIM alert.")
    ap.add_argument("--payload", choices=["inner", "raw", "full"],
                    default="inner",
                    help="What to put in DataValue.data. inner (default): the "
                         "inner document pruned to the index mapping; raw: the "
                         "inner document untouched; full: the whole envelope. "
                         "Only 'inner' is accepted by strict mappings.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Build the buffer and show what it contains, send nothing")
    ap.add_argument("--list", action="store_true",
                    help="Show replayable documents by collector, then exit")
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    corpus = load_json_corpus(args.events)

    if args.list:
        by_collector: dict[str, int] = {}
        by_module: dict[str, int] = {}
        for rows in corpus.values():
            for rec in rows:
                c = rec["doc"].get("collector", "?")
                m = rec["doc"].get("module", "(none)")
                by_collector[c] = by_collector.get(c, 0) + 1
                by_module[m] = by_module.get(m, 0) + 1
        if not by_collector:
            print("No state documents in this corpus — only log lines.")
            print("Harvest again; FIM and syscollector documents appear in "
                  "groups like *-modified, *-created and *-package-installed.")
            return 1
        print("By module:")
        for m, n in sorted(by_module.items(), key=lambda kv: -kv[1]):
            print(f"  {m:<24} {n:>6}")
        print("\nBy collector, and where each is sent:")
        for c, n in sorted(by_collector.items(), key=lambda kv: -kv[1]):
            target = COLLECTOR_INDEX.get(c, "-- not mapped, will be skipped --")
            print(f"  {c:<26} {n:>6}  -> {target}")
        return 0

    if not args.state or not args.state.exists():
        sys.exit("--state is required (path to agents/<name>.json)")

    plat = overlay_platform(PLATFORMS[args.profile], args.state)
    name = args.name or args.state.stem
    sender = StatefulSender(args.manager, args.port, args.prefix, args.state,
                            verify=args.verify_tls)
    agent = {"id": sender.agent_id, "name": name, "version": "v5.0.0",
             "groups": ["default"], "host": plat}

    print(f"agent {sender.agent_id} ({name}, {args.profile}) "
          f"module '{args.module}'")

    stop = {"now": False}
    signal.signal(signal.SIGINT, lambda *a: stop.update(now=True))
    signal.signal(signal.SIGTERM, lambda *a: stop.update(now=True))

    total = 0
    while True:
        buf, stats = build_batch(corpus, args.module, args.profile, agent,
                                 args.count, args.cluster, args.payload,
                                 args.change, args.events)
        if stats.get("note"):
            print(f"  note: {stats['note']}")
        if buf is None:
            print(f"  nothing to send: no '{args.module}' state documents "
                  f"plausible on {args.profile}")
            print("  try --list to see what the corpus holds")
            return 1

        if args.dry_run:
            parsed = fbs.parse_session(buf)
            print(f"  buffer {len(buf)} bytes, {stats['sent']} documents")
            print(f"  indices: {', '.join(stats['indices'])}")
            print(f"  start.agentid={parsed['start']['agentid']} "
                  f"module={parsed['start']['module']} "
                  f"hostname={parsed['start']['hostname']}")
            for v in parsed["values"][:3]:
                doc = json.loads(v["data"])
                print(f"    {v['index']}  id={v['id'][-12:]}  "
                      f"{json.dumps(doc)[:100]}")
            return 0

        code, body = sender.send(buf)
        if 200 <= code < 300:
            total += stats["sent"]
            what = "modified" if args.change else "recorded"
            print(f"  {stats['sent']} documents {what} "
                  f"({', '.join(stats['indices'])}) — total {total}")
            if not args.change:
                print("  baseline saved; run again with --change to modify "
                      "these same files and raise FIM alerts")
        else:
            print(f"  HTTP {code}: {body}")
            if code in (400, 413, 500):
                print("  the session was rejected — the body above is the "
                      "manager's own session result")

        if args.once or not args.loop or stop["now"]:
            break
        for _ in range(args.loop):
            if stop["now"]:
                break
            time.sleep(1)
        if stop["now"]:
            break

    return 0


if __name__ == "__main__":
    sys.exit(main())
