#!/usr/bin/env python3
"""
wazuh_fixture_player.py

Replays fixtures captured by wazuh_fixture_recorder.py back into the Wazuh 5.x
indexer, with refreshed timestamps, so IT Hygiene and Vulnerability Detection
stay populated for agents that are no longer running.

What it does NOT do: agent connection status. In Wazuh 5.x the dashboard reads
agent status from the manager API (port 55000), not from the indexer, so a
replayed agent still shows as disconnected. Making status real requires the
agent protocol client (1517 /enroll + /control), which is a separate piece.

Schema notes for this build (5.0.0-beta5, verified against a live cluster):
  - agent identity lives at  wazuh.agent.id / .name / .version / .groups
  - freshness field is       state.modified_at   (ISO8601, Z suffix)
  - state indices are NOT suffixed with the manager node name
  - inventory indices are STATE, so documents are upserted on their original
    _id. Generating new ids would accumulate duplicate packages every cycle.

Usage:
  export WAZUH_INDEXER_URL=https://127.0.0.1:9200
  export WAZUH_INDEXER_USER=admin
  export WAZUH_INDEXER_PASS='...'

  # one pass, see what would happen, change nothing
  python3 wazuh_fixture_player.py --fixtures ./fixtures --dry-run

  # one pass, for real
  python3 wazuh_fixture_player.py --fixtures ./fixtures --agents 004

  # run forever, refreshing every 5 minutes
  python3 wazuh_fixture_player.py --fixtures ./fixtures --agents 004 --loop 300

  # undo everything this script ever wrote
  python3 wazuh_fixture_player.py --purge
"""

from __future__ import annotations

import argparse
import json
import os
import random
import signal
import sys
import time
import urllib3
from datetime import datetime, timezone, timedelta
from pathlib import Path

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# These indices use strict dynamic mapping, so an extra top-level marker field
# (e.g. "simulated": true) is REJECTED by the indexer. Instead, replayed agents
# can be tagged by appending a group name to wazuh.agent.groups, which is an
# existing mapped field. Purge does not rely on this: it deletes the exact
# index/_id pairs recorded in the fixture set.
SIM_GROUP = "simulated"

# Indices holding inventory/vulnerability state. Anything else in the fixture
# set is skipped unless --include-fim is passed, because FIM state is large and
# rarely the point of a demo.
DEFAULT_SKIP_PREFIXES = ("wazuh-states-fim-",)

BULK_CHUNK = 500


class Indexer:
    def __init__(self, url, user, password, verify=False, timeout=120):
        self.url = url.rstrip("/")
        self.s = requests.Session()
        self.s.auth = (user, password)
        self.s.verify = verify
        self.timeout = timeout

    def bulk(self, lines: list[str]) -> dict:
        body = "\n".join(lines) + "\n"
        r = self.s.post(
            f"{self.url}/_bulk",
            data=body.encode("utf-8"),
            headers={"Content-Type": "application/x-ndjson"},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def delete_by_query(self, index_pattern: str, query: dict) -> dict:
        r = self.s.post(
            f"{self.url}/{index_pattern}/_delete_by_query",
            params={"conflicts": "proceed", "refresh": "true"},
            json={"query": query},
            timeout=self.timeout,
        )
        r.raise_for_status()
        return r.json()

    def ping(self) -> dict:
        r = self.s.get(f"{self.url}/", timeout=self.timeout)
        r.raise_for_status()
        return r.json()


def iso_now(offset_seconds: int = 0) -> str:
    t = datetime.now(timezone.utc) + timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def agent_id_of(source: dict) -> str | None:
    return (source.get("wazuh", {}).get("agent", {}) or {}).get("id")


def refresh_timestamps(source: dict, jitter: int = 0) -> dict:
    """Move the document's freshness fields to now.

    Only touches fields that represent "when did we last observe this", never
    fields that are part of the observed data itself (package build dates,
    CVE publication dates, boot time and so on). Getting that distinction
    wrong is what makes replayed data look obviously synthetic.
    """
    now = iso_now(-random.randint(0, jitter) if jitter else 0)

    st = source.get("state")
    if isinstance(st, dict):
        if "modified_at" in st:
            st["modified_at"] = now
        # bump the version so consumers see a change rather than a replay
        if isinstance(st.get("document_version"), int):
            st["document_version"] += 1

    # Top-level @timestamp appears on some state indices in this build.
    if "@timestamp" in source:
        source["@timestamp"] = now

    return source


def load_fixtures(fixtures: Path, include_fim: bool) -> dict[str, list[dict]]:
    docs_dir = fixtures / "docs"
    if not docs_dir.is_dir():
        raise SystemExit(f"No docs/ directory under {fixtures}. Run the recorder first.")

    by_index: dict[str, list[dict]] = {}
    for path in sorted(docs_dir.glob("*.jsonl")):
        index = path.stem
        if not include_fim and index.startswith(DEFAULT_SKIP_PREFIXES):
            continue
        records = []
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
        if records:
            by_index[index] = records
    return by_index


def parse_remap(specs: list[str] | None) -> dict[str, dict]:
    """--remap OLD:NEW[:NAME[:HOSTNAME]]

    Fixtures are recorded against the agent that produced them, and both the
    document _id (wazuh_<id>_<sha1>) and wazuh.agent.id carry that id. Replaying
    onto a different agent must rewrite both, or the documents land on the
    original agent instead of the simulated one.
    """
    out: dict[str, dict] = {}
    for spec in specs or []:
        parts = spec.split(":")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            raise SystemExit(f"Bad --remap '{spec}'. Use OLD:NEW[:NAME[:HOSTNAME]]")
        out[parts[0]] = {
            "id": parts[1],
            "name": parts[2] if len(parts) > 2 and parts[2] else None,
            "hostname": parts[3] if len(parts) > 3 and parts[3] else None,
        }
    return out


def apply_remap(doc_id: str, source: dict, target: dict, old_id: str) -> tuple[str, dict]:
    new_id = target["id"]

    # _id prefix: wazuh_<agentid>_<sha1>. Rewriting it keeps the simulated
    # agent's documents distinct from the original agent's.
    prefix = f"wazuh_{old_id}_"
    if doc_id.startswith(prefix):
        doc_id = f"wazuh_{new_id}_" + doc_id[len(prefix):]

    agent = source.setdefault("wazuh", {}).setdefault("agent", {})
    agent["id"] = new_id
    if target["name"]:
        agent["name"] = target["name"]
    if target["hostname"]:
        host = agent.get("host")
        if isinstance(host, dict):
            host["hostname"] = target["hostname"]
        if isinstance(source.get("host"), dict) and "hostname" in source["host"]:
            source["host"]["hostname"] = target["hostname"]

    return doc_id, source


def build_bulk_lines(index: str, records: list[dict], agents: set[str] | None,
                     jitter: int, tag: bool,
                     remap: dict[str, dict] | None = None) -> tuple[list[str], int]:
    lines: list[str] = []
    skipped = 0
    for rec in records:
        src = rec.get("_source", {})
        aid = agent_id_of(src)

        if agents is not None and aid not in agents:
            skipped += 1
            continue

        src = refresh_timestamps(json.loads(json.dumps(src)), jitter=jitter)
        doc_id = rec["_id"]

        if remap and aid in remap:
            doc_id, src = apply_remap(doc_id, src, remap[aid], aid)

        if tag:
            agent = src.setdefault("wazuh", {}).setdefault("agent", {})
            groups = agent.get("groups")
            if isinstance(groups, list) and SIM_GROUP not in groups:
                groups.append(SIM_GROUP)

        # Upsert on the _id. These indices hold state, not events.
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(src, ensure_ascii=False))
    return lines, skipped


def push(idx: Indexer, lines: list[str], dry_run: bool) -> tuple[int, int]:
    """Returns (indexed, errored)."""
    if dry_run:
        return len(lines) // 2, 0

    indexed = errored = 0
    for i in range(0, len(lines), BULK_CHUNK * 2):
        chunk = lines[i:i + BULK_CHUNK * 2]
        if not chunk:
            continue
        resp = idx.bulk(chunk)
        for item in resp.get("items", []):
            op = item.get("index") or item.get("create") or {}
            if op.get("error"):
                errored += 1
                if errored <= 3:
                    print(f"    ! {op['error'].get('type')}: "
                          f"{str(op['error'].get('reason'))[:160]}")
            else:
                indexed += 1
    return indexed, errored


def do_purge(idx: Indexer, by_index: dict[str, list[dict]],
             agents: set[str] | None, dry_run: bool,
             remap: dict[str, dict] | None = None) -> None:
    """Delete exactly the documents this player would have written.

    Driven by the fixture set rather than a marker field, because the state
    indices use strict mappings and reject extra fields. This only removes
    documents whose index/_id pair exists in the fixtures, so it cannot touch
    anything the recorder didn't originally capture.
    """
    print("Deleting replayed documents (matched by index and _id from fixtures)")
    total = 0
    for index, records in by_index.items():
        lines = []
        for rec in records:
            aid = agent_id_of(rec.get("_source", {}))
            if agents is not None and aid not in agents:
                continue
            doc_id = rec["_id"]
            if remap and aid in remap:
                prefix = f"wazuh_{aid}_"
                if doc_id.startswith(prefix):
                    doc_id = f"wazuh_{remap[aid]['id']}_" + doc_id[len(prefix):]
            lines.append(json.dumps({"delete": {"_index": index, "_id": doc_id}}))
        if not lines:
            continue
        if dry_run:
            print(f"  {index:<48} would delete {len(lines)}")
            total += len(lines)
            continue
        deleted = 0
        for i in range(0, len(lines), BULK_CHUNK):
            resp = idx.bulk(lines[i:i + BULK_CHUNK])
            for item in resp.get("items", []):
                op = item.get("delete") or {}
                if op.get("result") == "deleted":
                    deleted += 1
        print(f"  {index:<48} deleted {deleted}")
        total += deleted
    print(f"\n{'would delete' if dry_run else 'deleted'} {total} documents")


def one_pass(idx: Indexer, by_index: dict[str, list[dict]], agents: set[str] | None,
             jitter: int, tag: bool, dry_run: bool,
             remap: dict[str, dict] | None = None) -> None:
    total_in = total_err = 0
    for index, records in by_index.items():
        lines, skipped = build_bulk_lines(index, records, agents, jitter, tag, remap)
        if not lines:
            print(f"  {index:<48} no matching agents, skipped")
            continue
        indexed, errored = push(idx, lines, dry_run)
        total_in += indexed
        total_err += errored
        note = f"{indexed:>6} docs"
        if errored:
            note += f"  ({errored} FAILED)"
        if skipped:
            note += f"  [{skipped} other agents]"
        print(f"  {index:<48} {note}")

    verb = "would write" if dry_run else "wrote"
    print(f"\n{verb} {total_in} documents"
          + (f", {total_err} errors" if total_err else ""))


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("WAZUH_INDEXER_URL"))
    ap.add_argument("--user", default=os.environ.get("WAZUH_INDEXER_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("WAZUH_INDEXER_PASS"))
    ap.add_argument("--fixtures", type=Path, default=Path("./fixtures"))
    ap.add_argument("--agents", nargs="*", default=None,
                    help="Only replay these agent IDs, e.g. 004. Default: all "
                         "agents in the fixture set, which includes the manager.")
    ap.add_argument("--loop", type=int, default=0, metavar="SECONDS",
                    help="Repeat forever at this interval. 0 = single pass.")
    ap.add_argument("--jitter", type=int, default=120, metavar="SECONDS",
                    help="Spread refreshed timestamps over this many seconds so "
                         "documents don't all share one identical scan time.")
    ap.add_argument("--include-fim", action="store_true",
                    help="Also replay wazuh-states-fim-* (large, usually skip)")
    ap.add_argument("--tag-group", action="store_true",
                    help="Append a 'simulated' entry to wazuh.agent.groups so "
                         "replayed agents are identifiable in the dashboard. Off "
                         "by default because it alters displayed agent data.")
    ap.add_argument("--remap", nargs="*", metavar="OLD:NEW[:NAME[:HOSTNAME]]",
                    help="Replay one agent's fixtures as another agent. "
                         "Rewrites the document _id prefix and wazuh.agent.id, "
                         "e.g. --remap 004:007:win-demo:WIN-DEMO")
    ap.add_argument("--purge", action="store_true",
                    help="Delete the documents in the fixture set from the "
                         "indexer and exit. Honours --agents.")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verify-tls", action="store_true")
    args = ap.parse_args()

    if not args.url or not args.password:
        ap.error("--url and --password required (or WAZUH_INDEXER_URL / _PASS)")

    idx = Indexer(args.url, args.user, args.password, verify=args.verify_tls)
    try:
        info = idx.ping()
    except Exception as exc:
        print(f"ERROR: cannot reach indexer: {exc}", file=sys.stderr)
        return 1
    print(f"Connected to '{info.get('cluster_name')}' "
          f"({info.get('version', {}).get('number')})")

    by_index = load_fixtures(args.fixtures, args.include_fim)
    if not by_index:
        print("No fixtures loaded. Check --fixtures path.", file=sys.stderr)
        return 1

    agents = set(args.agents) if args.agents else None

    remap = parse_remap(args.remap)

    if args.purge:
        do_purge(idx, by_index, agents, args.dry_run, remap)
        return 0
    total_docs = sum(len(v) for v in by_index.values())
    print(f"Loaded {total_docs} documents across {len(by_index)} indices")
    print(f"Agents: {', '.join(sorted(agents)) if agents else 'all in fixture set'}")
    if args.dry_run:
        print("DRY RUN — nothing will be written\n")
    else:
        print()

    stop = {"now": False}

    def handle(signum, frame):
        stop["now"] = True
        print("\nStopping after current pass...")

    signal.signal(signal.SIGINT, handle)
    signal.signal(signal.SIGTERM, handle)

    while True:
        started = time.time()
        print(f"--- pass at {iso_now()} ---")
        try:
            one_pass(idx, by_index, agents, args.jitter,
                     args.tag_group, args.dry_run, remap)
        except requests.HTTPError as exc:
            print(f"ERROR during pass: {exc}", file=sys.stderr)

        if not args.loop or stop["now"]:
            break

        elapsed = time.time() - started
        sleep_for = max(1, args.loop - elapsed)
        print(f"sleeping {int(sleep_for)}s\n")
        for _ in range(int(sleep_for)):
            if stop["now"]:
                break
            time.sleep(1)
        if stop["now"]:
            break

    return 0


if __name__ == "__main__":
    sys.exit(main())
