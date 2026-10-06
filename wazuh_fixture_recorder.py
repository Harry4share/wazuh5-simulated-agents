#!/usr/bin/env python3
"""
wazuh_fixture_recorder.py

One-time capture of real Wazuh 5.x agent state from the indexer, saved as
replayable fixtures. Run this while the real agents are still connected and
have completed at least one full syscollector + vulnerability scan cycle.

Captures:
  - every wazuh-states-* index (IT Hygiene inventory + vulnerability state)
  - the agent registry / state index
  - a bounded sample of recent alerts per agent

Output layout:
  <outdir>/
    manifest.json              capture metadata, index list, doc counts
    mappings/<index>.json      index mappings, so the player can validate fields
    docs/<index>.jsonl         one record per line: {_index, _id, _source}
    alerts/<agent_id>.jsonl    sampled alerts, same record shape

Usage:
  export WAZUH_INDEXER_URL=https://10.0.44.61:9200
  export WAZUH_INDEXER_USER=admin
  export WAZUH_INDEXER_PASS=...
  python3 wazuh_fixture_recorder.py --outdir ./fixtures

  # restrict to specific agents (recommended)
  python3 wazuh_fixture_recorder.py --agents 001 002 --outdir ./fixtures

  # REFRESH a few agents inside fixtures you already have, leaving the rest alone
  python3 wazuh_fixture_recorder.py --agents 004 021 --outdir ./fixtures --merge

Without --merge every docs/<index>.jsonl is rewritten from scratch, so recording two
agents into an existing fixtures directory REPLACES the others. --merge swaps in only the
listed agents' documents, never shrinks an agent to nothing when the live index has none,
and makes a full copy of the existing fixtures first (<outdir>.bak-<time>).
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import urllib3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Index groups to sweep. Wildcards are resolved against _cat/indices so we pick
# up the manager-node suffix (e.g. wazuh-states-inventory-packages-<node>)
# without having to know the node name in advance.
STATE_PATTERNS = [
    "wazuh-states-*",
    "wazuh-agents*",
]

ALERT_PATTERNS = [
    "wazuh-alerts-*",
]

SCROLL_TTL = "2m"
PAGE_SIZE = 1000


class Indexer:
    def __init__(self, url: str, user: str, password: str, verify: bool = False,
                 timeout: int = 60):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.verify = verify
        self.session.headers.update({"Content-Type": "application/json"})
        self.timeout = timeout

    def _request(self, method: str, path: str, **kwargs):
        resp = self.session.request(
            method, f"{self.url}{path}", timeout=self.timeout, **kwargs
        )
        resp.raise_for_status()
        return resp.json() if resp.text else {}

    def ping(self) -> dict:
        return self._request("GET", "/")

    def resolve_indices(self, patterns: list[str]) -> list[str]:
        """Expand wildcard patterns to concrete index names, skipping system
        and closed indices."""
        found: set[str] = set()
        for pattern in patterns:
            try:
                rows = self._request(
                    "GET", f"/_cat/indices/{pattern}",
                    params={"format": "json", "h": "index,status,docs.count"},
                )
            except requests.HTTPError as exc:
                if exc.response is not None and exc.response.status_code == 404:
                    continue
                raise
            for row in rows:
                name = row.get("index", "")
                if name.startswith("."):
                    continue
                if row.get("status") != "open":
                    print(f"  ! skipping {name} (status={row.get('status')})")
                    continue
                found.add(name)
        return sorted(found)

    def get_mapping(self, index: str) -> dict:
        return self._request("GET", f"/{index}/_mapping")

    def scroll_all(self, index: str, query: dict, size: int = PAGE_SIZE):
        """Yield raw hits from an index using the scroll API."""
        body = {"size": size, "query": query}
        page = self._request(
            "POST", f"/{index}/_search",
            params={"scroll": SCROLL_TTL},
            data=json.dumps(body),
        )
        scroll_id = page.get("_scroll_id")
        try:
            while True:
                hits = page.get("hits", {}).get("hits", [])
                if not hits:
                    break
                for hit in hits:
                    yield hit
                page = self._request(
                    "POST", "/_search/scroll",
                    data=json.dumps({"scroll": SCROLL_TTL, "scroll_id": scroll_id}),
                )
                scroll_id = page.get("_scroll_id") or scroll_id
        finally:
            if scroll_id:
                try:
                    self.session.delete(
                        f"{self.url}/_search/scroll",
                        data=json.dumps({"scroll_id": [scroll_id]}),
                        timeout=self.timeout,
                    )
                except Exception:
                    pass


def agent_filter(agents: list[str] | None) -> dict:
    """Build a query restricted to the given agent IDs.

    Identity lives at wazuh.agent.id in the 5.x state indices, NOT at the
    ECS-style agent.id. An earlier version queried agent.id and silently
    matched zero documents, producing an empty fixture set that looked like a
    scan-cycle problem.
    """
    if not agents:
        return {"match_all": {}}
    return {
        "bool": {
            "should": [
                {"terms": {"wazuh.agent.id": agents}},
                {"terms": {"agent.id": agents}},
            ],
            "minimum_should_match": 1,
        }
    }


def alert_query(agents: list[str] | None, hours: int) -> dict:
    must: list[dict] = [
        {"range": {"@timestamp": {"gte": f"now-{hours}h"}}}
    ]
    if agents:
        must.append(agent_filter(agents))
    return {"bool": {"must": must}}


def write_jsonl(path: Path, records) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False, sort_keys=True) + "\n")
            count += 1
    return count


def hit_to_record(hit: dict) -> dict:
    """Preserve _index and _id. The _id matters: inventory indices are state,
    not events, so the player must upsert onto the same IDs or it will
    accumulate duplicates on every replay cycle."""
    return {
        "_index": hit.get("_index"),
        "_id": hit.get("_id"),
        "_source": hit.get("_source", {}),
    }


def record_agent(rec: dict) -> str:
    src = rec.get("_source", {})
    agent = (src.get("wazuh", {}) or {}).get("agent") or src.get("agent") or {}
    return str(agent.get("id") or "")


def read_jsonl(path: Path):
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except ValueError:
                    continue


def merge_records(path: Path, live: list[dict], agents: set[str]):
    """Swap the listed agents' documents for the live ones; keep everyone else's.

    An agent the live index has NO documents for keeps whatever was recorded: an empty
    live result usually means the agent was deleted or has not synced, not that its
    recorded data should be erased. Returns (records, notes).
    """
    old = list(read_jsonl(path)) if path.exists() else []
    kept = [r for r in old if record_agent(r) not in agents]
    old_n = Counter(record_agent(r) for r in old if record_agent(r) in agents)
    live_n = Counter(record_agent(r) for r in live)
    out, notes = list(kept), []
    for aid in sorted(agents):
        if live_n[aid]:
            out += [r for r in live if record_agent(r) == aid]
            if live_n[aid] != old_n[aid]:
                notes.append(f"{aid}: {old_n[aid]} -> {live_n[aid]}")
        elif old_n[aid]:
            out += [r for r in old if record_agent(r) == aid]
            notes.append(f"{aid}: live has none, kept the {old_n[aid]} recorded")
    return out, notes


def observed_agents(records: list[dict]) -> dict:
    """Summarise which agents appear in the capture, for the manifest.

    Identity is at wazuh.agent.*, with a fallback to the ECS-style agent.*
    for any index that uses it.
    """
    seen: dict[str, dict] = {}
    for rec in records:
        src = rec.get("_source", {})
        agent = (src.get("wazuh", {}) or {}).get("agent") or src.get("agent") or {}
        aid = agent.get("id")
        if not aid:
            continue
        entry = seen.setdefault(aid, {"id": aid, "names": set(), "versions": set()})
        if agent.get("name"):
            entry["names"].add(agent["name"])
        if agent.get("version"):
            entry["versions"].add(agent["version"])
    return {
        aid: {
            "id": v["id"],
            "names": sorted(v["names"]),
            "versions": sorted(v["versions"]),
        }
        for aid, v in seen.items()
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("WAZUH_INDEXER_URL"),
                    help="Indexer base URL, e.g. https://10.0.44.61:9200")
    ap.add_argument("--user", default=os.environ.get("WAZUH_INDEXER_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("WAZUH_INDEXER_PASS"))
    ap.add_argument("--outdir", default="./fixtures", type=Path)
    ap.add_argument("--agents", nargs="*", default=None,
                    help="Agent IDs to capture (e.g. 001 002). Default: all.")
    ap.add_argument("--alert-hours", type=int, default=24,
                    help="How far back to sample alerts (default 24)")
    ap.add_argument("--alert-cap", type=int, default=2000,
                    help="Max alerts to keep per agent (default 2000)")
    ap.add_argument("--verify-tls", action="store_true",
                    help="Verify indexer TLS certs (off by default for lab)")
    ap.add_argument("--skip-alerts", action="store_true")
    ap.add_argument("--merge", action="store_true",
                    help="Update only the --agents given inside the existing --outdir, "
                         "instead of rewriting it (a backup is made first). Alerts are "
                         "not touched.")
    args = ap.parse_args()

    if not args.url or not args.password:
        ap.error("--url and --password are required "
                 "(or set WAZUH_INDEXER_URL / WAZUH_INDEXER_PASS)")

    if args.merge and not args.agents:
        ap.error("--merge needs --agents (which agents to refresh)")

    idx = Indexer(args.url, args.user, args.password, verify=args.verify_tls)

    try:
        info = idx.ping()
    except Exception as exc:
        print(f"ERROR: cannot reach indexer at {args.url}: {exc}", file=sys.stderr)
        return 1

    cluster = info.get("cluster_name", "unknown")
    print(f"Connected to cluster '{cluster}' "
          f"({info.get('version', {}).get('number', '?')})")

    outdir: Path = args.outdir
    outdir.mkdir(parents=True, exist_ok=True)
    old_manifest: dict = {}
    if args.merge:
        mp = outdir / "manifest.json"
        if mp.exists():
            try:
                old_manifest = json.loads(mp.read_text(encoding="utf-8"))
            except ValueError:
                old_manifest = {}
        if (outdir / "docs").is_dir():
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            backup = outdir.parent / f"{outdir.name}.bak-{stamp}"
            shutil.copytree(outdir, backup)
            print(f"Merge mode: existing fixtures copied to {backup}")

    query = agent_filter(args.agents)
    manifest = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "cluster_name": cluster,
        "indexer_version": info.get("version", {}),
        "source_url": args.url,
        "agent_filter": args.agents or "all",
        "state_indices": {},
        "alert_indices": {},
        "agents_observed": {},
    }

    all_state_records: list[dict] = []

    # ---- state indices -------------------------------------------------
    print("\nResolving state indices...")
    state_indices = idx.resolve_indices(STATE_PATTERNS)
    if not state_indices:
        print("  ! no wazuh-states-* or wazuh-agents* indices found.")
        print("    Check the manager has synced inventory to the indexer.")
    for name in state_indices:
        records = [hit_to_record(h) for h in idx.scroll_all(name, query)]
        notes: list[str] = []
        if args.merge:
            records, notes = merge_records(outdir / "docs" / f"{name}.jsonl", records,
                                           set(args.agents))
        all_state_records.extend(records)
        n = write_jsonl(outdir / "docs" / f"{name}.jsonl", records)
        try:
            mapping = idx.get_mapping(name)
            mpath = outdir / "mappings" / f"{name}.json"
            mpath.parent.mkdir(parents=True, exist_ok=True)
            mpath.write_text(json.dumps(mapping, indent=2), encoding="utf-8")
        except Exception as exc:
            print(f"  ! mapping fetch failed for {name}: {exc}")
        manifest["state_indices"][name] = n
        print(f"  {name:<60} {n:>7} docs" + (f"   [{'; '.join(notes)}]" if notes else ""))

    manifest["agents_observed"] = observed_agents(all_state_records)

    if args.merge:
        # Indices that were not resolved this time keep their recorded counts, and the
        # original capture time stays: this is a refresh, not a new recording.
        manifest["state_indices"] = {**old_manifest.get("state_indices", {}),
                                     **manifest["state_indices"]}
        manifest["captured_at"] = old_manifest.get("captured_at", manifest["captured_at"])
        manifest["alert_indices"] = old_manifest.get("alert_indices", {})
        manifest["merged_at"] = datetime.now(timezone.utc).isoformat()
        manifest["merged_agents"] = args.agents
        manifest["agent_filter"] = old_manifest.get("agent_filter", manifest["agent_filter"])

    # ---- alerts --------------------------------------------------------
    if args.merge:
        print("\n(merge mode: alerts are not touched)")
    elif not args.skip_alerts:
        print("\nResolving alert indices...")
        alert_indices = idx.resolve_indices(ALERT_PATTERNS)
        pattern = ",".join(alert_indices) if alert_indices else None
        if not pattern:
            print("  ! no wazuh-alerts-* indices found.")
        else:
            targets = args.agents or sorted(manifest["agents_observed"].keys())
            if not targets:
                print("  ! no agents identified; skipping alert capture.")
            for aid in targets:
                q = alert_query([aid], args.alert_hours)
                records = []
                for hit in idx.scroll_all(pattern, q):
                    records.append(hit_to_record(hit))
                    if len(records) >= args.alert_cap:
                        break
                n = write_jsonl(outdir / "alerts" / f"{aid}.jsonl", records)
                manifest["alert_indices"][aid] = n
                print(f"  agent {aid:<10} {n:>7} alerts "
                      f"(last {args.alert_hours}h, cap {args.alert_cap})")

    (outdir / "manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )

    total = sum(manifest["state_indices"].values())
    print(f"\nCaptured {total} state docs across "
          f"{len(manifest['state_indices'])} indices -> {outdir}")

    if manifest["agents_observed"]:
        print("\nAgents in capture:")
        for aid, meta in sorted(manifest["agents_observed"].items()):
            names = ", ".join(meta["names"]) or "?"
            vers = ", ".join(meta["versions"]) or "?"
            print(f"  {aid}  {names}  ({vers})")

    # Loud warnings about the things that quietly ruin a fixture set.
    empty = [k for k, v in manifest["state_indices"].items() if v == 0]
    if total == 0:
        print("\nWARNING: NOTHING was captured from any index.")
        if args.agents:
            print(f"  The --agents filter {args.agents} matched no documents.")
            print("  Check the IDs exist and are producing inventory:")
            print("    curl -sk -u ... \"$WAZUH_INDEXER_URL"
                  "/wazuh-states-inventory-system/_search?pretty\"")
        else:
            print("  The state indices appear to be empty. Has any agent "
                  "completed a scan cycle?")
    elif empty:
        print("\nWARNING: these indices captured zero documents. If you expect "
              "data in them, the scan cycle probably hasn't completed yet:")
        for name in empty:
            print(f"  - {name}")

    print("\nDo not tear down the agents until you have reviewed manifest.json "
          "and confirmed the inventory indices are populated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
