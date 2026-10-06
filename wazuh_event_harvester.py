#!/usr/bin/env python3
"""
wazuh_event_harvester.py

Collects real log lines (event.original) that Wazuh's decoders already
processed, and saves them as a replayable corpus. Companion to
wazuh_event_player.py, which feeds them back through POST /stateless so the
manager's own pipeline decodes them again.

The point: the alerts produced are genuine. The decoder chain, the field
extraction and the classification are all done by Wazuh, not by us. Only the
input line is recycled, and it was a real line to begin with.

Output:
  <outdir>/
    manifest.json               what was harvested, when, and from where
    events/<group>.jsonl        one record per line:
                                {original, action, outcome, decoders,
                                 agent_id, platform, process}

Groups are named <platform>-<action>, e.g. linux-logged-in,
macos-sudo, linux-authentication-failure, so the player can pick
scenario-appropriate material.

Usage:
  export WAZUH_INDEXER_URL=https://127.0.0.1:9200
  export WAZUH_INDEXER_USER=admin
  export WAZUH_INDEXER_PASS=...

  # everything the auth decoder has touched, last 7 days
  python3 wazuh_event_harvester.py --outdir ./events

  # from real agents only -- the dependable way to keep simulated agents out
  python3 wazuh_event_harvester.py --decoder '' --agents 001 002 004 010 021

  # a specific decoder, or a specific agent
  python3 wazuh_event_harvester.py --decoder decoder/system-auth/0 --agents 002
  python3 wazuh_event_harvester.py --days 30 --per-group 500

Rule-driven harvest (--rule)
----------------------------
Instead of grouping by what an event IS (sudo, logged-in), group by which
DETECTION it triggered. Findings record the event they came from, so this
collects exactly the events a given rule fired on -- ideal for custom rules,
because replaying those events on a simulated agent makes the same rule fire
there too.

  # what rules have fired lately, and how often (find your rule's id/title)
  python3 wazuh_event_harvester.py --list-rules
  python3 wazuh_event_harvester.py --list-rules --rule "DEMO -"

  # harvest the events behind every rule whose title starts with "DEMO -"
  python3 wazuh_event_harvester.py --rule "DEMO -"

  # or by rule id (repeat --rule for several), from real agents only
  python3 wazuh_event_harvester.py --rule b7ab7d97-c94a-57ab-af87-f33213ecdf4d \
      --agents 002 004 021

Output groups are <platform>-rule-<title-slug>-<id8>.jsonl. Replay with the
player's  --scenario rule:<text>  where <text> is any part of the slug.

Simulated agents are excluded automatically, by id and by name (read from
./agents/*.json and demo.conf), because once a rule fires on a replayed event
the finding would otherwise be harvested again -- a copy of a copy. The run
says what it excluded, and warns loudly if it found nothing to exclude.
--include-simulated disables this; --exclude-agents adds ids by hand; a
--agents allow-list of real ids is the most direct way to be certain.
--rule runs INSTEAD of the normal event harvest.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib3
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EVENT_INDICES = "wazuh-events-v5-*"
FINDINGS_INDICES = "wazuh-findings-v5-*"

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$")

# The only finding fields rule mode needs. Findings carry large compliance and
# MITRE blocks nobody wants over the wire for thousands of hits.
RULE_SOURCE = [
    "@timestamp", "event.original", "event.index", "event.doc_id",
    "event.action", "event.outcome",
    "wazuh.rule.id", "wazuh.rule.sigma_id", "wazuh.rule.title",
    "wazuh.agent.id", "wazuh.agent.host.os.platform",
    "wazuh.integration.decoders", "process.name", "user.name", "source.ip",
]

# Lines whose content would be misleading or useless when replayed.
SKIP_PATTERNS = [
    re.compile(r"wazuh-(manager|agent|dashboard|indexer)", re.I),
    re.compile(r"opensearch", re.I),
]


class Indexer:
    def __init__(self, url, user, password, verify=False, timeout=60):
        self.url = url.rstrip("/")
        self.s = requests.Session()
        self.s.auth = (user, password)
        self.s.verify = verify
        self.timeout = timeout

    def ping(self):
        r = self.s.get(f"{self.url}/", timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def search(self, index, body):
        r = self.s.post(f"{self.url}/{index}/_search", json=body,
                        timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def mget(self, refs):
        """Fetch event.original for (index, id) pairs. Returns one entry per
        ref, in request order, so callers can zip the two together."""
        body = {"docs": [{"_index": i, "_id": d, "_source": ["event.original"]}
                         for i, d in refs]}
        r = self.s.post(f"{self.url}/_mget", json=body, timeout=self.timeout)
        r.raise_for_status()
        return r.json().get("docs", [])

    def scroll(self, index, query, size=1000, ttl="2m", source=None):
        payload = {"size": size, "query": query}
        if source:
            payload["_source"] = source
        page = self.s.post(f"{self.url}/{index}/_search",
                           params={"scroll": ttl},
                           json=payload,
                           timeout=self.timeout)
        page.raise_for_status()
        page = page.json()
        sid = page.get("_scroll_id")
        try:
            while True:
                hits = page.get("hits", {}).get("hits", [])
                if not hits:
                    break
                for h in hits:
                    yield h
                r = self.s.post(f"{self.url}/_search/scroll",
                                json={"scroll": ttl, "scroll_id": sid},
                                timeout=self.timeout)
                r.raise_for_status()
                page = r.json()
                sid = page.get("_scroll_id") or sid
        finally:
            if sid:
                try:
                    self.s.delete(f"{self.url}/_search/scroll",
                                  json={"scroll_id": [sid]}, timeout=10)
                except Exception:
                    pass


def dig(d: dict, path: str, default=None):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


def should_skip(line: str) -> bool:
    return any(p.search(line) for p in SKIP_PATTERNS)


def platform_of(src: dict) -> str:
    """Which platform this line came from, so it is only ever replayed as a
    host of that kind.

    The reporting agent's OS is authoritative. An earlier version inferred
    this from the decoder chain, which mislabels everything a Mac emits
    outside the ULS logcollector -- rootcheck, syscollector and service
    lifecycle events do not pass through decoder/macos-uls/0, so a Mac's
    events were being filed as Linux.
    """
    plat = (dig(src, "wazuh.agent.host.os.platform") or "").lower()
    if plat in ("darwin", "macos"):
        return "macos"
    if plat == "windows":
        return "windows"
    if plat:
        return "linux"

    # No agent OS recorded: fall back to the decoder chain.
    decoders = dig(src, "wazuh.integration.decoders", []) or []
    if any("macos-uls" in d for d in decoders):
        return "macos"
    if any("windows" in d for d in decoders):
        return "windows"
    return "linux"


def build_query(args, ex_ids=None, ex_names=None) -> dict:
    # NOTE: no {"exists": {"field": "event.original"}} clause here. That field
    # is present in _source but not indexed (it is a large raw blob nobody
    # searches), so an exists query matches ZERO documents and silently zeroes
    # out any query it is combined with. Documents lacking it are skipped
    # during iteration instead.
    must = [
        {"range": {"@timestamp": {"gte": f"now-{args.days}d"}}},
    ]
    if args.decoder:
        must.append({"term": {"wazuh.integration.decoders": args.decoder}})
    if args.agents:
        must.append({"terms": {"wazuh.agent.id": args.agents}})
    if args.action:
        must.append({"terms": {"event.action": args.action}})
    q: dict = {"bool": {"must": must}}
    must_not = []
    if ex_ids:
        must_not.append({"terms": {"wazuh.agent.id": sorted(ex_ids)}})
    if ex_names:
        must_not.append({"terms": {"wazuh.agent.name": sorted(ex_names)}})
    if must_not:
        q["bool"]["must_not"] = must_not
    return q



# ------------------------------------------------------------ rule mode ----
def slugify(text: str, limit: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:limit].rstrip("-") or "rule"


def title_stem(titles: list[str]) -> str:
    """The part of a rule's title that does not vary from event to event.

    Stock rule titles embed event data ("Wazuh FIM - File created - <path>").
    Naming a group after whichever title happened to be seen first is
    misleading: the first one can come from a different platform than the
    events the group actually holds. Keep the leading " - " segments every
    title shares instead.
    """
    if len(titles) == 1:
        return titles[0]
    common: list[str] = []
    for segs in zip(*[t.split(" - ") for t in titles]):
        if all(x == segs[0] for x in segs):
            common.append(segs[0])
        else:
            break
    return " - ".join(common) or titles[0]


def simulated_agents() -> tuple[set[str], set[str], list[str]]:
    """(ids, names, where-found) of the agents this toolkit manages.

    Three places, because any one of them can be missing or stale:
      agents/*.json   state files: the id and name of each enrolled agent
      demo.conf       AGENTS (names) and REMAP (the simulated side's ids/names)
    Names matter as well as ids. An agent that was deleted and re-enrolled has
    a new id, but the findings it produced under the old one are still in the
    index, still under the same name.
    """
    here = Path(__file__).resolve().parent
    ids: set[str] = set()
    names: set[str] = set()
    found: list[str] = []

    d = here / "agents"
    n = 0
    if d.is_dir():
        for f in d.glob("*.json"):
            try:
                o = json.loads(f.read_text())
            except (OSError, ValueError):
                continue
            if o.get("id"):
                ids.add(str(o["id"]))
                n += 1
            if o.get("name"):
                names.add(str(o["name"]))
    if n:
        found.append(f"{n} state file(s) in {d}")

    conf = here / "demo.conf"
    if conf.is_file():
        text = conf.read_text(errors="replace")
        m = re.search(r'^AGENTS="\n?(.*?)"', text, re.S | re.M)
        for line in (m.group(1).splitlines() if m else []):
            parts = line.strip().split(":")
            if len(parts) >= 3 and parts[0]:
                names.add(parts[0])
        m = re.search(r'^REMAP="?([^"\n]*)"?', text, re.M)
        for entry in (m.group(1).split() if m else []):
            parts = entry.split(":")       # OLD:NEW[:NAME[:HOSTNAME]]
            if len(parts) >= 2 and parts[1]:
                ids.add(parts[1])
            if len(parts) >= 3 and parts[2]:
                names.add(parts[2])
        found.append(f"AGENTS/REMAP in {conf}")
    return ids, names, found


def excluded_agents(args) -> tuple[set[str], set[str]]:
    """(ids, names) to leave out of a rule harvest.

    Once a rule fires on a replayed event, the finding looks exactly like one
    from a real machine. Harvesting it would capture a rewritten copy of a
    line we ourselves sent, and the corpus would slowly fill with echoes.

    An explicit --agents allow-list wins: those ids are kept even if they are
    simulated, and name-based exclusion is skipped since the list already says
    exactly which agents to read.
    """
    ids: set[str] = set()
    names: set[str] = set()
    if not args.include_simulated:
        ids, names, _ = simulated_agents()
        if args.agents:
            names = set()
        ids -= set(args.agents or [])
    ids |= set(args.exclude_agents or [])
    return ids, names


def describe_exclusion(args, ids: set[str], names: set[str]) -> None:
    if ids or names:
        bits = []
        if ids:
            bits.append("ids " + " ".join(sorted(ids)))
        if names:
            bits.append("names " + ", ".join(sorted(names)))
        print("Excluding simulated agents: " + "; ".join(bits))
    elif not args.include_simulated:
        here = Path(__file__).resolve().parent
        print(f"Note: no simulated agents found to exclude (looked for state "
              f"files in {here / 'agents'} and for AGENTS/REMAP in "
              f"{here / 'demo.conf'}).", file=sys.stderr)
        print("  Fine on a fresh install. If simulated agents DO exist, their "
              "findings will be harvested as if real; they are copies of "
              "lines we sent.", file=sys.stderr)
        print("  Pass --agents <real agent ids> to be certain.",
              file=sys.stderr)


def rule_clause(values: list[str]) -> dict:
    """A UUID is matched as a rule id; anything else as a title prefix.

    Prefix matching is case-insensitive, so "demo -" finds "DEMO - ...".
    """
    should = []
    for v in values:
        v = v.strip()
        if not v:
            continue
        if UUID_RE.match(v):
            # Findings carry the id twice; match either so a mapping quirk in
            # one field does not hide the rule.
            should.append({"term": {"wazuh.rule.id": v.lower()}})
            should.append({"term": {"wazuh.rule.sigma_id": v.lower()}})
        else:
            should.append({"prefix": {"wazuh.rule.title":
                                      {"value": v, "case_insensitive": True}}})
    return {"bool": {"should": should, "minimum_should_match": 1}}


def findings_query(args, ex_ids: set[str], ex_names: set[str]) -> dict:
    must: list[dict] = [{"range": {"@timestamp": {"gte": f"now-{args.days}d"}}}]
    if args.rule:
        must.append(rule_clause(args.rule))
    if args.agents:
        must.append({"terms": {"wazuh.agent.id": args.agents}})
    q: dict = {"bool": {"must": must}}
    must_not = []
    if ex_ids:
        must_not.append({"terms": {"wazuh.agent.id": sorted(ex_ids)}})
    if ex_names:
        must_not.append({"terms": {"wazuh.agent.name": sorted(ex_names)}})
    if must_not:
        q["bool"]["must_not"] = must_not
    return q


def list_rules(args, idx) -> int:
    ex_ids, ex_names = excluded_agents(args)
    query = findings_query(args, ex_ids, ex_names)
    body = {"size": 0, "track_total_hits": True, "query": query,
            "aggs": {"t": {"terms": {"field": "wazuh.rule.title",
                                     "size": args.top},
                           "aggs": {"i": {"terms": {"field": "wazuh.rule.id",
                                                    "size": 1}}}}}}
    try:
        res = idx.search(FINDINGS_INDICES, body)
    except requests.HTTPError:
        # wazuh.rule.id is not aggregatable on every build. The titles alone
        # are still enough to pick a rule, so retry without the sub-aggregation.
        body["aggs"]["t"].pop("aggs")
        res = idx.search(FINDINGS_INDICES, body)

    total = res.get("hits", {}).get("total", {}).get("value", 0)
    buckets = res.get("aggregations", {}).get("t", {}).get("buckets", [])
    scope = f"last {args.days}d" + (
        f", rule filter: {', '.join(args.rule)}" if args.rule else "")
    print(f"Findings in {FINDINGS_INDICES} ({scope}): {total}")
    describe_exclusion(args, ex_ids, ex_names)
    if not buckets:
        print("\nNo findings matched.", file=sys.stderr)
        print("  - Has the rule been promoted, and is a detector running it?",
              file=sys.stderr)
        print("  - Findings lag the event by a couple of minutes.",
              file=sys.stderr)
        print("  - Widen the window with --days.", file=sys.stderr)
        return 1
    print(f"\n  {'count':>7}  {'rule id':<36}  title")
    for b in buckets:
        sub = (b.get("i") or {}).get("buckets") or []
        rid = sub[0]["key"] if sub else "-"
        print(f"  {b['doc_count']:>7}  {rid:<36}  {b['key']}")
    print("\nHarvest one with:  --rule <rule id or title prefix>")
    return 0


def harvest_rules(args, idx, info) -> int:
    ex_ids, ex_names = excluded_agents(args)
    query = findings_query(args, ex_ids, ex_names)
    print(f"Harvesting {FINDINGS_INDICES}, last {args.days}d, rule filter: "
          + ", ".join(args.rule))
    describe_exclusion(args, ex_ids, ex_names)
    if args.debug:
        print("  query:", json.dumps(query))
    print()

    findings: list[dict] = []
    capped = False
    for hit in idx.scroll(FINDINGS_INDICES, query, source=RULE_SOURCE):
        findings.append(hit.get("_source", {}))
        if len(findings) >= args.max_findings:
            capped = True
            break

    if not findings:
        print("Nothing harvested: no findings matched.", file=sys.stderr)
        print("  Check what exists with:  --list-rules"
              + (f' --rule "{args.rule[0]}"' if args.rule else ""),
              file=sys.stderr)
        print("  Findings lag the event by a couple of minutes, and a rule "
              "only fires once a detector includes it.", file=sys.stderr)
        return 1

    # Most findings embed the raw event; fall back to fetching the source
    # event by the index and id the finding recorded, for any that do not.
    refs = sorted({(dig(f, "event.index"), dig(f, "event.doc_id"))
                   for f in findings
                   if not dig(f, "event.original")
                   and dig(f, "event.index") and dig(f, "event.doc_id")})
    fetched: dict = {}
    for i in range(0, len(refs), 100):
        chunk = refs[i:i + 100]
        for ref, doc in zip(chunk, idx.mget(chunk)):
            if doc.get("found"):
                original = dig(doc.get("_source", {}), "event.original")
                if original:
                    fetched[ref] = original

    def rule_id(f: dict) -> str:
        return dig(f, "wazuh.rule.id") or dig(f, "wazuh.rule.sigma_id") or "unknown"

    # Pass 1: every distinct title per rule, so the group can be named after
    # what the titles have in common rather than after the first one seen.
    titles: dict[str, list[str]] = {}
    for f in findings:
        rid = rule_id(f)
        t = dig(f, "wazuh.rule.title") or rid
        seen_t = titles.setdefault(rid, [])
        if t not in seen_t and len(seen_t) < 50:
            seen_t.append(t)
    stem = {rid: title_stem(ts) for rid, ts in titles.items()}
    slug_for = {rid: f"{slugify(st)}-{rid[:8]}" for rid, st in stem.items()}

    rules: dict[str, dict] = {}
    groups: dict[str, list[dict]] = defaultdict(list)
    seen: dict[str, set] = defaultdict(set)
    from_finding = via_fetch = unresolved = skipped = 0

    # Pass 2: sort the events into groups.
    for f in findings:
        rid = rule_id(f)
        title = dig(f, "wazuh.rule.title") or rid
        meta = rules.setdefault(rid, {"title": stem[rid],
                                      "varies": len(titles[rid]) > 1,
                                      "findings": 0, "agents": set()})
        meta["findings"] += 1
        aid = dig(f, "wazuh.agent.id")
        if aid:
            meta["agents"].add(str(aid))

        original = dig(f, "event.original")
        if original:
            from_finding += 1
        else:
            original = fetched.get((dig(f, "event.index"),
                                    dig(f, "event.doc_id")))
            if original:
                via_fetch += 1
            else:
                unresolved += 1
                continue

        if not args.no_skip and should_skip(original):
            skipped += 1
            continue

        platform = platform_of(f)
        group = f"{platform}-rule-{slug_for[rid]}"

        if len(groups[group]) >= args.per_group or original in seen[group]:
            continue
        seen[group].add(original)
        groups[group].append({
            "original": original,
            "action": dig(f, "event.action") or "unclassified",
            "outcome": dig(f, "event.outcome"),
            "decoders": dig(f, "wazuh.integration.decoders", []),
            "agent_id": aid,
            "platform": platform,
            "process": dig(f, "process.name"),
            "user": dig(f, "user.name"),
            "source_ip": dig(f, "source.ip"),
            "rule_id": rid,
            "rule_title": title,
        })

    print(f"  matched {len(findings)} finding(s) across {len(rules)} rule(s)"
          + (f"  [stopped at --max-findings {args.max_findings}; rarer rules "
             f"may be missing, so narrow by rule id or --agents]" if capped else ""))
    print(f"  event text: {from_finding} embedded in the finding, "
          f"{via_fetch} fetched from the source event, "
          f"{unresolved} unresolved, {skipped} skipped as Wazuh's own logs\n")

    if not groups:
        print("Nothing harvested: findings matched but none carried a usable "
              "event.", file=sys.stderr)
        if unresolved:
            print("  The source events may have aged out of the events index, "
                  "or the finding does not record where its event came from.",
                  file=sys.stderr)
        return 1

    outdir: Path = args.outdir
    (outdir / "events").mkdir(parents=True, exist_ok=True)
    mpath = outdir / "manifest.json"
    try:
        manifest = json.loads(mpath.read_text())
    except (OSError, ValueError):
        manifest = {}
    now = datetime.now(timezone.utc).isoformat()
    manifest.setdefault("harvested_at", now)
    manifest.setdefault("groups", {})
    manifest["rules_harvested_at"] = now
    rules_meta = manifest.setdefault("rules", {})

    for group, records in sorted(groups.items()):
        path = outdir / "events" / f"{group}.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        rid = records[0]["rule_id"]
        manifest["groups"][group] = len(records)
        rules_meta[group] = {"rule_id": rid, "title": rules[rid]["title"],
                             "lines": len(records),
                             "agents": sorted(rules[rid]["agents"])}
        note = "   (title varies per event)" if rules[rid]["varies"] else ""
        print(f"  {group}")
        print(f"      {len(records):>4} distinct line(s)   rule {rid}")
        print(f"      \"{rules[rid]['title']}\"{note}   from agent(s) "
              + (", ".join(sorted(rules[rid]["agents"])) or "?"))

    mpath.write_text(json.dumps(manifest, indent=2))

    first = sorted(groups)[0].split("-rule-", 1)[1]
    example = first.rsplit("-", 1)[0] or first
    print(f"\nHarvested {sum(len(v) for v in groups.values())} line(s) into "
          f"{len(groups)} group(s) in {outdir}")
    print("\nReplay on a simulated agent (text = any part of the group name "
          "after 'rule-'):")
    print(f"  ./democtl events <agent> rule:{example}")
    print(f"  python3 wazuh_event_player.py --state agents/<agent>.json "
          f"--events {outdir} --profile <platform> --scenario rule:{example} --once")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("WAZUH_INDEXER_URL"))
    ap.add_argument("--user", default=os.environ.get("WAZUH_INDEXER_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("WAZUH_INDEXER_PASS"))
    ap.add_argument("--outdir", type=Path, default=Path("./events"))
    ap.add_argument("--decoder", default="decoder/system-auth/0",
                    help="Decoder chain entry to harvest (default: %(default)s). "
                         "Pass an empty string for everything.")
    ap.add_argument("--agents", nargs="*", default=None)
    ap.add_argument("--action", nargs="*", default=None,
                    help="Only these event.action values")
    ap.add_argument("--days", type=int, default=7)
    ap.add_argument("--per-group", type=int, default=300,
                    help="Cap per group; distinct lines are preferred over "
                         "repeats of the same one (default: %(default)s)")
    ap.add_argument("--no-skip", action="store_true",
                    help="Do not filter out Wazuh's own application logs")
    ap.add_argument("--debug", action="store_true",
                    help="Print the query and the first matching document")
    ap.add_argument("--rule", action="append", metavar="ID_OR_TITLE_PREFIX",
                    help="Harvest the events behind a detection instead of "
                         "grouping by action. A UUID is matched as a rule id; "
                         "anything else as a case-insensitive title prefix "
                         "(e.g. 'DEMO -'). Repeat for several rules. Runs "
                         "INSTEAD of the normal event harvest.")
    ap.add_argument("--list-rules", action="store_true",
                    help="Show which rules have fired (count, id, title) in "
                         "the window, optionally narrowed by --rule, then exit")
    ap.add_argument("--top", type=int, default=25,
                    help="How many rules --list-rules shows (default: %(default)s)")
    ap.add_argument("--include-simulated", action="store_true",
                    help="Do not auto-exclude simulated agents from a rule "
                         "harvest (they are found from ./agents/*.json and "
                         "demo.conf, by id and by name)")
    ap.add_argument("--exclude-agents", nargs="*", default=None, metavar="ID",
                    help="Also leave these agent ids out, whatever "
                         "auto-detection finds")
    ap.add_argument("--max-findings", type=int, default=20000,
                    help="Stop scanning findings after this many "
                         "(default: %(default)s)")
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
    print(f"Connected to '{info.get('cluster_name')}'")

    if args.list_rules:
        return list_rules(args, idx)
    if args.rule:
        if not any(v.strip() for v in args.rule):
            ap.error("--rule needs a non-empty rule id or title prefix")
        return harvest_rules(args, idx, info)

    groups: dict[str, list[dict]] = defaultdict(list)
    seen: dict[str, set] = defaultdict(set)
    scanned = skipped = 0

    # Same safeguard as rule mode: events a simulated agent received were sent
    # by us, so harvesting them would feed the corpus its own output.
    ex_ids, ex_names = excluded_agents(args)
    query = build_query(args, ex_ids, ex_names)
    print(f"Harvesting {EVENT_INDICES}, last {args.days}d"
          + (f", decoder {args.decoder}" if args.decoder else "") + "\n")
    describe_exclusion(args, ex_ids, ex_names)
    if args.debug:
        print("  query:", json.dumps(query), "\n")

    for hit in idx.scroll(EVENT_INDICES, query):
        src = hit.get("_source", {})
        original = dig(src, "event.original")
        if not original:
            continue
        scanned += 1

        if args.debug and scanned == 1:
            print("  first match:", json.dumps(src)[:400], "\n")
        if not args.no_skip and should_skip(original):
            skipped += 1
            continue

        action = dig(src, "event.action") or "unclassified"
        platform = platform_of(src)
        group = f"{platform}-{action}"

        if len(groups[group]) >= args.per_group:
            continue
        # Prefer variety: skip a line we already have verbatim.
        if original in seen[group]:
            continue
        seen[group].add(original)

        groups[group].append({
            "original": original,
            "action": action,
            "outcome": dig(src, "event.outcome"),
            "decoders": dig(src, "wazuh.integration.decoders", []),
            "agent_id": dig(src, "wazuh.agent.id"),
            "platform": platform,
            "process": dig(src, "process.name"),
            "user": dig(src, "user.name"),
            "source_ip": dig(src, "source.ip"),
        })

    print(f"  scanned {scanned} documents, skipped {skipped} "
          f"(Wazuh's own logs), kept {sum(len(v) for v in groups.values())}")

    if not groups:
        print("\nNothing harvested.", file=sys.stderr)
        if scanned == 0:
            print("  The query matched no documents. Check the filter:",
                  file=sys.stderr)
            print("  " + json.dumps(query), file=sys.stderr)
            print("  Try: --decoder '' --days 90", file=sys.stderr)
        else:
            print(f"  {scanned} documents matched but all were skipped as "
                  f"Wazuh's own logs.", file=sys.stderr)
            print("  Use --no-skip to keep them.", file=sys.stderr)
        return 1

    outdir: Path = args.outdir
    (outdir / "events").mkdir(parents=True, exist_ok=True)

    manifest = {
        "harvested_at": datetime.now(timezone.utc).isoformat(),
        "source_url": args.url,
        "cluster": info.get("cluster_name"),
        "decoder_filter": args.decoder or "all",
        "days": args.days,
        "groups": {},
    }

    for group, records in sorted(groups.items()):
        path = outdir / "events" / f"{group}.jsonl"
        with path.open("w", encoding="utf-8") as fh:
            for r in records:
                fh.write(json.dumps(r, ensure_ascii=False) + "\n")
        manifest["groups"][group] = len(records)
        print(f"  {group:<40} {len(records):>5} lines")

    # Keep rule-driven groups (--rule) that live in the same corpus. Without
    # this, an ordinary re-harvest would rewrite the manifest and forget them.
    try:
        prev = json.loads((outdir / "manifest.json").read_text())
    except (OSError, ValueError):
        prev = {}
    for g, meta in (prev.get("rules") or {}).items():
        if (outdir / "events" / f"{g}.jsonl").exists():
            manifest.setdefault("rules", {})[g] = meta
            manifest["groups"][g] = meta.get("lines", 0)
    if "rules_harvested_at" in prev:
        manifest["rules_harvested_at"] = prev["rules_harvested_at"]

    (outdir / "manifest.json").write_text(json.dumps(manifest, indent=2))

    total = sum(len(v) for v in groups.values())
    print(f"\nHarvested {total} distinct lines into {outdir}")
    print(f"({scanned} scanned, {skipped} skipped as Wazuh's own logs)")

    fails = sum(len(v) for g, v in groups.items()
                if "failure" in g or "invalid" in g)
    if fails == 0:
        print("\nNOTE: no authentication failures in this corpus. Replaying it "
              "will produce benign activity only. To get attack material, "
              "generate real failures on a lab host (mistype an ssh password "
              "a few times) and harvest again.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
