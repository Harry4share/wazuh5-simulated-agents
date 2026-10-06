#!/usr/bin/env python3
"""
check_demo_rules.py

For each DEMO rule, answers three questions in order, and stops at the first
one that fails, because that is the link to fix:

  1. Did the real action reach the events index?   (from the REAL agent only)
  2. How did the decoder describe it?              (the fields the rule matches)
  3. Did a DEMO finding come out of it?

  export WAZUH_INDEXER_URL=https://127.0.0.1:9200
  export WAZUH_INDEXER_USER=admin
  export WAZUH_INDEXER_PASS=...
  python3 check_demo_rules.py                 # last 2 hours
  python3 check_demo_rules.py --minutes 15    # only what you just did

Only the real agents named below are looked at, so replayed events from
simulated agents can never make a rule look like it is working.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EVENTS = "wazuh-events-v5-*"
FINDINGS = "wazuh-findings-v5-*"

# What each rule matches, kept here so a mismatch can be pointed out.
RULES = [
    {
        "key": "linux", "label": "Linux",
        "title": "DEMO - Shadow file read via sudo",
        "agent_arg": "linux_agent",
        "action": "sudo  /etc/shadow",
        "run": "on ubuntu24:  sudo cat /etc/shadow >/dev/null",
        "event_clauses": [
            {"term": {"event.action": "sudo"}},
            {"wildcard": {"process.command_line": "*/etc/shadow*"}},
        ],
        "expect": {"event.action": "sudo"},
    },
    {
        "key": "macos", "label": "macOS",
        "title": "DEMO - Keychain secret read via sudo",
        "agent_arg": "macos_agent",
        "action": "sudo  find-generic-password",
        "run": "on the Mac VM:  sudo security find-generic-password -ga demo-item",
        "event_clauses": [
            {"term": {"event.action": "sudo"}},
            {"wildcard": {"process.command_line": "*find-generic-password*"}},
        ],
        "expect": {"event.action": "sudo"},
    },
    {
        "key": "windows", "label": "Windows",
        "title": "DEMO - User account created",
        "agent_arg": "windows_agent",
        "action": "event 4720",
        "run": ('in an ELEVATED prompt on win11:  net user demotest '
                '"Passw0rd!2026" /add   then   net user demotest /delete'),
        "event_clauses": [{"term": {"event.code": "4720"}}],
        # the two values the rule's detection block matches
        "expect": {"event.action": "user-created", "event.category": "iam"},
    },
]

SOURCE = ["@timestamp", "wazuh.agent.id", "wazuh.agent.name", "event.action",
          "event.category", "event.code", "process.command_line", "user.name"]


def dig(d, path, default=None):
    for part in path.split("."):
        if not isinstance(d, dict) or part not in d:
            return default
        d = d[part]
    return d


def search(s, url, index, body):
    r = s.post(f"{url}/{index}/_search", json=body, timeout=60)
    r.raise_for_status()
    return r.json()


def window(minutes):
    return {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}


def total(res):
    return res.get("hits", {}).get("total", {}).get("value", 0)


def check(s, url, rule, agent, minutes):
    out = {"agent": agent}

    ev = search(s, url, EVENTS, {
        "size": 1, "track_total_hits": True, "sort": [{"@timestamp": "desc"}],
        "_source": SOURCE,
        "query": {"bool": {"must": [{"term": {"wazuh.agent.id": agent}},
                                    window(minutes), *rule["event_clauses"]]}}})
    out["events"] = total(ev)
    out["event"] = (ev["hits"]["hits"] or [{}])[0].get("_source")

    fq = {"bool": {"must": [
        window(minutes),
        {"prefix": {"wazuh.rule.title":
                    {"value": rule["title"], "case_insensitive": True}}}]}}
    mine = dict(fq)
    mine = {"bool": {"must": fq["bool"]["must"]
                     + [{"term": {"wazuh.agent.id": agent}}]}}
    out["findings"] = total(search(s, url, FINDINGS,
                                   {"size": 0, "track_total_hits": True, "query": mine}))
    out["findings_any"] = total(search(s, url, FINDINGS,
                                       {"size": 0, "track_total_hits": True, "query": fq}))
    return out


def age_minutes(iso):
    from datetime import datetime, timezone
    try:
        t = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None
    return (datetime.now(timezone.utc) - t).total_seconds() / 60


# Account-management events a win11 box emits around creating/changing users.
ACCOUNT_CODES = ["4720", "4722", "4724", "4725", "4726", "4738"]


def diagnose(s, url, rule, agent, minutes):
    """Why might the action not have arrived? Two cheap questions.

    Is the agent sending anything at all right now, and has it EVER sent this
    kind of event? The first catches an offline agent, the second a collector
    that was never set up to capture it.
    """
    must_agent = {"term": {"wazuh.agent.id": agent}}
    last = search(s, url, EVENTS, {
        "size": 1, "sort": [{"@timestamp": "desc"}], "_source": ["@timestamp"],
        "query": {"bool": {"must": [must_agent]}}})
    last_ts = dig((last["hits"]["hits"] or [{}])[0].get("_source") or {}, "@timestamp")
    recent = total(search(s, url, EVENTS, {
        "size": 0, "track_total_hits": True,
        "query": {"bool": {"must": [must_agent, window(minutes)]}}}))

    info = {"last_ts": last_ts, "age": age_minutes(last_ts) if last_ts else None,
            "recent": recent}

    month = {"range": {"@timestamp": {"gte": "now-30d"}}}
    if rule["key"] == "windows":
        res = search(s, url, EVENTS, {
            "size": 0,
            "query": {"bool": {"must": [must_agent, month,
                                        {"terms": {"event.code": ACCOUNT_CODES}}]}},
            "aggs": {"c": {"terms": {"field": "event.code", "size": 10}}}})
        info["codes"] = {b["key"]: b["doc_count"]
                         for b in res.get("aggregations", {}).get("c", {}).get("buckets", [])}
    else:
        res = search(s, url, EVENTS, {
            "size": 1, "track_total_hits": True, "sort": [{"@timestamp": "desc"}],
            "_source": ["@timestamp", "process.command_line"],
            "query": {"bool": {"must": [must_agent, month,
                                        {"term": {"event.action": "sudo"}}]}}})
        info["sudo_count"] = total(res)
        info["sudo_last"] = dig((res["hits"]["hits"] or [{}])[0].get("_source") or {},
                                "process.command_line")
        # Lines from the sudo process that were decoded as something OTHER than
        # event.action=sudo. A collector can be forwarding sudo's output while
        # the decoder files it differently, and the query above cannot see that.
        res = search(s, url, EVENTS, {
            "size": 300, "track_total_hits": True, "sort": [{"@timestamp": "desc"}],
            "_source": ["@timestamp", "event.action", "event.category",
                        "process.command_line", "event.original"],
            "query": {"bool": {"must": [must_agent, month,
                                        {"term": {"process.name": "sudo"}}]}}})
        hits = [h.get("_source") or {} for h in res["hits"]["hits"]]
        # A genuine sudo log line carries COMMAND=. On macOS the collector also
        # forwards the sudo process's Activity/trace records (a few dozen per
        # run), which bury the real line when you only look at the newest few.
        real = [h for h in hits if "COMMAND=" in (dig(h, "event.original") or "")]
        info["proc_count"] = total(res)
        info["proc_fetched"] = len(hits)
        info["proc_real"] = real
        info["proc_noise"] = len(hits) - len(real)
    return info


def print_diagnosis(rule, agent, minutes, d):
    print(f"      Diagnosis for agent {agent}:")
    if d["last_ts"] is None:
        print(f"        - it has NEVER sent an event: wrong agent id, or it is not "
              f"enrolled/connected.")
        return
    age = d["age"]
    print(f"        - last event of any kind: {d['last_ts']}"
          + (f"  ({age:.0f} min ago)" if age is not None else "")
          + f";  {d['recent']} event(s) in the last {minutes} min")
    if age is not None and age > 15:
        print(f"        -> the agent has been silent for a while. Check it is "
              f"connected, then run the action again.")
        return
    if rule["key"] == "windows":
        codes = d.get("codes") or {}
        if codes:
            print("        - account-management events it HAS sent (30d): "
                  + ", ".join(f"{c} x{n}" for c, n in sorted(codes.items())))
            print("        -> it is sending and audits account changes, so most likely "
                  "the command was not run on this machine, or not elevated, or the "
                  "account was not created (check `net user` output).")
        else:
            print("        - it has sent NO account-management events in 30 days.")
            print("        -> user-account auditing may be off on this machine "
                  "(Audit User Account Management, success), so 4720 is never "
                  "written. Enable it, then run the action again.")
    else:
        n = d.get("sudo_count", 0)
        if n:
            print(f"        - it HAS sent {n} sudo event(s) in 30 days; latest: "
                  f"{d.get('sudo_last')}")
            print("        -> it is sending and does capture sudo, so most likely "
                  "the command was not run on this machine, or not yet.")
        elif d.get("proc_count"):
            real = d.get("proc_real", [])
            print(f"        - it has NEVER sent event.action=sudo, but it has sent "
                  f"{d['proc_count']} event(s) from the sudo process in 30 days.")
            print(f"        - of the latest {d['proc_fetched']}, {len(real)} carry "
                  f"COMMAND= (genuine sudo log lines); the other {d['proc_noise']} are "
                  f"Activity/trace chatter from the collector's activity setting.")
            if real:
                for sm in real[:3]:
                    print(f"            action={dig(sm,'event.action')}  "
                          f"category={dig(sm,'event.category')}  "
                          f"command_line={dig(sm,'process.command_line')}")
                    print(f"            raw: {(dig(sm,'event.original') or '')[:160]}")
                print("        -> genuine sudo lines ARE arriving but are not decoded as "
                      "event.action=sudo, so the rule cannot match them yet. Send me the "
                      "action/category shown above.")
            else:
                print("        -> no genuine sudo log line has arrived. Either macOS is not "
                      "writing it to the unified log, or the line is not being forwarded.")
                print("           On the Mac, right after a sudo command:")
                print("             sudo /usr/bin/log show --last 10m --info --predicate "
                      "'process == \"sudo\" and eventMessage contains \"COMMAND=\"' | tail -5")
        else:
            print("        - it has NEVER sent a sudo event in 30 days.")
            print("        -> either nobody ran sudo on it in that time, or its log "
                  "collection does not cover sudo.")
            print("           Tell them apart: run  sudo true  on that machine, wait "
                  "a minute, and re-run this check.")
            print("           If a sudo event still does not appear, the collector is "
                  "the problem (on macOS, check the logcollector query includes the "
                  "sudo process); running the action again will not help.")


def decoded_mismatches(rule, event):
    """Fields the rule matches that the decoder did NOT produce that way."""
    bad = []
    for field, want in rule["expect"].items():
        got = dig(event, field)
        values = got if isinstance(got, list) else [got]
        if want not in values:
            bad.append((field, want, got))
    return bad


def simulated_ids() -> set[str]:
    """Ids of the agents this toolkit enrolled (./agents/*.json beside the script)."""
    ids: set[str] = set()
    d = Path(__file__).resolve().parent / "agents"
    if d.is_dir():
        for f in d.glob("*.json"):
            try:
                ids.add(str(json.loads(f.read_text())["id"]))
            except (OSError, ValueError, KeyError):
                pass
    return ids


def resolve_agent(value: str) -> str:
    """An agent id, or the name of an agent enrolled by this toolkit.

    Anything else is refused outright. A typo or an unreplaced placeholder would
    otherwise be searched for as if it were an agent, find nothing, and look like
    a pipeline failure.
    """
    if value.isdigit():
        return value
    state = Path(__file__).resolve().parent / "agents" / f"{value}.json"
    try:
        return str(json.loads(state.read_text())["id"])
    except (OSError, ValueError, KeyError):
        print(f"ERROR: '{value}' is neither an agent id (digits) nor the name of an "
              f"enrolled agent (no state file {state}).", file=sys.stderr)
        sys.exit(2)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("WAZUH_INDEXER_URL"))
    ap.add_argument("--user", default=os.environ.get("WAZUH_INDEXER_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("WAZUH_INDEXER_PASS"))
    ap.add_argument("--minutes", type=int, default=120)
    ap.add_argument("--linux-agent", dest="linux_agent", default="002",
                    help="Linux agent id, or the name of an enrolled simulated agent "
                         "such as amzn-demo (default: %(default)s)")
    ap.add_argument("--macos-agent", dest="macos_agent", default="021",
                    help="real macOS agent id (default: %(default)s)")
    ap.add_argument("--windows-agent", dest="windows_agent", default="004",
                    help="real Windows agent id (default: %(default)s)")
    ap.add_argument("--only", nargs="+", choices=[r["key"] for r in RULES],
                    help="check just these platforms (default: all three)")
    ap.add_argument("--watch", type=int, default=0, metavar="SECONDS",
                    help="keep polling for up to this long, stopping as soon as every "
                         "selected rule has a finding. Run the action first, then this: "
                         "event lag and the detector's schedule stop mattering.")
    ap.add_argument("--interval", type=int, default=15,
                    help="seconds between polls with --watch (default: %(default)s)")
    args = ap.parse_args()
    if not args.url or not args.password:
        ap.error("--url and --password required (or WAZUH_INDEXER_URL / _PASS)")
    for name in ("linux_agent", "macos_agent", "windows_agent"):
        setattr(args, name, resolve_agent(getattr(args, name)))

    s = requests.Session()
    s.auth = (args.user, args.password)
    s.verify = False

    selected = [r for r in RULES if not args.only or r["key"] in args.only]

    if args.watch:
        import time
        deadline = time.time() + args.watch
        print(f"Watching up to {args.watch}s, polling every {args.interval}s "
              f"(stops when every selected rule has a finding)\n", flush=True)
        while True:
            done = True
            bits = []
            for rule in selected:
                try:
                    r = check(s, args.url, rule, getattr(args, rule["agent_arg"]),
                              args.minutes)
                except requests.RequestException as exc:
                    print(f"ERROR talking to the indexer: {exc}")
                    return 2
                bits.append(f"{rule['key']}: event={'yes' if r['events'] else 'no ':<3} "
                            f"finding={'yes' if r['findings'] else 'no'}")
                done = done and bool(r["findings"])
            print(time.strftime("[%H:%M:%S]  ") + "    ".join(bits), flush=True)
            if done or time.time() >= deadline:
                break
            time.sleep(args.interval)
        print()

    sim_ids = simulated_ids()
    print(f"DEMO rule pipeline, last {args.minutes} min "
          f"(simulated agents are marked)\n")
    worst = 0
    for rule in selected:
        agent = getattr(args, rule["agent_arg"])
        try:
            r = check(s, args.url, rule, agent, args.minutes)
        except requests.RequestException as exc:
            print(f"{rule['label']:<8} ERROR talking to the indexer: {exc}")
            return 2

        tag = " (simulated)" if agent in sim_ids else ""
        print(f"{rule['label']:<8} agent {agent}{tag}   {rule['title']}")
        if r["events"] == 0:
            print(f"   1. action reached the events index ........ NO")
            print(f"      Nothing from agent {agent} matching {rule['action']} in "
                  f"{args.minutes} min.")
            print(f"      Run it {rule['run']}")
            print(f"      Make sure it ran on THAT machine, then re-run this check.")
            try:
                print_diagnosis(rule, agent, args.minutes,
                                diagnose(s, args.url, rule, agent, args.minutes))
            except requests.RequestException as exc:
                print(f"      (diagnosis failed: {exc})")
            print()
            worst = max(worst, 1)
            continue
        print(f"   1. action reached the events index ........ yes  "
              f"({r['events']} event(s))")

        ev = r["event"] or {}
        shown = {k: dig(ev, k) for k in ("event.action", "event.category",
                                         "event.code", "process.command_line")
                 if dig(ev, k) is not None}
        print(f"   2. decoded as: " + ", ".join(f"{k}={v}" for k, v in shown.items()))
        bad = decoded_mismatches(rule, ev)
        for field, want, got in bad:
            print(f"      MISMATCH: the rule matches {field}={want!r} but the "
                  f"decoder produced {got!r}.")
            print(f"      Change that line in the rule (in Draft), then re-promote.")
        if bad:
            worst = max(worst, 1)

        if r["findings"]:
            print(f"   3. DEMO finding for this agent ............ yes  "
                  f"({r['findings']})\n")
            continue
        worst = max(worst, 1)
        print(f"   3. DEMO finding for this agent ............ NO")
        if bad:
            print(f"      Expected: the rule cannot match until the mismatch above "
                  f"is fixed.\n")
        else:
            print(f"      The event arrived and decodes as the rule expects, so look "
                  f"at the promotion/detector side:")
            print(f"        - is the rule in the Custom space with the current "
                  f"fields (re-promoted after edits)?")
            print(f"        - does an ENABLED detector include it, for the right "
                  f"log source?")
            print(f"        - findings lag the event by a few minutes.")
            if r["findings_any"]:
                print(f"      (the rule HAS fired {r['findings_any']} time(s) for "
                      f"other agents, so the rule and detector are live.)")
            print()
    if worst == 0:
        which = "All three rules" if len(selected) == len(RULES) else (
            "The selected rule" + ("s" if len(selected) > 1 else ""))
        agents = list(dict.fromkeys(getattr(args, r["agent_arg"]) for r in selected))
        real = [a for a in agents if a not in sim_ids]
        simulated = [a for a in agents if a in sim_ids]
        if simulated:
            print(f"{which} fired for simulated agent(s) {', '.join(simulated)}: "
                  f"findings from replayed events, not real actions.")
            print("Do NOT harvest from simulated agents: that would copy lines we sent "
                  "back into the corpus.")
        if real:
            print(f"{which} produced findings from real actions"
                  + (f" on agent(s) {', '.join(real)}." if simulated else "."))
            print(f'Next:  python3 wazuh_event_harvester.py --rule "DEMO -" '
                  f"--agents {' '.join(real)} --outdir ./events")
    return worst


if __name__ == "__main__":
    sys.exit(main())
