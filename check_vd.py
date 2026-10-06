#!/usr/bin/env python3
"""
check_vd.py

Why does a simulated agent's Vulnerability Detection panel look empty (or wrong)?

A simulated agent can only show vulnerability data that was RECORDED from a real
agent. This compares, for every recorded source, what the fixtures hold with what the
live indexer holds for that real agent right now, and says which of these you are in:

  - the real agent HAS vulnerabilities now but the fixtures do not -> refresh the fixtures
  - the real agent is connected but has none at all               -> nothing to replay;
                                                                     fix it at the source
  - the real agent is not connected                               -> reconnect it first

  cd /opt/wazuh-demo && set -a; source indexer.env; set +a
  python3 check_vd.py

Read-only. The refresh it recommends is `wazuh_fixture_recorder.py --merge`, which
replaces only the agents you name and backs up the fixtures first.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
HERE = Path(__file__).resolve().parent


def aid_of(src: dict) -> str:
    a = (src.get("wazuh") or {}).get("agent") or {}
    return str(a.get("id") or "")


def read_docs(fixtures: Path, name: str):
    f = fixtures / "docs" / f"{name}.jsonl"
    if not f.exists():
        return
    with f.open(encoding="utf-8") as fh:
        for line in fh:
            try:
                yield json.loads(line)["_source"]
            except (ValueError, KeyError, TypeError):
                continue


def load_conf() -> dict:
    conf = {}
    f = HERE / "demo.conf"
    if f.is_file():
        text = f.read_text(errors="replace")
        for key in ("MANAGER", "API_USER", "API_PASS"):
            m = re.search(rf'^{key}="?([^"\n]*)"?', text, re.M)
            conf[key] = m.group(1) if m else ""
    return conf


def fit_of(platform: str, name: str) -> str:
    t = f"{platform or ''} {name or ''}".lower()
    if "windows" in t:
        return "windows"
    if "darwin" in t or "macos" in t:
        return "macos"
    return "linux"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("WAZUH_INDEXER_URL"))
    ap.add_argument("--user", default=os.environ.get("WAZUH_INDEXER_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("WAZUH_INDEXER_PASS"))
    ap.add_argument("--fixtures", type=Path, default=HERE / "fixtures")
    ap.add_argument("--api-url", help="manager API base (default https://MANAGER:55000)")
    args = ap.parse_args()
    if not args.url or not args.password:
        ap.error("--url and --password required (or WAZUH_INDEXER_URL / _PASS)")

    # ---- the recorded sources and what the fixtures hold ----
    info = {}
    for src in read_docs(args.fixtures, "wazuh-states-inventory-system"):
        a = aid_of(src)
        os_ = (src.get("host") or {}).get("os") or {}
        if a:
            info[a] = {"os": f"{os_.get('name', '?')} {os_.get('version', '')}".strip(),
                       "fit": fit_of(os_.get("platform"), os_.get("name"))}
    if not info:
        print(f"No recorded sources found under {args.fixtures}/docs.", file=sys.stderr)
        return 2
    fixed = Counter(aid_of(s) for s in read_docs(args.fixtures, "wazuh-states-vulnerabilities"))

    # ---- what the live index holds now ----
    s = requests.Session()
    s.auth = (args.user, args.password)
    s.verify = False
    try:
        r = s.post(f"{args.url}/wazuh-states-vulnerabilities*/_search", timeout=60, json={
            "size": 0, "aggs": {"a": {"terms": {"field": "wazuh.agent.id", "size": 500}}}})
        r.raise_for_status()
        live = Counter({b["key"]: b["doc_count"]
                        for b in r.json()["aggregations"]["a"]["buckets"]})
    except (requests.RequestException, KeyError, ValueError) as exc:
        print(f"Could not read the live vulnerability index: {exc}", file=sys.stderr)
        return 2

    # ---- are the real agents connected? ----
    conf = load_conf()
    status: dict = {}
    note = ""
    api = args.api_url or (f"https://{conf.get('MANAGER')}:55000" if conf.get("MANAGER") else "")
    if api and conf.get("API_PASS"):
        try:
            tok = requests.post(f"{api}/security/user/authenticate?raw=true",
                                auth=(conf.get("API_USER") or "wazuh-wui", conf["API_PASS"]),
                                verify=False, timeout=30).text.strip()
            rr = requests.get(f"{api}/agents", params={"agents_list": ",".join(info)},
                              headers={"Authorization": f"Bearer {tok}"}, verify=False, timeout=30)
            for it in rr.json().get("data", {}).get("affected_items", []):
                status[str(it["id"])] = it.get("status", "?")
            if not status:
                note = f"manager API answered HTTP {rr.status_code} with no agents ({rr.text[:140].strip()})"
        except (requests.RequestException, ValueError, KeyError) as exc:
            note = f"manager API unavailable ({exc})"
    else:
        note = "no API_PASS in demo.conf, so connection status is not shown"

    print(f"{'source':<7} {'fits':<8} {'status':<13} {'fixtures':>9} {'live':>7}   OS")
    refresh: list[str] = []
    hints: list[str] = []
    for a in sorted(info):
        st = status.get(a, "?")
        fx, lv = fixed[a], live[a]
        if lv > fx:
            verdict = f"LIVE HAS MORE: refresh the fixtures ({fx} -> {lv})"
            refresh.append(a)
        elif lv == 0 and fx == 0:
            if st == "active":
                verdict = "connected but NO vulnerability data anywhere: nothing to replay"
                hints.append(a)
            elif st == "?" and status:
                # The manager answered, but does not list this agent: deleted, or never enrolled.
                # There is nothing to fix on a machine that is not an agent any more.
                verdict = ("none recorded, none live, and the manager does not list this agent "
                           "(deleted?). Do not use it as a source")
            elif st == "?":
                verdict = "none recorded and none live (connection status unknown)"
                hints.append(a)
            else:
                verdict = f"none recorded; agent is {st}, so it cannot produce any"
        elif fx > 0 and lv == 0:
            verdict = "recorded data kept; the live index has lost it (do not re-record)"
        else:
            verdict = "ok"
        print(f"{a:<7} {info[a]['fit']:<8} {st:<13} {fx:>9} {lv:>7}   {info[a]['os']}")
        print(f"          -> {verdict}")

    if refresh:
        ids = " ".join(refresh)
        print("\nRefresh just those sources. --merge leaves every other agent's fixtures alone "
              "and backs the directory up first:")
        print(f"  python3 wazuh_fixture_recorder.py --agents {ids} --outdir ./fixtures --merge")
        print("  ./democtl reload        # the replay reads the fixtures once, at start")
    if hints:
        print("\nFor the agents with no vulnerability data at all:")
        for a in hints:
            if info[a]["fit"] == "macos":
                print(f"  {a} (macOS): the known first-sync failure never retries. On that Mac:")
                print("      sudo /Library/Ossec/bin/wazuh-control stop")
                print("      sudo rm /Library/Ossec/queue/syscollector/db/local.db")
                print("      sudo /Library/Ossec/bin/wazuh-control start")
                print("    then wait for a full sync and run this again.")
            else:
                print(f"  {a} ({info[a]['fit']}): check what the manager's vulnerability scanner "
                      f"says about this agent:")
                print("      grep -iE 'vulnerab|scanner' /var/wazuh-manager/logs/wazuh-manager.log | tail -30")
    if note:
        print(f"\nnote: {note}")
    return 1 if (refresh or hints) else 0


if __name__ == "__main__":
    sys.exit(main())
