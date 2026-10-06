#!/usr/bin/env python3
"""
check_coverage.py

"Does every visualization have data?" made measurable.

For every simulated agent this checks each family of data that feeds an ENDPOINT
dashboard module, applies what that platform can reasonably be expected to produce, and
gives every gap a remedy:

  IT Hygiene                 inventory: system, hardware, packages, processes, ports,
                             services, users, groups, interfaces, networks, protocols,
                             (Windows) hotfixes
  Vulnerability Detection    wazuh-states-vulnerabilities
  Configuration Assessment   wazuh-states-sca
  File Integrity Monitoring  state (files, and registry on Windows) and FIM findings
  Threat Hunting             events by category, in the time window
  Findings                   count, severity spread, latest
  MITRE ATT&CK               distinct tactics seen in findings
  Compliance                 which frameworks the findings carry

It does NOT cover modules that only fill from other sources (Docker, AWS, GCP, Azure,
GitHub, Office 365, Suricata, ...). A simulated endpoint agent cannot feed those.

  cd /opt/wazuh-demo && set -a; source indexer.env; set +a
  python3 check_coverage.py                 # last 24 hours, every simulated agent
  python3 check_coverage.py --hours 72
  python3 check_coverage.py --agent win-demo

Exit status 1 if any required family is empty.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
HERE = Path(__file__).resolve().parent

REQ, OPT, NA = "required", "optional", "n/a"

# state index -> (module, {platform: expectation})
STATES = [
    ("wazuh-states-inventory-system",             "IT Hygiene", {"linux": REQ, "macos": REQ, "windows": REQ}),
    ("wazuh-states-inventory-hardware",           "IT Hygiene", {"linux": REQ, "macos": REQ, "windows": REQ}),
    ("wazuh-states-inventory-packages",           "IT Hygiene", {"linux": REQ, "macos": REQ, "windows": REQ}),
    ("wazuh-states-inventory-processes",          "IT Hygiene", {"linux": REQ, "macos": REQ, "windows": REQ}),
    ("wazuh-states-inventory-ports",              "IT Hygiene", {"linux": REQ, "macos": REQ, "windows": REQ}),
    ("wazuh-states-inventory-services",           "IT Hygiene", {"linux": REQ, "macos": OPT, "windows": REQ}),
    ("wazuh-states-inventory-users",              "IT Hygiene", {"linux": REQ, "macos": REQ, "windows": REQ}),
    ("wazuh-states-inventory-groups",             "IT Hygiene", {"linux": REQ, "macos": REQ, "windows": REQ}),
    ("wazuh-states-inventory-interfaces",         "IT Hygiene", {"linux": REQ, "macos": REQ, "windows": REQ}),
    ("wazuh-states-inventory-networks",           "IT Hygiene", {"linux": REQ, "macos": REQ, "windows": REQ}),
    ("wazuh-states-inventory-protocols",          "IT Hygiene", {"linux": REQ, "macos": REQ, "windows": REQ}),
    ("wazuh-states-inventory-hotfixes",           "IT Hygiene", {"linux": NA,  "macos": NA,  "windows": REQ}),
    ("wazuh-states-inventory-browser-extensions", "IT Hygiene", {"linux": OPT, "macos": OPT, "windows": OPT}),
    ("wazuh-states-vulnerabilities",              "Vulnerability Detection", {"linux": REQ, "macos": REQ, "windows": REQ}),
    ("wazuh-states-sca",                          "Configuration Assessment", {"linux": REQ, "macos": REQ, "windows": REQ}),
    ("wazuh-states-fim-files",                    "File Integrity Monitoring", {"linux": REQ, "macos": REQ, "windows": REQ}),
    ("wazuh-states-fim-registry-keys",            "File Integrity Monitoring", {"linux": NA,  "macos": NA,  "windows": REQ}),
    ("wazuh-states-fim-registry-values",          "File Integrity Monitoring", {"linux": NA,  "macos": NA,  "windows": REQ}),
]

EVENT_CATEGORIES = ["system-activity", "access-management", "security", "network-activity", "applications"]

# findings families: key -> (label, title match, {platform: expectation})
FAMILIES = {
    "fim":     ("FIM findings",              {"prefix": "Wazuh FIM"},                    {"linux": REQ, "macos": REQ, "windows": REQ}),
    "auth":    ("Authentication findings",   {"wildcard": "*authentication*"},           {"linux": REQ, "macos": OPT, "windows": REQ}),
    "sudo":    ("Sudo findings",             {"prefix": "Sudo command"},                 {"linux": REQ, "macos": OPT, "windows": NA}),
    "malware": ("Malware / rootcheck",       {"prefix": "Wazuh Rootcheck"},              {"linux": OPT, "macos": OPT, "windows": OPT}),
    "demo":    ("Custom DEMO rule findings", {"prefix": "DEMO -"},                       {"linux": OPT, "macos": OPT, "windows": OPT}),
}
FRAMEWORKS = ["pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc", "iso_27001", "nis2", "nist_800_171", "fedramp", "cmmc"]

REMEDY = {
    "states": "./democtl agent map <agent> <source>, then ./democtl reload. If the recorded source lacks it, refresh or "
              "re-record the source (check_vd.py, wazuh_fixture_recorder.py --merge).",
    "vd":     "python3 check_vd.py (does the real agent have vulnerabilities now? then refresh the fixtures with --merge).",
    "fim_state": "turn on 'File integrity' in the UI (INCLUDE_FIM=yes), ./democtl reload, then ./democtl fim <agent>.",
    "events": "./democtl events <agent> security-alerts (and ambient). Allow a few minutes for the detectors.",
    "fim":    "./democtl fim <agent>",
    "auth":   "./democtl events <agent> brute-force   (needs authentication lines in the recorded corpus)",
    "sudo":   "./democtl events <agent> privilege-escalation   (needs sudo lines in the recorded corpus)",
    "mitre":  "send more varied scenarios: security-alerts, brute-force, privilege-escalation, session-activity, fim-changes",
    "compliance": "findings from stock rules carry compliance arrays; custom DEMO rules do not unless you add them",
}


def dig(d, path, default=None):
    for part in path.split("."):
        if not isinstance(d, dict) or part not in d:
            return default
        d = d[part]
    return d


def load_conf() -> dict:
    conf: dict = {"agents": {}}
    f = HERE / "demo.conf"
    if not f.is_file():
        return conf
    text = f.read_text(errors="replace")
    m = re.search(r'^AGENTS="\n?(.*?)"', text, re.S | re.M)
    for line in (m.group(1).splitlines() if m else []):
        p = line.strip().split(":")
        if len(p) >= 3:
            conf["agents"][p[0]] = p[1]
    return conf


def simulated_agents(conf: dict, only: str | None):
    out = []
    d = HERE / "agents"
    for f in sorted(d.glob("*.json")) if d.is_dir() else []:
        try:
            o = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        if not o.get("id"):
            continue
        name = o.get("name") or f.stem
        if only and only not in (name, str(o["id"])):
            continue
        out.append({"id": str(o["id"]), "name": name, "profile": conf["agents"].get(name, "linux")})
    return out


def verdict(expect: str, n: int) -> str:
    if expect == NA:
        return "n/a"
    if n > 0:
        return "ok"
    return "GAP" if expect == REQ else "empty (optional)"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("WAZUH_INDEXER_URL"))
    ap.add_argument("--user", default=os.environ.get("WAZUH_INDEXER_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("WAZUH_INDEXER_PASS"))
    ap.add_argument("--hours", type=int, default=24, help="events/findings window (default: %(default)s)")
    ap.add_argument("--agent", help="only this agent, by name or id")
    args = ap.parse_args()
    if not args.url or not args.password:
        ap.error("--url and --password required (or WAZUH_INDEXER_URL / _PASS)")

    s = requests.Session()
    s.auth = (args.user, args.password)
    s.verify = False

    def search(index, body):
        r = s.post(f"{args.url}/{index}/_search", json=body, timeout=90)
        r.raise_for_status()
        return r.json()

    agents = simulated_agents(load_conf(), args.agent)
    if not agents:
        print("No simulated agents found in ./agents/*.json.", file=sys.stderr)
        return 2

    since = {"range": {"@timestamp": {"gte": f"now-{args.hours}h"}}}
    total_gaps = 0
    for a in agents:
        aid, name, plat = a["id"], a["name"], a["profile"] if a["profile"] in ("linux", "macos", "windows") else "linux"
        gaps: list[tuple[str, str, str]] = []
        print(f"{name}   agent {aid}   {plat}")

        # ---- states ----
        res = search("wazuh-states-*", {"size": 0, "query": {"term": {"wazuh.agent.id": aid}},
                                        "aggs": {"idx": {"terms": {"field": "_index", "size": 100}}}})
        have = {b["key"]: b["doc_count"] for b in res["aggregations"]["idx"]["buckets"]}
        module = None
        for index, mod, expect in STATES:
            # exact name, or with a node suffix some builds add (wazuh-states-...-<node>)
            n = sum(c for k, c in have.items() if k == index or k.startswith(index + "-"))
            v = verdict(expect[plat], n)
            if mod != module:
                print(f"  {mod}")
                module = mod
            label = index.replace("wazuh-states-", "")
            print(f"    {label:<34} {n:>8}   {v}")
            if v == "GAP":
                key = "vd" if "vulnerab" in index else "fim_state" if "fim" in index else "states"
                gaps.append((mod, label, REMEDY[key]))

        # ---- events ----
        res = search("wazuh-events-v5-*", {"size": 0,
                     "query": {"bool": {"filter": [{"term": {"wazuh.agent.id": aid}}, since]}},
                     "aggs": {"idx": {"terms": {"field": "_index", "size": 30}},
                              "last": {"max": {"field": "@timestamp"}}}})
        by_cat = {c: 0 for c in EVENT_CATEGORIES}
        for b in res["aggregations"]["idx"]["buckets"]:
            for c in EVENT_CATEGORIES:
                if c in b["key"]:
                    by_cat[c] += b["doc_count"]
        ev_total = sum(by_cat.values())
        print(f"  Threat Hunting (events, last {args.hours}h)")
        print(f"    {'all categories':<34} {ev_total:>8}   {verdict(REQ, ev_total)}")
        for c, n in by_cat.items():
            print(f"      {c:<32} {n:>8}")
        if ev_total == 0:
            gaps.append(("Threat Hunting", "events", REMEDY["events"]))

        # ---- findings ----
        def fam_filter(spec):
            (kind, val), = spec.items()
            return {kind: {"wazuh.rule.title": {"value": val, "case_insensitive": True}}}

        aggs = {
            "level": {"terms": {"field": "wazuh.rule.level", "size": 10}},
            "tactic": {"terms": {"field": "wazuh.rule.mitre.tactic.name", "size": 30}},
            "fam": {"filters": {"filters": {k: fam_filter(v[1]) for k, v in FAMILIES.items()}}},
            "comp": {"filters": {"filters": {fw: {"exists": {"field": f"wazuh.rule.compliance.{fw}"}}
                                             for fw in FRAMEWORKS}}},
            "last": {"max": {"field": "@timestamp"}},
        }
        res = search("wazuh-findings-v5-*", {"size": 0, "track_total_hits": True,
                     "query": {"bool": {"filter": [{"term": {"wazuh.agent.id": aid}}, since]}}, "aggs": aggs})
        f_total = res["hits"]["total"]["value"]
        ag = res["aggregations"]
        print(f"  Findings (last {args.hours}h)")
        print(f"    {'total':<34} {f_total:>8}   {verdict(REQ, f_total)}")
        if f_total == 0:
            gaps.append(("Findings", "total", REMEDY["events"]))
        levels = {b["key"]: b["doc_count"] for b in ag["level"]["buckets"]}
        print(f"    {'severity levels':<34} {len(levels):>8}   " + (", ".join(f"{k} {v}" for k, v in levels.items()) or "none"))
        for k, (label, _, expect) in FAMILIES.items():
            n = ag["fam"]["buckets"][k]["doc_count"]
            v = verdict(expect[plat], n)
            print(f"    {label:<34} {n:>8}   {v}")
            if v == "GAP":
                gaps.append(("Findings", label, REMEDY.get(k, REMEDY["events"])))
        tactics = [b["key"] for b in ag["tactic"]["buckets"]]
        print(f"  MITRE ATT&CK")
        print(f"    {'distinct tactics':<34} {len(tactics):>8}   "
              + ("GAP" if not tactics else "ok" if len(tactics) >= 3 else "thin (fewer than 3)")
              + (f"   {', '.join(tactics)}" if tactics else ""))
        if not tactics:
            gaps.append(("MITRE ATT&CK", "distinct tactics", REMEDY["mitre"]))
        fws = [fw for fw, b in ag["comp"]["buckets"].items() if b["doc_count"]]
        print(f"  Compliance")
        print(f"    {'frameworks present':<34} {len(fws):>8}   " + ("GAP" if not fws else "ok") + (f"   {', '.join(fws)}" if fws else ""))
        if not fws:
            gaps.append(("Compliance", "frameworks present", REMEDY["compliance"]))
        elif f_total:
            print("      (findings carry the data. If the dashboard's Compliance panel is still empty, it reads "
                  "something else; that is a dashboard question this tool cannot answer.)")

        if gaps:
            print(f"  -> {len(gaps)} gap(s):")
            for mod, what, fix in gaps:
                print(f"     - {mod}: {what}\n         {fix}")
        else:
            print("  -> no gaps in the families this tool can see")
        total_gaps += len(gaps)
        print()

    print("Not covered: modules that fill only from other sources (Docker, AWS, GCP, Azure, GitHub, Office 365,"
          " Suricata). A simulated endpoint agent cannot feed them.")
    return 1 if total_gaps else 0


if __name__ == "__main__":
    sys.exit(main())
