#!/usr/bin/env python3
"""
check_consistency.py

A simulated agent shows data that comes from DIFFERENT places, and nothing makes
them agree:

  registry   what the manager says about it: OS, version, architecture. This is
             what the dashboard header shows. It comes from the agent's keepalive.
  inventory  the recorded real machine's data, replayed: OS, hostname, hardware.
  events     what the manager stamps on its events and findings, and what the
             replayed log lines and file paths themselves look like.

This prints those side by side for every simulated agent and says exactly which
facets disagree, so a vague "the data looks inconsistent" becomes a specific list.

  cd /opt/wazuh-demo && set -a; source indexer.env; set +a
  python3 check_consistency.py
  python3 check_consistency.py --agent win-demo        # just one

Agents come from ./agents/*.json; the platform and mapped source from demo.conf.
The manager API (for the registry column) uses API_USER / API_PASS from demo.conf.
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


# ------------------------------------------------------------------ helpers ---
def dig(d, path, default=None):
    for part in path.split("."):
        if not isinstance(d, dict) or part not in d:
            return default
        d = d[part]
    return d


def load_conf() -> dict:
    conf: dict = {"agents": {}, "remap": {}}
    f = HERE / "demo.conf"
    if not f.is_file():
        return conf
    text = f.read_text(errors="replace")
    for key in ("MANAGER", "API_USER", "API_PASS"):
        m = re.search(rf'^{key}="?([^"\n]*)"?', text, re.M)
        conf[key] = m.group(1) if m else ""
    m = re.search(r'^AGENTS="\n?(.*?)"', text, re.S | re.M)
    for line in (m.group(1).splitlines() if m else []):
        p = line.strip().split(":")
        if len(p) >= 3:
            conf["agents"][p[0]] = p[1]                    # name -> profile
    m = re.search(r'^REMAP="([^"]*)"', text, re.M)
    for e in (m.group(1).split() if m else []):
        p = e.split(":")                                   # SOURCE:NEW:NAME:HOST
        if len(p) >= 2:
            conf["remap"][p[1]] = p[0]                     # new id -> source id
    return conf


def simulated_agents(conf: dict, only: str | None):
    out = []
    d = HERE / "agents"
    for f in sorted(d.glob("*.json")) if d.is_dir() else []:
        try:
            o = json.loads(f.read_text())
        except (OSError, ValueError):
            continue
        name = o.get("name") or f.stem
        if not o.get("id"):
            continue                       # not a state file (an agent always has an id)
        if only and only not in (name, str(o.get("id"))):
            continue
        out.append({"id": str(o.get("id")), "name": name,
                    "profile": conf["agents"].get(name, "?")})
    return out


def norm_tokens(name: str) -> set[str]:
    t = re.sub(r"[^a-z0-9 ]", " ", (name or "").lower()).split()
    return {w for w in t if w not in ("microsoft", "gnu", "linux")}


def same_os(a: str, b: str) -> bool:
    ta, tb = norm_tokens(a), norm_tokens(b)
    return not ta or not tb or ta <= tb or tb <= ta


def lead_version(v: str) -> str:
    m = re.match(r"\d+(\.\d+)*", (v or "").strip())
    return m.group(0) if m else ""


def same_version(a: str, b: str) -> bool:
    va, vb = lead_version(a), lead_version(b)
    return not va or not vb or va.startswith(vb) or vb.startswith(va)


def norm_arch(a: str) -> str:
    a = (a or "").lower()
    return {"amd64": "x86_64", "x64": "x86_64", "aarch64": "arm64"}.get(a, a)


def kind_of_line(raw: str) -> str | None:
    """Which platform a raw log line looks like, or None if it cannot be told."""
    r = raw.lstrip()
    if r.startswith("<Event"):
        return "windows"
    if re.match(r"\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d+[+-]\d{4}", r):
        return "macos"
    if re.match(r"[A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d ", r):
        return "linux"
    return None


def path_style(p: str) -> str | None:
    if re.match(r"[A-Za-z]:[\\/]", p or ""):
        return "windows"
    if (p or "").startswith("/"):
        return "unix"
    return None


# --------------------------------------------------------------------- main ---
def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("WAZUH_INDEXER_URL"))
    ap.add_argument("--user", default=os.environ.get("WAZUH_INDEXER_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("WAZUH_INDEXER_PASS"))
    ap.add_argument("--api-url", help="manager API base (default https://MANAGER:55000)")
    ap.add_argument("--agent", help="only this agent, by name or id")
    args = ap.parse_args()
    if not args.url or not args.password:
        ap.error("--url and --password required (or WAZUH_INDEXER_URL / _PASS)")

    conf = load_conf()
    agents = simulated_agents(conf, args.agent)
    if not agents:
        print("No simulated agents found in ./agents/*.json.", file=sys.stderr)
        return 2

    s = requests.Session()
    s.auth = (args.user, args.password)
    s.verify = False

    def search(index, body):
        r = s.post(f"{args.url}/{index}/_search", json=body, timeout=60)
        r.raise_for_status()
        return r.json()

    # ---- registry, from the manager API ----
    registry: dict = {}
    api = args.api_url or (f"https://{conf.get('MANAGER')}:55000" if conf.get("MANAGER") else "")
    api_note = ""
    if api and conf.get("API_PASS"):
        try:
            tok = requests.post(f"{api}/security/user/authenticate?raw=true",
                                auth=(conf.get("API_USER") or "wazuh-wui", conf["API_PASS"]),
                                verify=False, timeout=30).text.strip()
            ids = ",".join(a["id"] for a in agents)
            # No `select`: the API only allows os.name / os.version / os.arch style field names
            # there, and rejects a bare "os" with HTTP 400. Full records carry the os object.
            r = requests.get(f"{api}/agents", params={"agents_list": ids},
                             headers={"Authorization": f"Bearer {tok}"}, verify=False, timeout=30)
            for it in r.json().get("data", {}).get("affected_items", []):
                registry[str(it["id"])] = it
            if not registry:
                # A wrong password gives an error body, not a token, and the agent list then
                # comes back empty. Say so rather than printing a column of dashes.
                why = ("Check API_USER and API_PASS in demo.conf"
                       if r.status_code in (401, 403) else "see the response above")
                api_note = (f"the manager API answered HTTP {r.status_code} with no agents "
                            f"({r.text.strip()[:200]}). {why}; the registry column is empty "
                            f"until that works")
        except (requests.RequestException, ValueError, KeyError) as exc:
            api_note = f"manager API unavailable ({exc})"
    else:
        api_note = "no API_PASS in demo.conf, so the registry column is skipped"

    total_problems = 0
    for a in agents:
        aid, name, profile = a["id"], a["name"], a["profile"]
        src = conf["remap"].get(aid)
        print(f"{name}   agent {aid}   {profile}   "
              + (f"inventory from source {src}" if src else "NOT MAPPED to an inventory source"))
        problems: list[str] = []

        # inventory: system + hardware
        sysdoc = {}
        h = search("wazuh-states-inventory-system", {"size": 1, "query": {"term": {"wazuh.agent.id": aid}}})["hits"]["hits"]
        if h:
            sysdoc = h[0]["_source"]
        hw = {}
        h = search("wazuh-states-inventory-hardware", {"size": 1, "query": {"term": {"wazuh.agent.id": aid}}})["hits"]["hits"]
        if h:
            hw = h[0]["_source"]
        inv_os = dig(sysdoc, "host.os.name", "")
        inv_ver = dig(sysdoc, "host.os.version", "")
        inv_host = dig(sysdoc, "host.hostname") or dig(sysdoc, "host.name") or ""
        inv_arch = dig(sysdoc, "host.architecture", "")

        # registry
        reg = (registry.get(aid) or {}).get("os") or {}
        reg_os, reg_ver, reg_arch = reg.get("name", ""), reg.get("version", ""), reg.get("arch", "")

        # events: latest enrichment + recent content
        ev = search("wazuh-events-v5-*", {
            "size": 300, "sort": [{"@timestamp": "desc"}],
            "_source": ["wazuh.agent.host", "event.original", "file.path"],
            "query": {"term": {"wazuh.agent.id": aid}}})["hits"]["hits"]
        enr = (ev[0]["_source"].get("wazuh", {}).get("agent", {}).get("host") if ev else None) or {}
        ev_os, ev_ver = dig(enr, "os.name", ""), dig(enr, "os.version", "")
        ev_host, ev_arch = enr.get("hostname", ""), enr.get("architecture", "")

        def show(label, r, i, e):
            print(f"    {label:<13} registry: {r or '-':<38} inventory: {i or '-':<40} events: {e or '-'}")

        show("OS", f"{reg_os} {reg_ver}".strip(), f"{inv_os} {inv_ver}".strip(), f"{ev_os} {ev_ver}".strip())
        show("hostname", "", inv_host, ev_host)
        show("architecture", reg_arch, inv_arch, ev_arch)
        cpu = dig(hw, "host.cpu.name")
        if cpu or dig(hw, "host.memory.total"):
            print(f"    {'hardware':<13} {cpu or '-'}, {dig(hw, 'host.cpu.cores', '?')} cores, "
                  f"memory {dig(hw, 'host.memory.total', '?')}")

        if reg and inv_os and (not same_os(reg_os, inv_os) or not same_version(reg_ver, inv_ver)):
            problems.append(f"OS: the manager shows '{reg_os} {reg_ver}' (dashboard header) but the "
                            f"inventory is '{inv_os} {inv_ver}'.")
        if ev_os and inv_os and (not same_os(ev_os, inv_os) or not same_version(ev_ver, inv_ver)):
            problems.append(f"OS: events and findings are stamped '{ev_os} {ev_ver}' but the "
                            f"inventory is '{inv_os} {inv_ver}'.")
        if inv_host and ev_host and inv_host.lower() != ev_host.lower():
            problems.append(f"hostname: inventory says '{inv_host}', events say '{ev_host}'.")
        archs = {norm_arch(x) for x in (reg_arch, inv_arch, ev_arch) if x}
        if len(archs) > 1:
            problems.append(f"architecture differs across sources: {sorted(archs)}.")

        # content: do the replayed lines and paths look like THIS platform?
        kinds, styles = Counter(), Counter()
        for h in ev:
            sc = h["_source"]
            k = kind_of_line(dig(sc, "event.original", "") or "")
            if k:
                kinds[k] += 1
            ps = path_style(dig(sc, "file.path", "") or "")
            if ps:
                styles[ps] += 1
        want_style = "windows" if profile == "windows" else "unix"
        foreign = {k: n for k, n in kinds.items() if profile in ("windows", "linux", "macos") and k != profile}
        wrong_paths = {k: n for k, n in styles.items() if k != want_style}
        print(f"    content       {len(ev)} recent events: "
              + (", ".join(f"{n} look like {k}" for k, n in kinds.most_common()) or "no identifiable log lines")
              + ("; file paths: " + ", ".join(f"{n} {k}-style" for k, n in styles.most_common()) if styles else ""))
        if foreign:
            problems.append("log lines from another platform: "
                            + ", ".join(f"{n} {k}-style" for k, n in foreign.items())
                            + f" on a {profile} agent.")
        if wrong_paths:
            problems.append("file paths from another platform: "
                            + ", ".join(f"{n} {k}-style" for k, n in wrong_paths.items())
                            + f" on a {profile} agent.")
        if not ev:
            problems.append("no events yet for this agent, so only inventory can be compared.")

        for p in problems:
            print(f"    MISMATCH  {p}")
        if not problems:
            print("    consistent")
        total_problems += len([p for p in problems if not p.startswith("no events")])
        print()

    if api_note:
        print(f"note: {api_note}\n")
    if total_problems:
        print(f"{total_problems} inconsistenc{'y' if total_problems == 1 else 'ies'} found.")
        print("The OS, hostname and architecture the manager shows come from the simulated agent's own\n"
              "keepalive, not from the machine its inventory was recorded on; the two are set\n"
              "independently. Send me this output and tell me which panel looks wrong.")
    return 1 if total_problems else 0


if __name__ == "__main__":
    sys.exit(main())
