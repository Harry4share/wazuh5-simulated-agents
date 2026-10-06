#!/usr/bin/env python3
"""
inspect_detection.py

Answers two questions about the DEMO rules, from the indexer itself:

  1. What do the PROMOTED copies say? (v1 matched process.args, which sudo
     events never have; v2 matches process.command_line. Editing a rule in
     Draft does not change the copy that was already promoted.)
  2. Is each rule actually included in an ENABLED detector? A rule that no
     detector runs never produces a finding.

  export WAZUH_INDEXER_URL=https://127.0.0.1:9200
  export WAZUH_INDEXER_USER=admin
  export WAZUH_INDEXER_PASS=...
  python3 inspect_detection.py
  python3 inspect_detection.py --prefix "DEMO -" --raw     # dump raw JSON too

It uses the Security Analytics plugin's own API and falls back to reading the
plugin's config indices, and says which one worked. If neither returns
anything, run it with --raw and send me the output.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ALL = {"size": 2000, "query": {"match_all": {}}}


def post(s, url, path, body):
    r = s.post(url + path, json=body, timeout=60)
    try:
        data = r.json()
    except ValueError:
        data = {"_raw": r.text[:300]}
    return r.status_code, data


def hits_from(s, url, attempts):
    """First attempt that returns a search result. Returns (hits, label, notes)."""
    notes = []
    for label, path in attempts:
        try:
            code, data = post(s, url, path, ALL)
        except requests.RequestException as exc:
            notes.append(f"{label}: {exc}")
            continue
        if code == 200 and isinstance(data.get("hits"), dict):
            return data["hits"].get("hits", []), label, notes
        notes.append(f"{label}: HTTP {code} {json.dumps(data)[:160]}")
    return [], None, notes


def space_of(src):
    sp = src.get("space")
    return (sp.get("name") if isinstance(sp, dict) else sp) or "?"


def ids_of(hit):
    """Every id a rule may be referenced by. The store's _id is one; the id inside
    the rule's own YAML (and a document id, if present) are others, and a detector
    may use any of them."""
    import re
    src = hit.get("_source", {})
    ids = {hit.get("_id")}
    doc = src.get("document")
    if isinstance(doc, dict) and doc.get("id"):
        ids.add(doc["id"])
    body = src.get("rule")
    if isinstance(body, str):
        ids.update(re.findall(r"(?m)^\s*id:\s*([0-9A-Fa-f-]{36})\s*$", body))
    ids.discard(None)
    return ids


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("WAZUH_INDEXER_URL"))
    ap.add_argument("--user", default=os.environ.get("WAZUH_INDEXER_USER", "admin"))
    ap.add_argument("--password", default=os.environ.get("WAZUH_INDEXER_PASS"))
    ap.add_argument("--prefix", default="DEMO -", help="rule title prefix (default: %(default)s)")
    ap.add_argument("--raw", action="store_true", help="also print the raw JSON found")
    args = ap.parse_args()
    if not args.url or not args.password:
        ap.error("--url and --password required (or WAZUH_INDEXER_URL / _PASS)")

    s = requests.Session()
    s.auth = (args.user, args.password)
    s.verify = False

    det_hits, det_via, det_notes = hits_from(s, args.url, [
        ("detectors API", "/_plugins/_security_analytics/detectors/_search"),
        ("detectors config index", "/.opensearch-sap-detectors-config/_search"),
    ])
    rule_hits, rule_via, rule_notes = hits_from(s, args.url, [
        ("custom rules API", "/_plugins/_security_analytics/rules/_search?pre_packaged=false"),
        ("custom rules config index", "/.opensearch-sap-custom-rules-config/_search"),
    ])
    stock_hits, stock_via, _ = hits_from(s, args.url, [
        ("stock rules API", "/_plugins/_security_analytics/rules/_search?pre_packaged=true"),
        ("stock rules config index", "/.opensearch-sap-pre-packaged-rules-config/_search"),
    ])
    stock = {h.get("_id"): ((h.get("_source") or {}).get("title", ""),
                            (h.get("_source") or {}).get("category"))
             for h in stock_hits}

    # ---- detectors ---------------------------------------------------------
    print(f"DETECTORS  (via {det_via or 'nothing worked'})")
    detectors = []
    for h in det_hits:
        src = h.get("_source", {})
        di = ((src.get("inputs") or [{}])[0]).get("detector_input", {})
        custom = [r.get("id") for r in di.get("custom_rules", [])]
        period = (src.get("schedule") or {}).get("period") or {}
        every = f"{period.get('interval')} {period.get('unit')}" if period else "?"
        detectors.append({"name": src.get("name"), "enabled": src.get("enabled"),
                          "type": src.get("detector_type"), "custom": custom,
                          "pre": len(di.get("pre_packaged_rules", [])),
                          "indices": list(di.get("indices") or []), "every": every,
                          "stock_ids": [r.get("id") for r in di.get("pre_packaged_rules", [])]})
        print(f"  {src.get('name')!s:<28} enabled={src.get('enabled')!s:<5} "
              f"type={src.get('detector_type')!s:<14} "
              f"custom rules={len(custom):<3} stock rules={len(di.get('pre_packaged_rules', [])):<3} "
              f"runs every {every}")
    if not det_hits:
        print("  none found.")
        for n in det_notes:
            print(f"    - {n}")

    # A detector that holds the right rules but reads the wrong index never
    # produces a finding, and nothing complains. Compare each detector that
    # carries custom rules with what the stock detectors read.
    from collections import Counter
    usual = Counter(tuple(sorted(d["indices"])) for d in detectors
                    if not d["custom"] and d["indices"])
    common = usual.most_common(1)[0][0] if usual else None
    mine = [d for d in detectors if d["custom"]]
    if mine:
        print("\nDETECTORS THAT CARRY CUSTOM RULES")
        for d in mine:
            reads = ", ".join(d["indices"]) or "(none)"
            print(f"  {d['name']}: enabled={d['enabled']}  runs every {d['every']}  "
                  f"custom rules={len(d['custom'])}")
            print(f"    reads: {reads}")
            if common:
                missing = [i for i in common if i not in d["indices"]]
                if missing:
                    print(f"    <- MISSING {', '.join(missing)}, which the stock detectors "
                          f"read. Events there will never be seen by this detector.")
                elif tuple(sorted(d["indices"])) != common:
                    print(f"    ok: reads a superset of what the stock detectors read "
                          f"({', '.join(common)})")
            if not d["enabled"]:
                print("    <- DISABLED: enable it.")

    def title_of(src):
        return src.get("title") or (src.get("metadata") or {}).get("title") or "?"

    by_any_id: dict[str, list] = {}
    for h in rule_hits:
        src = h.get("_source", {})
        for i in ids_of(h):
            by_any_id.setdefault(i, []).append((title_of(src), h.get("_id"), space_of(src)))
    if mine:
        print("\n  what is attached to them:")
        for d in mine:
            for cid in d["custom"]:
                hit = by_any_id.get(cid)
                if hit:
                    spaces = ", ".join(sorted({h[2] for h in hit}))
                    if len(hit) == 1:
                        extra = f"rule copy {hit[0][1]}, space={hit[0][2]}"
                    else:
                        extra = (f"{len(hit)} copies share this id, in spaces: {spaces}; "
                                 f"the detector cannot tell them apart here")
                    print(f"    {d['name']}: {cid}  ->  {hit[0][0]}   ({extra})")
                elif cid in stock:
                    print(f"    {d['name']}: {cid}  ->  a STOCK rule: {stock[cid][0]}")
                else:
                    print(f"    {d['name']}: {cid}  ->  not found among the custom or "
                          f"stock rules listed")

    # ---- the promoted DEMO rules ------------------------------------------
    print(f"\nPROMOTED RULES starting '{args.prefix}'  (via {rule_via or 'nothing worked'})")
    demo = []
    for h in rule_hits:
        src = h.get("_source", {})
        title = src.get("title") or (src.get("metadata") or {}).get("title") or ""
        if title.lower().startswith(args.prefix.lower()):
            demo.append((h.get("_id"), src, title))
    if rule_hits:
        print("  rule document fields: " + ", ".join(sorted(rule_hits[0].get("_source", {}))))
    if not demo:
        print(f"  none found among {len(rule_hits)} custom rule(s).")
        for n in rule_notes:
            print(f"    - {n}")
        print("  Either the rules were not promoted into this store, or this build keeps")
        print("  custom content elsewhere. Run with --raw and send me the output.")

    # Which detector holds STOCK rules of each category? A custom rule belongs in
    # the detector whose log type matches its own category.
    home: dict[str, dict[str, int]] = {}
    for d in detectors:
        for rid in d["stock_ids"]:
            cat = stock.get(rid, (None, None))[1]
            if cat:
                home.setdefault(cat, {}).setdefault(d["name"], 0)
                home[cat][d["name"]] += 1
    en = {d["name"]: d["enabled"] for d in detectors}

    by_title: dict[str, list] = {}
    for rid, src, title in demo:
        by_title.setdefault(title, []).append((rid, src))
    worst = 0 if demo else 1
    for title, copies in by_title.items():
        cat = copies[0][1].get("category")
        print(f"\n  {title}   ({len(copies)} cop{'y' if len(copies) == 1 else 'ies'}, "
              f"log source={cat}, level={copies[0][1].get('level')})")
        any_running = False
        for rid, src in copies:
            blob = json.dumps(src)
            fields = [f for f in ("process.command_line", "process.args",
                                  "event.action", "event.code", "event.category") if f in blob]
            q = ((src.get("queries") or [{}])[0] or {}).get("value", "")
            mine_ids = ids_of({"_id": rid, "_source": src})
            where = [d["name"] for d in detectors if mine_ids & set(d["custom"])]
            running = [d["name"] for d in detectors if mine_ids & set(d["custom"]) and d["enabled"]]
            direct = [d["name"] for d in detectors if rid in d["custom"]]
            via = " (via shared rule id)" if where and not direct else ""
            status = (f"in ENABLED detector: {', '.join(running)}{via}" if running else
                      f"in detector {', '.join(where)} but DISABLED{via}" if where else
                      "in NO detector")
            any_running = any_running or bool(running)
            note = ""
            if "process.args" in fields and "process.command_line" not in fields:
                note = "   <- OLD v1 (process.args never exists on sudo events)"
            print(f"    {rid}   space={space_of(src)}   {status}{note}")
            print(f"        matches: {', '.join(fields) or '(could not read the rule body)'}")
            if q:
                print(f"        compiled query: {q[:170]}")
            if not running:
                worst = 1
            if args.raw:
                print("        raw: " + json.dumps(src)[:1500])
        if any_running and len(copies) > 1:
            print("    (the Draft, Test and Custom copies share one id, so a detector's "
                  "reference cannot be told apart per copy; the Custom copy is the one "
                  "that counts.)")
        homes = {} if any_running else home.get(cat, {})
        if any_running:
            pass
        elif homes:
            ranked = sorted(homes.items(), key=lambda kv: -kv[1])
            print(f"    stock rules with log source '{cat}' run in: "
                  + ", ".join(f"{n} ({c} rules, {'enabled' if en.get(n) else 'DISABLED'})"
                              for n, c in ranked))
            print(f"    -> add the Custom-space copy of this rule to {ranked[0][0]!r}.")
        elif cat:
            print(f"    no stock rule uses log source '{cat}', so no detector obviously "
                  f"fits. Create one with log type '{cat}' and add this rule.")

    sudo_home = sorted({d["name"] for d in detectors for rid in d["stock_ids"]
                        if stock.get(rid, ("",))[0].lower().startswith("sudo command executed")})
    if sudo_home:
        print(f"\n  For reference, the stock 'Sudo command executed' rule runs in: "
              f"{', '.join(sudo_home)}")

    if args.raw and det_hits:
        print("\nRAW first detector: " + json.dumps(det_hits[0].get("_source"))[:2500])
    return worst


if __name__ == "__main__":
    sys.exit(main())
