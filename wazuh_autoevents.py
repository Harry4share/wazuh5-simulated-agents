#!/usr/bin/env python3
"""
wazuh_autoevents.py

Keeps alerts flowing for every simulated agent, so the dashboard has recent events
and findings whenever someone opens it, without anyone pushing scenarios by hand.

Dashboards default to the last 24 hours, and a replayed event is stamped with the time
it was sent. Send once and it ages out. This runs beside the agents (`./democtl start`
starts it; `./democtl stop` stops it) and keeps sending on a schedule:

  scenario              every (normal)   platforms
  ambient               10 min           all          benign background activity
  security-alerts       45 min           all
  session-activity      90 min           all
  fim-changes           2 h              all          file-integrity alerts
  brute-force           2 h              linux, windows
  privilege-escalation  3 h              linux, macos
  rule:<each captured>  4 h              per platform, found by itself in events/

Every interval gets +-25% jitter and the agents are staggered, so traffic is spread out
instead of arriving in bursts. On first start every job runs once within a couple of
minutes (a warm-up), so alerts appear right after install. The schedule is kept in
run/autoevents.json, so a restart or reboot does not cause a burst.

Three kinds of "no", handled differently:
  empty   the corpus has no lines for that scenario on that platform (sudo lines on a Mac).
          Retried every 12 hours, and at once when the corpus changes (you seed or harvest).
  retry   lines exist but every random draw was rejected as implausible or unparseable.
          Tried again soon: 5 minutes, doubling to 2 hours, reset by the next success.
  fail    a real error (manager unreachable, 401, ...). 1 minute, doubling to 30.

Agents are read from demo.conf on every pass, so adding or removing one needs no restart.

  python3 wazuh_autoevents.py                 # run (democtl does this for you)
  python3 wazuh_autoevents.py --status        # what ran, what is next
  python3 wazuh_autoevents.py --once          # run every job once now, then exit
  python3 wazuh_autoevents.py --once --dry-run   # show what that would send

Settings in demo.conf:  AUTO_EVENTS=yes|no   AUTO_EVENTS_LEVEL=light|normal|busy
(light = half as often, busy = twice as often)
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUN = HERE / "run"
LOGS = HERE / "logs"
AGENTS_DIR = HERE / "agents"
PLAYER = HERE / "wazuh_event_player.py"

LEVELS = {"light": 2.0, "normal": 1.0, "busy": 0.5}
ALL = ("linux", "macos", "windows")

# scenario, minutes between runs at level "normal", platforms, extra player arguments
JOBS = [
    ("ambient",              10,  ALL,                     []),
    ("security-alerts",      45,  ALL,                     []),
    ("session-activity",     90,  ALL,                     []),
    ("fim-changes",          120, ALL,                     ["--fim-count", "3"]),
    ("brute-force",          120, ("linux", "windows"),    []),
    ("privilege-escalation", 180, ("linux", "macos"),      []),
]
RULE_MINUTES = 240
EMPTY_BACKOFF = 12 * 3600
RETRY_FIRST, RETRY_MAX = 5 * 60, 2 * 3600
FAIL_BACKOFF_FIRST, FAIL_BACKOFF_MAX = 60, 30 * 60
JITTER = 0.25
WARMUP_STEP = 4                    # seconds between jobs at first start

clock = time.time                  # replaced in tests
rng = random.Random()


# ------------------------------------------------------------------ config ---
def read_conf(path: Path) -> dict:
    text = path.read_text(errors="replace") if path.is_file() else ""

    def val(key: str, default: str = "") -> str:
        m = re.search(rf'^{key}="?([^"\n]*)"?', text, re.M)
        return re.split(r"\s+#", m.group(1))[0].strip() if m else default

    agents = []
    m = re.search(r'^AGENTS="\n?(.*?)"', text, re.S | re.M)
    for line in (m.group(1).splitlines() if m else []):
        p = line.strip().split(":")
        if len(p) >= 3 and p[0] and p[1] in ALL:
            agents.append((p[0], p[1]))
    return {"manager": val("MANAGER"), "level": val("AUTO_EVENTS_LEVEL", "normal"),
            "agents": agents}


def enrolled(conf: dict) -> list[tuple[str, str]]:
    """Agents listed in demo.conf that also have credentials, i.e. that can receive events."""
    out = []
    for name, profile in conf["agents"]:
        try:
            ok = bool(json.loads((AGENTS_DIR / f"{name}.json").read_text()).get("id"))
        except (OSError, ValueError):
            ok = False
        if ok:
            out.append((name, profile))
    return out


def rule_scenarios(events_dir: Path, platform: str) -> list[str]:
    """Captured custom-rule events for a platform: files <platform>-rule-<slug>-<id>.jsonl."""
    d = events_dir / "events"
    out = []
    for f in sorted(d.glob(f"{platform}-rule-*.jsonl")) if d.is_dir() else []:
        out.append("rule:" + f.stem[len(f"{platform}-rule-"):])
    return out


def corpus_stamp(events_dir: Path, platform: str) -> str:
    """Changes when a group file for this platform is added, removed or rewritten."""
    d = events_dir / "events"
    files = sorted(d.glob(f"{platform}-*.jsonl")) if d.is_dir() else []
    newest = 0.0
    for f in files:
        try:
            newest = max(newest, f.stat().st_mtime)
        except OSError:
            pass
    return f"{len(files)}:{int(newest)}"


def jobs_for(platform: str, events_dir: Path) -> list[tuple[str, int, list[str]]]:
    jobs = [(s, m * 60, extra) for s, m, plats, extra in JOBS if platform in plats]
    jobs += [(s, RULE_MINUTES * 60, []) for s in rule_scenarios(events_dir, platform)]
    return jobs


# ------------------------------------------------------------------- state ---
def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def save_state(path: Path, state: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True))
    os.replace(tmp, path)


def interval(base: int, level: str, scale: float) -> float:
    return base * LEVELS.get(level, 1.0) / scale


def jittered(secs: float) -> float:
    return secs * rng.uniform(1 - JITTER, 1 + JITTER)


def ensure(state: dict, key: str, now: float, order: int, level: str, base: int, scale: float) -> None:
    """Give a job its first due time. New jobs warm up in a staggered run; a job left
    overdue by a long stop runs soon, but once, and spread out."""
    st = state.get(key)
    every = interval(base, level, scale)
    if st is None or "next" not in st:
        state[key] = {"next": now + (5 + WARMUP_STEP * order) / scale, "ok": 0, "empty": 0, "fail": 0}
    elif st["next"] < now - every:
        st["next"] = now + rng.uniform(5, 60) / scale + WARMUP_STEP * order / scale


def record(state: dict, key: str, outcome: str, note: str, now: float, base: int,
           level: str, scale: float, corpus: str | None = None) -> None:
    st = state[key]
    st["last"], st["result"], st["note"] = now, outcome, note
    if corpus is not None:
        st["corpus"] = corpus
    if outcome == "ok":
        st["ok"] += 1
        st["fails_in_row"] = 0
        st["retries_in_row"] = 0
        st["next"] = now + jittered(interval(base, level, scale))
    elif outcome == "empty":
        st["empty"] += 1
        st["next"] = now + EMPTY_BACKOFF / scale
    elif outcome == "retry":
        st["retry"] = st.get("retry", 0) + 1
        st["retries_in_row"] = st.get("retries_in_row", 0) + 1
        back = min(RETRY_FIRST * 2 ** (st["retries_in_row"] - 1), RETRY_MAX)
        st["next"] = now + back / scale
    else:
        st["fail"] += 1
        st["fails_in_row"] = st.get("fails_in_row", 0) + 1
        back = min(FAIL_BACKOFF_FIRST * 2 ** (st["fails_in_row"] - 1), FAIL_BACKOFF_MAX)
        st["next"] = now + back / scale


# --------------------------------------------------------------------- run ---
def run_job(manager: str, name: str, profile: str, scenario: str, extra: list[str],
            events: Path, timeout: int = 180) -> tuple[str, str]:
    cmd = [sys.executable, str(PLAYER), "--manager", manager,
           "--state", str(AGENTS_DIR / f"{name}.json"), "--events", str(events),
           "--profile", profile, "--name", name, "--scenario", scenario, "--once", *extra]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "fail", f"timed out after {timeout}s"
    except OSError as exc:
        return "fail", str(exc)
    out = (r.stdout + r.stderr).strip()
    if r.returncode == 0:
        m = re.search(r"(\d+)[^\n]*accepted", out)
        return "ok", f"{m.group(1)} accepted" if m else "sent"
    if "nothing to send" in out:
        if "rejected as implausible" in out:
            # Lines exist, but every one drawn this time was rejected. A different draw may pass.
            return "retry", "every line drawn was rejected as implausible or unparseable; will draw again"
        return "empty", "nothing in the corpus for this platform"
    last = out.splitlines()[-1].strip() if out else f"exit {r.returncode}"
    return "fail", last[:140]


def stamp(t: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(clock() if t is None else t))


def log(msg: str) -> None:
    print(f"{stamp()} {msg}", flush=True)


def ago(t: float | None, now: float) -> str:
    if not t:
        return "never"
    s = max(0, int(now - t))
    return f"{s}s ago" if s < 120 else f"{s // 60}m ago" if s < 7200 else f"{s // 3600}h ago"


def inn(t: float, now: float) -> str:
    s = int(t - now)
    return "now" if s <= 0 else f"{s}s" if s < 120 else f"{s // 60}m" if s < 7200 else f"{s // 3600}h"


def show_status(state_file: Path, conf: dict, level: str) -> int:
    pidf = RUN / "autoevents.pid"
    pid = None
    try:
        pid = int(pidf.read_text())
        os.kill(pid, 0)
    except (OSError, ValueError):
        pid = None
    state = load_state(state_file)
    now = clock()
    head = (f"Automatic events: running (pid {pid}), level {level}, {len(enrolled(conf))} agent(s)"
            if pid else "Automatic events: NOT running")
    print(head)
    if not pid:
        print("  Start it with ./democtl start (AUTO_EVENTS=yes in demo.conf). Without it, events age out of the "
              "dashboard's 24-hour window.")
    for name, profile in conf["agents"]:
        rows = {k: v for k, v in state.items() if k.startswith(name + "|")}
        if not rows:
            continue
        print(f"  {name} ({profile})")
        for key, st in sorted(rows.items()):
            scen = key.split("|", 1)[1]
            print(f"    {scen:<44} last {ago(st.get('last'), now):<9} next in {inn(st['next'], now):<5} "
                  f"{st.get('result', '-'):<6} {st.get('note', '')}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--conf", type=Path, default=HERE / "demo.conf")
    ap.add_argument("--level", choices=sorted(LEVELS), help="override AUTO_EVENTS_LEVEL")
    ap.add_argument("--tick", type=float, default=15, help="seconds between passes (default %(default)s)")
    ap.add_argument("--once", action="store_true", help="run every job once now, then exit")
    ap.add_argument("--pause", type=float, default=2,
                    help="seconds between two sends, to be gentle on the manager (default %(default)s)")
    ap.add_argument("--dry-run", action="store_true", help="with --once: print the plan, send nothing")
    ap.add_argument("--status", action="store_true", help="show what ran and what is next, then exit")
    ap.add_argument("--time-scale", type=float, default=1.0, help=argparse.SUPPRESS)  # tests
    args = ap.parse_args()

    state_file = RUN / "autoevents.json"
    conf = read_conf(args.conf)
    level = args.level or conf["level"]
    if level not in LEVELS:
        print(f"unknown AUTO_EVENTS_LEVEL '{level}', using normal", file=sys.stderr)
        level = "normal"
    if args.status:
        return show_status(state_file, conf, level)

    scale = max(args.time_scale, 0.001)
    events = HERE / "events"
    stopping = {"now": False}
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopping.update(now=True))

    state = load_state(state_file)
    if not args.once:
        log(f"autoevents started: level {level}, schedule in {state_file.name}")

    while not stopping["now"]:
        conf = read_conf(args.conf)
        usable = enrolled(conf)
        if not conf["manager"]:
            log("MANAGER is not set in demo.conf; nothing to do")
        now = clock()

        stamps = {profile: corpus_stamp(events, profile) for _, profile in usable}
        plan = []                                    # (key, name, profile, scenario, base, extra)
        order = 0
        per_agent = [(name, profile, jobs_for(profile, events)) for name, profile in usable]
        # Round-robin across agents, so at first start every agent gets its first events
        # within the first minute instead of the last agent waiting for all the others.
        for i in range(max((len(j) for _, _, j in per_agent), default=0)):
            for name, profile, jobs in per_agent:
                if i >= len(jobs):
                    continue
                scenario, base, extra = jobs[i]
                key = f"{name}|{scenario}"
                plan.append((key, name, profile, scenario, base, extra))
                ensure(state, key, now, order, level, base, scale)
                st = state[key]
                if st.get("result") in ("empty", "retry") and st.get("corpus") != stamps[profile]:
                    # The corpus changed since this job found nothing: look again now, not in hours.
                    # (A schedule written by an older version has no stamp, which also counts as
                    # changed: one extra look at upgrade is cheap, and it wakes jobs that went to
                    # sleep for 12 hours before the corpus was filled.)
                    st["next"] = min(st["next"], now + rng.uniform(2, 30) / scale)
                    st["corpus"] = stamps[profile]
                if args.once:
                    st["next"] = now
                order += 1

        due = sorted((p for p in plan if state[p[0]]["next"] <= now), key=lambda p: state[p[0]]["next"])
        for key, name, profile, scenario, base, extra in due:
            if stopping["now"]:
                break
            if args.dry_run:
                print(f"would send {scenario:<44} to {name} ({profile})")
                continue
            outcome, note = run_job(conf["manager"], name, profile, scenario, extra, events)
            record(state, key, outcome, note, clock(), base, level, scale, stamps[profile])
            log(f"{name} {scenario} {outcome} {note}")
            save_state(state_file, state)
            time.sleep(args.pause / scale)

        if not args.dry_run:
            save_state(state_file, state)
        if args.once:
            return 0
        # Sleep until the next job is due (at most one tick, so config changes are seen),
        # in short slices so a stop request is honoured at once.
        wake = min((state[p[0]]["next"] for p in plan), default=clock() + args.tick / scale)
        delay = min(args.tick / scale, max(0.2 / scale, wake - clock()))
        end = time.monotonic() + delay
        while time.monotonic() < end and not stopping["now"]:
            time.sleep(min(0.5, max(0.0, end - time.monotonic())))

    save_state(state_file, state)
    log("autoevents stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
