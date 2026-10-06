#!/usr/bin/env python3
"""
wazuh_sim_ui.py — web control panel for the simulated agent environment.

Stdlib only. Shares the run/<name>.pid convention with democtl, so both can be
used interchangeably: agents started here show up in ./democtl status and vice
versa.

    python3 wazuh_sim_ui.py --port 8088 --bind 0.0.0.0

Then open http://<manager>:8088/

There is no authentication. Bind to 127.0.0.1 and tunnel over SSH, or restrict
the port to your management network. It can enrol agents and stop processes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import signal
import ssl
import subprocess
import sys
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
CONF = HERE / "demo.conf"
ENVF = HERE / "indexer.env"
STATE = HERE / "agents"
RUN = HERE / "run"
LOGS = HERE / "logs"
SIM = HERE / "wazuh_agent_sim.py"
PLAYER = HERE / "wazuh_fixture_player.py"
EVENTS = HERE / "events"
EVENT_PLAYER = HERE / "wazuh_event_player.py"
RECORDER = HERE / "wazuh_fixture_recorder.py"
HARVESTER = HERE / "wazuh_event_harvester.py"
SEEDER = HERE / "wazuh_event_seed.py"
FIXTURES = HERE / "fixtures"

PROFILES = ["macos", "windows", "linux"]

# Filled from demo.conf at startup. Empty means no authentication.
SERVER_AUTH: dict[str, str] = {}

_SSL = ssl.create_default_context()
_SSL.check_hostname = False
_SSL.verify_mode = ssl.CERT_NONE


# ----------------------------------------------------------------- config ---
def parse_shell_conf(path: Path) -> dict:
    """Minimal parser for the bash-style demo.conf. Handles KEY=value and
    KEY="multi line value"."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    text = path.read_text()
    for m in re.finditer(r'^\s*([A-Z_]+)=("(?:[^"]*)"|\'(?:[^\']*)\'|[^\s#]*)',
                         text, re.M):
        key, val = m.group(1), m.group(2)
        if val[:1] in "\"'":
            val = val[1:-1]
        out[key] = val.strip()
    return out


def load_conf() -> dict:
    c = parse_shell_conf(CONF)
    c.update({k: v for k, v in parse_shell_conf(ENVF).items() if v})
    return c


def agent_specs(conf: dict) -> list[dict]:
    """AGENTS entries are name:profile:ip, newline or space separated."""
    out = []
    for entry in conf.get("AGENTS", "").split():
        parts = entry.split(":")
        if len(parts) >= 3:
            out.append({"name": parts[0], "profile": parts[1], "ip": parts[2]})
    return out


# -------------------------------------------------------------- processes ---
def pidfile(name: str) -> Path:
    return RUN / f"{name}.pid"


def _is_zombie(pid: int) -> bool:
    """A finished child that nobody reaped still answers kill(pid, 0).

    The UI spawns tasks and never wait()s on them, so short-lived jobs become
    zombies and would otherwise appear to run forever.
    """
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            data = fh.read().decode("latin-1")
        # state is the field after the (comm) parenthesised name
        return data[data.rindex(")") + 2] == "Z"
    except (OSError, ValueError, IndexError):
        return False


def running(name: str) -> int | None:
    pf = pidfile(name)
    if not pf.exists():
        return None
    try:
        pid = int(pf.read_text().strip())
        os.kill(pid, 0)
    except (ValueError, ProcessLookupError, PermissionError, OSError):
        pf.unlink(missing_ok=True)
        return None

    if _is_zombie(pid):
        # Reap it if it is ours, then treat it as finished.
        try:
            os.waitpid(pid, os.WNOHANG)
        except (ChildProcessError, OSError):
            pass
        pf.unlink(missing_ok=True)
        return None
    return pid


def spawn(name: str, argv: list[str]) -> tuple[bool, str]:
    if running(name):
        return False, "already running"
    RUN.mkdir(exist_ok=True)
    LOGS.mkdir(exist_ok=True)
    log = (LOGS / f"{name}.log").open("a")
    log.write(f"=== started {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} "
              f"(ui) ===\n")
    log.flush()
    env = dict(os.environ, PYTHONUNBUFFERED="1")
    try:
        p = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                             cwd=str(HERE), env=env, start_new_session=True)
    except OSError as exc:
        return False, str(exc)
    pidfile(name).write_text(str(p.pid))
    time.sleep(1.2)
    rc = p.poll()
    if rc is None:
        return True, f"pid {p.pid}"

    # Already finished. Short-lived tasks (seeding) legitimately complete in
    # well under a second, so exit 0 is success, not a failed start.
    pidfile(name).unlink(missing_ok=True)
    try:
        tail = (LOGS / f"{name}.log").read_text(
            errors="replace").strip().splitlines()[-3:]
    except OSError:
        tail = []
    summary = " / ".join(t.strip() for t in tail if t.strip())
    if rc == 0:
        msg = summary[:200] or "completed"
        if name.startswith("task-seed-"):
            plat = name.rsplit("-", 1)[-1]
            msg = (f"Lines written to the corpus. Now use Events \u2192 "
                   f"security-alerts on the {plat} agent to send them.")
        elif name == "task-harvest-events":
            msg = "Corpus updated. Use Events on an agent to send lines."
        return True, msg
    return False, summary[:200] or f"exited with status {rc}"


def terminate(name: str) -> tuple[bool, str]:
    pid = running(name)
    if not pid:
        pidfile(name).unlink(missing_ok=True)
        return True, "not running"
    try:
        os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            time.sleep(0.25)
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
        else:
            os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    pidfile(name).unlink(missing_ok=True)
    return True, "stopped"


# ---------------------------------------------------------------- queries ---
def agent_id(name: str) -> str | None:
    f = STATE / f"{name}.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text()).get("id")
    except Exception:
        return None


def http_json(url: str, method="GET", headers=None, data=None, timeout=6):
    req = urllib.request.Request(url, method=method, data=data,
                                 headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout, context=_SSL) as r:
        return json.loads(r.read().decode())


_tok_cache = {"tok": None, "exp": 0.0}


def manager_agents(conf: dict) -> dict:
    """Agent status from the manager API — the authoritative source."""
    mgr = conf.get("MANAGER")
    user = conf.get("API_USER")
    pw = conf.get("API_PASS")
    if not (mgr and user and pw):
        return {}
    try:
        if _tok_cache["exp"] < time.time():
            import base64
            auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
            req = urllib.request.Request(
                f"https://{mgr}:55000/security/user/authenticate?raw=true",
                method="POST", headers={"Authorization": f"Basic {auth}"})
            with urllib.request.urlopen(req, timeout=6, context=_SSL) as r:
                _tok_cache["tok"] = r.read().decode().strip()
                _tok_cache["exp"] = time.time() + 600
        d = http_json(
            f"https://{mgr}:55000/agents?select=id,name,status,lastKeepAlive,os.name",
            headers={"Authorization": f"Bearer {_tok_cache['tok']}"})
        return {a["id"]: a for a in d["data"]["affected_items"]}
    except Exception:
        _tok_cache["exp"] = 0
        return {}


def recent_events(conf: dict, aid: str, minutes: int = 15) -> int | None:
    """How many events this agent has landed recently.

    This is the difference between "nothing was sent" and "it was sent and
    silently dropped": /stateless returns 202 for any batch it accepts, so the
    send always looks successful even when the line fails to decode.
    """
    url = conf.get("WAZUH_INDEXER_URL")
    pw = conf.get("WAZUH_INDEXER_PASS")
    if not (url and pw and aid):
        return None
    try:
        import base64
        auth = base64.b64encode(
            f"{conf.get('WAZUH_INDEXER_USER', 'admin')}:{pw}".encode()).decode()
        body = json.dumps({"query": {"bool": {"must": [
            {"term": {"wazuh.agent.id": aid}},
            {"range": {"@timestamp": {"gte": f"now-{minutes}m"}}}]}}}).encode()
        d = http_json(f"{url}/wazuh-events-v5-*/_count", method="POST", data=body,
                      headers={"Authorization": f"Basic {auth}",
                               "Content-Type": "application/json"})
        return d.get("count")
    except Exception:
        return None


def inventory_count(conf: dict, aid: str) -> int | None:
    url = conf.get("WAZUH_INDEXER_URL")
    pw = conf.get("WAZUH_INDEXER_PASS")
    if not (url and pw and aid):
        return None
    try:
        import base64
        auth = base64.b64encode(
            f"{conf.get('WAZUH_INDEXER_USER', 'admin')}:{pw}".encode()).decode()
        body = json.dumps({"query": {"term": {"wazuh.agent.id": aid}}}).encode()
        d = http_json(f"{url}/wazuh-states-inventory-packages/_count",
                      method="POST", data=body,
                      headers={"Authorization": f"Basic {auth}",
                               "Content-Type": "application/json"})
        return d.get("count")
    except Exception:
        return None


def build_state() -> dict:
    conf = load_conf()
    mgr = manager_agents(conf)
    specs = agent_specs(conf)
    remap = parse_remap(conf)
    sim_ids = set()

    agents = []
    for s in specs:
        aid = agent_id(s["name"])
        if aid:
            sim_ids.add(aid)
        api = mgr.get(aid or "", {})
        agents.append({
            "name": s["name"],
            "profile": s["profile"],
            "ip": s["ip"],
            "id": aid,
            "pid": running(s["name"]),
            "events_pid": running(s["name"] + "-events"),
            "status": api.get("status"),
            "last_seen": api.get("lastKeepAlive"),
            "os": (api.get("os") or {}).get("name"),
            "packages": inventory_count(conf, aid) if aid else None,
            "events_recent": recent_events(conf, aid) if aid else None,
            "enrolled": aid is not None,
            "remap_source": remap.get(aid or ""),
        })

    real = [
        {"id": a["id"], "name": a.get("name"), "status": a.get("status"),
         "os": (a.get("os") or {}).get("name"), "last_seen": a.get("lastKeepAlive")}
        for aid, a in sorted(mgr.items()) if aid not in sim_ids
    ]

    return {
        "agents": agents,
        "real": real,
        "replay": {"pid": running("replay"),
                   "fixture_agents": conf.get("FIXTURE_AGENTS", ""),
                   "remap": conf.get("REMAP", "")},
        "manager": conf.get("MANAGER", "?"),
        "manager_reachable": bool(mgr),
        "profiles": PROFILES,
        "scenarios": SCENARIOS,
        "corpus": corpus_groups(),
        "fim_count": fim_document_count(),
        "fixture_sources": fixture_sources(),
        "real_ids": [a["id"] for a in real],
        "tasks": task_state(),
        "has_fixtures": (FIXTURES / "docs").is_dir(),
        "include_fim": (conf.get("INCLUDE_FIM") or "no").lower() == "yes",
        "now": time.strftime("%H:%M:%S", time.gmtime()),
    }


# ---------------------------------------------------------------- actions ---
def start_agent(name: str) -> tuple[bool, str]:
    conf = load_conf()
    spec = next((s for s in agent_specs(conf) if s["name"] == name), None)
    if not spec:
        return False, "unknown agent"
    if not (STATE / f"{name}.json").exists():
        return False, "not enrolled"
    argv = [sys.executable, str(SIM),
            "--manager", conf.get("MANAGER", ""),
            "--profile", spec["profile"],
            "--reported-ip", spec["ip"],
            "--state", str(STATE / f"{name}.json")]
    ident = STATE / f"{name}.identity"
    if ident.is_file():
        # Report the machine this agent's inventory came from, not the built-in profile.
        argv += ["--identity", str(ident)]
    return spawn(name, argv)


def enroll_agent(name: str, profile: str, ip: str) -> tuple[bool, str]:
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,48}", name or ""):
        return False, "name must be 1-48 chars: letters, digits, . _ -"
    if profile not in PROFILES:
        return False, "unknown profile"
    if not re.fullmatch(r"[0-9a-fA-F.:]{3,45}", ip or ""):
        return False, "invalid IP"
    if (STATE / f"{name}.json").exists():
        return False, "already enrolled"

    conf = load_conf()
    STATE.mkdir(exist_ok=True)
    r = subprocess.run(
        [sys.executable, str(SIM), "--manager", conf.get("MANAGER", ""),
         "--profile", profile, "--name", name, "--reported-ip", ip,
         "--state", str(STATE / f"{name}.json"), "--once"],
        cwd=str(HERE), capture_output=True, text=True, timeout=45)
    if r.returncode != 0:
        return False, (r.stdout + r.stderr).strip().splitlines()[-1][:200]

    # append to demo.conf so democtl and the UI agree on the agent list
    try:
        text = CONF.read_text()
        m = re.search(r'^AGENTS="\n?(.*?)"', text, re.S | re.M)
        if m and f"{name}:" not in m.group(1):
            block = m.group(1).rstrip("\n")
            new = f'AGENTS="\n{block}\n{name}:{profile}:{ip}\n"'
            CONF.write_text(text[:m.start()] + new + text[m.end():])
    except Exception as exc:
        return True, f"enrolled, but demo.conf not updated: {exc}"
    return True, f"enrolled as agent {agent_id(name)}"


def fixture_sources() -> dict:
    """Which agents' inventory is available to replay, from the recorder's
    manifest. These are the REAL agents the fixtures were captured from."""
    mf = HERE / "fixtures" / "manifest.json"
    if not mf.exists():
        return {}
    try:
        m = json.loads(mf.read_text())
    except Exception:
        return {}
    out = {}
    for aid, meta in (m.get("agents_observed") or {}).items():
        names = meta.get("names") or []
        out[aid] = names[0] if names else aid
    return out


def parse_remap(conf: dict) -> dict:
    """REMAP is 'OLD:NEW[:NAME[:HOSTNAME]] ...'. Return {target_id: source_id}."""
    out = {}
    for entry in (conf.get("REMAP") or "").split():
        parts = entry.split(":")
        if len(parts) >= 2:
            out[parts[1]] = parts[0]
    return out


def set_remap(name: str, source_id: str | None) -> tuple[bool, str]:
    """Point one simulated agent's inventory at a recorded agent, or clear it.

    Rewrites REMAP and FIXTURE_AGENTS in demo.conf together: the player needs
    the source id in FIXTURE_AGENTS to load those fixtures at all, and the
    remap entry to re-address them. Setting one without the other is the most
    common way to end up with an agent that has status but no inventory.
    """
    conf = load_conf()
    spec = next((x for x in agent_specs(conf) if x["name"] == name), None)
    if not spec:
        return False, "unknown agent"
    target = agent_id(name)
    if not target:
        return False, "agent not enrolled yet"
    if source_id and source_id not in fixture_sources():
        return False, f"no fixtures recorded for agent {source_id}"

    entries = [e for e in (conf.get("REMAP") or "").split()
               if len(e.split(":")) < 2 or e.split(":")[1] != target]
    if source_id:
        host = PLATFORM_HOSTNAMES.get(spec["profile"], name)
        entries.append(f"{source_id}:{target}:{name}:{host}")
    new_remap = " ".join(sorted(entries))

    sources = sorted({e.split(":")[0] for e in entries})
    new_fixtures = " ".join(sources)

    try:
        text = CONF.read_text()
        text = re.sub(r'^REMAP=.*$', f'REMAP="{new_remap}"', text,
                      count=1, flags=re.M)
        text = re.sub(r'^FIXTURE_AGENTS=.*$', f'FIXTURE_AGENTS="{new_fixtures}"',
                      text, count=1, flags=re.M)
        CONF.write_text(text)
    except Exception as exc:
        return False, f"could not write demo.conf: {exc}"

    # The agent must REPORT the machine its inventory came from, or the dashboard header and
    # the inventory disagree (Windows 11 Pro vs Home, macOS 26.7 vs 15.0.1, Amazon Linux vs
    # Ubuntu). Same helper the CLI's `agent map` uses.
    note = ""
    ident_path = STATE / f"{name}.identity"
    if source_id:
        import wazuh_identity
        got = wazuh_identity.write_identity(
            FIXTURES / "docs", source_id, spec["profile"],
            PLATFORM_HOSTNAMES.get(spec["profile"], name), ident_path)
        note = (f"; reports as {got}" if got else
                "; no OS record for that source, so it keeps the default identity")
    else:
        ident_path.unlink(missing_ok=True)
        note = "; back to the default identity"
    if running(name):
        terminate(name)
        start_agent(name)

    if running("replay"):
        terminate("replay")
        start_replay()
        return True, f"{name} → agent {source_id or 'none'}; replay restarted{note}"
    return True, f"{name} → agent {source_id or 'none'} (start replay to apply){note}"


PLATFORM_HOSTNAMES = {
    "macos": "MAC-demo-MacBook-Air.local",
    "windows": "WIN-DEMO",
    "linux": "amazonlinux-demo",
}


# ---------------------------------------------------------- maintenance ---
# Long-running jobs run as tracked background processes under the same
# pid/log convention as the agents, so the UI can show progress and the log
# rather than blocking an HTTP request for a minute.
TASKS = ("record-fixtures", "harvest-events",
         "seed-macos", "seed-linux", "seed-windows")


def task_state() -> dict:
    out = {}
    for t in TASKS:
        pid = running(f"task-{t}")
        log = LOGS / f"task-{t}.log"
        tail = ""
        if log.exists():
            try:
                lines = log.read_text(errors="replace").strip().splitlines()
                tail = lines[-1][:120] if lines else ""
            except OSError:
                pass
        out[t] = {"pid": pid, "last": tail}
    return out


def run_task(task: str, real_agents: list[str] | None = None) -> tuple[bool, str]:
    conf = load_conf()
    if running(f"task-{task}"):
        return False, "already running"

    ids = [a for a in (real_agents or []) if re.fullmatch(r"[0-9]{3,6}", a)]

    if task == "record-fixtures":
        if running("replay"):
            return False, ("stop the inventory replay first — recording while it "
                           "runs captures the replay's own output")
        # Fall back to whatever the last manifest recorded, so the button still
        # works without a selection.
        ids = ids or sorted(fixture_sources().keys())
        if not ids:
            return False, "pick at least one agent to record from"
        argv = [sys.executable, str(RECORDER), "--outdir", str(FIXTURES),
                "--agents", *ids]
    elif task == "harvest-events":
        argv = [sys.executable, str(HARVESTER), "--outdir", str(EVENTS),
                "--decoder", "", "--days", "30"]
        if ids:
            argv += ["--agents", *ids]
    elif task.startswith("seed-"):
        plat = task.split("-", 1)[1]
        argv = [sys.executable, str(SEEDER), "--outdir", str(EVENTS),
                "--platform", plat, "--count", "40", "--merge"]
    else:
        return False, "unknown task"

    if not conf.get("WAZUH_INDEXER_PASS") and task != "seed-macos" \
            and not task.startswith("seed-"):
        return False, "no indexer credentials (indexer.env)"
    return spawn(f"task-{task}", argv)


def purge_inventory() -> tuple[bool, str]:
    """Delete exactly what the player wrote, via the player's own --purge."""
    conf = load_conf()
    fa = (conf.get("FIXTURE_AGENTS") or "").split()
    if not fa:
        return False, "FIXTURE_AGENTS not set"
    argv = [sys.executable, str(PLAYER), "--fixtures", str(FIXTURES),
            "--agents", *fa]
    remap = (conf.get("REMAP") or "").split()
    if remap:
        argv += ["--remap", *remap]
    argv += ["--purge"]
    r = subprocess.run(argv, cwd=str(HERE), capture_output=True, text=True,
                       timeout=300)
    out = (r.stdout + r.stderr).strip().splitlines()
    line = next((l for l in reversed(out) if "deleted" in l), out[-1] if out else "")
    return r.returncode == 0, line[:200] or "done"


def purge_events(older_than_hours: int | None) -> tuple[bool, str]:
    """Remove replayed events and findings for the simulated agents only."""
    conf = load_conf()
    ids = [aid for aid in (agent_id(s["name"]) for s in agent_specs(conf)) if aid]
    if not ids:
        return False, "no enrolled simulated agents"
    must: list[dict] = [{"terms": {"wazuh.agent.id": ids}}]
    if older_than_hours:
        must.append({"range": {"@timestamp": {"lte": f"now-{older_than_hours}h"}}})
    body = json.dumps({"query": {"bool": {"must": must}}}).encode()

    url = conf.get("WAZUH_INDEXER_URL")
    pw = conf.get("WAZUH_INDEXER_PASS")
    if not (url and pw):
        return False, "no indexer credentials"
    import base64
    auth = base64.b64encode(
        f"{conf.get('WAZUH_INDEXER_USER', 'admin')}:{pw}".encode()).decode()
    total = 0
    for idx in ("wazuh-events-v5-*", "wazuh-findings-v5-*"):
        try:
            d = http_json(f"{url}/{idx}/_delete_by_query?refresh=true&conflicts=proceed",
                          method="POST", data=body,
                          headers={"Authorization": f"Basic {auth}",
                                   "Content-Type": "application/json"},
                          timeout=120)
            total += d.get("deleted", 0)
        except Exception as exc:
            return False, f"{idx}: {exc}"
    scope = f"older than {older_than_hours}h" if older_than_hours else "all"
    return True, f"deleted {total} documents ({scope})"


def delete_agent(name: str) -> tuple[bool, str]:
    """Remove a simulated agent completely: process, manager record, local
    credential, demo.conf entry and its remap."""
    conf = load_conf()
    aid = agent_id(name)
    terminate(name)
    terminate(f"{name}-events")

    removed_remote = False
    mgr, user, pw = conf.get("MANAGER"), conf.get("API_USER"), conf.get("API_PASS")
    if aid and mgr and user and pw:
        try:
            import base64
            auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
            req = urllib.request.Request(
                f"https://{mgr}:55000/security/user/authenticate?raw=true",
                method="POST", headers={"Authorization": f"Basic {auth}"})
            with urllib.request.urlopen(req, timeout=8, context=_SSL) as r:
                tok = r.read().decode().strip()
            http_json(f"https://{mgr}:55000/agents?agents_list={aid}"
                      f"&status=all&older_than=0s", method="DELETE",
                      headers={"Authorization": f"Bearer {tok}"})
            removed_remote = True
        except Exception:
            pass

    (STATE / f"{name}.json").unlink(missing_ok=True)
    (STATE / f"{name}.identity").unlink(missing_ok=True)

    try:
        text = CONF.read_text()
        m = re.search(r'^AGENTS="\n?(.*?)"', text, re.S | re.M)
        if m:
            kept = [l for l in m.group(1).splitlines()
                    if l.strip() and not l.strip().startswith(f"{name}:")]
            text = text[:m.start()] + 'AGENTS="\n' + "\n".join(kept) + '\n"' \
                + text[m.end():]
        if aid:
            entries = [e for e in (conf.get("REMAP") or "").split()
                       if len(e.split(":")) < 2 or e.split(":")[1] != aid]
            text = re.sub(r'^REMAP=.*$', f'REMAP="{" ".join(entries)}"', text,
                          count=1, flags=re.M)
            # FIXTURE_AGENTS must list exactly the sources still in REMAP. A source left there
            # with no REMAP entry would replay onto the ORIGINAL real agent.
            used = list(dict.fromkeys(e.split(":")[0] for e in entries))
            text = re.sub(r'^FIXTURE_AGENTS=.*$', f'FIXTURE_AGENTS="{" ".join(used)}"',
                          text, count=1, flags=re.M)
        CONF.write_text(text)
    except Exception as exc:
        return True, f"removed, but demo.conf not updated: {exc}"

    # The running replay still carries the removed agent's mapping.
    if running("replay"):
        terminate("replay")
        start_replay()

    return True, (f"{name} removed"
                  + ("" if removed_remote else " (manager record may remain)"))


def corpus_groups() -> dict:
    """What the event harvester has collected, for the UI."""
    d = EVENTS / "events"
    if not d.is_dir():
        return {}
    out = {}
    for f in sorted(d.glob("*.jsonl")):
        try:
            out[f.stem] = sum(1 for l in f.open() if l.strip())
        except OSError:
            pass
    return out


def fim_document_count() -> int:
    """How many harvested lines are FIM state-change JSON rather than plain
    log text. Cheap re-check of the same distinction wazuh_event_player.py's
    is_fim_json makes, done here without importing that module just to avoid a
    hard dependency between the UI and the players' internals."""
    d = EVENTS / "events"
    if not d.is_dir():
        return 0
    count = 0
    for f in d.glob("*.jsonl"):
        if "-rule-" in f.stem:
            continue  # rule-driven groups are sent by name, not by fim-changes
        try:
            for line in f.open():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    inner = json.loads(rec.get("original", ""))
                except (json.JSONDecodeError, TypeError, AttributeError):
                    continue
                if isinstance(inner, dict) and inner.get("module") == "fim":
                    count += 1
        except OSError:
            pass
    return count


SCENARIOS = ["ambient", "security-alerts", "brute-force",
             "privilege-escalation", "session-activity"]


STATEFUL_PLAYER = HERE / "wazuh_stateful_player.py"


def send_fim(name: str) -> tuple[bool, str]:
    """Raise a File Integrity Monitoring alert for one agent, in one click.

    This is two steps that previously had to be run by hand in sequence:
      1. wazuh_stateful_player.py writes a FIM baseline (what file.previous
         will be compared against) via /stateful.
      2. wazuh_event_player.py --scenario fim-changes sends the JSON change
         event via /stateless on the syscheck queue, which is what
         decoder/wazuh-fim/0 turns into a real "Wazuh FIM - File modified"
         finding.

    Skipping step 1 for an agent with no prior baseline still works -- the
    change event carries its own file.previous -- but running both keeps the
    IT Hygiene / File Integrity Monitoring inventory tab in sync with the
    alert, which is what most people expect to see together.
    """
    conf = load_conf()
    spec = next((x for x in agent_specs(conf) if x["name"] == name), None)
    if not spec:
        return False, "unknown agent"
    st = STATE / f"{name}.json"
    if not st.exists():
        return False, "not enrolled"
    if not (EVENTS / "events").is_dir():
        return False, "no harvested events — run wazuh_event_harvester.py"

    common = ["--manager", conf.get("MANAGER", ""), "--state", str(st),
              "--events", str(EVENTS), "--profile", spec["profile"]]

    baseline = subprocess.run(
        [sys.executable, str(STATEFUL_PLAYER), *common,
         "--module", "fim", "--count", "5", "--once"],
        cwd=str(HERE), capture_output=True, text=True, timeout=60)
    base_out = (baseline.stdout + baseline.stderr).strip().splitlines()
    base_note = base_out[-1][:160] if base_out else ""

    changes = subprocess.run(
        [sys.executable, str(EVENT_PLAYER), *common, "--name", name,
         "--scenario", "fim-changes", "--fim-count", "5", "--once"],
        cwd=str(HERE), capture_output=True, text=True, timeout=60)
    if changes.returncode != 0:
        out = (changes.stdout + changes.stderr).strip().splitlines()
        return False, out[-1][:200] if out else "failed"

    return True, (f"FIM baseline + change sent ({base_note}) \u2014 "
                  f"alerts appear in 2-3 minutes")


def send_events(name: str, scenario: str) -> tuple[bool, str]:
    """Fire one scenario batch through /stateless as the named agent. This is
    a one-shot subprocess, not a managed process: a demo operator presses the
    button and the alerts appear."""
    if scenario not in SCENARIOS:
        return False, "unknown scenario"
    conf = load_conf()
    spec = next((x for x in agent_specs(conf) if x["name"] == name), None)
    if not spec:
        return False, "unknown agent"
    st = STATE / f"{name}.json"
    if not st.exists():
        return False, "not enrolled"
    if not (EVENTS / "events").is_dir():
        return False, "no harvested events — run wazuh_event_harvester.py"

    r = subprocess.run(
        [sys.executable, str(EVENT_PLAYER),
         "--manager", conf.get("MANAGER", ""),
         "--state", str(st), "--events", str(EVENTS),
         "--profile", spec["profile"], "--name", name,
         "--scenario", scenario, "--once"],
        cwd=str(HERE), capture_output=True, text=True, timeout=60)
    out = (r.stdout + r.stderr).strip().splitlines()
    if r.returncode != 0:
        return False, out[-1][:200] if out else "failed"
    accepted = next((l for l in out if "accepted" in l), "sent")
    return True, (f"{scenario}: {accepted.strip()} \u2014 alerts appear in "
                  f"2-3 minutes")


def start_mirror(name: str, source_id: str) -> tuple[bool, str]:
    """Follow a real agent and replay its events onto this simulated one.

    A simulated agent cannot receive a real alert -- alerts belong to the agent
    that produced the event. Mirroring is the closest equivalent: the content
    is whatever a real machine is generating right now, re-addressed to the
    simulated agent so it stays as active as its real counterpart.
    """
    conf = load_conf()
    spec = next((x for x in agent_specs(conf) if x["name"] == name), None)
    if not spec:
        return False, "unknown agent"
    st = STATE / f"{name}.json"
    if not st.exists():
        return False, "not enrolled"
    if not re.fullmatch(r"[0-9]{3,6}", source_id or ""):
        return False, "pick a real agent to mirror"
    if not conf.get("WAZUH_INDEXER_PASS"):
        return False, "no indexer credentials (indexer.env)"
    return spawn(f"{name}-events", [
        sys.executable, str(EVENT_PLAYER),
        "--manager", conf.get("MANAGER", ""),
        "--state", str(st), "--events", str(EVENTS),
        "--profile", spec["profile"], "--name", name,
        "--mirror", source_id, "--loop", "60"])


def start_ambient(name: str) -> tuple[bool, str]:
    """Continuous low-rate background activity for one agent."""
    conf = load_conf()
    spec = next((x for x in agent_specs(conf) if x["name"] == name), None)
    if not spec:
        return False, "unknown agent"
    st = STATE / f"{name}.json"
    if not st.exists():
        return False, "not enrolled"
    if not (EVENTS / "events").is_dir():
        return False, "no harvested events"
    return spawn(f"{name}-events", [
        sys.executable, str(EVENT_PLAYER),
        "--manager", conf.get("MANAGER", ""),
        "--state", str(st), "--events", str(EVENTS),
        "--profile", spec["profile"], "--name", name,
        "--scenario", "ambient", "--loop", "30"])


def start_replay() -> tuple[bool, str]:
    conf = load_conf()
    fa = conf.get("FIXTURE_AGENTS", "").split()
    if not fa:
        return False, "FIXTURE_AGENTS not set in demo.conf"
    if not (HERE / "fixtures" / "docs").is_dir():
        return False, "no fixtures recorded"
    if not conf.get("WAZUH_INDEXER_PASS"):
        return False, "no indexer credentials (indexer.env)"
    argv = [sys.executable, str(PLAYER), "--fixtures", str(HERE / "fixtures"),
            "--agents", *fa]
    remap = conf.get("REMAP", "").split()
    if remap:
        argv += ["--remap", *remap]
    if (conf.get("INCLUDE_FIM") or "no").lower() == "yes":
        argv.append("--include-fim")
    argv += ["--loop", conf.get("REPLAY_INTERVAL", "300")]
    return spawn("replay", argv)


# ------------------------------------------------------------------- HTTP ---
class Handler(BaseHTTPRequestHandler):
    server_version = "wazuh-sim-ui"

    def log_message(self, *a):
        pass

    def authorised(self) -> bool:
        """HTTP Basic, when UI_USER/UI_PASS are set in demo.conf.

        Off by default so a loopback-only instance needs no setup, but strongly
        recommended whenever the UI is bound to a routable address: it can
        enrol agents, stop processes and delete data.
        """
        want_u = SERVER_AUTH.get("user")
        want_p = SERVER_AUTH.get("password")
        if not (want_u and want_p):
            return True
        hdr = self.headers.get("Authorization", "")
        if not hdr.startswith("Basic "):
            return False
        try:
            import base64
            got = base64.b64decode(hdr[6:]).decode("utf-8", "replace")
            u, _, pw = got.partition(":")
        except Exception:
            return False
        import hmac as _hmac
        return (_hmac.compare_digest(u, want_u)
                and _hmac.compare_digest(pw, want_p))

    def deny(self):
        body = b'{"error":"authentication required"}'
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Wazuh simulator"')
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code=200):
        self._send(code, json.dumps(obj).encode(), "application/json")

    def do_GET(self):
        if not self.authorised():
            return self.deny()
        path = urlparse(self.path).path
        if path == "/":
            self._send(200, PAGE.encode(), "text/html; charset=utf-8")
        elif path == "/api/state":
            try:
                self._json(build_state())
            except Exception as exc:
                self._json({"error": str(exc)}, 500)
        elif path.startswith("/api/log/"):
            name = path.rsplit("/", 1)[-1]
            f = LOGS / f"{re.sub(r'[^A-Za-z0-9._-]', '', name)}.log"
            text = ""
            if f.exists():
                text = "\n".join(f.read_text(errors="replace")
                                 .splitlines()[-120:])
            self._json({"log": text})
        else:
            self._json({"error": "not found"}, 404)

    def do_POST(self):
        if not self.authorised():
            return self.deny()
        path = urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            payload = {}

        def reply(res):
            ok, msg = res
            self._json({"ok": ok, "message": msg}, 200 if ok else 400)

        try:
            m = re.fullmatch(r"/api/agent/([A-Za-z0-9._-]+)/(start|stop)", path)
            if m:
                name, action = m.groups()
                return reply(start_agent(name) if action == "start"
                             else terminate(name))
            m = re.fullmatch(r"/api/agent/([A-Za-z0-9._-]+)/events/"
                             r"(ambient|security-alerts|brute-force|"
                             r"privilege-escalation|session-activity)", path)
            if m:
                return reply(send_events(m.group(1), m.group(2)))
            m = re.fullmatch(r"/api/agent/([A-Za-z0-9._-]+)/fim", path)
            if m:
                return reply(send_fim(m.group(1)))
            m = re.fullmatch(r"/api/agent/([A-Za-z0-9._-]+)/mirror", path)
            if m:
                return reply(start_mirror(m.group(1),
                                          (payload.get("source") or "").strip()))
            m = re.fullmatch(r"/api/agent/([A-Za-z0-9._-]+)/ambient/(start|stop)",
                             path)
            if m:
                name, action = m.groups()
                return reply(start_ambient(name) if action == "start"
                             else terminate(name + "-events"))
            m = re.fullmatch(r"/api/agent/([A-Za-z0-9._-]+)/delete", path)
            if m:
                return reply(delete_agent(m.group(1)))
            m = re.fullmatch(r"/api/task/([a-z-]+)", path)
            if m:
                return reply(run_task(m.group(1), payload.get("agents")))
            if path == "/api/fim":
                want = "yes" if payload.get("enabled") else "no"
                try:
                    text = CONF.read_text()
                    if re.search(r'^INCLUDE_FIM=', text, re.M):
                        text = re.sub(r'^INCLUDE_FIM=.*$', f'INCLUDE_FIM={want}',
                                      text, count=1, flags=re.M)
                    else:
                        text += f'\nINCLUDE_FIM={want}\n'
                    CONF.write_text(text)
                except Exception as exc:
                    return reply((False, f"could not write demo.conf: {exc}"))
                if running("replay"):
                    terminate("replay")
                    start_replay()
                    return reply((True, f"file integrity data {'on' if want=='yes' else 'off'}; replay restarted"))
                return reply((True, f"file integrity data {'on' if want=='yes' else 'off'}"))
            if path == "/api/purge/inventory":
                return reply(purge_inventory())
            if path == "/api/purge/events":
                hrs = payload.get("hours")
                return reply(purge_events(int(hrs) if hrs else None))
            m = re.fullmatch(r"/api/agent/([A-Za-z0-9._-]+)/remap", path)
            if m:
                return reply(set_remap(m.group(1),
                                       (payload.get("source") or "").strip() or None))
            if path == "/api/replay/start":
                return reply(start_replay())
            if path == "/api/replay/stop":
                return reply(terminate("replay"))
            if path == "/api/enroll":
                return reply(enroll_agent(payload.get("name", "").strip(),
                                          payload.get("profile", ""),
                                          payload.get("ip", "").strip()))
            if path == "/api/all/start":
                out = [start_agent(s["name"])[1]
                       for s in agent_specs(load_conf())
                       if (STATE / f"{s['name']}.json").exists()]
                start_replay()
                return reply((True, f"{len(out)} agents"))
            if path == "/api/all/stop":
                for s in agent_specs(load_conf()):
                    terminate(s["name"])
                terminate("replay")
                return reply((True, "all stopped"))
        except Exception as exc:
            return self._json({"ok": False, "message": str(exc)}, 500)
        self._json({"error": "not found"}, 404)


# --------------------------------------------------------------------- UI ---
PAGE = r"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Simulated agents</title>
<style>
/* Matches the Wazuh dashboard, which is OpenSearch Dashboards / EUI:
   light grey canvas, white panels with hairline borders, #006BB4 primary. */
:root{
  --bg:#f5f7fa; --panel:#fff; --line:#d3dae6; --line-soft:#eef1f6;
  --text:#343741; --muted:#69707d; --primary:#006bb4; --primary-hi:#0d94d3;
  --success:#00bfb3; --danger:#bd271e; --warn:#f5a700;
  --font:"Inter","Helvetica Neue",Helvetica,Arial,sans-serif;
  --mono:"SFMono-Regular",Consolas,"Liberation Mono",Menlo,monospace;
  --shadow:0 .7px 1.4px rgba(0,0,0,.07),0 1.9px 4px rgba(0,0,0,.05);
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font-family:var(--font);
  font-size:14px;line-height:1.5;-webkit-font-smoothing:antialiased}
.nav{background:#1a1c21;color:#fff;padding:0 16px;height:48px;display:flex;
  align-items:center;gap:12px}
.nav .brand{font-weight:600;font-size:15px;letter-spacing:-.01em}
.nav .env{color:#98a2b3;font-family:var(--mono);font-size:12px}
.nav .spacer{flex:1}
.nav .clock{color:#98a2b3;font-family:var(--mono);font-size:12px}
.wrap{max-width:1180px;margin:0 auto;padding:20px 16px 56px}
h1{font-size:20px;font-weight:600;margin:4px 0 2px;letter-spacing:-.02em}
.lede{color:var(--muted);font-size:13px;margin:0 0 18px}

.panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;
  box-shadow:var(--shadow);margin-bottom:18px;overflow:hidden}
.panel > header{display:flex;align-items:center;gap:10px;padding:12px 16px;
  border-bottom:1px solid var(--line-soft)}
.panel h2{font-size:14px;font-weight:600;margin:0}
.panel .count{color:var(--muted);font-weight:400}
.panel .tools{margin-left:auto;display:flex;gap:8px;align-items:center}

button{font:inherit;font-size:13px;padding:5px 12px;border-radius:4px;
  border:1px solid var(--primary);background:var(--primary);color:#fff;
  cursor:pointer;line-height:1.4}
button:hover{background:var(--primary-hi);border-color:var(--primary-hi)}
button.sec{background:#fff;color:var(--primary)}
button.sec:hover{background:#e6f1f8}
button.sub{background:transparent;border-color:transparent;color:var(--primary);
  padding:4px 8px}
button.sub:hover{background:var(--line-soft)}
button.danger{background:#fff;color:var(--danger);border-color:var(--danger)}
button.danger:hover{background:#fdf3f2}
button:disabled{opacity:.4;cursor:not-allowed}
button:focus-visible{outline:2px solid var(--primary-hi);outline-offset:1px}

table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:12px;font-weight:600;color:var(--muted);
  padding:8px 16px;border-bottom:1px solid var(--line);white-space:nowrap}
td{padding:10px 16px;border-bottom:1px solid var(--line-soft);vertical-align:middle}
tr:last-child td{border-bottom:none}
tbody tr:hover{background:#fafbfd}
.id{font-family:var(--mono);font-size:12.5px;color:var(--muted)}
.name{font-weight:500}
.dim{color:var(--muted);font-size:12.5px}
.actions{text-align:right;white-space:nowrap}

.pill{display:inline-flex;align-items:center;gap:6px;font-size:12.5px}
.pill::before{content:"";width:8px;height:8px;border-radius:50%;
  background:var(--line)}
.pill.active::before{background:var(--success)}
.pill.disconnected::before{background:var(--danger)}
.pill.pending::before{background:var(--warn)}

.os{display:inline-flex;align-items:center;gap:7px}
.os svg{width:14px;height:14px;flex:none;opacity:.8}

select,input{font:inherit;font-size:13px;padding:5px 8px;border:1px solid var(--line);
  border-radius:4px;background:#fff;color:var(--text);max-width:100%}
select:focus,input:focus{outline:2px solid var(--primary-hi);outline-offset:-1px;
  border-color:var(--primary-hi)}
label{font-size:12px;color:var(--muted);display:flex;flex-direction:column;gap:3px}
form.row{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap;padding:14px 16px}

.callout{padding:10px 16px;background:#fdf6e7;border-bottom:1px solid var(--line-soft);
  font-size:12.5px;color:#7a5c00}
.empty{padding:20px 16px;color:var(--muted);font-size:13px}

dialog{border:1px solid var(--line);border-radius:6px;padding:0;width:min(720px,94vw);
  box-shadow:0 8px 24px rgba(0,0,0,.18)}
dialog::backdrop{background:rgba(26,28,33,.4)}
dialog header{display:flex;align-items:center;padding:12px 16px;
  border-bottom:1px solid var(--line-soft)}
dialog header strong{font-size:14px}
dialog header button{margin-left:auto}
.dbody{padding:16px}
pre{background:#1a1c21;color:#d8dce3;padding:12px;border-radius:4px;overflow:auto;
  max-height:360px;font-family:var(--mono);font-size:12px;line-height:1.55;margin:0}
.chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:10px}
.chip{font-family:var(--mono);font-size:11.5px;background:var(--line-soft);
  border-radius:3px;padding:2px 7px;color:var(--muted)}

#toast{position:fixed;left:50%;transform:translateX(-50%);bottom:24px;
  background:#1a1c21;color:#fff;padding:9px 16px;border-radius:4px;font-size:13px;
  opacity:0;pointer-events:none;transition:opacity .2s;max-width:90vw;z-index:9}
#toast.show{opacity:1}
#toast.err{background:var(--danger)}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
</style></head><body>

<div class="nav">
  <span class="brand">Wazuh</span>
  <span class="env" id="navenv">&mdash;</span>
  <span class="spacer"></span>
  <span class="clock" id="navclock"></span>
</div>

<div class="wrap">
  <div style="display:flex;align-items:flex-end;justify-content:space-between;
       gap:16px;flex-wrap:wrap;margin-bottom:16px">
    <div>
      <h1 style="margin-bottom:2px">Simulated agents</h1>
      <p class="lede" style="margin:0">Endpoints that report to the manager with no
        machine behind them.</p>
    </div>
    <button class="sub" id="notestoggle" onclick="toggleNotes()">Show notes</button>
  </div>

  <div class="panel" style="margin-bottom:18px">
    <div id="summary" style="display:flex;flex-wrap:wrap"></div>
  </div>

  <div id="health"></div>

  <div class="panel">
    <header>
      <h2>Simulated <span class="count" id="simcount"></span></h2>
      <div class="tools">
        <span class="dim" id="replaystate">&mdash;</span>
        <button class="sub" id="fimbtn" onclick="toggleFim()">&mdash;</button>
        <button class="sub" id="rbtn" onclick="toggleReplay()">&mdash;</button>
        <button class="sec" onclick="post('/api/all/stop')">Stop all</button>
        <button onclick="post('/api/all/start')">Start all</button>
      </div>
    </header>
    <div class="callout note" style="display:none;background:#f0f6fb;color:#2c5877">
      <b>Start/Stop</b> controls the keepalive: stopping one makes that agent go
      disconnected within a few minutes. <b>Inventory replay</b> refreshes scan
      timestamps every few minutes so IT Hygiene never looks stale &mdash; leave it
      running.
    </div>
    <div id="simwrap"></div>
  </div>

  <div class="panel">
    <header><h2>Add agent</h2></header>
    <form class="row" onsubmit="enroll(event)">
      <label>Name<input id="e-name" placeholder="macos-demo-2" required size="18"></label>
      <label>Platform<select id="e-profile"></select></label>
      <label>Reported IP<input id="e-ip" value="10.0.44.210" required size="14"></label>
      <button>Enrol</button>
      <span class="dim note" style="display:none;flex-basis:100%">The IP is what the agent claims in
        its keepalive. It does not need to exist or be reachable &mdash; nothing
        connects to it.</span>
    </form>
  </div>

  <div class="panel">
    <header><h2>Data</h2>
      <div class="tools"><span class="dim" id="fixstate"></span></div>
    </header>
    <div id="tasks"></div>
    <div class="callout" id="taskwarn" style="display:none"></div>
  </div>

  <div class="panel">
    <header><h2>Reset</h2></header>
    <div style="padding:14px 16px;display:flex;gap:10px;flex-wrap:wrap;align-items:center">
      <button class="sec" onclick="confirmPurge('inventory')">Purge inventory</button>
      <button class="sec" onclick="confirmPurge('events-old')">Trim events &gt;2h</button>
      <button class="danger" onclick="confirmPurge('events')">Purge all events &amp; alerts</button>
      <span class="dim note" style="display:none;flex-basis:100%">Affects simulated agents only; real
        agents are never touched. Purged <b>inventory</b> returns on the next replay
        pass. Purged <b>events and alerts</b> do not come back &mdash; send a
        scenario to generate more.</span>
    </div>
  </div>

  <div class="panel">
    <header><h2>Real agents <span class="count">not controlled here</span></h2></header>
    <div id="realwrap"></div>
  </div>

  <div class="panel note" style="display:none">
    <header><h2>Worth knowing</h2></header>
    <div style="padding:12px 16px">
      <div class="dim" style="margin-bottom:8px">&bull; <b>Alerts lag events by two
        to three minutes.</b> An empty alerts panel right after sending a scenario
        is normal.</div>
      <div class="dim" style="margin-bottom:8px">&bull; <b>Sending always reports
        success.</b> The manager returns 202 for any batch it accepts, decoded or
        not. The Activity column is the real confirmation.</div>
      <div class="dim" style="margin-bottom:8px">&bull; <b>Deleting an agent here
        also deletes its manager record.</b> Removing only the local credential
        leaves the name registered, and re-enrolment then fails as a duplicate.</div>
      <div class="dim" style="margin-bottom:8px">&bull; <b>Re-enrolment assigns new
        IDs</b>, so inventory mappings have to be set again.</div>
      <div class="dim">&bull; <b>Stop the inventory replay before recording
        fixtures</b>, or the recording captures its own output.</div>
    </div>
  </div>
</div>

<dialog id="scndlg">
  <header><strong id="scnname"></strong>
    <button class="sub" onclick="scndlg.close()">Close</button></header>
  <div class="dbody">
    <p class="dim" style="margin:0 0 12px">Replays log lines through the manager,
      which decodes them and raises real alerts with genuine rule, MITRE and
      compliance metadata. Timestamps are rewritten to now, and only lines
      belonging to this platform are used.</p>
    <p class="dim" style="margin:0 0 12px;padding:8px 10px;background:#fdf6e7;
       color:#7a5c00;border-radius:4px">
      Alerts take <b>two to three minutes</b> to appear in the dashboard. Fire a
      scenario before you start talking about that agent, not while people are
      watching an empty panel. <b>ambient</b> produces events but rarely alerts;
      use <b>security-alerts</b> for something visible.
    </p>
    <div id="scnbtns" style="display:flex;gap:8px;flex-wrap:wrap"></div>
    <div class="chips" id="scncorpus"></div>

    <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--line-soft)">
      <div class="name" style="margin-bottom:4px">File Integrity Monitoring</div>
      <p class="dim" style="margin:0 0 10px">Writes a file baseline, then sends a
        change to the same file, on paths that look native to this platform.
        Populates both the IT Hygiene / File Integrity tab and a real
        "Wazuh FIM - File modified" alert.</p>
      <div id="fimrow" style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"></div>
    </div>

    <div style="margin-top:18px;padding-top:14px;border-top:1px solid var(--line-soft)">
      <div class="name" style="margin-bottom:4px">Mirror a real agent</div>
      <p class="dim" style="margin:0 0 10px">Continuously replays whatever a real
        agent is producing right now, re-addressed to this one. A simulated agent
        cannot receive a real alert &mdash; alerts belong to the agent that
        generated the event &mdash; so this is the closest equivalent: live
        content, simulated identity. Lines that would not make sense on this
        platform are skipped.</p>
      <div style="display:flex;gap:10px;align-items:flex-end">
        <label style="flex:1">Follow agent
          <select id="mirrorsel"></select></label>
        <span id="mirrorbtn"></span>
      </div>
    </div>
  </div>
</dialog>

<dialog id="pickdlg">
  <header><strong id="pickname"></strong>
    <button class="sub" onclick="pickdlg.close()">Close</button></header>
  <div class="dbody">
    <p class="dim" id="pickhint" style="margin:0 0 12px"></p>
    <div id="pickboxes" style="display:flex;gap:14px;flex-wrap:wrap"></div>
    <div style="margin-top:16px;display:flex;gap:8px">
      <button onclick="runPicked()">Run</button>
      <button class="sec" onclick="pickdlg.close()">Cancel</button>
    </div>
  </div>
</dialog>

<dialog id="mapdlg">
  <header><strong id="mapname"></strong>
    <button class="sub" onclick="mapdlg.close()">Close</button></header>
  <div class="dbody">
    <p class="dim" style="margin:0 0 12px">Choose which recorded agent's inventory
      this simulated agent serves. Updates REMAP and FIXTURE_AGENTS together and
      restarts the replay. An <b>unmapped</b> agent shows active status with empty
      IT Hygiene and Vulnerability Detection panels. Pick a source of the same
      platform &mdash; Windows fixtures on a Windows agent.</p>
    <div style="display:flex;gap:10px;align-items:flex-end">
      <label style="flex:1">Inventory source
        <select id="mapsel"></select></label>
      <button onclick="saveRemap()">Apply</button>
    </div>
    <p class="dim" style="margin:12px 0 0" id="maphint"></p>
  </div>
</dialog>

<dialog id="logdlg">
  <header><strong id="logname"></strong>
    <button class="sub" onclick="logdlg.close()">Close</button></header>
  <div class="dbody"><pre id="logbody"></pre></div>
</dialog>

<div id="toast"></div>

<script>
const $ = s => document.querySelector(s);
const esc = s => String(s ?? '').replace(/[<>&"']/g, c =>
  ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;',"'":'&#39;'}[c]));

const ICONS = {
  darwin:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M16.4 12.8c0-2.3 1.9-3.4 2-3.5-1.1-1.6-2.8-1.8-3.4-1.8-1.4-.1-2.8.9-3.5.9s-1.8-.8-3-.8c-1.5 0-2.9.9-3.7 2.3-1.6 2.7-.4 6.8 1.1 9 .8 1.1 1.7 2.3 2.9 2.2 1.2 0 1.6-.7 3-.7s1.8.7 3 .7 2-1.1 2.8-2.2c.9-1.2 1.2-2.5 1.2-2.5s-2.4-.9-2.4-3.6zM14.2 5.9c.6-.8 1.1-1.9 1-3-.9 0-2.1.6-2.8 1.4-.6.7-1.2 1.8-1 2.9 1 .1 2.1-.5 2.8-1.3z"/></svg>',
  windows:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M3 5.5l7-1v7H3v-6zm8-1.1L21 3v9h-10V4.4zM3 12.5h7v7l-7-1v-6zm8 0h10V21l-10-1.4v-7.1z"/></svg>',
  linux:'<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2c-2 0-3 1.7-3 3.8 0 1.3-.2 2-.8 2.9C7 10.4 6 12 6 14.5c0 1.3-.5 2.2-1 3-.6.9-.2 1.9 1 2 .9.1 1.6.4 2 .9.6.7 1.6 1.1 4 1.1s3.4-.4 4-1.1c.4-.5 1.1-.8 2-.9 1.2-.1 1.6-1.1 1-2-.5-.8-1-1.7-1-3 0-2.5-1-4.1-2.2-5.8-.6-.9-.8-1.6-.8-2.9C15 3.7 14 2 12 2zm-1.4 3.3c.4 0 .7.4.7.9s-.3.9-.7.9-.7-.4-.7-.9.3-.9.7-.9zm2.8 0c.4 0 .7.4.7.9s-.3.9-.7.9-.7-.4-.7-.9.3-.9.7-.9z"/></svg>'
};
const PLATMAP = {macos:'darwin', windows:'windows', linux:'linux'};

function toast(m, err){
  const t = $('#toast'); t.textContent = m;
  t.className = 'show' + (err ? ' err' : '');
  setTimeout(() => t.className = '', 2600);
}
function age(iso){
  if(!iso) return '\u2014';
  const s = Math.floor((Date.now() - new Date(iso))/1000);
  if(!isFinite(s) || s < 0) return '\u2014';
  if(s < 60) return s + 's ago';
  if(s < 3600) return Math.floor(s/60) + 'm ago';
  return Math.floor(s/3600) + 'h ago';
}
async function post(url, body){
  try{
    const r = await fetch(url, {method:'POST',
      headers:{'Content-Type':'application/json'}, body: JSON.stringify(body||{})});
    const d = await r.json();
    toast(d.message || (d.ok ? 'Done' : 'Failed'), !d.ok);
  }catch(e){ toast(String(e), true); }
  load();
}

function osCell(profile, os){
  const ic = ICONS[PLATMAP[profile]] || '';
  return `<span class="os">${ic}${esc(os || profile)}</span>`;
}

function simRow(a){
  const live = a.status === 'active' && a.pid;
  const cls = live ? 'active' : (a.status === 'disconnected' ? 'disconnected'
              : (a.pid ? 'pending' : ''));
  const inv = (a.packages === null || a.packages === undefined) ? '\u2014'
            : (a.packages === 0 ? '<span style="color:var(--warn)">none</span>'
                                : a.packages + ' pkgs');
  const src = a.remap_source
    ? `from ${esc(a.remap_source)}` : '<span style="color:var(--warn)">unmapped</span>';
  const ev = a.events_recent;
  const act = (ev === null || ev === undefined) ? '<span class="dim">&mdash;</span>'
    : (ev > 0 ? `${ev} events<div class="dim">last 15 min</div>`
              : '<span style="color:var(--muted)">quiet</span>'
                + '<div class="dim">no events 15 min</div>');
  return `<tr>
    <td class="id">${esc(a.id || '\u2014')}</td>
    <td><div class="name">${esc(a.name)}</div>
        <div class="dim">${esc(a.ip)}${a.events_pid ? ' &middot; events on' : ''}</div></td>
    <td>${osCell(a.profile, a.os)}</td>
    <td><span class="pill ${cls}">${esc(a.status || (a.pid ? 'starting' : 'stopped'))}</span>
        <div class="dim">${age(a.last_seen)}</div></td>
    <td>${inv}<div class="dim">${src}</div></td>
    <td>${act}</td>
    <td class="actions">
      <button class="sub" onclick="openMap('${esc(a.name)}')">Inventory</button>
      ${a.pid ? `<button class="sub" onclick="fire('${esc(a.name)}')">Events</button>` : ''}
      <button class="sub" onclick="showLog('${esc(a.name)}')">Log</button>
      ${a.pid ? `<button class="sec" onclick="post('/api/agent/${esc(a.name)}/stop')">Stop</button>`
              : `<button onclick="post('/api/agent/${esc(a.name)}/start')" ${a.enrolled?'':'disabled'}>Start</button>`}
      <button class="sub" style="color:var(--danger)"
        onclick="delAgent('${esc(a.name)}')" title="Remove agent entirely">&times;</button>
    </td></tr>`;
}

function realRow(a){
  return `<tr>
    <td class="id">${esc(a.id)}</td>
    <td class="name">${esc(a.name || '?')}</td>
    <td>${esc(a.os || '\u2014')}</td>
    <td><span class="pill ${a.status === 'active' ? 'active' : 'disconnected'}">${esc(a.status || '?')}</span>
        <div class="dim">${age(a.last_seen)}</div></td>
    </tr>`;
}

async function load(){
  let d;
  try{ d = await (await fetch('/api/state')).json(); }
  catch(e){ $('#navenv').textContent = 'backend unreachable'; return; }
  if(d.error){ $('#navenv').textContent = d.error; return; }
  window._state = d;

  const up = d.agents.filter(a => a.status === 'active' && a.pid).length;
  $('#navenv').textContent = d.manager + (d.manager_reachable ? '' : ' (API unreachable)');
  $('#navclock').textContent = d.now + ' UTC';
  $('#simcount').textContent = `${up} of ${d.agents.length} active`;

  $('#simwrap').innerHTML = d.agents.length ? `<table>
    <thead><tr><th>ID</th><th>Name</th><th>Operating system</th><th>Status</th>
      <th>Inventory</th><th>Activity</th><th></th></tr></thead>
    <tbody>${d.agents.map(simRow).join('')}</tbody></table>`
    : '<p class="empty">No agents configured yet. Add one below.</p>';

  $('#realwrap').innerHTML = d.real.length ? `<table>
    <thead><tr><th>ID</th><th>Name</th><th>Operating system</th><th>Status</th></tr></thead>
    <tbody>${d.real.map(realRow).join('')}</tbody></table>`
    : '<p class="empty">None, or the manager API is unreachable.</p>';

  $('#replaystate').textContent = d.replay.pid
    ? 'Inventory replay running' : 'Inventory replay stopped';
  $('#rbtn').textContent = d.replay.pid ? 'Stop replay' : 'Start replay';
  $('#fimbtn').textContent = d.include_fim
    ? 'File integrity: on' : 'File integrity: off';
  $('#fimbtn').title = d.include_fim
    ? 'Monitored-file baseline is replayed. Click to exclude it.'
    : 'File Integrity Monitoring panels will be empty. Click to include the baseline.';
  window._replay = !!d.replay.pid;

  renderSummary(d);
  renderHealth(d);
  renderTasks(d);

  const sel = $('#e-profile');
  if(!sel.options.length)
    sel.innerHTML = (d.profiles||[]).map(p => `<option>${esc(p)}</option>`).join('');
}

const TASK_LABEL = {
  'record-fixtures': ['Record inventory fixtures', 'once',
    'Captures inventory from the real agents, then map it with Inventory on \
each agent row. Stop the replay first.'],
  'harvest-events': ['Harvest log lines', 'once',
    'Collects real log lines into the corpus. Nothing is sent until you use \
Events on an agent.'],
  'seed-macos': ['Seed macOS lines', 'optional',
    'Adds synthetic macOS auth lines to the corpus, for when none were \
recorded. Writes to disk only \u2014 use Events \u2192 security-alerts to send them.'],
  'seed-linux': ['Seed Linux lines', 'optional',
    'Adds synthetic Linux auth lines to the corpus. Writes to disk only \
\u2014 use Events \u2192 security-alerts to send them.'],
  'seed-windows': ['Seed Windows events', 'optional',
    'Adds synthetic EventChannel XML (4625, 4624, 4634, 4672, 4720). Writes \
to disk only \u2014 use Events \u2192 security-alerts to send them.']
};

function stat(value, label, tone){
  return `<div style="flex:1;min-width:150px;padding:14px 16px;
      border-right:1px solid var(--line-soft)">
    <div style="font-size:24px;font-weight:500;letter-spacing:-.02em;
      color:${tone || 'var(--text)'}">${esc(value)}</div>
    <div class="dim" style="margin-top:2px">${esc(label)}</div></div>`;
}

function renderSummary(d){
  const live = d.agents.filter(a => a.status === 'active' && a.pid).length;
  const pkgs = d.agents.reduce((n, a) => n + (a.packages || 0), 0);
  const evts = d.agents.reduce((n, a) => n + (a.events_recent || 0), 0);
  $('#summary').innerHTML =
      stat(live, live === 1 ? 'endpoint reporting' : 'endpoints reporting',
           live ? 'var(--success)' : null)
    + stat('0', 'machines running')
    + stat(pkgs.toLocaleString(), 'inventory records')
    + stat(evts, 'events, last 15 min');
}

let _notes = false;
function toggleNotes(){
  _notes = !_notes;
  document.querySelectorAll('.note').forEach(n =>
    n.style.display = _notes ? '' : 'none');
  $('#notestoggle').textContent = _notes ? 'Hide notes' : 'Show notes';
}

function renderHealth(d){
  const issues = [];
  if(!d.has_fixtures)
    issues.push('No inventory fixtures recorded. Data \u2192 Record inventory '
      + 'fixtures, then map a source to each agent.');
  const unmapped = d.agents.filter(a => a.enrolled && !a.remap_source).map(a => a.name);
  if(unmapped.length)
    issues.push(`No inventory source for ${unmapped.join(', ')}. Those agents show `
      + 'active with empty IT Hygiene. Use the Inventory button on each row.');
  const stale = d.agents.filter(a => a.remap_source
    && d.fixture_sources && !(a.remap_source in d.fixture_sources)).map(a => a.name);
  if(stale.length)
    issues.push(`Inventory source no longer exists for ${stale.join(', ')} \u2014 `
      + 'probably a re-enrolment. Pick a source again.');
  const stopped = d.agents.filter(a => a.enrolled && !a.pid).map(a => a.name);
  if(stopped.length)
    issues.push(`Keepalive stopped for ${stopped.join(', ')}; they will go `
      + 'disconnected within a few minutes.');
  if(d.has_fixtures && !d.include_fim)
    issues.push('File integrity data is excluded from the replay, so the File '
      + 'Integrity Monitoring module will be empty for simulated agents. Use '
      + 'the "File integrity" toggle to include it.');
  if(!d.replay.pid && d.has_fixtures)
    issues.push('Inventory replay is stopped. Scan timestamps will go stale.');
  if(!Object.keys(d.corpus || {}).length)
    issues.push('No log lines harvested, so no events or alerts can be produced. '
      + 'Data \u2192 Harvest log lines.');
  const sent = d.agents.filter(a => a.enrolled && a.events_recent === 0);
  if(sent.length === d.agents.filter(a => a.enrolled).length && d.agents.length)
    issues.push('No agent has landed an event in 15 minutes. That is normal if you '
      + 'have not sent a scenario; if you have, the lines are being dropped \u2014 '
      + 'check the manager log.');

  $('#health').innerHTML = issues.length ? `<div class="panel">
    <header><h2 style="color:var(--warn)">Needs attention</h2></header>
    <div style="padding:12px 16px">${issues.map(i =>
      `<div class="dim" style="margin-bottom:6px">&bull; ${i}</div>`).join('')}</div>
  </div>` : '';
}

function renderTasks(d){
  const t = d.tasks || {};
  $('#fixstate').textContent = d.has_fixtures ? 'fixtures present' : 'no fixtures recorded';
  const need = d.corpus && Object.keys(d.corpus).length;
  $('#tasks').innerHTML =
    `<div class="callout note" style="display:${_notes ? '' : 'none'};
        background:#f0f6fb;color:#2c5877;border-bottom:1px solid var(--line-soft)">
       These jobs prepare data on disk. <b>They do not send anything</b> &mdash;
       use <b>Events</b> on an agent row to push log lines and raise alerts.
       Run on demand, not on a schedule: once fixtures and the corpus exist, the
       environment runs without this panel. A working demo needs the two
       <b>once</b> jobs; the <b>optional</b> ones only fill a gap where a
       platform recorded no security activity.
     </div><table><tbody>` +
  Object.entries(TASK_LABEL).map(([k, [title, when, hint]]) => {
    const st = t[k] || {};
    const done = (k === 'record-fixtures' && d.has_fixtures)
              || (k === 'harvest-events' && need);
    const badge = when === 'once'
      ? `<span class="chip" style="background:${done ? '#e6f4ea' : '#fdf6e7'};color:${done ? '#1e7b46' : '#7a5c00'}">${done ? 'done' : 'needed'}</span>`
      : `<span class="chip">optional</span>`;
    return `<tr>
      <td><div class="name">${esc(title)} ${badge}</div>
        <div class="dim">${esc(hint)}</div>
        ${st.last ? `<div class="dim" style="font-family:var(--mono);font-size:11.5px">${esc(st.last)}</div>` : ''}</td>
      <td class="actions">
        <button class="sub" onclick="showLog('task-${esc(k)}')">Log</button>
        ${st.pid ? `<button class="sec" disabled>Running\u2026</button>`
                 : (k === 'record-fixtures' || k === 'harvest-events'
                    ? `<button class="sec" onclick="pickAgents('${esc(k)}')">Run</button>`
                    : `<button class="sec" onclick="post('/api/task/${esc(k)}')">Run</button>`)}
      </td></tr>`;
  }).join('') + `</tbody></table>`;

  const rec = (t['record-fixtures']||{}).pid;
  const warn = $('#taskwarn');
  if(d.replay.pid && !rec){
    warn.style.display = 'block';
    warn.textContent = 'Stop the inventory replay before recording fixtures, '
      + 'otherwise the recording captures the replay\'s own output.';
  } else { warn.style.display = 'none'; }
}

function delAgent(name){
  if(!confirm(`Remove ${name}?\n\nStops it, deletes the manager record and the `
    + `local credential, and removes it from demo.conf. Its replayed inventory `
    + `stays until you purge.`)) return;
  post(`/api/agent/${name}/delete`);
}

function confirmPurge(kind){
  const msg = {
    'inventory': 'Delete replayed inventory for the simulated agents?',
    'events-old': 'Delete simulated agents\' events and alerts older than 2 hours?',
    'events': 'Delete ALL events and alerts for the simulated agents?'
  }[kind];
  if(!confirm(msg)) return;
  if(kind === 'inventory') post('/api/purge/inventory');
  else if(kind === 'events-old') post('/api/purge/events', {hours: 2});
  else post('/api/purge/events', {});
}

function toggleReplay(){ post(window._replay ? '/api/replay/stop' : '/api/replay/start'); }

function toggleFim(){
  const on = !!(window._state || {}).include_fim;
  if(!on && !confirm('Include file integrity data in the replay?\n\n'
      + 'This adds the monitored-file baseline so the File Integrity Monitoring '
      + 'module is populated. It is by far the largest part of a recording '
      + '(tens of thousands of documents), so each replay pass takes longer.'))
    return;
  post('/api/fim', {enabled: !on});
}

function enroll(ev){
  ev.preventDefault();
  post('/api/enroll', {name:$('#e-name').value.trim(),
    profile:$('#e-profile').value, ip:$('#e-ip').value.trim()});
  $('#e-name').value = '';
}

/* ---- agent picker for capture tasks ---- */
let _pickTask = null;
function pickAgents(task){
  _pickTask = task;
  const d = window._state || {};
  const reals = d.real_ids || [];
  $('#pickname').textContent = task === 'record-fixtures'
    ? 'Record inventory fixtures' : 'Harvest log lines';
  $('#pickhint').textContent = task === 'record-fixtures'
    ? 'Which real agents to record inventory from. Recording replaces the '
      + 'fixtures for those agents; others are left alone.'
    : 'Which real agents to collect log lines from. Leave all selected to '
      + 'harvest everything.';
  $('#pickboxes').innerHTML = reals.length
    ? reals.map(id => `<label style="flex-direction:row;align-items:center;gap:6px">
        <input type="checkbox" value="${esc(id)}" checked> agent ${esc(id)}</label>`).join('')
    : '<em class="dim">No real agents visible. Check the manager API credentials.</em>';
  pickdlg.showModal();
}
function runPicked(){
  const ids = [...document.querySelectorAll('#pickboxes input:checked')]
    .map(c => c.value);
  post(`/api/task/${_pickTask}`, {agents: ids});
  pickdlg.close();
}

/* ---- inventory mapping ---- */
let _mapAgent = null;
function openMap(name){
  _mapAgent = name;
  const d = window._state || {};
  const a = (d.agents||[]).find(x => x.name === name) || {};
  const src = d.fixture_sources || {};
  $('#mapname').textContent = name + ' \u2014 inventory source';
  const opts = ['<option value="">(none)</option>'].concat(
    Object.entries(src).map(([id, nm]) =>
      `<option value="${esc(id)}" ${a.remap_source===id?'selected':''}>${esc(id)} \u2014 ${esc(nm)}</option>`));
  $('#mapsel').innerHTML = opts.join('');
  $('#maphint').textContent = Object.keys(src).length
    ? 'Sources come from fixtures/manifest.json. Re-record fixtures to add more.'
    : 'No fixtures recorded yet. Run wazuh_fixture_recorder.py first.';
  mapdlg.showModal();
}
function saveRemap(){
  post(`/api/agent/${_mapAgent}/remap`, {source: $('#mapsel').value});
  mapdlg.close();
}

/* ---- events ---- */
let _scnAgent = null;
function fire(name){
  _scnAgent = name;
  const d = window._state || {};
  const a = (d.agents||[]).find(x => x.name === name) || {};
  const groups = d.corpus || {};
  const mine = Object.entries(groups).filter(([g]) => g.startsWith(a.profile + '-'));
  $('#scnname').textContent = name + ' \u2014 send events';
  $('#scnbtns').innerHTML = mine.length
    ? (d.scenarios||[]).map(s => `<button onclick="runScenario('${esc(s)}')">${esc(s)}</button>`).join('')
      + (a.events_pid
          ? `<button class="danger" onclick="ambient('stop')">Stop ambient</button>`
          : `<button class="sec" onclick="ambient('start')">Start ambient</button>`)
    : `<em class="dim">No ${esc(a.profile)} lines harvested. Run
       wazuh_event_harvester.py against a real ${esc(a.profile)} agent.</em>`;
  $('#scncorpus').innerHTML = mine
    .map(([g, n]) => `<span class="chip">${esc(g.replace(a.profile + '-', ''))} ${n}</span>`)
    .join('');

  const fimCount = d.fim_count || 0;
  $('#fimrow').innerHTML = fimCount
    ? `<button onclick="fireFim()">Raise a File Integrity alert</button>
       <span class="dim">${fimCount} FIM change document(s) available</span>`
    : `<em class="dim">No FIM change documents harvested yet.</em>`;

  const reals = d.real_ids || [];
  $('#mirrorsel').innerHTML = reals.length
    ? reals.map(id => `<option value="${esc(id)}">agent ${esc(id)}</option>`).join('')
    : '<option value="">no real agents</option>';
  $('#mirrorbtn').innerHTML = a.events_pid
    ? `<button class="danger" onclick="ambient('stop')">Stop following</button>`
    : `<button ${reals.length ? '' : 'disabled'} onclick="startMirror()">Follow</button>`;
  scndlg.showModal();
}
function runScenario(s){ post(`/api/agent/${_scnAgent}/events/${s}`); scndlg.close(); }
function fireFim(){ post(`/api/agent/${_scnAgent}/fim`); scndlg.close(); }
function startMirror(){
  post(`/api/agent/${_scnAgent}/mirror`, {source: $('#mirrorsel').value});
  scndlg.close();
}
function ambient(action){ post(`/api/agent/${_scnAgent}/ambient/${action}`); scndlg.close(); }

async function showLog(name){
  $('#logname').textContent = name + '.log';
  $('#logbody').textContent = 'Loading\u2026';
  logdlg.showModal();
  const d = await (await fetch('/api/log/' + encodeURIComponent(name))).json();
  $('#logbody').textContent = d.log || '(empty)';
  $('#logbody').scrollTop = $('#logbody').scrollHeight;
}

load();
setInterval(load, 5000);
</script></body></html>
"""


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8088)
    ap.add_argument("--bind", default="127.0.0.1",
                    help="default 127.0.0.1; there is no authentication")
    ap.add_argument("--dump-state", action="store_true",
                    help="print the same JSON the dashboard's /api/state "
                         "returns, then exit. No server is started. This is "
                         "what democtl status shells out to, so the CLI and "
                         "the dashboard can never disagree about what they "
                         "report.")
    args = ap.parse_args()

    if not CONF.exists():
        print(f"No demo.conf at {CONF}. Run ./democtl setup first.", file=sys.stderr)
        return 1

    if args.dump_state:
        try:
            print(json.dumps(build_state()))
        except Exception as exc:
            print(json.dumps({"error": str(exc)}))
            return 1
        return 0

    conf = load_conf()
    SERVER_AUTH["user"] = conf.get("UI_USER", "")
    SERVER_AUTH["password"] = conf.get("UI_PASS", "")

    srv = ThreadingHTTPServer((args.bind, args.port), Handler)
    print(f"Simulated agent UI on http://{args.bind}:{args.port}/")
    if SERVER_AUTH["user"] and SERVER_AUTH["password"]:
        print(f"Basic authentication enabled (user {SERVER_AUTH['user']})")
    elif args.bind not in ("127.0.0.1", "localhost"):
        print("WARNING: reachable from the network with NO authentication. "
              "Anyone who can reach this port can enrol agents, stop processes "
              "and delete data. Set UI_USER and UI_PASS in demo.conf.",
              file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
