# Wazuh 5.x Simulated Agent Environment — Complete Guide

Run a Wazuh 5.x demo with **zero endpoint instances**. Agents report as active,
IT Hygiene and Vulnerability Detection are populated, and real alerts appear —
all driven from a web UI.

Verified against Wazuh 5.0.0-beta5, indexer 3.6.0, manager `10.0.44.61`.

---

## Part 1 — What this is

### The problem

A demo needs a Mac, a Windows box and a Linux box, each running an agent. That is
three cloud machines running continuously so someone can occasionally look at a
dashboard. macOS is the expensive one: Apple hardware is rented as a whole physical
machine with a 24-hour minimum. Windows adds licensing.

### The insight

The dashboard draws from two independent sources, and only one was a problem.

| What you see | Where it comes from | Can we write it? |
|---|---|---|
| Agent list, status, OS | Manager API (55000) | Only by speaking the agent protocol |
| IT Hygiene inventory | `wazuh-states-inventory-*` | Yes, directly |
| Vulnerability Detection | `wazuh-states-vulnerabilities` | Yes, directly |
| SCA | `wazuh-states-sca` | Yes, directly |
| Events | `wazuh-events-v5-*` | Only via the manager's `/stateless` |
| Alerts | `wazuh-findings-v5-*` | Only the rule engine writes these |

We proved status is manager-owned by injecting an "active" record into the indexer
for a stopped agent: the dashboard kept showing it offline.

### The design

Three independent pieces:

| Piece | Talks to | Provides | Cadence |
|---|---|---|---|
| `wazuh_agent_sim.py` | manager :1517 | agent exists, **active status**, declared OS | 10 s |
| `wazuh_fixture_player.py` | indexer :9200 | inventory, vulnerabilities, SCA | 5 min |
| `wazuh_event_player.py` | manager :1517 | log events → **real alerts** | on demand |

Nothing is faked at the point where it matters:

- The agent genuinely connects and checks in, so "active" is true.
- Inventory is recorded verbatim from real machines.
- Alerts are produced by Wazuh's own decoders and rules, with real MITRE and
  compliance tagging.

The only fabricated element is the optional seed corpus (Part 6), used when a
platform has no recorded security activity to replay.

---

## Part 2 — Installation

### Requirements

- Wazuh 5.x manager, indexer and dashboard, already running
- Python 3.9+ with `requests` on the manager host
- At least one real agent connected, to record from

### Step 1 — place the files

```bash
sudo mkdir -p /opt/wazuh-demo && cd /opt/wazuh-demo
# copy the scripts here, then:
sudo chmod +x democtl
```

Expected contents:

```
democtl                      control script
demo.conf.example            config template
wazuh_agent_sim.py           enrol + keepalive  (status)
wazuh_fixture_recorder.py    capture inventory
wazuh_fixture_player.py      replay inventory
wazuh_event_harvester.py     capture log lines
wazuh_event_player.py        replay log lines   (alerts)
wazuh_event_seed.py          synthesise log lines
wazuh_enroll_token.py        token generator    (diagnostic)
wazuh_sim_ui.py              web UI
```

### Step 2 — the manager API password

The UI needs it to read agent status. The dashboard stores its copy in a write-only
keystore, so **it cannot be read back** — reset it:

```bash
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh \
  -A -u wazuh-wui -p '<new-api-password>' -au wazuh -ap 'wazuh'
```

The tool accepts only `.*+?-` as symbols and reports anything else as a length error.
A password ending in `!` fails; one using `-` works.

Verify:

```bash
curl -sk -u wazuh-wui:'<new-api-password>' -X POST \
  "https://127.0.0.1:55000/security/user/authenticate?raw=true" | head -c 40
```

### Step 3 — run setup

```bash
./democtl setup
```

It creates `demo.conf` and `indexer.env` (mode 600), prompts for the manager address
and indexer credentials, verifies it can reach the indexer and the manager on 1517,
and offers to record fixtures.

Use `https://127.0.0.1:9200` for the indexer — port 9200 binds loopback.

### Step 4 — define your agents

Edit `demo.conf`:

```bash
MANAGER=10.0.44.61

# name:platform:reported_ip
AGENTS="
macos-demo:macos:10.0.44.200
win-demo:windows:10.0.44.201
amzn-demo:linux:10.0.44.202
"

API_USER=wazuh-wui
API_PASS=<your-api-password>
REPLAY_INTERVAL=300
CLEAN_SHUTDOWN=yes
```

Leave `FIXTURE_AGENTS` and `REMAP` empty — the UI sets them.

```bash
chmod 600 demo.conf indexer.env
```

### Step 5 — start everything

```bash
./democtl start
```

That enrols any new agents, starts the keepalives and the inventory replay, starts
the automatic event scheduler (Step 5b), and starts the web UI. The UI is reachable
from the network by default:

```
http://<manager>:8088/
```

`setup` prompts for a UI password. If you skipped it, set one now — the UI can enrol
agents, stop processes and delete data, so an open port is the same as leaving those
controls open:

```bash
# demo.conf
UI_USER=demo
UI_PASS=choose-something
```

then `./democtl restart`. The startup output says whether authentication is on.

To keep it on the manager host only, set `UI_BIND=127.0.0.1` and tunnel:

```bash
ssh -L 8088:127.0.0.1:8088 root@10.0.44.61
```

| Setting | Default | Meaning |
|---|---|---|
| `UI_ENABLED` | `yes` | Start the UI with the environment |
| `UI_PORT` | `8088` | Listening port |
| `UI_BIND` | `0.0.0.0` | `127.0.0.1` restricts to the manager host |
| `UI_USER` / `UI_PASS` | unset | HTTP Basic credentials; blank disables auth |
| `AUTO_EVENTS` | `yes` | Run the automatic event scheduler with `start` (Step 5b) |
| `AUTO_EVENTS_LEVEL` | `normal` | `light` = half as often, `busy` = twice as often |

### Step 5b — automatic events (on by default)

Dashboards default to the last 24 hours, and a replayed event is stamped with the time it
was sent, so anything sent once ages out. `./democtl start` therefore also runs a
scheduler, `wazuh_autoevents.py`, that keeps sending every scenario to every simulated
agent. Nobody has to push anything.

On first start every job runs once within a couple of minutes, interleaved across the
agents, so alerts appear right after install. After that each scenario repeats with
±25% jitter:

| Scenario | Every (`normal`) | Platforms |
|---|---|---|
| `ambient` | 10 min | all |
| `security-alerts` | 45 min | all |
| `session-activity` | 90 min | all |
| `fim-changes` | 2 h | all |
| `brute-force` | 2 h | Linux, Windows |
| `privilege-escalation` | 3 h | Linux, macOS |
| each captured custom-rule scenario (`rule:…`) | 4 h | its own platform, found in `events/` |

The schedule is saved in `run/autoevents.json`, so a restart or reboot does not cause a
burst. Agents added to or removed from `demo.conf` are picked up without a restart. A
scenario a platform has nothing for (sudo lines on a Mac, say) is tried once and then
only every 12 hours; a failure backs off from one minute to thirty.

```bash
# demo.conf
AUTO_EVENTS=yes            # no: stop sending; events then age out of the 24-hour window
AUTO_EVENTS_LEVEL=normal   # light = half as often, busy = twice as often
```

Check it with `./democtl status` or `python3 wazuh_autoevents.py --status`; every send
is one line in `logs/autoevents.log`. `python3 wazuh_autoevents.py --once` sends every
job once now (add `--dry-run` to see what it would send).

Limits: events are stamped when sent, so the 24-hour charts fill over the first hours
rather than appearing full at once. The volume has not been measured: use `light`, or
`AUTO_EVENTS=no`, if the indexer is small. If you also start the UI's ambient loop you
get both, which doubles the background traffic.

### Step 6 — install as a service (optional)

```bash
sudo ./democtl install
sudo systemctl start wazuh-sim
```

The unit starts and stops the environment as a whole. It does not supervise
individual processes, so `systemctl status` can read active while one keepalive has
died. `./democtl status` is the accurate view.

---

## Part 3 — First run, from the UI

Everything below is done in the browser.

### 1. Record inventory fixtures

**Data → Record inventory fixtures → Run.**

Captures current inventory from your real agents into `fixtures/`. Takes under a
minute for ~60k documents.

Two conditions:

- **Stop the inventory replay first.** The UI warns you. Recording while it runs
  captures the replay's own output, which compounds on every cycle.
- Confirm in the dashboard that IT Hygiene and Vulnerability Detection are populated
  for the real agents first. Recording during the first scan window produces
  half-empty fixtures.

### 2. Map inventory to each agent

For each simulated agent: **Inventory → pick a source → Apply.**

The list comes from `fixtures/manifest.json`. Choosing one rewrites `REMAP` and
`FIXTURE_AGENTS` together and restarts the replay.

Fixtures carry the recording agent's id in two places — `wazuh.agent.id` and the
document `_id` (`wazuh_004_<sha1>`) — so both are rewritten. Without this the data
lands on the original agent and your simulated agent shows status but no inventory.

Map like platform to like: a Windows fixture to a Windows agent.

### 3. Harvest log lines

**Data → Harvest log lines → Run.**

Collects every log line your real agents produced, grouped as
`<platform>-<action>` — `linux-sudo`, `windows-authentication-failure` and so on.
Expect several thousand lines across sixty-odd groups.

### 4. Check status

The agents table should show all agents **active**, with non-zero inventory counts
and an inventory source listed.

### 5. Alerts

Nothing to do: the automatic event scheduler (Step 5b) has already started sending
every scenario, so Findings fill in by themselves a few minutes after `start`. To show
one scenario on demand, use **Events → security-alerts** on any agent.

Alerts appear in the dashboard after **two to three minutes**. Findings lag events;
this caused several false alarms during development.

---

## Part 4 — The UI

### Top bar
Manager address and UTC clock. Shows "(API unreachable)" if `API_PASS` is wrong.

### Simulated agents

| Column | Source |
|---|---|
| ID | Assigned by the manager at enrolment |
| Name | `demo.conf`, plus reported IP and ambient-event state |
| Operating system | Declared by the agent in its keepalive |
| Status | Manager API — the authoritative record, not the dashboard's rendering |
| Inventory | Package count and which recorded agent it maps from |

Header: **Start all**, **Stop all**, replay toggle.

Per agent:

| Button | Does |
|---|---|
| Inventory | Pick the inventory source; rewrites REMAP and FIXTURE_AGENTS |
| Events | Send log lines to produce alerts |
| Log | Last 120 lines from that process |
| Start / Stop | The keepalive process |
| × | Remove the agent entirely |

### Scenarios

| Scenario | Produces |
|---|---|
| `ambient` | Background activity. Decodes into events; rarely raises alerts. |
| `security-alerts` | Auth failures, sudo, malware, privilege assignment. **Use this for visible alerts.** |
| `brute-force` | A burst of failed authentications, then a success |
| `privilege-escalation` | Failures, then sudo and privilege assignment |
| `session-activity` | Logins and logouts |

Plus **Start ambient** / **Stop ambient** for a continuous loop. The scheduler already
sends `ambient` every ten minutes, so use the loop only for a denser stream; it adds
to the scheduler's traffic, it does not replace it.

### Add agent
Name, platform, reported IP. Enrols, writes the credential at mode 600, and appends
to `demo.conf` so the UI and `democtl` agree.

### Data
The four maintenance jobs, each with a Run button and a log. They run in the
background; the row shows progress and the last output line.

### Reset

| Button | Effect |
|---|---|
| Purge inventory | Deletes exactly the documents the player wrote |
| Trim events >2h | Keeps recent activity, drops accumulation |
| Purge all events & alerts | Clears everything for the simulated agents |

All three affect simulated agents only.

### Real agents
Listed for context, with no controls, so nobody stops a real agent by accident.

---

## Part 5 — Running a demo

Half an hour before:

1. **Reset → Trim events >2h** so volume looks plausible.
2. Check `./democtl status` shows **Automatic events** running. Set
   `AUTO_EVENTS_LEVEL=light` for a quieter environment.
3. Confirm all agents active with inventory counts.

During:

- Open the agents list. Point out the platforms, the icons, the active status.
- Open IT Hygiene for one agent — real packages, current scan times.
- Alerts are already there, because the scheduler keeps them current. Fire
  `security-alerts` only if you want a fresh one at a particular moment; it lands two
  to three minutes later.
- Show the alert detail: rule title, MITRE technique, compliance mappings.

If you also run the UI's ambient loop, set it to `--loop 300`, not 30. During
development agent 015 accumulated 11,154 events against the real Mac's 567, which
reads as implausible.

---

## Part 6 — Synthetic seed lines

Harvesting only captures behaviour that happened. An idle Mac produces no
authentication failures, so there is nothing to record.

**Data → Seed macOS lines** generates lines shaped exactly like that platform's, which
Wazuh's decoders parse normally.

What is real and what is not:

- **The alert is real** — decoder chain, field extraction, rule match, MITRE and
  compliance tags all come from the manager.
- **The log line is fabricated**, though its grammar comes from the patterns
  `decoder/system-auth/0` parses, and its content matches the platform
  (`ttys000`, `/Users/...`, `com.apple.*`).

Attacker IPs use documentation ranges (203.0.113.x, 198.51.100.x, 192.0.2.x).

Prefer harvested lines. Use seeds to fill a gap, and say so if asked. When the real
machine is available again, generate genuine failures on it — a few mistyped sudo
passwords — and harvest those instead.

---

## Part 7 — Protocol reference

From `wazuh/wazuh` tag `5.0.0`. All endpoints need `protocol-version: 1`. Tokens live
60 seconds.

**`POST /wazuh-manager/enroll`** — `Authorization: Bearer <wazuh-enroll+jwt>`
```
key    = HKDF-SHA256(IKM=authd.pass, salt=32×0x00,
                     info="WAZUH-ENROLL-JWT-KEY"||0x01, L=32)
header = {"alg":"HS256","typ":"wazuh-enroll+jwt"}      (no kid)
claims = {exp, iat, jti, nbf}                          (no iss/sub)
body   = {"name","version","ip"?,"groups"?}            groups is a STRING
→ 200 {"id","ip","key","name"}                         key = 64 hex chars
```

**`POST /wazuh-manager/control`** — `Authorization: Bearer <wazuh-agent+jwt>`
```
key    = enrolment key hex-DECODED to 32 raw bytes
header = {"alg":"HS256","typ":"wazuh-agent+jwt","kid":"<id>"}
claims = {exp, iat, jti, nbf, iss:"wazuh-agent/<id>", sub:"<id>"}
body   = {"type":"startup"|"notify"|"shutdown", ...}
```

**`POST /wazuh-manager/stateless`** — `Content-Type: application/x-ndjson`
```
H {"wazuh":{"agent":{"id":"015",...},"protocol":{"queue":49,"location":"macos"}}}
E 1:macos:<raw log line>
E 1:macos:<raw log line>
```

The `<queue-char>:<location>:` prefix is **required**. Queue 49 (`1`) for
logcollector, 102 (`f`) for Windows EventChannel.

Sources: `shared_modules/utils/jwt/jwtEnrollProfileV1.hpp`, `jwtProfileV1.hpp`,
`remoted/remoted_module/src/endpoints/{controlEndpoint,statelessEndpoint}.cpp`,
`.../auth/authMiddleware.cpp`, `.../enrollment/enrollmentEndpoint.cpp`.

---

## Part 8 — Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Keepalive returns 401 | Manager purged the agent. Delete `agents/<name>.json`, restart; it re-enrols with a new id. Update the inventory mapping. |
| Active but no inventory | No mapping, or it points at a stale id. Fix via **Inventory**. |
| Events sent, nothing indexed | The line did not decode. 202 means queued, not decoded. Check `/var/wazuh-manager/logs/wazuh-manager.log`. |
| Events indexed, no alerts | The action matches no rule, or you checked too soon. Use `security-alerts` and wait 2–3 minutes. |
| Dashboard empty after some hours | The automatic events are not running (`AUTO_EVENTS=no`, or the process died). `./democtl status`, then `./democtl start`. Replayed events age out of the 24-hour window. |
| "candidates rejected as implausible" | No lines for that platform. Harvest from a real one, or seed. |
| Recorder captures nothing | The agent filter matched nothing — check the ids. |
| macOS events show integration `linux` | Pre-existing Wazuh behaviour: `decoder/system-auth/0` belongs to the `linux` integration and is shared. Real Macs do the same. |

### Field names that cost us a day

- Identity is **`wazuh.agent.id`**, not `agent.id`.
- Rule metadata is **`wazuh.rule.*`**, not `rule.*`.
- **`event.original` is stored but not indexed.** An `exists` query on it matches zero
  documents and silently zeroes any query it joins.
- Queue byte: **49** logcollector, **102** EventChannel. Wrong byte, silent drop.
- `/stateless` returns **202 for anything it accepts**, decoded or not.
- State indices use **strict dynamic mapping** — one unknown field fails the whole
  bulk request.
- Inventory indices hold **state, not events**: upsert on the original `_id`.
- The content ruleset directory rotates (`cmsync_standard_*`), so custom rules cannot
  live there.

---

## Part 9 — Maintenance

**After a Wazuh upgrade**, re-record fixtures and re-harvest events (both from the
Data panel), then verify one agent end to end. If enrolment starts failing, re-read
`jwtEnrollProfileV1.hpp` and `jwtProfileV1.hpp` — the profile header states that a
token is either exactly right or rejected, so it fails loudly.

**Never replay onto a running agent.** Two writers on the same document ids means the
player silently reverts real changes. Map fixtures onto simulated ids only.

**Re-record after the real agents change**, so inventory stays representative.

---

## Part 10 — Outcome

| Before | After |
|---|---|
| macOS Dedicated Host (24 h minimum) | none |
| Windows instance | none |
| Linux instance | none, or keep one real |

One-time cost: recording sessions on real machines. Everything after that is free,
and additional simulated endpoints cost nothing.
