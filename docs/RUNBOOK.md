# Wazuh 5.x Simulated Agent Environment

Run a Wazuh 5.x demo environment with **zero endpoint EC2 instances**. Agents appear
active because they genuinely are connected to the manager; IT Hygiene and
Vulnerability Detection stay populated from recorded fixtures.

Verified against **Wazuh 5.0.0-beta5**, indexer 3.6.0, cluster `wazuh`, manager `10.0.44.61`.

---

## 0. In plain terms — what we did and how

*Read this first. Everything below is the detail.*

### The problem

A good demo needs a Mac, a Windows box and a Linux box, each running a Wazuh agent.
That's three cloud machines running around the clock so someone can look at them
occasionally. The Mac is the expensive one: Apple hardware has to be rented as a whole
physical machine, minimum a full day at a time.

### The insight

The dashboard gets its information from two different places, and only one of them was
a problem.

Most of what you see — installed software, open ports, running processes,
vulnerabilities — lives in a database (the indexer) that we can write to ourselves.

But whether an agent shows as **online** is different. That's the manager's own record
of "has this machine checked in recently", and no amount of writing to the database
changes it. We found that out by trying: we wrote a record saying an agent was active,
and the dashboard carried on showing it as offline.

### Solving the data half

We ran real machines **once**, recorded everything they reported, then shut them down.
A script replays those recordings into the database every few minutes with refreshed
timestamps, so the dashboard always shows current-looking information.

Like a recorded camera feed played back with today's date on it — except the recording
is genuine output from a real agent, so every field is correct by construction.

### Solving the "agent is live" half

This is the part that took the work.

**Step 1 — find where status actually comes from.** We tailed the dashboard's logs
while reloading the agents page and saw it repeatedly calling the manager API directly
rather than reading the database. Status is the manager's opinion, full stop.

**Step 2 — find how an agent talks to the manager.** The agent's own config pointed at
port 1517, and a packet capture showed it opening a brief encrypted connection every
ten seconds, sending something small, and closing. That's the check-in.

**Step 3 — work out what it sends.** The traffic is encrypted, so we couldn't just
read it. Instead:

- The manager's compiled files contained a leftover log message listing the available
  web addresses, which gave us the destinations (`/enroll`, `/control`, and others).
- We sent deliberately malformed requests and read the errors. The server told us what
  was missing each time — first a version header, then a security token.
- The token was the wall. It's derived from the enrollment password through a
  scrambling process whose exact recipe is compiled in, where no error message would
  ever reveal it.

**Step 4 — read the source.** Wazuh is open source. The compiled file had leaked its
original filename, so we knew exactly which file to open on GitHub. The recipe was
written out in a comment at the top of it: the ingredients, the order, the exact
label. Twenty minutes, versus a day of guessing or waiting on another team.

**Step 5 — build it.** We generated the token, enrolled an agent called `macos-demo`,
and the manager accepted it, handing back an agent ID and key exactly as it would for
a real machine. Then we started a loop that checks in every ten seconds.

### The honest framing

The status is **not faked**. Our program genuinely connects to the manager and
genuinely checks in, so when the manager reports "active" it is telling the truth.
Something really is connected. It just isn't a Mac.

This also explains why we wrote our own client rather than running a stripped-down
real agent: a real Linux agent would report itself as Linux, which defeats the purpose
when the machine you're avoiding buying is a Mac. Writing our own means we declare
what we are.

### The result

Three demo endpoints with correct platforms, correct icons, live status and populated
inventory. Zero endpoint machines running. The only remaining cost is borrowing a real
Mac for about an hour, once, to record its software inventory.

**One line for a technical audience:** agent status comes from the manager API, not the
indexer — so we implemented the agent check-in protocol rather than trying to fake it,
and found the specification in Wazuh's own public source.

---

## 1. Quick start

Everything runs through one control script.

```bash
cd /opt/wazuh-demo
chmod +x democtl

./democtl setup      # creates config files, checks connectivity, offers to record fixtures
./democtl start      # enrol anything new, start keepalives, inventory replay, automatic events
./democtl status     # processes, agent IDs, manager view, inventory counts
./democtl logs       # tail everything
./democtl stop       # stop all, mark agents disconnected cleanly
./democtl restart
./democtl purge      # remove replayed documents from the indexer
```

`setup` is the only step that needs your input. It creates `demo.conf` and
`indexer.env` (mode 600), prompts for the manager address and indexer credentials,
verifies it can reach both the indexer and the manager on 1517, and offers to record
fixtures. Safe to re-run: it leaves existing files alone and just re-checks
connectivity.

After the first `start`, run `./democtl status` to see which agent IDs were assigned,
then set `REMAP` in `demo.conf` to match. That is the one value the script cannot infer.

`start` is idempotent: run it twice and it reports what is already up rather than
spawning duplicates. Enrolment only happens for agents with no state file, so restarts
reuse existing credentials instead of creating new agents each time.

To make it permanent and survive reboots:

```bash
sudo ./democtl install
sudo systemctl start wazuh-sim
```

---

## 2. Credentials

Two sets, in two files. Both are secrets: `chmod 600`, and keep them out of any git
repository.

`./democtl setup` creates both files for you. The manual equivalents are below for
reference, or if you need to change a credential later.

### Indexer — `indexer.env`

Needed by the replay. Without it `./democtl start` refuses to start the replay and says
so explicitly.

```bash
cd /opt/wazuh-demo
sudo install -m 600 /dev/stdin indexer.env <<'EOF'
WAZUH_INDEXER_URL=https://127.0.0.1:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=your-password
EOF
```

Use `127.0.0.1`. Port 9200 binds loopback on the manager host; the LAN address is
refused.

### Manager API — `wazuh-wui`

Used by `./democtl status` to show the manager's view. The dashboard keeps its own copy
in a write-only keystore, so **the existing password cannot be read back**. If you do
not know it, reset it.

```bash
sudo /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh \
  -A -u wazuh-wui -p '<new-api-password>' -au wazuh -ap 'wazuh'
```

- `-A` selects API password mode, `-u` the user, `-p` the new password
- `-au` / `-ap` are the API's own admin account, `wazuh` / `wazuh` on a fresh install

**The password character set is restricted.** The tool accepts only `.*+?-` as symbols
and rejects anything else with a misleading "must have a length between 8 and 64
characters" error. A password ending in `!` fails; one using `-` succeeds.

Verify it, then record it in `demo.conf` rather than relying on shell history:

```bash
curl -sk -u wazuh-wui:'<new-api-password>' -X POST \
  "https://127.0.0.1:55000/security/user/authenticate?raw=true" | head -c 40
```

```bash
chmod 600 demo.conf indexer.env
```

Resetting is safe on a running system: the dashboard does not use this credential for
its own operation, and no restart is required.

### Agent keys — `agents/*.json`

Written by the simulator at enrolment, chmod 600 automatically. These are real agent
credentials. Deleting one means the next start enrols a **new** agent rather than
reusing the old, orphaning the previous one in the manager.

---

## 3. Configuration — `demo.conf`

```bash
MANAGER=10.0.44.61

# name:profile:reported_ip      profile = macos | windows | linux
AGENTS="
macos-demo:macos:10.0.44.200
win-demo:windows:10.0.44.201
amzn-demo:linux:10.0.44.202
"

# Agent IDs in ./fixtures to replay — the REAL agents they were recorded from
FIXTURE_AGENTS="004 002"

# Map recorded agent -> simulated agent:  OLD:NEW[:NAME[:HOSTNAME]]
REMAP="004:007:win-demo:WIN-DEMO 002:008:amzn-demo:amazonlinux-demo"

REPLAY_INTERVAL=300
API_USER=wazuh-wui
API_PASS=<your-api-password>
CLEAN_SHUTDOWN=yes

# keep alerts flowing automatically (default yes); light | normal | busy
AUTO_EVENTS=yes
AUTO_EVENTS_LEVEL=normal
```

Run `./democtl status` after the first enrolment to see which IDs were assigned, then
set `REMAP` accordingly. Getting this wrong is the difference between populated panels
and empty ones.

---

## 4. What this solves

A realistic demo needs a macOS, a Windows and a Linux endpoint. Running them costs
real money — macOS especially, since EC2 Mac instances are Dedicated Hosts with a
24-hour minimum allocation. Windows adds licensing. Linux is nearly free.

This removes the endpoints while keeping the dashboard experience intact.

---

## 5. How Wazuh 5.x sources its data (and why there are two processes)

The single most important finding from this work: **agent status and agent data come
from different places.**

| What the dashboard shows | Source | Writable by us? |
|---|---|---|
| Agent list, status, OS, keepalive | Manager API (55000), proxied via `POST /api/request` | Only by speaking the agent protocol |
| IT Hygiene inventory | `wazuh-states-inventory-*` indices | Yes, directly |
| Vulnerability Detection | `wazuh-states-vulnerabilities` | Yes, directly |
| SCA | `wazuh-states-sca` | Yes, directly |

We proved this empirically: injecting a document into `wazuh-metrics-agents` claiming
`status: active` for a stopped agent changed nothing in the UI, while the manager API
continued to report `disconnected`. Writing to the indexer cannot fake status.

Hence two processes:

| Process | Talks to | Provides | Cadence |
|---|---|---|---|
| `wazuh_agent_sim.py` | manager remoted, **1517** | agent exists, **active status**, reported OS | 10 s |
| `wazuh_fixture_player.py` | indexer, **9200** | inventory, vulnerabilities, SCA | 5 min |

The keepalive is not a spoof. The simulator really speaks the 5.x agent protocol, so
the manager is *correct* when it reports the agent as connected. Only the hardware is
fictional.

---

## 6. The scripts

### `democtl` — control script

Start, stop, status, logs, enrol, purge. `start` also launches the automatic event
scheduler (`wazuh_autoevents.py`, below). Reads `demo.conf` and `indexer.env`, keeps PID
files in `run/` and per-process logs in `logs/`. Runs children with
`PYTHONUNBUFFERED=1` so log lines appear immediately rather than after a 4 KB buffer
fills, and writes a timestamped marker at each start so restarts are visible in the log.
It does not restart children that die — use systemd for that (section 13).

### `wazuh_fixture_recorder.py` — capture (run once per platform)

Pulls every document real agents produced and writes them to disk as replayable
fixtures.

Why record rather than generate: the state indices are wide, mappings shift between
builds, and a missing subfield produces a silently empty dashboard panel rather than
an error. Capturing real output means the schema is correct by construction, and a
Wazuh upgrade means re-recording rather than rewriting.

- Resolves `wazuh-states-*` and `wazuh-agents*` via `_cat/indices`, so no index names
  are hardcoded
- Saves `docs/<index>.jsonl` (with `_index`, `_id`, `_source`), `mappings/<index>.json`,
  and a `manifest.json` with counts and observed agents
- Warns loudly about indices that captured zero documents

```bash
python3 wazuh_fixture_recorder.py --outdir ./fixtures [--agents 002 004]
```

### `wazuh_enroll_token.py` — enrollment token generator (diagnostic)

Standalone tool that derives the `wazuh-enroll+jwt` bearer and prints either the raw
token or a ready-to-run curl command. Useful for testing enrollment by hand or
debugging a 401. `wazuh_agent_sim.py` does this internally, so this script is not
needed in normal operation.

```bash
python3 wazuh_enroll_token.py --curl --name macos-demo --manager 10.0.44.61
```

### `wazuh_agent_sim.py` — the agent (status)

Enrolls once, then sends `startup` followed by `notify` keepalives forever. Collects
nothing. Because the notify body declares the host and OS, the simulator can claim to
be macOS — which a stripped-down real Linux agent could not.

- `--profile macos|windows|linux` sets the declared OS and architecture
- `--state FILE` persists the agent id and key (chmod 600 — it is a real credential)
  so restarts reuse the enrollment instead of creating a new agent
- `--once` sends startup + one notify and exits, for testing
- `--shutdown` marks the agent disconnected immediately rather than waiting for timeout

```bash
python3 wazuh_agent_sim.py --manager 10.0.44.61 --profile macos \
  --name macos-demo --hostname macbook-demo --reported-ip 10.0.44.200 \
  --state ./agents/macos-demo.json
```

### `wazuh_fixture_player.py` — the data (inventory)

Loads fixtures, refreshes their timestamps, and bulk-upserts them back into the
indexer on a loop.

- Only rewrites freshness fields (`state.modified_at`, `@timestamp`) and bumps
  `state.document_version`. Observed data — package versions, CVE dates, boot time —
  is left alone, because rewriting it is what makes replayed data look synthetic
- `--jitter` spreads timestamps over a window so documents don't share one identical
  scan time
- Upserts on the document's own `_id`, since these indices hold **state, not events**.
  Generating fresh ids would accumulate duplicate packages every cycle
- `--remap OLD:NEW[:NAME[:HOSTNAME]]` replays one agent's fixtures as another agent,
  rewriting both the `_id` prefix (`wazuh_<id>_<sha1>`) and `wazuh.agent.id`
- `--purge` deletes exactly the index/`_id` pairs in the fixture set, honouring remap
- Skips `wazuh-states-fim-*` by default (44k of 62k documents, rarely demoed);
  `--include-fim` to include

```bash
python3 wazuh_fixture_player.py --fixtures ./fixtures \
  --agents 004 002 \
  --remap 004:007:win-demo:WIN-DEMO 002:008:amzn-demo:amazonlinux-demo \
  --loop 300
```

### `wazuh_autoevents.py` — events on a schedule

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

---

## 7. Protocol reference

From `wazuh/wazuh` at tag **`5.0.0`**. Both endpoints require `protocol-version: 1`.
Tokens live 60 s and are regenerated per request.

**`POST /wazuh-manager/enroll`** — `Authorization: Bearer <wazuh-enroll+jwt>`
```
key    = HKDF-SHA256(IKM=authd.pass, salt=32×0x00, info="WAZUH-ENROLL-JWT-KEY"||0x01, L=32)
header = {"alg":"HS256","typ":"wazuh-enroll+jwt"}          (no kid)
claims = {exp, iat, jti, nbf}                              (no iss/sub)
body   = {"name","version","ip"?,"groups"?,"key_hash"?}
         groups is a comma-separated STRING, not an array
→ 200 {"id","ip","key","name"}                             key = 64 lowercase hex chars
```

**`POST /wazuh-manager/control`** — `Authorization: Bearer <wazuh-agent+jwt>`
```
key    = enrollment key hex-DECODED to 32 raw bytes        (must be exactly 32)
header = {"alg":"HS256","typ":"wazuh-agent+jwt","kid":"<id>"}
claims = {exp, iat, jti, nbf, iss:"wazuh-agent/<id>", sub:"<id>"}
body   = {"type":"startup","version":"v5.0.0"}
       | {"type":"notify","agent":{"version":...},
          "host":{"hostname","architecture","ip",
                  "os":{"name","version","platform","type"}}}
       | {"type":"shutdown"}
```

Other routes under the prefix: `/stateful`, `/stateless`, `/config`, `/metrics`,
`/stats`, `/download`. Unprefixed paths return 404 by design.

Sources: `src/shared_modules/utils/jwt/jwtEnrollProfileV1.hpp`,
`src/shared_modules/utils/jwt/jwtProfileV1.hpp`,
`src/remoted/remoted_module/src/endpoints/controlEndpoint.cpp`,
`src/remoted/remoted_module/src/auth/authMiddleware.cpp`,
`src/remoted/remoted_module/src/enrollment/enrollmentEndpoint.cpp`.

---

## 8. Setup

```bash
export WAZUH_INDEXER_URL=https://127.0.0.1:9200      # NOT the LAN IP; 9200 binds loopback
export WAZUH_INDEXER_USER=admin
read -rs WAZUH_INDEXER_PASS && export WAZUH_INDEXER_PASS

curl -sk -u "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASS" "$WAZUH_INDEXER_URL" | head -3
sudo cat /var/wazuh-manager/etc/authd.pass
```

Scripts live in `/opt/wazuh-demo/`.

---

## 9. Phase 1 — Record fixtures (needs live agents)

Confirm in the dashboard that IT Hygiene and Vulnerability Detection are **already
populated** for each agent. Recording during the first scan window produces
half-empty fixtures.

```bash
python3 wazuh_fixture_recorder.py --outdir ./fixtures
```

Review `fixtures/manifest.json` and the zero-document warnings before decommissioning
anything.

### The macOS gap

There are no macOS fixtures and they cannot be convincingly fabricated — the field
sets genuinely differ from Linux, and macOS is the platform where a wrong-looking
package list is most visible.

1. **Borrow a real Mac** — install the beta5 agent on any colleague's machine, join it
   over Tailscale, let one scan cycle finish, record, uninstall. Free, ~1 hour.
2. **EC2 `mac2.metal`** — 24-hour minimum (~$16). Same cost for ten minutes or a day.

Do **not** run macOS under QEMU/KVM. It violates Apple's licence terms and is not
appropriate for commercial demo infrastructure. Nested virtualization also requires
`.metal` instances, which cost more than what you're trying to avoid.

---

## 10. Phase 2 — Enroll simulated agents

```bash
mkdir -p agents

python3 wazuh_agent_sim.py --manager 10.0.44.61 --profile macos \
  --name macos-demo --hostname macbook-demo --reported-ip 10.0.44.200 \
  --state ./agents/macos-demo.json --once

python3 wazuh_agent_sim.py --manager 10.0.44.61 --profile windows \
  --name win-demo --hostname WIN-DEMO --reported-ip 10.0.44.201 \
  --state ./agents/win-demo.json --once

python3 wazuh_agent_sim.py --manager 10.0.44.61 --profile linux \
  --name amzn-demo --hostname amazonlinux-demo --reported-ip 10.0.44.202 \
  --state ./agents/amzn-demo.json --once
```

Both `startup` and `notify` must return 200. Record which IDs were assigned — they are
needed for the remap in Phase 3.

Current environment:

| ID | Name | Type | Platform |
|---|---|---|---|
| 001 | Wazuh-server | real (manager) | Ubuntu 24.04 |
| 002 | ubuntu24 | real | Ubuntu 24.04 |
| 004 | win11 | real | Windows 11 |
| 005 | macos-demo | simulated (superseded — delete) | macOS |
| 006 | macos-demo | simulated | macOS 15.6.1 |
| 007 | win-demo | simulated | Windows 11 Pro |
| 008 | amzn-demo | simulated | Amazon Linux 2023 |

---

## 11. Phase 3 — Run

```bash
# keepalives: one process per simulated agent
python3 wazuh_agent_sim.py --manager 10.0.44.61 --profile macos \
  --reported-ip 10.0.44.200 --state ./agents/macos-demo.json &
python3 wazuh_agent_sim.py --manager 10.0.44.61 --profile windows \
  --reported-ip 10.0.44.201 --state ./agents/win-demo.json &
python3 wazuh_agent_sim.py --manager 10.0.44.61 --profile linux \
  --reported-ip 10.0.44.202 --state ./agents/amzn-demo.json &

# inventory: one process, with remap from recorded agent → simulated agent
python3 wazuh_fixture_player.py --fixtures ./fixtures \
  --agents 004 002 \
  --remap 004:007:win-demo:WIN-DEMO 002:008:amzn-demo:amazonlinux-demo \
  --loop 300 &
```

**The remap is mandatory.** Fixtures carry the recording agent's id in both
`wazuh.agent.id` and the document `_id` (`wazuh_004_<sha1>`). Without `--remap`, the
data lands on the original agent and the simulated agents' panels stay empty.

Events need no process of their own to start: `./democtl start` runs
`wazuh_autoevents.py`, which keeps alerts flowing (section 6). To run it alone:
`python3 wazuh_autoevents.py &`.

---

## 12. Phase 4 — Verification

| # | Check | How | Expect |
|---|---|---|---|
| 1 | Agents active | `GET /agents` | 006/007/008 active |
| 2 | Keepalive advancing | re-run after 60 s | `lastKeepAlive` moves |
| 3 | OS correct | `select=os.name,os.version` | macOS / Windows / Amazon Linux |
| 4 | Dashboard list | Agents page | correct icons and status |
| 5 | Inventory present | IT Hygiene → agent 007 | packages, ports, processes |
| 6 | Inventory fresh | scan time column | within 5 min |
| 7 | Vulnerabilities | Vulnerability Detection → 007 | findings listed |
| 8 | No manager errors | `tail /var/wazuh-manager/logs/wazuh-manager.log` | no integrity/checksum errors |
| 9 | Survives restart | kill and restart both | status recovers <1 min |

```bash
TOKEN=$(curl -sk -u wazuh-wui:'<api-pass>' -X POST \
  "https://127.0.0.1:55000/security/user/authenticate?raw=true")
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://127.0.0.1:55000/agents?pretty=true&select=id,name,status,lastKeepAlive,os.name"

for a in 006 007 008; do
  printf 'agent %s packages: ' "$a"
  curl -sk -u "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASS" \
    "$WAZUH_INDEXER_URL/wazuh-states-inventory-packages/_count" \
    -H 'Content-Type: application/json' -d "{\"query\":{\"term\":{\"wazuh.agent.id\":\"$a\"}}}"
  echo
done
```

---

## 13. Phase 5 — Permanent deployment

```bash
sudo ./democtl install     # writes and enables the systemd unit
sudo systemctl start wazuh-sim
```

That generates `/etc/systemd/system/wazuh-sim.service` pointing at wherever the script
lives, reloads systemd, and enables it at boot. The environment then survives reboots
and no longer depends on your shell session.

```bash
sudo systemctl status wazuh-sim     # did it start
./democtl status                    # the detailed view
sudo ./democtl uninstall            # remove the unit; config and keys are kept
```

The unit is `Type=oneshot` with `RemainAfterExit=yes`: it calls `democtl start` once
and `democtl stop` on shutdown. It does **not** supervise individual processes, so if a
single keepalive dies, systemd still reports the service as active while
`./democtl status` shows 3/4 up. Re-run `systemctl restart wazuh-sim` to recover.

If you want per-process supervision with `Restart=always`, write one unit per agent
invoking `wazuh_agent_sim.py` directly, plus one for `wazuh_fixture_player.py`. That is
more robust and more files to maintain; the wrapper is usually enough for a demo
environment.

---

## 14. Rollback

```bash
sudo systemctl disable --now 'wazuh-sim-agent@*' wazuh-sim-replay

# remove replayed documents (exact ids, honours remap — touches nothing else)
python3 wazuh_fixture_player.py --fixtures ./fixtures --agents 004 002 \
  --remap 004:007 002:008 --purge

# mark an agent disconnected immediately
python3 wazuh_agent_sim.py --manager 10.0.44.61 \
  --state ./agents/macos-demo.json --shutdown

# delete simulated agents from the manager
curl -sk -H "Authorization: Bearer $TOKEN" -X DELETE \
  "https://127.0.0.1:55000/agents?agents_list=005,006,007,008&status=all&older_than=0s"
```

---

## 15. Known issues

**Agent 006 (macOS) has no inventory.** No macOS fixtures exist. Status works, panels
are empty. This is the one outstanding piece of work.

**Agent 008 reports Amazon Linux but carries Ubuntu packages.** The Linux fixture came
from agent 002 (Ubuntu 24.04) while 008 enrolled as Amazon Linux 2023, so the agent
list and the package list disagree. Either edit the `linux` profile in
`wazuh_agent_sim.py` to declare Ubuntu, or record a real Amazon Linux agent.

**`host.os.platform` does not exist in most state indices.** Only `system` and
`hardware` carry it; packages, ports and processes nest it under
`wazuh.agent.host.os.platform`. Dashboard filter pills using `host.os.platform`
silently empty those panels. This is pre-existing Wazuh UI behaviour, not caused by
replay. Filter on `wazuh.agent.host.os.platform` instead.

**State indices use strict dynamic mapping.** Any field not in the mapping (e.g. a
`simulated: true` marker) is rejected wholesale, failing the entire bulk request. The
player therefore adds nothing by default; `--tag-group` appends to the existing
`wazuh.agent.groups` array instead.

**Never replay onto a running agent.** Two writers on the same document ids means the
player silently reverts real changes. Only target retired agents, or remap onto
simulated ids.

**Inventory is state, not events.** Documents must upsert onto their own `_id`.

**Vulnerability scans are delta-triggered** (`reason=package_delta`). Replaying
identical packages produces no delta and no rescan. Mutating packages later will fire
real scans.

**Protocol stability is not guaranteed.** `jwtProfileV1.hpp` states a token is either
exactly the profile or rejected. Pin the source revision you built against and re-read
both JWT profile headers after any upgrade.

**Ignored manager features.** The simulator does not act on the `tasks` array or fetch
`/config` when `config_hash` changes, so remote upgrades and config pushes never
execute. Harmless for a demo.

**Indexer binds loopback.** Use `https://127.0.0.1:9200`, not the LAN address.

**Old errors persist in logs.** `democtl` appends rather than truncating, so a failed
start leaves its error at the end of the file until the next start writes its timestamp
marker. Check the marker before assuming an error is current.

**The manager API password cannot be recovered**, only reset — see section 2. Record it
in `demo.conf` rather than relying on shell history.

---

## 16. Method — how this was worked out

The plain-language version is in section 0. This is the same sequence with the
specifics, recorded for whoever maintains this after a Wazuh upgrade, since the same
steps apply.

1. **Assumed the indexer was authoritative.** Wrong. Injecting an `active` document
   into `wazuh-metrics-agents` for a stopped agent changed nothing in the UI.
2. **Found the real read path** by tailing the dashboard journal while reloading the
   agents page: repeated `POST /api/request`, the plugin's proxy to the manager API on
   55000. Status is manager-owned.
3. **Found the agent protocol** from the agent's own config (`port: 1517`,
   `endpoint: wazuh-manager`) and a tcpdump showing short-lived TLS connections every
   10 s — plain HTTPS request/response, not a persistent binary channel.
4. **Enumerated routes** with `strings` on `libremoted_module.so`, which included a log
   line documenting the global prefix and the route list.
5. **Walked the error chain.** `POST` with an empty body returned
   `Missing required header: protocol-version`; adding it returned 401 with
   `WWW-Authenticate: Bearer`. The server documented its own contract.
6. **Hit the wall** at the bearer token: the raw authd password was rejected, and the
   HKDF salt/info are compiled constants no error message will reveal.
7. **Read the source.** Wazuh is open source. `strings` had already leaked the build
   path, giving the exact file. `jwtEnrollProfileV1.hpp` states the full derivation in
   a comment. Twenty minutes, versus a day of guessing or waiting on another team.

The lesson worth carrying forward: for an open-source product, read the source first.
It was faster and more accurate than both binary archaeology and internal escalation.

---

## 17. Outcome

| Before | After |
|---|---|
| macOS Dedicated Host (24 h min) | none |
| Windows instance | none |
| Linux instance | none (or keep one real) |

One-time cost: a single macOS recording session. Everything after that is free, and
adding more simulated endpoints costs nothing.
