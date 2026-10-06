# Operating the simulated environment

Day-to-day reference. Full background is in RUNBOOK.md.

---

## 1. Cleanup — reset to a known state

Run this before a demo, or whenever the environment has drifted.

```bash
cd /opt/wazuh-demo

# 1. stop everything, including stray event loops started by hand
./democtl stop
pkill -f wazuh_event_player || true
pkill -f wazuh_sim_ui || true

# 2. confirm nothing is left
ps aux | grep -E '[w]azuh_(event_player|agent_sim|fixture_player|sim_ui)' || echo "clean"

# 3. clear replayed inventory (exact ids from the fixture set; touches nothing else)
set -a; source indexer.env; set +a
./democtl purge

# 4. clear replayed events and findings for the simulated agents only
for IDX in wazuh-events-v5 wazuh-findings-v5; do
  curl -sk -u "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASS" -X POST \
    "$WAZUH_INDEXER_URL/${IDX}-*/_delete_by_query?refresh=true" \
    -H 'Content-Type: application/json' \
    -d '{"query":{"terms":{"wazuh.agent.id":["012","013","014","015"]}}}'
  echo
done
```

Adjust that agent list if your ids differ — `./democtl status` shows the current ones.

### Removing agents entirely

Only if you want to start over. Deleting the state file orphans the agent in the
manager, so delete it there too.

```bash
TOKEN=$(curl -sk -u wazuh-wui:"$API_PASS" -X POST \
  "https://127.0.0.1:55000/security/user/authenticate?raw=true")

# list first, so you delete what you mean to
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://127.0.0.1:55000/agents?pretty=true&select=id,name,status"

# then remove the simulated ones and their local credentials
curl -sk -H "Authorization: Bearer $TOKEN" -X DELETE \
  "https://127.0.0.1:55000/agents?agents_list=012,013,014,015&status=all&older_than=0s"
rm -f agents/*.json
```

`./democtl start` re-enrols anything missing and assigns new ids, so update REMAP
afterwards (or set it from the UI).

### Trimming event volume

The ambient loop is easy to leave running. Agent 015 reached 11,154 events against
the real Mac's 567, which reads as implausibly busy.

```bash
# keep only the last 2 hours for the simulated agents
curl -sk -u "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASS" -X POST \
  "$WAZUH_INDEXER_URL/wazuh-events-v5-*/_delete_by_query?refresh=true" \
  -H 'Content-Type: application/json' -d '{
  "query": {"bool": {"must": [
    {"terms": {"wazuh.agent.id": ["012","013","014","015"]}},
    {"range": {"@timestamp": {"lte": "now-2h"}}}]}}}'
```

Use `--loop 300` rather than `--loop 30` for ambient traffic. Five-minute intervals
keep the environment alive without generating twenty times what a real machine does.

---

## 2. Starting and stopping

### From the command line

```bash
./democtl start      # enrol anything new, start keepalives + inventory replay
./democtl status     # processes, agent ids, manager view, inventory counts
./democtl stop       # stop all, mark agents disconnected cleanly
./democtl restart
./democtl logs       # tail everything
```

### From the UI

```bash
python3 wazuh_sim_ui.py --port 8088
```

Then from your laptop:

```bash
ssh -L 8088:127.0.0.1:8088 root@10.0.44.61
```

and open `http://localhost:8088`.

The UI binds to loopback because it has **no authentication** — anything that can
reach the port can enrol agents and stop processes. Use `--bind 0.0.0.0` only on a
trusted management network.

### As a service

```bash
sudo ./democtl install      # generate and enable the systemd unit
sudo systemctl start wazuh-sim
sudo systemctl status wazuh-sim
sudo ./democtl uninstall    # remove it; config and keys are kept
```

The unit starts and stops the environment as a whole. It does **not** restart
individual processes that die, so `systemctl status` can read "active" while
`./democtl status` shows 4 of 5 up.

---

## 3. The UI

Top bar shows the manager address and UTC clock. Everything else is panels.

### Simulated agents table

| Column | Meaning |
|---|---|
| ID | Agent id assigned by the manager at enrolment |
| Name | Config name, plus reported IP and whether ambient events are running |
| Operating system | What the agent declares in its keepalive |
| Status | From the manager API, not the dashboard — the authoritative record |
| Inventory | Package count, and which recorded agent it is mapped from |

Header buttons: **Start all**, **Stop all**, and a replay toggle.

### Per-agent buttons

**Inventory** — choose which recorded agent's data this agent serves. The list comes
from `fixtures/manifest.json`. Applying it rewrites `REMAP` and `FIXTURE_AGENTS`
together and restarts the replay. Setting one without the other is the usual cause of
an agent that has status but no inventory, which is why the UI does both.

**Events** — send log lines through the manager so it raises real alerts:

| Scenario | Produces |
|---|---|
| `ambient` | Background activity. Decodes into events; rarely raises alerts. |
| `security-alerts` | Auth failures, sudo, malware, privilege assignment. This is the one that produces visible alerts. |
| `brute-force` | A burst of failed authentications, then a success. |
| `privilege-escalation` | Failures followed by sudo and privilege assignment. |
| `session-activity` | Logins and logouts. |

Also **Start ambient** / **Stop ambient** for a continuous low-rate loop.

**Log** — last 120 lines from that process.

**Start / Stop** — the keepalive process. Stopping it means the agent goes
disconnected within a few minutes.

### Add agent

Name, platform and reported IP. Enrols against the manager, writes the credential to
`agents/<name>.json` at mode 600, and appends the agent to `demo.conf` so `democtl`
and the UI stay in agreement.

### Real agents

Listed for context with no controls, so nobody stops a real agent by accident.

---

## 4. Running a demo

```bash
# ambient traffic on all three, gentle rate
for a in macos-demo win-demo amzn-demo; do
  python3 wazuh_event_player.py --state agents/$a.json --events ./events \
    --profile $(grep "^$a:" demo.conf | cut -d: -f2) --scenario ambient --loop 300 &
done
```

Then during the demo, press **Events → security-alerts** on whichever agent you are
talking about. Alerts appear in the dashboard about two to three minutes later.

**Findings lag events by minutes, not seconds.** Fire the scenario before you start
talking about that agent, not while everyone is watching an empty panel.

---

## 5. Health checks

```bash
./democtl status
```

Expect all processes up, all agents active, non-zero inventory counts.

```bash
# alerts by agent
curl -sk -u "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASS" \
  "$WAZUH_INDEXER_URL/wazuh-findings-v5-*/_search?pretty" \
  -H 'Content-Type: application/json' -d '{
  "size": 0,
  "query": {"terms": {"wazuh.agent.id": ["012","013","015"]}},
  "aggs": {"by_agent": {"terms": {"field": "wazuh.agent.id"},
    "aggs": {"rules": {"terms": {"field": "wazuh.rule.title", "size": 8}}}}}}'

# inventory freshness — should be within the replay interval
curl -sk -u "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASS" \
  "$WAZUH_INDEXER_URL/wazuh-states-inventory-system/_search?pretty" \
  -H 'Content-Type: application/json' -d '{
  "size": 5, "_source": ["wazuh.agent.id","state.modified_at"]}'
```

Troubleshooting:

| Symptom | Cause |
|---|---|
| Agent enrols but keepalive returns 401 | Manager purged the agent. Delete `agents/<name>.json` and restart. |
| Status active, inventory empty | REMAP not set, or points at an old id. Fix in the UI. |
| Events sent (202) but nothing indexed | Line did not decode. Check the manager log; 202 means queued, not decoded. |
| Events indexed but no alerts | Action does not match a rule. Use `security-alerts`, and wait a few minutes. |
| "candidates rejected as implausible" | Corpus has no lines for that platform. Expected for macOS unless seeded. |

---

## 6. Field names that bite

Cost most of a day between them.

- Identity is **`wazuh.agent.id`**, not `agent.id`.
- Rule metadata is **`wazuh.rule.*`**, not `rule.*`.
- **`event.original` is stored but not indexed** — an `exists` query on it matches
  zero documents and silently zeroes any query it is combined with.
- Queue byte is **49** for logcollector (macOS, Linux) and **102** for Windows
  EventChannel. Wrong byte, wrong decoder set, silent drop.
- `/stateless` returns **202 for anything it accepts**, decoded or not.
- The content ruleset directory rotates (`cmsync_standard_*`), so nothing custom
  survives there.
