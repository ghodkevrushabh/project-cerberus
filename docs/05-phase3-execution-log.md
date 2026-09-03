# Phase 3 — Execution Log
## Command & Control Beaconing (T1071.001)

Retrospective record of what actually happened executing Phase 3 — distinct from the prescriptive implementation guide. All screenshots referenced below are in [`evidence/phase3/`](evidence/phase3/).

---

## Attack Concept

Once a foothold is established on a host, malware typically doesn't maintain a single, always-open connection back to its operator — that would be conspicuous and fragile. Instead, it **beacons**: waking up on a schedule to briefly "call home," check for new instructions, and go quiet again. This is Command & Control (C2) communication, and its regularity is both its strength (efficient, low-profile) and its weakness (statistically detectable).

Real C2 frameworks add **jitter** — a small, randomized variance to the sleep interval — specifically to defeat naive detection based on perfectly identical, clockwork timing. But even a jittered beacon retains a level of regularity that genuine human or application traffic essentially never exhibits; people and normal software don't communicate at intervals varying by only a few percent, beacon after beacon, hour after hour.

**What the detection actually looks for:** rather than matching a specific signature or payload, this detection is purely statistical — measuring the *coefficient of variation* (standard deviation divided by mean) across the time gaps between successive connections to the same destination. A low coefficient of variation (this project's threshold: under 15%) indicates a scheduled, programmatic process rather than organic usage — the core idea behind beacon/jitter analysis as a network security monitoring technique.

---

## Attack Summary

**Team A** simulated a compromised host on the Workstation, sending a low-jitter, scheduled outbound heartbeat to the Monitoring instance (standing in for a C2 server, since network visibility constraints from earlier phases mean the "attack" traffic must terminate on the box running the network sensor). **Team B** built a standalone jitter-analysis script against Zeek's `conn.log`, confirmed it correctly flagged the beacon pattern, then remediated with an outbound firewall block and confirmed the same beacon failed on retry — both at the endpoint and at the network layer.

**Result:** Full beacon executed, detected with a clean 2.26% jitter measurement (well under threshold), and fully remediated with verified failure on retry.

---

## Setup — Beacon Script (run on the Workstation)

```powershell
$dest = "10.0.10.178"
$port = 443
$baseInterval = 60
$jitterPercent = 0.10

while ($true) {
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.Connect($dest, $port)
        $client.Close()
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Beacon sent to ${dest}:${port}"
    } catch {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Beacon attempt failed"
    }
    $jitter = Get-Random -Minimum (-1 * $jitterPercent) -Maximum $jitterPercent
    $sleepTime = $baseInterval * (1 + $jitter)
    Start-Sleep -Seconds $sleepTime
}
```

**Design decision:** the destination is deliberately the Monitoring instance's own IP, not an arbitrary "external" address. As established in Phase 1, network-level visibility in this AWS architecture is limited to traffic terminating on the box running the sensor (Suricata/Zeek) — a beacon aimed at any other instance would be invisible to Zeek entirely, regardless of how correct the detection logic is.

---

## Issue 1 — `nc` listener failed with "Permission denied" on the Monitor

**Symptom:** Team B's listener (`nc -l -p 443`) failed repeatedly with `Permission denied`. See [`evidence/phase3/01-nc-permission-denied-privileged-port.png`](evidence/phase3/01-nc-permission-denied-privileged-port.png).

**Root cause:** Port 443 is a privileged port (below 1024) — binding to it requires root, and `nc` was being run as the normal `ubuntu` user.

**Fix:**
```bash
sudo bash -c 'while true; do nc -l -p 443; done'
```

**Why this mattered:** A standard Linux privilege boundary, easy to forget when the port in question (443) is more commonly associated with "just a web port" than with the OS-level permission model governing who can bind to it.

---

## Issue 2 — Beacon script syntax error: `$dest:$port` misparsed as a drive reference

**Symptom:** The beacon script failed immediately with `Variable reference is not valid. ':' was not followed by a valid variable name character.` See [`evidence/phase3/02-beacon-script-syntax-error.png`](evidence/phase3/02-beacon-script-syntax-error.png).

**Root cause:** In PowerShell string interpolation, `$variablename:` is valid syntax for a **drive reference** (like `C:` or `HKLM:`). Writing `"$dest:$port"` caused PowerShell to try interpreting `$dest:` as a drive path rather than "the value of `$dest`, followed by a literal colon."

**Fix:** Wrapped the variable name in `${}` to disambiguate it from the following colon:
```powershell
"Beacon sent to ${dest}:${port}"
```
Confirmed working immediately afterward. See [`evidence/phase3/03-beacon-fixed-first-success.png`](evidence/phase3/03-beacon-fixed-first-success.png).

**Why this mattered:** A genuinely non-obvious PowerShell quirk — the kind of error that looks like it should be a simple string formatting mistake but is actually rooted in PowerShell's drive-provider syntax overlapping with normal variable interpolation.

---

## Issue 3 — `nc`'s restart loop produced noisy "Address already in use" errors

**Symptom:** Between successful beacon connections, the listener loop repeatedly logged `Address already in use`.

**Root cause:** After each connection closed, the OS held port 443 in a brief `TIME_WAIT` state before releasing it, and the loop's immediate restart attempt sometimes raced against that release window.

**Assessment:** Cosmetic only — did not affect beacon delivery, confirmed by successful "Beacon sent" messages appearing on the Workstation throughout. Left as-is rather than adding a `sleep` delay, since it didn't impact the actual evidence being collected.

---

## Beacon Execution — Results

Five beacons were sent over roughly 4 minutes, landing at ~54-66 second intervals as designed. See [`evidence/phase3/06-workstation-five-beacons-sent.png`](evidence/phase3/06-workstation-five-beacons-sent.png):
```
16:58:43 - Beacon sent to 10.0.10.178:443
16:59:48 - Beacon sent to 10.0.10.178:443
17:00:44 - Beacon sent to 10.0.10.178:443
17:01:48 - Beacon sent to 10.0.10.178:443
17:02:50 - Beacon sent to 10.0.10.178:443
```

Confirmed independently in Zeek's `conn.log` — raw connection entries between `10.0.6.93` (Workstation) and `10.0.10.178:443` (Monitor). See [`evidence/phase3/04-zeek-connlog-raw-entries-a.png`](evidence/phase3/04-zeek-connlog-raw-entries-a.png) and [`evidence/phase3/05-zeek-connlog-raw-entries-b.png`](evidence/phase3/05-zeek-connlog-raw-entries-b.png).

---

## Issue 4 — Jitter-analysis script initially found zero matching connections

**Symptom:** The custom jitter-analysis script (see below) reported `Found 0 matching connections`, despite the beacon having clearly succeeded minutes earlier. See [`evidence/phase3/07-jitter-script-permission-denied.png`](evidence/phase3/07-jitter-script-permission-denied.png) — note this screenshot actually also captured a related permission error on the log file itself, requiring `sudo` to read it at all.

**Root cause:** Two layered issues:
1. `/opt/zeek/logs/current/conn.log` is owned by the `zeek` user — reading it requires `sudo`, same class of permission issue as Issue 1.
2. Zeek rotates `current/conn.log` hourly. By the time the script was run, the beacon's timeframe had already rotated into an archived, gzipped file under a dated folder (`/opt/zeek/logs/2026-09-02/`), so `current/conn.log` simply no longer contained the relevant data.

**Diagnosis method:** Checked the first/last timestamps in `current/conn.log` and found they were hours later than the beacon window, confirming rotation rather than a script bug. Located the correct archived file by matching the beacon's timestamp against Zeek's hour-range file naming convention (`conn.HH:00:00-HH:00:00.log.gz`).

**Fix:** Extended the script to accept a log path argument and transparently handle `.gz` files:
```python
import gzip
def open_log(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt")
    return open(path, "r")
```
Ran with `sudo` against the correct archived file:
```bash
sudo python3 beacon_jitter_check.py /opt/zeek/logs/2026-09-02/conn.17:00:00-18:00:00.log.gz
```

**Why this mattered:** A realistic operational lesson — in a real investigation, "the log doesn't show it" is often a sign of looking in the wrong rotation window, not evidence the activity didn't happen. Understanding a log management system's rotation behavior is as important as writing correct detection logic against it.

---

## Detection — Confirmed Firing Correctly

```
$ sudo python3 beacon_jitter_check.py /opt/zeek/logs/2026-09-02/conn.17:00:00-18:00:00.log.gz
[*] Found 3 matching connections: 10.0.6.93 -> 10.0.10.178:443
[*] Intervals between connections (seconds): [64.01, 62.0]
[*] Mean interval: 63.01s
[*] Std deviation: 1.42s
[*] Coefficient of variation (jitter): 2.26%

[!] ALERT: Regular beaconing pattern detected (jitter 2.26% < 15% threshold)
[!] Possible C2 beacon: 10.0.6.93 -> 10.0.10.178:443 (T1071.001)
```

A 2.26% coefficient of variation is a strikingly clean beacon signature — well inside the 15% threshold, and far tighter than typical human or application-driven traffic would ever produce. (No separate screenshot exists for this specific run; the terminal output above is reproduced verbatim from the session.)

---

## Remediation — Confirmed Effective

**Applied** on the Workstation:
```powershell
New-NetFirewallRule -DisplayName "Block-C2-Beacon" -Direction Outbound -RemoteAddress 10.0.10.178 -RemotePort 443 -Protocol TCP -Action Block
```
See [`evidence/phase3/08-remediation-firewall-rule-created.png`](evidence/phase3/08-remediation-firewall-rule-created.png) — confirmed `Status: The rule was parsed successfully from the store`.

**Re-tested** with the identical beacon script — four consecutive failures at the same ~60s cadence:
```
06:57:00 - Beacon attempt failed
06:57:54 - Beacon attempt failed
06:58:59 - Beacon attempt failed
06:59:56 - Beacon attempt failed
```
See [`evidence/phase3/10-remediation-four-beacons-failed.png`](evidence/phase3/10-remediation-four-beacons-failed.png).

**Confirmed at the network layer too** — Zeek's `conn.log` shows zero new connections matching the beacon pattern after the block:
```bash
sudo tail -20 /opt/zeek/logs/current/conn.log | grep "10.0.6.93.*443"
# (no output)
```
See [`evidence/phase3/09-remediation-zeek-confirms-no-new-connections.png`](evidence/phase3/09-remediation-zeek-confirms-no-new-connections.png).

**Note on why Zeek shows nothing rather than a rejected-connection entry:** the outbound firewall block operates on the Workstation itself, before any packet reaches the network at all — a stronger remediation outcome than a network-level reject would be, since the traffic never left the compromised host in the first place.

---

## Architectural Note — Why This Detection Lives Outside Wazuh

Unlike Phases 1 and 2, Phase 3's detection was never routed through the Wazuh dashboard. This is intentional, not a gap: the original design specifies a "Zeek connection-log time-delta query," and Zeek's logs were never wired into Wazuh (unlike Suricata's, which were explicitly configured to forward into the SIEM back on Day 1). Standalone Zeek log analysis is a legitimate, common network-security-monitoring technique in its own right — demonstrating a detection that operates directly against raw telemetry, without needing every signal to be pre-aggregated into a single dashboard.

---

## Summary Table

| # | Issue | Root Cause | Fix | Outcome |
|---|---|---|---|---|
| 1 | `nc` listener permission denied | Port 443 requires root to bind | Ran listener with `sudo` | Listener operational |
| 2 | Beacon script syntax error | `$dest:` misparsed as a PowerShell drive reference | Used `${dest}:${port}` | Script ran correctly |
| 3 | Noisy "Address already in use" | TCP `TIME_WAIT` race in restart loop | Assessed as cosmetic, left as-is | No impact on evidence |
| 4 | Jitter script found 0 connections | Log file permissions + hourly rotation moved data to an archived file | Added `sudo` + gzip support + located correct archive | Detection confirmed working |

---

## What This Demonstrates

- Built a standalone, from-scratch detection script rather than relying solely on pre-built SIEM tooling — demonstrating comfort working directly with raw log data.
- Correctly diagnosed a log-rotation issue as the cause of a "missing data" symptom, rather than assuming the detection logic itself was broken.
- Verified remediation on two independent levels (endpoint firewall behavior and network-layer log absence), rather than trusting a single signal.
- Understood and could articulate a deliberate architectural choice (Zeek analysis outside the SIEM) rather than treating every detection as needing to look identical.

*Log current as of: Phase 3 (C2 Beaconing) fully executed, detected, and remediated. Next: Phase 4 — Defense Evasion.*
