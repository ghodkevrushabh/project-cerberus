# Phase 1 — Execution Log
## Initial Access: Password Spray + Port Sweep (T1110)

This is the retrospective record of what actually happened when Phase 1 was executed — as distinct from [`02-phase1-phase2-implementation.md`](02-phase1-phase2-implementation.md), which is the prescriptive step-by-step guide written before execution. Screenshots referenced below are in [`evidence/phase1/`](evidence/phase1/).

---

## Attack Concept

**Password spraying** is a credential-guessing technique that inverts the usual brute-force approach: instead of trying many passwords against one account (which quickly triggers account lockout), an attacker tries a small number of common or likely passwords across *many* accounts, staying under the per-account lockout threshold the whole time. Real attackers favor this because most organizations lock an account after 5-10 failed attempts *on that account*, but far fewer correlate failures *across many accounts* originating from a single source — exactly the gap this project's detection is built to close.

The accompanying **port sweep** is basic network reconnaissance — scanning a range of ports on a target to discover which services are actually running (RDP, SMB, LDAP, etc.) before deciding how to proceed. It's typically one of the very first actions in a real intrusion, well before credential attacks begin.

**What the detection actually looks for:** the Suricata rule watches for a burst of connection attempts to many different ports from one source within a short window — a pattern distinct from normal usage, where a single client rarely touches more than a handful of ports on a host. The Wazuh correlation rule watches for repeated Windows logon failures (Event 4625) from the same source within a short time window — the signature of a spray, as opposed to a single user occasionally mistyping their own password.

---

## Attack Summary

**Team A** ran a port sweep against all three targets, followed by a password spray against the DC and Workstation using `netexec` (the actively-maintained successor to `crackmapexec`). **Team B** watched detections fire live in the Wazuh dashboard, then applied remediation and confirmed the same attack failed on retry.

**Result:** Full compromise achieved (`jsmith:Summer2024!` valid on both DC and Workstation), both detections fired correctly, and remediation fully blocked a repeat attempt.

---

## Issue 1 — `netexec` default thread count overwhelmed the target instances

**Symptom:** The first two spray attempts produced almost entirely `Connection Error: The NETBIOS connection with the remote host timed out` lines rather than genuine `STATUS_LOGON_FAILURE` results, even though the password list contained several intentionally wrong passwords. See [`evidence/phase1/01-spray-first-attempt-timeouts.png`](evidence/phase1/01-spray-first-attempt-timeouts.png).

**Root cause:** `netexec` defaults to 256 concurrent connection threads — tuned for large enterprise networks, not a `t3.medium` lab instance. The volume of simultaneous SMB session-setup attempts caused most connections to queue and time out before authentication was even attempted, rather than being cleanly accepted or rejected.

**Diagnosis method:** Confirmed the password list genuinely contained multiple wrong entries (ruling out "nothing to fail against"), then noted the specific error type — a pre-authentication connection timeout, not a post-authentication rejection — pointing at a connection-layer bottleneck rather than a credential or Wazuh problem.

**Fix:**
```bash
nxc smb 10.0.8.58 10.0.6.93 -u users.txt -p passwords.txt --continue-on-success -t 1 --smb-timeout 10
```
Serialized to one connection at a time (`-t 1`) with a longer per-connection timeout (`--smb-timeout 10`).

**Why this mattered:** Incidentally reproduced the same operational logic real attackers use — throttling a spray to avoid overwhelming (and alerting) the target — which became a useful, honest talking point rather than just a bug fix.

---

## Issue 2 — Windows Firewall blocked ICMP on the Workstation, mirroring an earlier DC issue

**Symptom:** During Pre-Attack connectivity checks, Kali could reach the Monitoring instance and DC, but the Workstation (`10.0.6.93`) returned 100% packet loss.

**Root cause:** Windows Firewall on the Workstation was blocking ICMP by default — the same class of issue already resolved on the DC during the Day 1 environment build, but not yet addressed on this second Windows machine.

**Fix:**
```powershell
Set-NetFirewallProfile -All -Enabled False
```

**Why this mattered:** A reminder that OS-level firewall configuration is per-machine, not something that "carries over" once fixed on one instance in the environment — each new Windows machine needs the same checks applied independently.

---

## Attack Execution — Results

**Port sweep** (`nmap -sS -T4 -p 1-1000`) against all three targets confirmed expected open ports on the DC (Kerberos, LDAP, SMB, etc.) and Workstation (SMB, RPC), and against the Monitoring instance (SSH, HTTPS) — the latter deliberately included so Suricata, which can only see traffic terminating on its own host, had genuine traffic to alert on.

**Password spray** (`netexec smb`, throttled per Issue 1's fix) succeeded against the `jsmith` account on both the DC and Workstation, alongside multiple genuine `STATUS_LOGON_FAILURE` results from intentionally wrong passwords in the list — a realistic, both-outcomes spray demonstration.

---

## Detection — Confirmed Live

Both custom detections fired correctly, confirmed in the dashboard (`wazuh-alerts-*` index, query `rule.id: 100010 or rule.groups: suricata`):

- **Suricata (`sid:1000001`, surfaced as Wazuh `rule.id: 86601`)** — fired on the port sweep against the Monitoring instance.
- **Wazuh correlation (`rule.id: 100010`)** — fired on the password spray against both the DC and Workstation.

See [`evidence/phase1/03-dashboard-detection-hits.png`](evidence/phase1/03-dashboard-detection-hits.png) — 3 hits, clean timestamp cluster, both rule types represented.

---

## Remediation — Two-Stage Result (a genuine, unplanned demonstration of defense-in-depth)

Remediation was applied in two passes, and the first pass produced an unplanned but valuable result:

**Pass 1:** A firewall block rule was applied against Kali's IP on the DC only. Retrying the attack showed:
- DC: fully blocked (100% ping loss, no SMB response).
- Workstation: **not yet blocked**, so the spray retry reached it — and the account lockout policy (5 failures / 15-minute window, applied earlier) triggered mid-attack, visible directly in the terminal output as `STATUS_ACCOUNT_LOCKED_OUT` on `jsmith`, including against the previously-valid password. See [`evidence/phase1/02-remediation-block-and-lockout.png`](evidence/phase1/02-remediation-block-and-lockout.png).

This was not staged — the lockout policy caught the retry attempt live, independent of the firewall rule, demonstrating that the two remediations (network-level block, account-level lockout) work as genuinely independent layers of defense.

**Pass 2:** The firewall block rule was extended to the Workstation as well. A final retry confirmed complete coverage:
```
ping -c3 10.0.8.58  → 100% packet loss
ping -c3 10.0.6.93  → 100% packet loss
netexec spray       → zero output (no connections completed at all)
nmap port sweep     → all 1000 ports reported "filtered (no-response)" on both hosts
```
The "filtered" result specifically confirms packets are being silently dropped by the firewall rule, distinct from "closed" (actively rejected) — the expected signature of a working block, and clearly different from the original scan's real open-port results.

---

## Summary Table

| # | Issue | Root Cause | Fix | Outcome |
|---|---|---|---|---|
| 1 | Spray produced mostly timeouts, not real failures | `netexec` default 256 threads overwhelmed a `t3.medium` target | Throttled to `-t 1 --smb-timeout 10` | Clean spray showing genuine successes and failures |
| 2 | Kali couldn't ping the Workstation | Windows Firewall blocking ICMP (same class of issue as the DC, not yet applied here) | Disabled Windows Firewall on the Workstation | Connectivity confirmed for attack execution |

---

## What This Demonstrates

- Diagnosed a tool-default-vs-environment mismatch by distinguishing pre-authentication connection failures from post-authentication credential rejections — a meaningful distinction, not just "it's not working."
- Captured an unplanned but genuine demonstration of independent, overlapping defenses (firewall block + account lockout) triggering separately rather than needing to stage each in isolation.
- Verified remediation completeness using protocol-level evidence (`filtered` vs `open` port states), not just "the command produced no output."

*Log current as of: Phase 1 (Initial Access) fully executed, detected, and remediated. Next: Phase 2 — Credential Theft (Kerberoasting).*
