# Project Cerberus — Incident Response Runbook
## Structured per NIST SP 800-61 (Computer Security Incident Handling Guide)

This runbook generalizes the response procedures demonstrated across all five phases of Project Cerberus into a reusable structure, following NIST SP 800-61's four-phase incident response lifecycle: **Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity**. Each section references the specific tooling, rules, and real worked examples built during this project.

---

## 1. Preparation

Preparation is everything done *before* an incident occurs — the tooling, telemetry, and processes that make detection and response possible at all.

### 1.1 Telemetry Sources Deployed

| Source | Purpose | Deployed On |
|---|---|---|
| Sysmon (SwiftOnSecurity config) | Process creation, file/registry activity | Workstation |
| Windows Security Event Log | Authentication, Kerberos ticket operations | DC, Workstation |
| PowerShell Script Block Logging (Event 4104) | Decoded script execution, regardless of obfuscation | Workstation |
| Suricata (network IDS) | Signature-based network alerting | Monitoring instance |
| Zeek (network security monitor) | Connection-level metadata, behavioral analysis | Monitoring instance |
| Wazuh agents | Central log forwarding and correlation | DC, Workstation → Monitoring instance |

### 1.2 Detection Rules in Place

All custom rules are version-controlled in this repository:
- [`rules/wazuh/local_rules.xml`](../rules/wazuh/local_rules.xml) — 4 custom correlation rules (100010, 100020, 100030, 100040)
- [`rules/suricata/local.rules`](../rules/suricata/local.rules) — network scan detection
- [`rules/sigma/`](../rules/sigma/) — 5 hand-written Sigma rules, one per phase, portable to other SIEM platforms
- [`scripts/beacon_jitter_check.py`](../scripts/beacon_jitter_check.py) — standalone behavioral analysis tool

### 1.3 Baseline Verification

Before investigating any suspected incident, confirm the monitoring pipeline itself is healthy:
```bash
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
sudo systemctl status suricata
sudo /opt/zeek/bin/zeekctl status
```
A response built on a broken telemetry pipeline is worse than no response at all — it creates false confidence. This project's own Day 1 build log documents multiple real instances where pipeline health had to be re-verified before trusting any alert.

### 1.4 Evidence Collection Tooling

[`scripts/collect_evidence.sh`](../scripts/collect_evidence.sh) — captures process list, network connections, auditd logs, running services, and scheduled tasks into a timestamped, checksummed archive. Kept ready to run at the first sign of active compromise, not built reactively during an incident.

---

## 2. Detection & Analysis

This is the phase of determining *whether* an incident occurred, *what* happened, and *how severe* it is.

### 2.1 Initial Triage Checklist

1. **Confirm the alert is real, not noise.** This project repeatedly demonstrated that a broad search or an assumed field/rule condition can surface irrelevant matches (see Phase 2's `svc-sql` vs. machine-account ticket confusion, Phase 4's PowerShell-engine-boilerplate 4104 events, and Phase 5's PowerShell-logging-noise false lead). **Always verify the specific event correlates to the specific entity or activity under investigation** — don't trust a keyword match alone.
2. **Identify the affected host(s) and account(s).** Cross-reference `agent.name`, `data.win.eventdata.targetUserName` / `ipAddress`, and timestamps against known-good baselines.
3. **Determine the ATT&CK technique and tactic.** Use the rule's `mitre.id`/`mitre.tactic` fields directly — every custom rule in this project carries this mapping.
4. **Establish a timeline.** Correlate the earliest suspicious event with subsequent activity — this project's phases consistently showed detection firing within seconds of the triggering action, making tight timeline correlation realistic.

### 2.2 Phase-Specific Detection Reference

| Indicator | Likely Technique | Reference |
|---|---|---|
| Repeated Event 4625 from one source across multiple accounts | T1110 — Password Spray | [`03-phase1-execution-log.md`](03-phase1-execution-log.md) |
| Event 4769 with RC4 ticket encryption (`0x17`) | T1558.003 — Kerberoasting | [`04-phase2-execution-log.md`](04-phase2-execution-log.md) |
| Regular, low-variance outbound connection timing | T1071.001 — C2 Beaconing | [`08-jitter-beacon-analysis.md`](08-jitter-beacon-analysis.md) |
| Event 4104 containing `-enc`, `FromBase64String`, `IEX` | T1059.001 — Obfuscated PowerShell | [`06-phase4-execution-log.md`](06-phase4-execution-log.md) |
| Archive utility launched from a temp directory | T1560 — Data Staging | [`07-phase5-execution-log.md`](07-phase5-execution-log.md) |

### 2.3 Severity Assessment

Use the rule's `level` field as a starting point (this project's custom rules are all set to level 10-12, reflecting high-confidence, high-severity indicators), but always weigh it against:
- Whether the technique **succeeded** (e.g., a cracked password vs. a failed crack attempt)
- Whether it's an **isolated event** or part of a broader, multi-technique pattern (this project's own kill chain demonstrates how phases build on each other — a Phase 1 compromise directly enabled Phase 2's Kerberoasting via a captured low-privilege account)

---

## 3. Containment, Eradication & Recovery

### 3.1 Containment — Stop the Bleeding

Immediate actions to prevent further damage, without necessarily fixing the root cause yet:

| Technique | Containment Action | Verified In |
|---|---|---|
| Password Spray | Account lockout policy; firewall block against source IP | Phase 1 |
| Kerberoasting | N/A (offline attack — containment focuses on Eradication below) | Phase 2 |
| C2 Beaconing | Outbound firewall block against C2 destination | Phase 3 |
| Obfuscated PowerShell | N/A (containment overlaps with Eradication — see below) | Phase 4 |
| Data Staging | Endpoint isolation (firewall block against attacker IP), Kerberos ticket revocation | Phase 5 |

**General principle demonstrated throughout this project:** always verify containment actually worked with a concrete re-test, not just by confirming the containment action was applied. Every phase in this project included a "re-run the identical attack" step specifically to prove the block was effective, not merely present.

### 3.2 Eradication — Remove the Root Cause

| Technique | Eradication Action | Verified In |
|---|---|---|
| Password Spray | N/A beyond containment (no persistent foothold created) | Phase 1 |
| Kerberoasting | Rotate the compromised account's credentials; enforce AES-only Kerberos encryption (or deploy a gMSA) | Phase 2 |
| C2 Beaconing | Terminate the beaconing process on the affected host | Phase 3 |
| Obfuscated PowerShell | Re-enable any disabled security controls (Defender); enforce PowerShell Constrained Language Mode | Phase 4 |
| Data Staging | Delete staged archives; investigate for additional staged data elsewhere on the host | Phase 5 |

### 3.3 Recovery — Return to Normal Operation

- Confirm all remediation-blocking rules (firewall blocks, account lockouts) are either permanent policy or explicitly scheduled for review/removal, so they don't silently interfere with legitimate future activity — this project's own Phase 2 execution directly demonstrated this: a leftover Phase 1 firewall block had to be deliberately removed before Phase 2 could proceed, and this was documented rather than silently worked around.
- Re-verify monitoring pipeline health after any remediation involving service restarts (Wazuh manager, Suricata, Zeek) — a remediation step that inadvertently breaks telemetry defeats its own purpose.
- Confirm affected accounts/hosts return to expected baseline behavior before considering the incident closed.

---

## 4. Post-Incident Activity

### 4.1 Documentation

Every phase of this project was documented using a consistent structure — Symptom → Root Cause → Diagnosis Method → Fix → Why It Mattered — specifically because this is the structure most useful for both a written incident report and for explaining the incident verbally afterward (e.g., in an interview or a post-incident review meeting). See [`03-phase1-execution-log.md`](03-phase1-execution-log.md) through [`07-phase5-execution-log.md`](07-phase5-execution-log.md) for worked examples of this format.

### 4.2 Lessons Learned

Patterns that recurred across multiple phases of this project, worth carrying forward into any future incident response work:

1. **Verify field-level assumptions against real events before trusting a detection rule** — this project's Phase 2 and Phase 4 verification checks both confirmed original assumptions were correct, while Phase 5's verification caught a genuine rule defect (`if_group` assumption). Knowing the difference between "my search was wrong" and "my detection logic was wrong" is itself a key incident-analysis skill.
2. **A broad keyword search will return contextually-irrelevant matches.** Every phase encountered at least one instance of this. Narrow searches to the specific entity (account, process, destination) under investigation, not just the event type.
3. **Cross-phase interference is real.** A prior phase's remediation can silently block a later, legitimate investigation or attack-chain continuation (Phase 2's leftover firewall rule). Always check for and document this rather than assuming a clean slate.
4. **Modern defaults sometimes already mitigate classic attacks.** Phase 2's discovery that Windows Server 2025 defaults new accounts toward AES (not RC4) encryption is a direct example — verify assumptions about "default" vulnerable configurations rather than assuming older attack patterns still apply unmodified.

### 4.3 Evidence Retention

All evidence for this project is retained in version control:
- Screenshots: [`docs/evidence/`](evidence/) organized per phase
- Raw evidence packages: generated via [`scripts/collect_evidence.sh`](../scripts/collect_evidence.sh), checksummed with SHA256 for integrity verification
- Detection rule versions: [`rules/`](../rules/) — the exact rule content in place at the time of each detection is preserved

### 4.4 Follow-Up Actions

- [ ] Review whether Constrained Language Mode (Phase 4's remediation) should be extended to other hosts beyond the Workstation
- [ ] Evaluate whether gMSA deployment (rather than AES-only encryption alone) is warranted for the Phase 2 service account in a production equivalent
- [ ] Consider VPC Traffic Mirroring if broader network-level visibility across all hosts (not just traffic terminating on the Monitoring instance) becomes a requirement
- [ ] Periodically re-verify all custom Wazuh rules against the currently installed ruleset version, since base rule IDs and group tags are not guaranteed stable across Wazuh upgrades (as directly encountered in Phase 5)

---

*This runbook reflects the response procedures demonstrated across Project Cerberus's five-phase kill chain emulation. Referenced logs and evidence are version-controlled in this repository.*
