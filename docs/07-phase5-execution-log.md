# Phase 5 — Execution Log
## Data Staging & Impact: Archive Creation (T1560)

Retrospective record of what actually happened executing Phase 5 — the final phase of the kill chain. Screenshots referenced below are in [`evidence/phase5/`](evidence/phase5/).

---

## Attack Concept

**Data staging** is the step immediately before exfiltration in a ransomware or data-theft operation: once an attacker has identified valuable files, they consolidate them into a single package — almost always a compressed, often password-protected archive — before moving them off the compromised host. This serves two purposes for the attacker: it's far more efficient to exfiltrate one file than thousands of small ones, and a password-protected archive defeats content-inspection tools (DLP, antivirus scanning) that can't see inside an encrypted container.

Real attackers favor common, legitimate archive utilities (7-Zip, WinRAR) for this rather than custom tooling, for the same "living off the land" reasoning as Phase 4's PowerShell abuse — a signed, trusted binary draws far less suspicion than a bespoke exfiltration tool. Staging the archive in a **temp folder** specifically is a deliberate choice: temp directories are high-churn, high-noise locations where routine application activity constantly creates and deletes files, making a malicious archive easier to overlook amid legitimate clutter.

**What the detection actually looks for:** Sysmon's Event ID 1 (Process Create) captures every process launch, including the full command line and working directory. The detection combines two conditions that are individually common but suspicious together: an archive utility (`7z.exe`, `winrar.exe`, `rar.exe`) launched **specifically from within a temp directory** — a combination far more indicative of staging behavior than either signal alone, since archive tools are also used constantly for entirely legitimate purposes elsewhere on a system.

---

## Attack Summary

**Team B** enabled the final Sysmon-based detection rule, installed 7-Zip, and staged target files. **Team A** created a password-protected archive of the staged files from within the Workstation's temp directory. **Team B** initially investigated the wrong event type during verification (a recurring pattern across this project), then found a genuine gap in the rule's logic — not just a wrong search — fixed it, and confirmed detection firing correctly. Remediation followed with Kerberos ticket revocation and endpoint isolation, the final response actions specified in the original project design.

**Result:** Full data staging attack executed, a genuine rule defect identified and corrected (not just a verification miss), detection confirmed with full MITRE mapping, and complete remediation with the project's evidence-collection script run as the closing response action.

---

## Setup

**Confirmed Sysmon running, installed 7-Zip, staged target files** on the Workstation:
```powershell
Get-Service Sysmon64
Invoke-WebRequest -Uri "https://www.7-zip.org/a/7z2408-x64.exe" -OutFile "$env:TEMP\7zsetup.exe"
Start-Process -FilePath "$env:TEMP\7zsetup.exe" -ArgumentList "/S" -Wait
Test-Path "C:\Program Files\7-Zip\7z.exe"   # True
New-Item -ItemType Directory -Path "C:\Users\Administrator\Documents\FinancialRecords" -Force
"Confidential Q3 financials" | Out-File "C:\Users\Administrator\Documents\FinancialRecords\report.txt"
```
See [`evidence/phase5/01-setup-sysmon-7zip-target-files.png`](evidence/phase5/01-setup-sysmon-7zip-target-files.png).

**Deployed the detection rule** (initial version, later corrected — see Issue 2 below):
```xml
<group name="local,cerberus,">
  <rule id="100040" level="12">
    <if_group>sysmon_process_create</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)(7z\.exe|winrar\.exe|rar\.exe)</field>
    <field name="win.eventdata.currentDirectory" type="pcre2">(?i)\\temp\\</field>
    <description>CERBERUS - Archive utility executed from temp folder, possible data staging (T1560)</description>
    <mitre>
      <id>T1560</id>
    </mitre>
  </rule>
</group>
```
See [`evidence/phase5/02-wazuh-rule-100040-created.png`](evidence/phase5/02-wazuh-rule-100040-created.png).

---

## Attack Execution — Results

```powershell
cd $env:TEMP
& "C:\Program Files\7-Zip\7z.exe" a -p"StolenData123!" "$env:TEMP\exfil_staging.zip" "C:\Users\Administrator\Documents\FinancialRecords\*"
```
Archive created successfully — note the actual resolved path was `C:\Users\Administrator\AppData\Local\Temp\2\`, not a literal `$env:TEMP` string, a Windows per-session temp-folder quirk worth noting for accuracy. See [`evidence/phase5/03-archive-created-in-temp.png`](evidence/phase5/03-archive-created-in-temp.png).

---

## Issue 1 — Verification initially matched unrelated PowerShell logging events, not the actual attack

**Symptom:** Searching for `FinancialRecords OR exfil_staging` returned 4 hits, but expanding them showed PowerShell Script Block Logging content (Event 4104) and a routine, irrelevant Wazuh rule (`91816`, "Powershell script querying system environment variables," MITRE Discovery/T1082) — nothing related to the actual archive creation or rule `100040`. See [`evidence/phase5/04-wrong-event-powershell-noise-a.png`](evidence/phase5/04-wrong-event-powershell-noise-a.png), [`05-wrong-event-powershell-noise-b.png`](evidence/phase5/05-wrong-event-powershell-noise-b.png), and [`06-wrong-event-search-hits-list.png`](evidence/phase5/06-wrong-event-search-hits-list.png).

**Root cause:** The search terms ("FinancialRecords", "exfil_staging") appeared as plain text inside the *PowerShell command itself*, which 4104 logs regardless of what the command does — matching the search on text content rather than on the actual Sysmon process-creation event the rule was built to catch. This is the same class of false-positive-search issue encountered in Phases 2 and 4: a broad text search across all event types will surface anything mentioning the right words, not necessarily the right event.

**Fix:** Searched specifically for the Sysmon process event instead: `data.win.eventdata.image: *7z.exe*`. This correctly surfaced the real Process Create event, confirming both `win.eventdata.image` and `win.eventdata.currentDirectory` held exactly the expected values (`C:\Program Files\7-Zip\7z.exe` and `...\AppData\Local\Temp\2\`, respectively). See [`evidence/phase5/07-real-sysmon-event-found-raw-log.png`](evidence/phase5/07-real-sysmon-event-found-raw-log.png), [`08-real-sysmon-event-fields-confirmed.png`](evidence/phase5/08-real-sysmon-event-fields-confirmed.png), [`09-real-sysmon-event-search-result.png`](evidence/phase5/09-real-sysmon-event-search-result.png), and [`10-real-sysmon-event-additional-fields.png`](evidence/phase5/10-real-sysmon-event-additional-fields.png).

---

## Issue 2 — The rule still did not fire, despite confirmed-correct field values (a genuine rule defect, not a search miss)

**Symptom:** With the correct event located and both field values confirmed exactly matching the rule's expectations, a direct check (`data.win.eventdata.image: *7z.exe* AND rule.id: 100040`) returned **zero results**. See [`evidence/phase5/11-rule-100040-not-yet-matching.png`](evidence/phase5/11-rule-100040-not-yet-matching.png).

**Root cause:** Unlike every previous field-verification check in this project (which had each confirmed the *original* assumption correct), this was a genuine defect: the rule's `<if_group>sysmon_process_create</if_group>` condition assumed Wazuh's ruleset tags Sysmon Event ID 1 events with a group literally named `sysmon_process_create`. This group tag either doesn't exist, or isn't applied the way assumed, in this Wazuh version/ruleset — meaning the rule's very first condition failed silently, before the field-matching logic was ever evaluated.

**Diagnosis method:** Since the field values were already independently confirmed correct (Issue 1's fix), the remaining variable was the rule's structural conditions rather than its field references — pointing directly at the `if_group` assumption as the most likely failure point.

**Fix:** Replaced the unverified group-tag dependency with the same explicit, directly-verified pattern already proven reliable in Phases 2 and 4 — matching on `win.system.eventID` and `win.system.channel` directly rather than trusting an assumed group name:
```xml
<group name="local,cerberus,">
  <rule id="100040" level="12">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^1$</field>
    <field name="win.system.channel">^Microsoft-Windows-Sysmon/Operational$</field>
    <field name="win.eventdata.image" type="pcre2">(?i)(7z\.exe|winrar\.exe|rar\.exe)</field>
    <field name="win.eventdata.currentDirectory" type="pcre2">(?i)\\temp\\</field>
    <description>CERBERUS - Archive utility executed from temp folder, possible data staging (T1560)</description>
    <mitre>
      <id>T1560</id>
    </mitre>
  </rule>
</group>
```
Re-running the identical attack produced an immediate match. See [`evidence/phase5/12-rule-100040-fired-full-detail.png`](evidence/phase5/12-rule-100040-fired-full-detail.png), [`13-fixed-event-raw-log.png`](evidence/phase5/13-fixed-event-raw-log.png), [`14-fixed-event-full-fields.png`](evidence/phase5/14-fixed-event-full-fields.png), and [`15-rule-100040-confirmed-in-list.png`](evidence/phase5/15-rule-100040-confirmed-in-list.png).

**Why this mattered — the most important distinction of the project's whole troubleshooting arc:** every prior "field verification" check in Phases 2 and 4 had confirmed the original assumption was already correct — the actual problem each time was finding the right *event* to check. This issue was different: the verification process worked exactly as designed and successfully identified a real defect in the rule's own logic, not a search or event-selection mistake. That distinction — knowing when a check confirms your work versus when it reveals a genuine bug — is the actual point of building a verification habit in the first place, and this is the clearest demonstration of it paying off across the entire project.

---

## Detection — Confirmed Firing Correctly

```json
"rule": {
  "level": 12,
  "description": "CERBERUS - Archive utility executed from temp folder, possible data staging (T1560)",
  "groups": ["local", "cerberus"],
  "mitre": {
    "id": ["T1560"],
    "tactic": ["Collection"],
    "technique": ["Archive Collected Data"]
  }
}
```
Confirmed against the real attack event: `image: C:\Program Files\7-Zip\7z.exe`, `currentDirectory: C:\Users\Administrator\AppData\Local\Temp\2\`, `commandLine` showing the full password-protected archive command.

---

## Remediation — Confirmed Effective

**Kerberos ticket revocation:**
```powershell
klist purge
klist   # Cached Tickets: (0)
```

**Endpoint isolation** (both directions, targeted at the attacker's IP):
```powershell
New-NetFirewallRule -DisplayName "Isolate-WKS1-Compromised" -Direction Outbound -Action Block -Profile Any -RemoteAddress 10.0.9.173
New-NetFirewallRule -DisplayName "Isolate-WKS1-Compromised-In" -Direction Inbound -Action Block -Profile Any -RemoteAddress 10.0.9.173
```
See [`evidence/phase5/17-remediation-inbound-firewall-rule.png`](evidence/phase5/17-remediation-inbound-firewall-rule.png) and [`18-remediation-tickets-purged-outbound-rule.png`](evidence/phase5/18-remediation-tickets-purged-outbound-rule.png).

**Containment verified:**
```bash
ping -c3 10.0.6.93   # 100% packet loss
```
See [`evidence/phase5/16-remediation-ping-fails-containment.png`](evidence/phase5/16-remediation-ping-fails-containment.png).

**IR evidence collection executed** as the closing response action:
```bash
sudo ./collect_evidence.sh
```
Produced `cerberus_evidence_20260903_084937.tar.gz` (6,627 bytes) with matching SHA256 checksum, confirming the evidence package's integrity for chain-of-custody purposes. See [`evidence/phase5/19-evidence-collection-script-run.png`](evidence/phase5/19-evidence-collection-script-run.png).

---

## Summary Table

| # | Issue | Root Cause | Fix | Outcome |
|---|---|---|---|---|
| 1 | Verification matched unrelated PowerShell logging noise | Search terms appeared as plain text inside a logged command, unrelated to the actual Sysmon event | Searched specifically for the Sysmon process-creation event by image path | Correctly located the real attack event |
| 2 | Rule still didn't fire despite correct, confirmed field values | `if_group: sysmon_process_create` assumption was structurally wrong for this ruleset — a genuine rule defect, not a search miss | Replaced with explicit `win.system.eventID`/`win.system.channel` matching, the same reliable pattern used in Phases 2 and 4 | Rule fired correctly on the very next attempt |

---

## What This Demonstrates

- Correctly distinguished a search/event-selection mistake (Issue 1, consistent with earlier phases) from a genuine detection-logic defect (Issue 2, a new category of problem for this project) — and diagnosed each with the appropriate method.
- Understood and could articulate why data staging specifically targets temp directories, and why combining two individually-common signals (archive tool + temp location) produces a meaningfully better detection than either alone.
- Closed out the full incident response lifecycle for the project's final phase: detect, contain (isolation), revoke trust (Kerberos tickets), and collect evidence — using the project's own purpose-built tooling for the last step.
- Completed the entire five-phase kill chain with every phase independently attacked, detected, and remediated, closing Project Cerberus's core objective in full.

*Log current as of: Phase 5 (Data Staging) fully executed, detected, and remediated. This concludes all five phases of Project Cerberus.*
