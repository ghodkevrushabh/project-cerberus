# Phase 4 — Execution Log
## Defense Evasion: Obfuscated PowerShell (T1059.001)

Retrospective record of what actually happened executing Phase 4 — distinct from the prescriptive implementation guide. Screenshots referenced below are in [`evidence/phase4/`](evidence/phase4/).

---

## Attack Concept

Attackers favor **PowerShell** for malicious activity because it's a trusted, digitally-signed, pre-installed Windows binary with deep system access — using it is a "living off the land" technique that avoids dropping a suspicious standalone executable that antivirus tooling would likely flag immediately. PowerShell itself is never the problem; what it's told to do is.

**Base64 encoding via `-EncodedCommand`** is a common obfuscation layer on top of this: it hides the actual command from casual observation, from simple string-matching detection, and from anyone glancing at a process list or command history, since the plaintext command never appears directly in the process's visible command line — only the encoded blob does. Attackers commonly use exactly this technique as a precursor step: disabling or weakening security tooling (in this case, Windows Defender's real-time protection) before deploying further malicious activity that the now-blinded defenses won't catch.

**What the detection actually looks for:** PowerShell's **Script Block Logging** (Event ID 4104) captures the script content *as the engine actually executes it* — meaning the logged event contains the fully decoded, de-obfuscated command, regardless of how heavily it was originally encoded or wrapped when invoked. This is what makes it such a powerful detection source: it doesn't matter how the attacker obscured the command on the way in, since the log captures what actually ran, not what was typed. This detection searches decoded script block content for known-suspicious indicators (`IEX`, `-EncodedCommand`, `FromBase64String`, Defender-tampering cmdlets like `DisableRealtimeMonitoring`).

**Why the remediation (Constrained Language Mode) works so effectively:** it doesn't just block specific malicious commands — it restricts PowerShell to a safe subset of the language, disallowing arbitrary calls into most .NET types and methods. Since the *obfuscation machinery itself* (Base64 encoding/decoding, byte-array manipulation) relies on exactly the kind of .NET method calls Constrained Language Mode blocks, this remediation can prevent an attacker from even *constructing* an obfuscated payload in the first place — not just from running one, as this project's own testing directly demonstrated.

---

## Attack Summary

**Team B** enabled PowerShell Script Block Logging and deployed a Wazuh detection rule watching for suspicious decoded script content. **Team A** executed a Base64-encoded command disabling Windows Defender's real-time protection. **Team B** confirmed the detection fired correctly with full MITRE mapping, then remediated with PowerShell Constrained Language Mode — after which the identical attack failed not just at execution, but at the payload-construction stage itself.

**Result:** Attack succeeded (Defender disabled), detection confirmed firing correctly, and remediation proven to block the attack at a deeper level than initially expected.

---

## Setup

**Enable Script Block Logging** (Workstation):
```powershell
$path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $path -Force
Set-ItemProperty -Path $path -Name "EnableScriptBlockLogging" -Value 1
```
See [`evidence/phase4/03-script-block-logging-enabled.png`](evidence/phase4/03-script-block-logging-enabled.png).

**Forward the PowerShell Operational channel** to Wazuh (Workstation agent config):
```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
See [`evidence/phase4/02-ossec-conf-powershell-channel-added.png`](evidence/phase4/02-ossec-conf-powershell-channel-added.png).

**Deploy the detection rule** (Monitor):
```xml
<group name="local,cerberus,">
  <rule id="100030" level="12">
    <if_group>windows</if_group>
    <field name="win.system.eventID">^4104$</field>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)(-enc|FromBase64String|IEX|Invoke-Expression)</field>
    <description>CERBERUS - Possible obfuscated/encoded PowerShell execution (T1059.001)</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>
</group>
```
See [`evidence/phase4/01-wazuh-rule-100030-created.png`](evidence/phase4/01-wazuh-rule-100030-created.png).

---

## Issue 1 — Initial verification investigated the wrong Event ID 4104

**Symptom:** Before trusting the rule against a real attack, the field name was checked against a live 4104 event — but the event found contained generic PowerShell engine startup boilerplate ("Creating Scriptblock text... #requires -version 3.0... Set-StrictMode"), not any attacker-controlled content. See [`evidence/phase4/05-initial-wrong-event-investigated.png`](evidence/phase4/05-initial-wrong-event-investigated.png).

**Root cause:** Event ID 4104 fires for **every** script block the PowerShell engine parses — including its own internal module-loading and startup scripts — not exclusively for user-run commands. A single PowerShell session can generate dozens of 4104 events before the attacker's actual payload ever runs, and a bare `4104` search surfaces all of them indiscriminately.

**Diagnosis method:** Recognized the returned content didn't match the actual attack command at all, and searched more specifically for content unique to the real payload (`4104 AND "DisableRealtimeMonitoring"`) rather than trusting the first 4104 result found.

**Fix:** No rule change was actually needed — this narrowed search located the genuine attack event, which confirmed the original field name (`win.eventdata.scriptBlockText`) was correct all along. See [`evidence/phase4/07-detection-scriptblocktext-raw.png`](evidence/phase4/07-detection-scriptblocktext-raw.png).

**Why this mattered:** A useful, repeatable lesson (echoing Phase 2's Issue 3) — a broad search on a common event type will often return technically-matching but contextually-irrelevant noise, and the fix isn't to distrust the detection logic, but to narrow the search to something distinctive about the actual activity being investigated.

---

## Attack Execution — Results

Encoded payload generated:
```powershell
$command = 'IEX "Set-MpPreference -DisableRealtimeMonitoring `$true"'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
$encoded = [Convert]::ToBase64String($bytes)
```
See [`evidence/phase4/04-encoded-payload-generated.png`](evidence/phase4/04-encoded-payload-generated.png).

Executed:
```powershell
powershell.exe -EncodedCommand $encoded
```

Confirmed successful:
```powershell
Get-MpPreference | Select DisableRealtimeMonitoring
# DisableRealtimeMonitoring : True
```
See [`evidence/phase4/08-attack-succeeded-defender-disabled.png`](evidence/phase4/08-attack-succeeded-defender-disabled.png).

---

## Detection — Confirmed Firing Correctly

```json
"data.win.eventdata.scriptBlockText": "IEX \"Set-MpPreference -DisableRealtimeMonitoring `$true\"",
"data.win.eventdata.scriptBlockId": "c3208a4d-a2fa-4329-994e-a61d72e51aa7",
"rule": {
  "level": 12,
  "description": "CERBERUS - Possible obfuscated/encoded PowerShell execution (T1059.001)",
  "mitre": { "technique": ["PowerShell"], "id": ["T1059.001"] }
}
```
See [`evidence/phase4/06-detection-rule-fired-match.png`](evidence/phase4/06-detection-rule-fired-match.png) and [`evidence/phase4/07-detection-scriptblocktext-raw.png`](evidence/phase4/07-detection-scriptblocktext-raw.png). The decoded script block text matches the attack command exactly, confirming Script Block Logging's core value: the obfuscation layer (Base64/`-EncodedCommand`) made no difference to what was actually logged.

---

## Remediation — Confirmed Effective, at a Deeper Level Than Expected

**Applied** (Workstation):
```powershell
Set-MpPreference -DisableRealtimeMonitoring $false   # undo the attack's effect first
[Environment]::SetEnvironmentVariable('__PSLockdownPolicy', '4', 'Machine')   # 4 = Constrained Language Mode
```
See [`evidence/phase4/09-remediation-applied-defender-restored-clm-set.png`](evidence/phase4/09-remediation-applied-defender-restored-clm-set.png).

**Verified** (new session required for the policy to take effect):
```powershell
$ExecutionContext.SessionState.LanguageMode
# ConstrainedLanguage
```
See [`evidence/phase4/10-remediation-clm-mode-confirmed.png`](evidence/phase4/10-remediation-clm-mode-confirmed.png).

**Re-tested** with the identical attack sequence:
```powershell
$bytes = [System.Text.Encoding]::Unicode.GetBytes($command)
# Cannot invoke method. Method invocation is supported only on core types in this language mode.
$encoded = [Convert]::ToBase64String($bytes)
# Cannot invoke method. Method invocation is supported only on core types in this language mode.
```
See [`evidence/phase4/11-remediation-attack-fails-construction-blocked.png`](evidence/phase4/11-remediation-attack-fails-construction-blocked.png).

**Notable outcome:** remediation didn't just block the final `-EncodedCommand` execution — it blocked the attacker's ability to even *construct* the encoded payload in the first place, since building it requires calling `.GetBytes()` and `.ToBase64String()`, both restricted under Constrained Language Mode (`MethodInvocationNotSupportedInConstrainedLanguage`). This is a stronger remediation outcome than initially anticipated: the defense operates earlier in the attack chain than just "block the malicious command," closing off the entire obfuscation technique rather than one specific payload.

---

## Summary Table

| # | Issue | Root Cause | Fix | Outcome |
|---|---|---|---|---|
| 1 | Verification initially matched an unrelated 4104 event | Event ID 4104 fires for every script block, including PowerShell's own internal startup scripts | Searched for content unique to the actual payload instead of a bare event-ID search | Correctly located the real attack event; confirmed the original field name was right all along |

---

## What This Demonstrates

- Understood why attackers use trusted, living-off-the-land tooling (PowerShell) and obfuscation (Base64 encoding) rather than dropping custom malicious binaries.
- Correctly distinguished a contextually-irrelevant matching event from the real attack, rather than assuming the first search result was authoritative — a repeated, reinforced skill across multiple phases of this project.
- Demonstrated the specific value of Script Block Logging as a detection source: it defeats obfuscation entirely by logging *executed* content, not *typed* content.
- Verified remediation went beyond the expected outcome, discovering and correctly explaining that Constrained Language Mode blocks payload construction, not merely final execution.

*Log current as of: Phase 4 (Defense Evasion) fully executed, detected, and remediated. Next: Phase 5 — Data Staging.*
