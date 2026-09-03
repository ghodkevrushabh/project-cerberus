# Phase 2 — Execution Log
## Credential Theft: Kerberoasting (T1558.003)

Retrospective record of what actually happened executing Phase 2 — distinct from the prescriptive implementation guide. Screenshots referenced below are in [`evidence/phase2/`](evidence/phase2/).

---

## Attack Concept

**Kerberoasting** exploits a structural feature of Kerberos authentication rather than a bug: any authenticated domain user can request a service ticket (TGS) for *any* service registered with a Service Principal Name (SPN), without needing any special privileges. That ticket is encrypted using a key derived from the target service account's own password hash. If the attacker can get a copy of that ticket, they can take it completely offline and try to crack it — with no further interaction with the Domain Controller, no lockout risk, and unlimited guesses at their own pace.

Real attackers favor this because service accounts are notoriously under-maintained in production environments: they're often created once, given a long or "set-and-forget" password, and rarely rotated, since rotating them risks breaking whatever service depends on them. A weak or old password on a service account becomes a silent, low-visibility path to credential theft.

**Why RC4 encryption matters specifically:** older Kerberos tickets (RC4-HMAC) are dramatically faster and easier to crack offline than modern AES-encrypted ones. A well-maintained, modern AD environment defaults new accounts toward AES — meaning Kerberoasting a truly modern, correctly-configured account is far less practical, as this project's own Issue 2 (below) directly demonstrates.

**What the detection actually looks for:** Windows logs a 4769 event for *every* Kerberos service ticket request — entirely normal, high-volume background traffic. The tell is a ticket requested with RC4 encryption specifically for a service account, which stands out against an environment where AES is the expected norm.

---

## Attack Summary

**Team B** created a deliberately vulnerable service account and enabled Kerberos ticket auditing. **Team A** enumerated it, extracted a service ticket, and cracked the recovered hash. **Team B** confirmed detection fired correctly, then remediated by forcing AES-only encryption, after which the same attack was re-run and confirmed both uncrackable and correctly undetected (by design, since the rule specifically targets RC4).

**Result:** Full attack chain demonstrated end-to-end — enumeration, ticket extraction, detection, password recovery, and remediation with verified before/after contrast.

---

## Setup

```powershell
New-ADUser -Name "svc-sql" -SamAccountName "svc-sql" `
  -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true
setspn -A MSSQLSvc/cerberus-dc.cerberus.local:1433 cerberus\svc-sql

auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
```

---

## Issue 1 — Leftover Phase 1 firewall rule almost blocked the attack before it started

**Symptom:** N/A — caught proactively before running anything, rather than discovered through failure.

**Root cause:** Phase 1's remediation left an inbound block rule against Kali's IP active on both the DC and Workstation. Since Kerberoasting needs LDAP and Kerberos connectivity (not just SMB, which Phase 1's block also happened to cover), running the attack without removing this rule first would have produced a confusing connectivity failure that looked like a broken attack rather than an intentional block from a previous phase.

**Fix:** Removed both firewall rules before starting:
```powershell
Remove-NetFirewallRule -DisplayName "Block-Kali-Cerberus"
Remove-NetFirewallRule -DisplayName "Block-Kali-Cerberus-WKS"
```

**Why this mattered:** A genuinely good catch — recognizing that a previous phase's remediation would silently interfere with the next phase's attack narrative. Documented here as a deliberate design point: in a real engagement this would represent an attacker rotating source IP after being blocked, or a controlled test temporarily lifting a block.

---

## Issue 2 — First ticket request came back AES-encrypted, not RC4

**Symptom:** The first `GetUserSPNs.py` run against `svc-sql` returned a ticket starting with `$krb5tgs$18$` — AES256, not the RC4 (`$23$`) the project design specifically requires. See [`evidence/phase2/01-initial-ticket-was-aes-not-rc4.png`](evidence/phase2/01-initial-ticket-was-aes-not-rc4.png).

**Root cause:** Windows Server 2025 domains default new accounts to AES-capable Kerberos encryption unless explicitly restricted. `New-ADUser` alone doesn't force RC4 — a modern AD environment actively defends against the classic Kerberoasting weakness by default, which is itself a notable finding.

**Fix:**
```powershell
Set-ADUser -Identity svc-sql -KerberosEncryptionType RC4
```
Re-running the same attack afterward produced `$krb5tgs$23$` as expected. See [`evidence/phase2/02-ticket-rc4-after-fix.png`](evidence/phase2/02-ticket-rc4-after-fix.png).

**Why this mattered:** This is a genuinely interesting, report-worthy finding in its own right — modern AD defaults have quietly closed part of the classic Kerberoasting attack surface, and demonstrating it required deliberately downgrading the account, which is worth stating explicitly rather than glossing over (it's a stronger, more accurate story than implying RC4 accounts are still the default).

---

## Issue 3 — Initially investigated the wrong Kerberos event

**Symptom:** An early dashboard check for `4769` events returned a result with `ticketEncryptionType: 0x12` (AES), which looked like a contradiction — the rule seemingly wasn't matching the "attack."

**Root cause:** That particular event was an unrelated, routine machine-account ticket renewal (`serviceName: CERBERUS-WKS1$`), not the actual Kerberoasting attempt against `svc-sql`. A generic `4769` search surfaces all Kerberos ticket activity on the DC, including normal background domain operations.

**Diagnosis method:** Checked the `serviceName` field on the returned event and noticed it didn't match `svc-sql` at all — prompting a narrower, correctly-scoped search.

**Fix:** Searched specifically for `4769 AND svc-sql` instead of a bare `4769`, isolating the actual attack event from routine domain noise.

**Why this mattered:** A useful reminder that a broad search term can return technically-matching but contextually-irrelevant results — narrowing to the specific target account is what actually confirms an attack, not just the event type.

---

## Issue 4 — `rockyou.txt` not present by default on the Kali Marketplace AMI

**Symptom:** `rockyou.txt` didn't exist anywhere on the system, unlike a full desktop Kali ISO where it ships pre-installed (compressed).

**Root cause:** The AWS Marketplace Kali image is a minimal build and doesn't include the `wordlists` package by default.

**Fix:** Installed it, then hit a second, unrelated issue appending a test password to it:
```bash
sudo apt install -y wordlists
```
Appending failed with `sudo echo '...' >> file: Permission denied` even with `sudo` — a classic shell redirection trap, where `>>` is set up by the calling shell (as the normal user) before `sudo` ever takes effect on the command itself. Fixed with:
```bash
echo 'Summer2024!' | sudo tee -a /usr/share/wordlists/rockyou.txt
```

**Why this mattered:** A good, concrete example of a common Linux misunderstanding — `sudo` elevates the command, not any redirection attached to it — worth being able to explain precisely rather than just knowing the `tee` workaround by rote.

---

## Issue 5 — Hashcat had no usable compute device on this instance

**Symptom:** `hashcat -m 13100 ...` failed immediately: `CL_PLATFORM_NOT_FOUND_KHR` / "No OpenCL, HIP or CUDA compatible platform found."

**Root cause:** The `t3.medium` Kali instance has no GPU, and no CPU-based OpenCL runtime (like PoCL) was installed. Even `--force -D 1` (forcing CPU device mode) couldn't help, since hashcat still needs *some* OpenCL runtime present to enumerate any device, GPU or CPU.

**Fix:** Abandoned hashcat for this attempt and switched to **John the Ripper**, which has a native `krb5tgs` format and runs on pure CPU with no OpenCL dependency at all:
```bash
sudo apt install -y john
john --format=krb5tgs svc-sql.hash --wordlist=/usr/share/wordlists/rockyou.txt
john --show --format=krb5tgs svc-sql.hash
```
**Result:** Cracked in 19 seconds — `Summer2024!`. See [`evidence/phase2/04-password-cracked-john.png`](evidence/phase2/04-password-cracked-john.png).

**Why this mattered:** A practical lesson in tool flexibility — rather than spending further time chasing a missing package for hashcat's benefit, switching to an equally valid, purpose-built alternative (John's `krb5tgs` mode exists specifically for this hash type) got to a real result faster.

---

## Detection — Confirmed Firing Correctly

The RC4 ticket request against `svc-sql` correctly triggered the custom Wazuh rule, with full MITRE mapping intact:

```
rule.id: 100020
rule.description: CERBERUS - Possible Kerberoasting: RC4 service ticket requested (T1558.003)
rule.mitre.id: T1558.003
rule.mitre.tactic: Credential Access
rule.mitre.technique: Kerberoasting
```

See [`evidence/phase2/03-wazuh-rule-100020-fired.png`](evidence/phase2/03-wazuh-rule-100020-fired.png) for the full expanded event, confirmed via `data.win.eventdata.ticketEncryptionType: 0x17` (RC4), `targetUserName: jsmith@CERBERUS.LOCAL` (the low-privilege account used), and `ipAddress: ::ffff:10.0.9.173` (Kali).

---

## Remediation — Confirmed Effective

```powershell
Set-ADUser -Identity svc-sql -KerberosEncryptionType AES128,AES256
```

Re-running the identical attack afterward produced a clean, complete before/after contrast:

| | Before remediation | After remediation |
|---|---|---|
| Ticket format | `$krb5tgs$23$` (RC4) | `$krb5tgs$18$` (AES256) |
| Crackable with John | Yes — 19 seconds | No — "No password hashes loaded," John's `krb5tgs` format doesn't support AES |
| Wazuh rule 100020 fired | Yes | No — correctly silent, since the rule specifically targets RC4 (`0x17`), not AES |

See [`evidence/phase2/05-remediation-aes-ticket-uncrackable.png`](evidence/phase2/05-remediation-aes-ticket-uncrackable.png) and [`evidence/phase2/06-remediation-rule-silent-confirmed.png`](evidence/phase2/06-remediation-rule-silent-confirmed.png).

**Note on rule behavior:** The absence of an alert after remediation is the *correct* outcome, not a detection gap — rule 100020 was deliberately scoped to RC4 specifically, since that's the actual vulnerability signature. A rule that fired on all Kerberos ticket activity regardless of encryption type would be far too noisy for real use.

---

## Summary Table

| # | Issue | Root Cause | Fix | Outcome |
|---|---|---|---|---|
| 1 | Leftover firewall block would have masked the attack | Phase 1 remediation still active | Removed both block rules before starting | Clean environment for Phase 2 |
| 2 | First ticket was AES, not RC4 | Windows Server 2025 defaults new accounts to AES-capable | Forced `KerberosEncryptionType RC4` | Correct, crackable ticket format |
| 3 | Investigated an unrelated 4769 event | Broad search matched routine machine-account traffic | Narrowed search to `4769 AND svc-sql` | Correctly isolated the real attack event |
| 4 | `rockyou.txt` missing; `sudo` append failed | Minimal AMI lacked the wordlist package; shell redirection runs before `sudo` takes effect | Installed `wordlists`; used `tee -a` under `sudo` instead of `>>` | Wordlist ready for cracking |
| 5 | Hashcat had no usable compute device | No GPU, no CPU OpenCL runtime available/installable | Switched to John the Ripper's native `krb5tgs` format | Password cracked in 19 seconds |

---

## What This Demonstrates

- Recognized and neutralized cross-phase interference (a prior phase's remediation silently affecting the current attack) before it caused confusion.
- Correctly diagnosed a real security-relevant finding — modern AD's default AES preference — rather than treating an unexpected result as a simple bug.
- Distinguished a contextually-irrelevant matching event from the actual attack through careful field-level inspection, rather than assuming the first match was correct.
- Solved a tooling dependency gap (hashcat's missing compute runtime) by substituting a purpose-built alternative rather than sinking further time into package troubleshooting.
- Verified remediation completeness on two independent axes: cryptographic (can the hash even be cracked) and detection (does the rule correctly stay silent on the now-benign ticket type).

*Log current as of: Phase 2 (Credential Theft) fully executed, detected, cracked, and remediated. Next: Phase 3 — C2 Beaconing.*
