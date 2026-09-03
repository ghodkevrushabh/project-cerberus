# Project Cerberus — Day 1 Log
## Environment Build, Wazuh Deployment & Agent Enrollment

**Team A (Red Team / Attacker):** owns and operates the Kali Linux instance.
**Team B (Blue Team):** owns and operates the Monitoring stack, Domain Controller, and Workstation — the full defensive and Active Directory side of the environment.

This log documents the full Day 1 build on AWS: infrastructure setup, all four instances, every issue hit along the way, and full pipeline verification before any attack phase begins.

---

## Part 1 — Infrastructure Setup (Team B)

1. AWS account confirmed (Free Tier), billing budget configured as a safety net against runaway spend.
2. EC2 key pair created for SSH/RDP access across all instances.
3. VPC built: single VPC, single Availability Zone, single public subnet.
4. Shared Security Group created to govern all internal and external traffic:
   - Inbound: all traffic, source = itself (self-referencing rule — lets all four instances communicate freely, replacing the need for a traditional bridged LAN)
   - Inbound: SSH (22), RDP (3389), HTTPS (443) — each restricted to the team's own public IP, never opened to `0.0.0.0/0`
5. Elastic IPs allocated for the Monitoring instance, Domain Controller, and Workstation — the Kali instance intentionally excluded, since Team A only powers it on during active attack execution and doesn't need a fixed address.

---

## Part 2 — Instance Build Order

1. **Monitoring instance** (Team B): Ubuntu Server 24.04 LTS, sized generously (4 vCPU / 16GB) specifically to avoid resource-contention issues under the combined load of Wazuh + Suricata + Zeek running simultaneously.
2. **Domain Controller** (Team B): Windows Server 2025 Base — see Issue 1 below for a rebuild that occurred here.
3. **Workstation** (Team B): Windows Server 2025 Base, configured as a domain-joined member server rather than a true Windows 10/11 client — see Issue 2 for why.
4. **Attacker** (Team A): Official Kali Linux Marketplace AMI, no Elastic IP, accessed via SSH from Team A's own terminal.

---

## Part 3 — Issues Encountered and Resolved

### Issue 1 — DC lost all network connectivity after a static IP misconfiguration, requiring a full rebuild

**Symptom:** During AD DS promotion, Windows warned that the DC should have a static IP. A static IP was applied using subnet mask `255.255.0.0`, based on an incorrect assumption that the VPC's overall CIDR pool applied directly to the instance's own network config. Immediately after applying, RDP access was lost entirely and never returned.

**Root cause:** The VPC's overall CIDR is the *total address pool*, not the specific subnet's CIDR — the subnet actually assigned to the instance had its own, smaller range, requiring a different (and larger) subnet mask. Applying the wrong mask made the instance believe it was on a different network entirely, breaking its route back to the gateway.

**Diagnosis method:** Attempted EC2 Serial Console recovery — connected, but produced no usable prompt, likely because Emergency Management Services wasn't enabled on this image. Attempted AWS Systems Manager Run Command as a network-independent fallback — unavailable, since the instance had no IAM role permitting SSM registration. With both remote-recovery paths exhausted, a full disk-detach-and-repair was considered but judged not worth the time investment given how early in the build this occurred.

**Fix:** Terminated the broken instance and launched a clean replacement rather than pursuing offline disk repair.

**Why this mattered:** Surfaced an important fact that changed the approach for every instance going forward: an EC2 instance's private IP is guaranteed not to change for the life of the instance (confirmed via AWS documentation) — it only changes on termination, never on stop/start or reboot. This meant manually setting a static IP wasn't actually necessary at all; the safer approach adopted from this point on was to leave IP addressing on DHCP entirely and only override DNS settings where needed.

---

### Issue 2 — Windows 10/11 is not available on standard EC2 instances

**Symptom:** N/A — identified proactively before attempting the workstation build, rather than discovered through failure.

**Root cause:** Microsoft's licensing terms restrict Windows 10/11 client OS to EC2 Dedicated Hosts or Amazon WorkSpaces with a BYOL license — it cannot run on standard shared-tenancy EC2 the way Windows Server can. This is a Microsoft licensing restriction, not an AWS platform limitation.

**Fix:** Used Windows Server 2025 Base as the workstation, configured as a plain domain-joined member server. Functionally equivalent for every phase of this project — Sysmon, Kerberoasting as a target, PowerShell execution, and archive staging all behave identically on Server as they would on a client OS.

**Why this mattered:** Avoided a costly, time-consuming detour into Dedicated Host provisioning that the project's timeline could not absorb, while preserving full technical fidelity to the original design.

---

### Issue 3 — Workstation domain join failed with "domain controller could not be contacted"

**Symptom:** Attempting to join the domain from the workstation failed immediately, despite the DC being fully promoted and reachable by IP.

**Root cause:** The workstation's DNS was still pointing at the default VPC resolver, not the Domain Controller. AD domain join relies on DNS (via SRV records) to locate the DC — a workstation that can't resolve the domain through the actual DC has no way to find it, regardless of raw IP connectivity.

**Diagnosis method:** Ran `ping` and `nslookup` against the DC's IP directly from the workstation — both timed out completely, ruling out a DNS-specific issue first and pointing at either a Security Group block or a deeper network gap. Cross-checked Security Group attachment on both instances (confirmed correct) before re-examining DNS configuration specifically.

**Fix:** Manually set the workstation's DNS server to the DC's private IP instead of leaving it on the default resolver.

**Why this mattered:** Reinforces a foundational AD networking principle — every domain member must point its DNS at the domain's own DNS server, not a generic resolver — surfaced here in a context where the "default" DNS behavior differs from a traditional office/home network.

---

### Issue 4 — Wazuh agent enrollment silently failed due to a scripting error in the MSI install command

**Symptom:** Both agents appeared registered in the Wazuh dashboard but showed "never connected" rather than Active, even though the install and enrollment commands completed without visible errors.

**Root cause:** The MSI install command wrapped the manager's IP address in single quotes for the `WAZUH_MANAGER` property. Windows' `msiexec` does not strip these quotes the way a shell would — they were written literally into the agent's config as part of the IP value, producing an address the agent could never resolve or connect to.

**Diagnosis method:** Confirmed the agent service was running (ruling out a crash), then directly inspected the config file's address field and spotted the stray quote characters visually.

**Fix:** Edited the config file directly on both machines to remove the erroneous quotes, restarted the agent service, and confirmed raw TCP connectivity to the manager's port before rechecking the dashboard.

**Why this mattered:** A reminder that command-line quoting conventions aren't universal across shells and installers — a pattern that would work correctly elsewhere silently corrupted a config value instead of throwing a visible error.

---

### Issue 5 — Sysmon events invisible in the dashboard despite confirmed local logging and Active agents

**Symptom:** With both agents Active and Sysmon confirmed logging locally on the workstation, a Notepad open/close test produced no visible results in the Wazuh dashboard's default view, even with a wide time range and correct agent filter.

**Root cause:** Wazuh's default alerts index only stores events that match a detection rule. A plain Notepad launch matches no default rule, so the event is correctly collected but never surfaces in the default alerts view — it's a visibility/indexing distinction, not a broken pipeline.

**Diagnosis method:** Checked the manager's raw log output directly rather than relying solely on the dashboard, which confirmed events were arriving even though they weren't visible in the default index.

**Fix:** Enabled full raw-event archiving on the manager (`logall`/`logall_json`), enabled the corresponding Filebeat archives setting, restarted both services, and created a new `wazuh-archives-*` index pattern in the dashboard specifically for this kind of verification. Confirmed full event detail visible afterward, including the exact process image path.

**Why this mattered:** Established a clear operational distinction going forward: the **archives** index is for verification/diagnostics (confirming telemetry arrives at all), while the **alerts** index is what a real detection workflow should be built around — since only rule-matched events belong in day-to-day analyst triage.

---

## Part 4 — Time Synchronization

Configured all four machines to prevent clock drift, which would otherwise make attack-to-alert timestamp correlation unreliable:
- **DC:** synced to AWS's internal time service, set as the domain's authoritative time source (PDC Emulator role).
- **Workstation:** resynced against the DC via standard domain member behavior.
- **Monitoring instance:** confirmed synchronized via `chrony`.
- **Kali:** confirmed synchronized via `timedatectl`.
- All four set to **UTC** to eliminate timezone confusion across screenshots and log correlation.

---

## Summary Table

| # | Issue | Root Cause | Fix | Component Validated |
|---|---|---|---|---|
| 1 | DC lost connectivity after static IP change, required rebuild | Confused the VPC's overall CIDR with the actual subnet CIDR | Terminated and relaunched; adopted DHCP-only addressing (AWS private IPs persist for instance lifetime) | Correct AWS subnet/IP addressing model |
| 2 | Windows 10/11 unavailable on standard EC2 | Microsoft licensing restricts client OS to Dedicated Hosts/BYOL | Substituted Windows Server 2025 as a domain-joined member server | Workstation build strategy |
| 3 | Workstation domain join failed | DNS pointed at the default resolver, not the DC | Set workstation DNS to the DC's private IP | AD DNS dependency for domain join |
| 4 | Wazuh agents showed "never connected" | Quoted IP in MSI command written literally into config | Edited the config file directly, removed stray quotes | Wazuh agent enrollment |
| 5 | Sysmon events invisible in dashboard | Fresh manager lacked archives configuration | Enabled `logall`/`logall_json` + Filebeat archives + new index pattern | Full telemetry pipeline |

---

## Part 5 — Evidence Checklist (what to actually screenshot)

1. **Time sync confirmation** — clock status on all four machines, captured within the same minute.
2. **Wazuh Agents page** — both the DC and Workstation showing **Active**.
3. **Expanded Sysmon event detail** — the full document view showing the correct process image path, proving the pipeline end-to-end.
4. **AD verification output** — domain and DNS resolution both confirmed working.
5. **Security Group configuration** — one clean screenshot of the inbound rules, useful for the architecture section.

Routine command outputs, individual install runs, and intermediate failed attempts don't need to be captured — only evidence that independently proves something works.

---

## What This Demonstrates

- Correctly diagnosed a self-inflicted networking lockout by cross-referencing actual cloud IP-persistence behavior against incorrect assumptions.
- Identified and worked around a genuine third-party licensing constraint before it became a blocking failure.
- Diagnosed an indexing/visibility distinction (alerts vs. archives) that is a common point of confusion for anyone new to Wazuh, and built a lasting operational convention around it.
- Understood that AD's DNS dependency for domain join applies identically in a cloud context, even though the "default" networking behavior differs from a traditional LAN.

*Log current as of: environment build complete, both agents enrolled and verified, before Phase 1 (Initial Access) execution.*
