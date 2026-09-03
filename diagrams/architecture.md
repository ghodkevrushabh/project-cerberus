# Project Cerberus — Infrastructure Diagram

**Team A (Red Team / Attacker):** owns the Kali instance.
**Team B (Blue Team):** owns the Monitoring instance, Domain Controller, and Workstation.

```mermaid
graph TB
    Internet(["Internet"])
    IGW["Internet Gateway"]

    subgraph AWS["AWS Account — us-east-1"]
        subgraph VPC["VPC: cerberus-vpc"]
            subgraph Subnet["Subnet (single AZ)"]
                subgraph SG["Security Group: cerberus-internal"]
                    MON["cerberus-monitor — Team B<br/>Ubuntu Server 24.04 | t3.xlarge<br/>Wazuh Manager+Indexer+Dashboard<br/>Suricata + Zeek<br/>Elastic IP: attached"]
                    DC["cerberus-dc — Team B<br/>Windows Server 2025 Base | t3.medium<br/>AD DS + DNS (cerberus.local)<br/>Elastic IP: attached"]
                    WKS["cerberus-wks1 — Team B<br/>Windows Server 2025 Base | t3.medium<br/>Domain-joined member server<br/>Sysmon installed, confirmed logging<br/>Elastic IP: attached"]
                    KALI["cerberus-kali — Team A<br/>Official Kali Linux AMI | t3.medium<br/>nmap, crackmapexec, Impacket<br/>No Elastic IP — SSH via key pair<br/>Powered on only during attacks"]
                end
            end
        end
    end

    Internet <--> IGW
    IGW <--> VPC

    TeamB(["Team B — laptop/terminal"]) -.->|"RDP 3389, restricted to Team B's IP"| DC
    TeamB -.->|"RDP 3389, restricted to Team B's IP"| WKS
    TeamB -.->|"SSH 22 + HTTPS 443, restricted to Team B's IP"| MON
    TeamA(["Team A — laptop/terminal"]) -.->|"SSH 22, restricted to Team A's IP"| KALI

    DC ==>|"AD domain join, DNS"| WKS
    KALI -.->|"Attack traffic<br/>(self-referencing SG rule allows this)"| DC
    KALI -.->|"Attack traffic"| WKS
    DC ==>|"Wazuh agent → manager"| MON
    WKS ==>|"Wazuh agent → manager"| MON
```

---

### Reference details

| Field | Value |
|---|---|
| VPC CIDR | `10.0.0.0/16` |
| Subnet CIDR | `10.0.0.0/20` (confirm your own via VPC console — don't assume) |
| Security Group | `cerberus-internal` — self-referencing all-traffic rule for internal communication, plus SSH/RDP/HTTPS restricted to each team's own IP |
| DC private IP | fill in from console |
| Workstation private IP | fill in from console |
| Monitor private IP | fill in from console |
| Kali private IP | fill in from console (changes on stop/start — no Elastic IP) |

### Notes

- **Windows 10/11 client OS is not available on standard shared-tenancy EC2** (Microsoft licensing restricts it to Dedicated Hosts or WorkSpaces BYOL) — the Workstation runs Windows Server 2025 as a domain-joined member server instead. Functionally identical for every phase of this project.
- Each instance's private IP is persistent for the life of the instance — it does not change on stop/start, only on termination. Static IP configuration inside the OS is unnecessary; only DNS settings need manual adjustment (Workstation → DC, DC → itself).
