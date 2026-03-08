# Home Lab Architecture: Splunk SIEM Detection Lab

![Splunk](https://img.shields.io/badge/Tool-Splunk_Enterprise-000000?style=flat&logo=splunk&logoColor=white)
![Platform](https://img.shields.io/badge/Hypervisor-VMware_Workstation_Pro-607078?style=flat&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Detection_Engineering-4CAF50?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Purpose:** Isolated attack simulation, log generation, and SIEM-based detection validation

---

## Overview

Single-host virtualization lab running three VMs on an isolated host-only network. Kali Linux generates controlled attacks against a Windows target, which forwards Security Event Logs to a Splunk SIEM for detection rule validation and alerting. No VM has internet access — the environment is fully air-gapped from external networks.

---

## Virtual Machines

| VM | OS | RAM | vCPU | Storage | Role |
|----|----|----|------|---------|------|
| Splunk SIEM | Ubuntu 22.04 | 8GB | 4 | 200GB | Log collection, analysis, alerting |
| Windows Target | Windows 11 Pro | 4GB | 2 | 100GB | Attack target — generates Security Event Logs |
| Kali Linux | Kali Linux | 2GB | 2 | 50GB | Controlled attack simulation |

---

## Network Configuration

- **Topology:** VMware host-only network — isolated from host machine's external interfaces
- **Subnet:** `192.168.100.0/24`
- **Internet access:** None — all VMs restricted to lab subnet only

| Host | IP Address |
|------|------------|
| Splunk SIEM | `192.168.100.150` |
| Windows Target | `192.168.100.20` |
| Kali Linux (attacker) | `192.168.100.50` |

---

## Log Flow

```
Kali Linux (attack simulation)
        ↓
Windows Target (Security Event Logs generated)
        ↓
Splunk Universal Forwarder (port 9997, SSL, compression)
        ↓
Splunk SIEM (192.168.100.150)
        ↓
Indexes → Detection Rules → Alerts & Dashboards
```

---

## Splunk Universal Forwarder — Windows Configuration

**Config path:** `C:\Program Files\SplunkUniversalForwarder\etc\apps\SplunkUniversalForwarder\local\inputs.conf`

**Collected Event IDs:**

| Event ID | Description | Detection Use |
|----------|-------------|---------------|
| 4624 | Successful logon | Post-brute-force access confirmation |
| 4625 | Failed logon | Brute force and password spray detection |
| 4688 | Process creation | Execution chain and lateral movement detection |
| 4720 | User account created | Persistence via local account creation |
| 4740 | Account locked out | Lockout policy trigger — high-volume attack indicator |

**Forwarding:** destination `192.168.100.150:9997`, SSL enabled, compression enabled

---

## Splunk SIEM Configuration

| Setting | Value |
|---------|-------|
| Indexes | `windows`, `network`, `security` |
| Sourcetypes | `WinEventLog:Security`, `syslog` |
| Field extractions | Usernames, source IPs, logon types, process names |
| Receiving port | 9997 |

---

## Hardware

| Spec | Minimum | Recommended | Tested On |
|------|---------|-------------|-----------|
| RAM | 16GB | 32GB | 32GB DDR4 |
| CPU | 4-core | 8-core | Intel i7-12700H |
| Storage | 500GB SSD | 1TB SSD | 1TB NVMe SSD |

---

## Validation

The lab was confirmed operational through:

- Log ingestion verification — Event IDs appearing correctly in Splunk indexes
- Attack simulation — Hydra brute force against Windows RDP generating 4625 events
- Detection rule firing — SPL queries triggering alerts on threshold breaches
- Performance testing — sustained attack load without forwarder drops or indexing lag

---

## Scalability

The host-only subnet supports additional VMs without reconfiguration. Planned additions:

- Linux server target (SSH brute force, sudo escalation detection)
- Windows Server with Active Directory (lateral movement, Kerberoasting detection)
- Network device syslog source (firewall rule violation detection)
