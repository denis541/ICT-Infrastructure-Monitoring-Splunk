# Lab Architecture

## Lab Overview
Single-host virtualization lab using **VMware Workstation Pro**.  
The lab runs on an **isolated host-only network** to allow safe attack simulation, log generation, and security monitoring without exposing external networks.

---

## Core Components

### Virtual Machines

#### Splunk SIEM VM
- **OS:** Ubuntu 22.04
- **Resources:**  
  - 8GB RAM  
  - 4 vCPU  
  - 200GB storage
- **Software:** Splunk Enterprise (Free Tier)
- **Purpose:**  
  - Centralized log collection  
  - Analysis and alerting  

---

#### Windows Target VM
- **OS:** Windows 11 Pro
- **Resources:**  
  - 4GB RAM  
  - 2 vCPU  
  - 100GB storage
- **Configuration:**  
  - Domain-joined  
  - Typical enterprise workstation setup
- **Purpose:**  
  - Generates Windows Security Event Logs  

---

#### Kali Linux VM (Attack Simulator)
- **OS:** Kali Linux
- **Resources:**  
  - 2GB RAM  
  - 2 vCPU  
  - 50GB storage
- **Purpose:**  
  - Controlled attack simulation
- **Restrictions:**  
  - No internet access  
  - Isolated to lab network only  

---

## Network Configuration
- **Subnet:** `192.168.100.0/24`
- **Firewall Model:** Host-only networking (no internet access)

### Static IP Assignments
| Machine | IP Address |
|-------|------------|
| Splunk SIEM | `192.168.100.150` |
| Windows Target | `192.168.100.20` |
| Kali Linux | `192.168.100.50` |

---

## Log Flow Architecture
Kali Linux (Attacks)

↓

Windows Target (Event Logs Generated)

↓

Splunk Universal Forwarder

↓

Splunk SIEM

↓

Alerts & Dashboards

---

## Key Configurations

### Splunk Universal Forwarder (Windows)
- **Config Path:**
C:\Program Files\SplunkUniversalForwarder\etc\apps\SplunkUniversalForwarder\local\inputs.conf

- **Collected Logs:**
- Windows Security Event Logs
- Event IDs:
  - `4624` (Successful logon)
  - `4625` (Failed logon)
  - `4688` (Process creation)
- **Forwarding:**
- Destination: Splunk SIEM
- Port: `9997`
- Compression: Enabled
- SSL: Enabled

---

### Splunk SIEM Configuration
- **Indexes:**
- `windows`
- `network`
- `security`
- **Sourcetypes:**
- `WinEventLog:Security`
- `syslog`
- **Parsing & Enrichment:**
- Field extractions for:
  - Usernames
  - Source IPs
  - Logon types
  - Process names

---

## Why This Setup Works
- **Realistic:** Uses enterprise-grade tools (Splunk, Windows Event Logging)
- **Safe:** Fully isolated from production and external networks
- **Reproducible:** All configurations are documented and version-controlled
- **Scalable:** Additional VMs can be added (Linux servers, firewalls, web apps)

---

## Hardware Requirements

### Minimum
- 16GB RAM
- 4-core CPU
- 500GB SSD

### Recommended
- 32GB RAM
- 8-core CPU
- 1TB SSD

### Tested On
- Intel i7-12700H  
- 32GB DDR4  
- 1TB NVMe SSD  

---

## Validation
The lab has been tested and confirmed working through:
- Log ingestion verification
- Attack simulation detection
- Alert triggering validation
- Performance testing under sustained load
