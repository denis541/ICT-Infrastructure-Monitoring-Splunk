# Incident Response Playbook: Malicious or Unknown Process Detected

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Sysmon](https://img.shields.io/badge/Data_Source-Sysmon-0078D4?style=flat&logo=windows&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Incident_Response-E01B1B?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Trigger:** Splunk alert — suspicious process name, path, hash, or parent-child relationship (Sysmon Event ID 1)  
**Tactic:** Execution (TA0002)  
**Severity:** Critical — treat as active compromise until proven otherwise  
**SLA:** Triage within 5 minutes; contain within 15 minutes if malicious process confirmed

---

## Scope

This playbook covers detection and response to suspicious or unknown processes identified via SIEM alerts or EDR. The first priority is establishing whether the process is malicious before taking containment action — premature termination of a process can destroy volatile evidence (memory, open handles, network connections) that is needed for the full investigation.

---

## Step 1 — Validate the Process

Pull the full process creation context from Sysmon:

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| where host="<affected_host>"
| table _time, host, user, Image, CommandLine, ParentImage, ParentCommandLine, Hashes
| sort -_time
```

**Validate each field:**

| Field | What to Check | Red Flags |
|-------|--------------|-----------|
| `Image` (process path) | Should match expected system path | `C:\Users\<user>\AppData\` running as a system process name; `C:\Temp\`; random directory |
| `CommandLine` | Arguments should be expected for the binary | Encoded strings, unusual flags, C2 URLs embedded |
| `ParentImage` | What launched this process | Office app spawning cmd/PowerShell; `svchost.exe` spawning `cmd.exe` |
| `Hashes` | SHA256 hash for threat intel lookup | Unknown hash or known-malicious hash |
| `user` | Who the process runs as | SYSTEM running a user-space binary; standard user running a privileged tool |

**Hash verification:**

```spl
| lookup threat_hashes hash AS sha256_hash OUTPUT malware_family, confidence
| where isnotnull(malware_family)
```

Also submit the hash to VirusTotal or Cisco Talos if not in the local threat intel lookup.

---

## Step 2 — Map the Process Tree

A single process in isolation tells an incomplete story. Map the full execution chain:

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| where host="<affected_host>" earliest=-30m
| table _time, user, ParentImage, Image, CommandLine
| sort _time
```

**Suspicious parent-child patterns:**

| Parent | Child | Assessment |
|--------|-------|------------|
| `winword.exe` / `excel.exe` | `cmd.exe`, `powershell.exe`, `wscript.exe` | Macro-based execution — malicious document |
| `mshta.exe` | Any shell or downloader | HTA-based phishing delivery |
| `svchost.exe` | `cmd.exe` or `powershell.exe` | Service hijacking or exploitation |
| `explorer.exe` | Random binary from `%TEMP%` or `%APPDATA%` | User-initiated or social engineering execution |
| `lsass.exe` | Anything | Credential dumping tool — critical severity |

---

## Step 3 — Check Network Connections and File Activity

Before terminating the process, capture its current network connections and file activity — this evidence disappears when the process ends:

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID IN (3, 11, 23)
| where host="<affected_host>" AND earliest=-30m
| table _time, EventID, Image, DestinationIp, DestinationPort, TargetFilename
| sort _time
```

| Sysmon Event | What It Shows |
|-------------|---------------|
| Event ID 3 (Network Connection) | Outbound C2 connections, download URLs, lateral movement targets |
| Event ID 11 (File Create) | Dropped payloads, staging files, persistence files |
| Event ID 23 (File Delete) | Anti-forensic file deletion post-execution |

**Enrich any outbound IPs:**

```spl
| lookup threat_ips ip AS DestinationIp OUTPUT threat_category, confidence
```

---

## Step 4 — Check for Persistence

Before containment, determine whether the process has already installed persistence — removing the process without removing persistence means it will return:

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID IN (12, 13, 14)
| where host="<affected_host>" earliest=-1h
| search TargetObject="*\\Run\\*" OR TargetObject="*\\RunOnce\\*" OR TargetObject="*\\Services\\*"
| table _time, EventID, Image, TargetObject, Details
```

Also check for scheduled tasks and new services:

```spl
index=windows sourcetype="WinEventLog:Security" EventCode IN (4698, 7045)
| where host="<affected_host>" earliest=-1h
| table _time, EventCode, user, TaskName, ServiceName
```

| Event ID | Meaning |
|----------|---------|
| 4698 | Scheduled task created |
| 7045 | New service installed |
| Sysmon 13 | Registry value set — run key persistence |

---

## Step 5 — Containment

**Preserve before terminating** — if EDR is available, take a memory capture before killing the process. Encoded payloads, injected shellcode, and C2 keys exist only in memory and are lost on process termination.

**Terminate the malicious process:**

```powershell
Stop-Process -Id <PID> -Force
```

**Block C2 destinations** identified in Step 3 at the firewall and proxy.

**Isolate the host** if any of the following are true:
- Known-malicious hash confirmed by threat intel
- Active outbound C2 connection observed
- Lateral movement targets identified in network connections
- Persistence mechanisms installed

**Do not reimage immediately** — preserve the host for forensic analysis if the infection vector is unknown.

---

## Step 6 — Eradication

Remove all artifacts identified during the investigation:

- Delete malicious files identified via Sysmon Event ID 11
- Remove registry run keys added by the process (Sysmon Event ID 13)
- Delete scheduled tasks created during the infection window (Event ID 4698)
- Remove any services installed by the malware (Event ID 7045)
- Remove backdoor accounts if created (Event ID 4720)

Verify removal by re-running the detection query and confirming the process does not respawn.

---

## Step 7 — Recovery and Validation

Before reconnecting the host:

1. Confirm all persistence mechanisms have been removed
2. Verify no C2 connections are re-established after reconnection to the network
3. Run a full AV/EDR scan on the restored host
4. Restore from backup only if system files were modified and cannot be reliably cleaned

Monitor the host for 24 hours post-recovery for re-infection indicators.

---

## Step 8 — Document and Close

| Field | Required Content |
|-------|----------------|
| Process name and path | Full `Image` path — note if outside expected system directories |
| Hash | SHA256 — threat intel result |
| Parent process | Full parent-child chain documented |
| Network connections | C2 IPs/domains identified and blocked |
| Files dropped | Paths and hashes |
| Persistence mechanisms | Registry keys, scheduled tasks, services, accounts |
| Containment actions | Process terminated, host isolated, C2 blocked |
| Eradication confirmed | Yes / No |
| Root cause | Initial access vector if determined |
| Escalated to Tier 2 | Yes / No |

---

## MITRE ATT&CK Relevance

| Technique | ID | Step |
|-----------|----|------|
| Command and Scripting Interpreter | T1059 | Step 1 — suspicious process in execution chain |
| Masquerading | T1036 | Step 1 — process path outside expected system directory |
| Boot or Logon Autostart: Registry Run Keys | T1547.001 | Step 4 — Sysmon Event ID 13 run key check |
| Scheduled Task | T1053.005 | Step 4 — Event ID 4698 persistence check |
| Create or Modify System Process: Windows Service | T1543.003 | Step 4 — Event ID 7045 service installation |
| Exfiltration Over C2 Channel | T1041 | Step 3 — outbound connections from malicious process |
| Indicator Removal: File Deletion | T1070.004 | Step 3 — Sysmon Event ID 23 file deletion detection |
