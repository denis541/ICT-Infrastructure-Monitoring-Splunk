# Incident Response Playbook: Suspicious PowerShell Execution

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Sysmon](https://img.shields.io/badge/Data_Source-Sysmon_EventID_1-0078D4?style=flat&logo=windows&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Incident_Response-E01B1B?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Trigger:** Splunk alert — `powershell.exe` launched with `-enc` or `-EncodedCommand` parameter (Sysmon Event ID 1)  
**Tactic:** Execution (TA0002), Defense Evasion (TA0005)  
**SLA:** Decode payload within 5 minutes of alert; contain within 20 minutes if malicious payload confirmed

---

## Scope

This playbook covers detections of PowerShell processes launched with encoded command parameters. The encoding itself is not malicious — the playbook's purpose is to rapidly decode the payload, establish whether it is malicious, and determine what it did or attempted to do on the host.

---

## Step 1 — Extract and Decode the Payload

Pull the full command line from the alert:

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| where like(CommandLine, "%-enc%") OR like(CommandLine, "%-EncodedCommand%")
| table _time, host, user, ParentImage, CommandLine
```

Extract the Base64 string from the `CommandLine` field — everything after `-enc` or `-EncodedCommand` — and decode it. PowerShell uses **UTF-16LE** encoding, not UTF-8. Use the following to decode correctly:

```powershell
[System.Text.Encoding]::Unicode.GetString(
    [System.Convert]::FromBase64String("<paste_base64_string_here>")
)
```

**Do not use a standard Base64 web decoder** — it will produce garbage output because it assumes UTF-8. The PowerShell one-liner above handles the correct encoding.

Document the decoded plaintext payload before proceeding. Everything from Step 2 onward depends on knowing what the script actually does.

---

## Step 2 — Classify the Parent Process

The parent process is the most important severity indicator. Pull it from the same Sysmon event:

| Parent Process | Assessment | Severity |
|----------------|------------|----------|
| `winword.exe`, `excel.exe`, `powerpnt.exe` | Office macro executing PowerShell — malicious document | **Critical** |
| `wscript.exe`, `cscript.exe` | Script-based dropper — JS or VBS executing PowerShell | **Critical** |
| `mshta.exe` | HTA-based execution — common in phishing chains | **Critical** |
| `cmd.exe` spawned by `svchost.exe` | Suspicious service-to-shell chain | **High** |
| `explorer.exe` | User-initiated — lower initial severity, investigate intent | **Medium** |
| Known admin tool (SCCM, Ansible) | Likely legitimate — verify against change records | **Low** |

If the parent is an Office application, a script interpreter, or `mshta.exe` — treat as malicious and move to containment immediately without waiting for further investigation steps.

---

## Step 3 — Analyse the Decoded Payload

Read the decoded script and identify what it attempts to do. Common malicious patterns:

| Payload Pattern | Indicator | Technique |
|-----------------|-----------|-----------|
| `IEX` / `Invoke-Expression` | Executes a string as code — often used to run a second-stage payload | T1059.001 |
| `DownloadString` / `WebClient` | Downloads content from a remote URL | T1105 |
| `New-LocalUser` / `Add-LocalGroupMember` | Creates or elevates a local account | T1136.001 |
| `Set-ItemProperty HKCU:\...Run` | Registry run key persistence | T1547.001 |
| `Disable-WindowsDefender` / `Set-MpPreference` | AV/EDR disabling | T1562.001 |
| `Compress-Archive` + outbound connection | Data staging and exfiltration | T1048 |
| `-nop -w hidden -ep bypass` flags | Execution policy bypass + hidden window — evasion | T1027 |

If the payload contains any of the above, classify as **confirmed malicious** and proceed to Step 5 containment immediately.

---

## Step 4 — Establish Execution Context

Determine who ran the command, when, and whether it executed successfully:

```spl
index=windows EventID IN (1, 3, 11) earliest=-30m
| where host="<affected_host>"
| table _time, EventID, user, Image, CommandLine, DestinationIp, TargetFilename
| sort _time
```

| Sysmon Event | What It Reveals |
|-------------|-----------------|
| Event ID 1 (Process Create) | What processes spawned — confirm PowerShell child processes |
| Event ID 3 (Network Connection) | Outbound connections made by `powershell.exe` — C2 or download URLs |
| Event ID 11 (File Create) | Files dropped to disk by the script — payloads, persistence files |

**Key questions to answer before proceeding:**
- Did `powershell.exe` make any outbound network connections? (Event ID 3)
- Were any files written to disk? (Event ID 11) If so, where?
- Were any child processes spawned by `powershell.exe`? (Event ID 1, parent = powershell)
- Was the user account running this a standard user or a privileged account?

---

## Step 5 — Containment

**If payload is confirmed malicious or parent is high-severity:**

1. **Isolate the host** from the network — prevent any active C2 or lateral movement
2. **Kill the PowerShell process** if still running:
```powershell
Stop-Process -Name powershell -Force
```
3. **Block any C2 or download URLs** identified in the decoded payload at the firewall and proxy
4. **Preserve evidence** before remediation:
   - Export Sysmon logs for the affected timeframe
   - Capture memory if EDR is available — encoded PowerShell often runs entirely in memory
5. **Check for persistence** — registry run keys, scheduled tasks, new local accounts:
```spl
index=windows EventID IN (1, 13) earliest=-1h
| where host="<affected_host>"
| search TargetObject="*\\Run\\*" OR CommandLine="*schtasks*" OR EventID=4720
| table _time, EventID, user, TargetObject, CommandLine
```
6. **Escalate to Tier 2** if persistence, lateral movement, or data exfiltration is confirmed

---

## Step 6 — Document and Close

| Field | Required Content |
|-------|----------------|
| Decoded payload | Full plaintext — document what the script does |
| Parent process | What launched PowerShell |
| Malicious indicators found | IEX, WebClient, persistence, AV disabling, etc. |
| Network connections made | C2 / download URLs from Sysmon Event ID 3 |
| Files dropped | Paths and hashes from Sysmon Event ID 11 |
| Containment actions | Host isolation, process termination, IP/URL blocking |
| Persistence confirmed | Yes / No — registry, scheduled tasks, new accounts |
| Escalated | Yes / No |

---

## MITRE ATT&CK Relevance

| Technique | ID | Step |
|-----------|----|------|
| PowerShell | T1059.001 | Step 1 — encoded command execution |
| Obfuscated Files or Information | T1027 | Step 1 — Base64 encoding hides payload |
| Phishing: Malicious Attachment | T1566.001 | Step 2 — Office parent process indicates document-based delivery |
| Ingress Tool Transfer | T1105 | Step 3 — `WebClient`/`DownloadString` in decoded payload |
| Boot or Logon Autostart: Registry Run Keys | T1547.001 | Step 5 — persistence check |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Step 3 — AV disabling in payload |
