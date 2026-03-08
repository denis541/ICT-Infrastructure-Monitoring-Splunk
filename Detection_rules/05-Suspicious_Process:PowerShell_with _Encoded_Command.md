# Detection Rule: PowerShell Encoded Command Execution

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Sysmon](https://img.shields.io/badge/Data_Source-Sysmon_EventID_1-0078D4?style=flat&logo=windows&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Detection_Engineering-4CAF50?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Tactic:** Execution (TA0002), Defense Evasion (TA0005)  
**Technique:** Command and Scripting Interpreter: PowerShell (T1059.001) + Obfuscated Files or Information (T1027)  
**Data Source:** Sysmon Event ID 1 — Process Creation  
**Query Language:** SPL (Splunk Processing Language)

---

## Objective

Detect PowerShell processes launched with the `-EncodedCommand` (or `-enc`) parameter — a Base64 encoding flag used by attackers and malware to hide script payloads from signature-based detection and casual log inspection.

---

## Detection Query

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| search CommandLine="* -enc*" OR CommandLine="* -EncodedCommand *"
| table _time, host, user, CommandLine
```

---

## Query Logic

| Stage | SPL | Purpose |
|-------|-----|---------|
| Filter | `EventID=1` | Sysmon Process Creation events — captures full command-line arguments at process launch |
| Search | `CommandLine="* -enc*" OR "* -EncodedCommand *"` | Matches both the abbreviated (`-enc`) and full (`-EncodedCommand`) parameter forms — attackers commonly use the short form to reduce log visibility |
| Output | `table _time, host, user, CommandLine` | Returns timestamp, host, executing user, and the full command line for analyst review |

**Why Sysmon over native Windows logs:** Native Windows PowerShell logging (Event ID 4104) captures script block content but can be disabled. Sysmon Event ID 1 captures the process creation at the OS level regardless of PowerShell logging configuration — making it harder to evade by disabling script block logging alone.

---

## Why `-EncodedCommand` Is High Signal

The `-EncodedCommand` flag accepts a Base64-encoded string and executes it directly without writing a script file to disk. This serves two attacker purposes simultaneously:

1. **Obfuscation** — the payload is not human-readable in the process creation log without decoding
2. **Fileless execution** — no `.ps1` script file is written to disk, reducing forensic artifacts

Legitimate administrative use of `-EncodedCommand` exists but is uncommon in most enterprise environments. Scheduled tasks and deployment tools occasionally use it, but these should be attributable to known service accounts and documented processes. Any instance from an interactive user session or an unexpected process parent warrants investigation.

---

## Decoding the Payload

When this alert fires, the encoded payload should be decoded immediately as part of triage:

```powershell
# Decode the Base64 payload from the CommandLine
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("<paste_encoded_string>"))
```

PowerShell encoded commands use **UTF-16LE** encoding (Unicode), not standard Base64 UTF-8 — using a standard Base64 decoder will produce garbage output. The PowerShell one-liner above handles this correctly.

---

## Extended Query — Parent Process Context

The executing user and command line alone are insufficient for full triage. The parent process reveals whether PowerShell was launched legitimately or spawned by a suspicious process:

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| search CommandLine="* -enc*" OR CommandLine="* -EncodedCommand *"
| table _time, host, user, ParentImage, Image, CommandLine
```

| Parent Process | Assessment |
|----------------|------------|
| `explorer.exe` | User-initiated — investigate but lower initial severity |
| `winword.exe`, `excel.exe` | Macro-based execution — high severity, likely malicious document |
| `cmd.exe` spawned by `svchost.exe` | Suspicious process chain — investigate immediately |
| `wscript.exe`, `mshta.exe` | Script-based dropper — high severity |
| Scheduled Task host (`taskeng.exe`) | Verify against known scheduled tasks |

---

## Tuning Recommendations

To reduce false positives from known deployment tooling:

```spl
index=windows sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1
| search CommandLine="* -enc*" OR CommandLine="* -EncodedCommand *"
NOT user IN ("svc-deployment", "svc-sccm")
NOT ParentImage IN ("C:\\Program Files\\known-tool\\tool.exe")
| table _time, host, user, ParentImage, CommandLine
```

---

## MITRE ATT&CK Relevance

| Technique | ID | Detail |
|-----------|----|--------|
| PowerShell | T1059.001 | `-EncodedCommand` is the primary PowerShell execution evasion technique |
| Obfuscated Files or Information | T1027 | Base64 encoding hides payload from signature detection and log inspection |
| Fileless Execution | T1059.001 | No script file written to disk — encoded payload executed entirely in memory |
| Phishing: Malicious Attachment | T1566.001 | Office macro → PowerShell `-enc` is a common initial access → execution chain |
| Defense Evasion: Disable or Modify Tools | T1562 | Encoded commands are used to disable AV/EDR as a follow-on action |
