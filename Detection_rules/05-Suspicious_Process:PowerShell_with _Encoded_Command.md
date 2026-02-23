![Status: Production](https://img.shields.io/badge/Status-Production-green)
![Tactic: Execution](https://img.shields.io/badge/Tactic-Execution-blue)
![Technique: PowerShell](https://img.shields.io/badge/Technique-PowerShell-orange)
![Query Language: SPL](https://img.shields.io/badge/Query%20Language-SPL-yellowgreen)
![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D6)

```bash
index=windows sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 

| search CommandLine="* -enc*" OR CommandLine="* -EncodedCommand *"
| table _time, host, user, CommandLine
```
# Description:
Detects when PowerShell is launched with the -EncodedCommand (or -e) parameter. This is a common technique used by malware, red‑team tools, and attackers to hide the true intent of a script by Base64‑encoding the payload. Legitimate administrative use is rare, making this a strong indicator of suspicious activity.
