![Status: Production](https://img.shields.io/badge/Status-Production-green)
![Technique: Create Account](https://img.shields.io/badge/Technique-Create%20Account-orange)
![Data Source: Windows Security Logs](https://img.shields.io/badge/Data%20Source-Windows%20Security%20Logs-lightgrey)
![EventCode: 4720](https://img.shields.io/badge/EventCode-4720-yellow)
![Query Language: SPL](https://img.shields.io/badge/Query%20Language-SPL-yellowgreen)
![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D6)
```bash
index=windows sourcetype="WinEventLog:Security" EventCode=4720 
| table _time, member_id, dest, user
```
New Local User Created
Monitors for the creation of new local user accounts (EventCode 4720), which is a common persistence technique used by attackers.

