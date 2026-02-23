![Status: Production](https://img.shields.io/badge/Status-Production-green)
![Tactic: Privilege Escalation](https://img.shields.io/badge/Tactic-Privilege%20Escalation-blue)
![Technique: Sudo](https://img.shields.io/badge/Technique-Sudo-orange)
![Data Source: Linux Secure Logs](https://img.shields.io/badge/Data%20Source-Linux%20Secure%20Logs-lightgrey)
![Query Language: SPL](https://img.shields.io/badge/Query%20Language-SPL-yellowgreen)
![Platform: Linux](https://img.shields.io/badge/Platform-Linux-000000)
```bash
index=linux sourcetype=linux_secure "session opened for user root by" 

| stats count by user, host 
| sort -count
```
# Description:
Detects whenever a user successfully uses sudo to gain root-level permissions. Excessive or unexpected usage can indicate a compromised account.
