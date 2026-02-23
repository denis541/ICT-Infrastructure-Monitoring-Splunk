![Status: Production](https://img.shields.io/badge/Status-Production-green)
![Tactic: Credential Access](https://img.shields.io/badge/Tactic-Credential%20Access-blue)
![Technique: Brute Force](https://img.shields.io/badge/Technique-Brute%20Force-orange)
![Data Source: Authentication Logs](https://img.shields.io/badge/Data%20Source-Authentication%20Logs-lightgrey)
![Query Language: SPL](https://img.shields.io/badge/Query%20Language-SPL-yellow)
![Platform: Windows](https://img.shields.io/badge/Platform-Windows-0078D6)
# Detection Rule: Linux Brute Force Monitor
This detection rule identifies potential brute force attacks targeting Linux systems by monitoring failed authentication attempts within the secure logs.
```bash
index=realtime sourcetype=linux_secure Failed

| rex field=_raw "from (?<source_ip>\d+\.\d+\.\d+\.\d+)"
| stats count as Failed_Attempts dc(user) as Unique_Users by source_ip
| sort -Failed_Attempts
| head 20
```
## Rule Logic
The query filters for "Failed" login events, extracts the attacker's IP address, and aggregates the data to highlight the most active threats.
## Key Performance Indicators
**Failed_Attempts:** Total number of unsuccessful logins from a single IP.

**Unique_Users:** Number of different usernames the attacker tried to guess.

**Source_IP:** The origin of the malicious traffic.
