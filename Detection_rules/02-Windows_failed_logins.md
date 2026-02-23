![Brute Force](https://img.shields.io/badge/Detection-Brute%20Force-orange)
![Windows 4625](https://img.shields.io/badge/Windows-4625-blue)
![SPL](https://img.shields.io/badge/SPL-Query-green)
```bash
index=windows sourcetype="WinEventLog:Security" EventCode=4625 

| stats count as failure_count dc(user) as unique_users by src_ip 
| where failure_count > 10
```
# Description
Detects potential brute‑force attempts on Windows systems by identifying an unusual spike in failed login events (EventCode 4625) originating from a single source IP. A high number of failures in a short period may indicate password‑guessing or credential‑stuffing activity
