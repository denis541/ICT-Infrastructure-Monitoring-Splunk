# Detection Rule: Windows Brute Force Authentication Monitor (Event ID 4625)

![Splunk](https://img.shields.io/badge/Tool-Splunk-000000?style=flat&logo=splunk&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?style=flat&logo=windows&logoColor=white)
![Domain](https://img.shields.io/badge/Domain-Detection_Engineering-4CAF50?style=flat&logoColor=white)

**Analyst:** Denis O. Onduso  
**Tactic:** Credential Access (TA0006)  
**Technique:** Brute Force (T1110)  
**Data Source:** Windows Security Event Log — Event ID 4625 (An account failed to log on)  
**Query Language:** SPL (Splunk Processing Language)

---

## Objective

Detect brute force attempts against Windows hosts by aggregating Event ID 4625 (failed logon) entries per source IP — surfacing IPs exceeding a failure threshold that indicates automated or manual password-guessing activity.

---

## Detection Query

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625
| stats count as failure_count dc(user) as unique_users by src_ip
| where failure_count > 10
```

---

## Query Logic

| Stage | SPL | Purpose |
|-------|-----|---------|
| Filter | `EventCode=4625` | Isolates failed logon events from the Windows Security log — the authoritative source for authentication failures on Windows hosts |
| Aggregate | `stats count ... dc(user) ... by src_ip` | Groups by source IP; counts total failures and distinct usernames attempted per IP |
| Threshold | `where failure_count > 10` | Filters out low-volume noise — only surfaces IPs with more than 10 failures, indicating sustained or automated activity |

---

## Event ID 4625 — Logon Failure Types

Not all 4625 events are equal. The `LogonType` and `SubStatus` fields in the event provide additional context worth adding to the query for higher-fidelity detections:

| LogonType | Meaning | Relevance |
|-----------|---------|-----------|
| 3 | Network logon | Remote authentication attempt — most relevant for brute force over SMB, RDP |
| 10 | RemoteInteractive | RDP logon failure — high-value target for brute force |
| 2 | Interactive | Local console logon failure |

| SubStatus Code | Meaning |
|----------------|---------|
| `0xC000006A` | Correct username, wrong password — confirms valid account being targeted |
| `0xC0000064` | Username does not exist — attacker is enumerating accounts |
| `0xC000006D` | General logon failure |

Adding `SubStatus=0xC000006A` to the filter surfaces only failures against *valid* accounts — a tighter, higher-confidence signal for credential stuffing or targeted attacks.

---

## Key Metrics

**`failure_count`** — Total failed logon attempts from a single IP. Above 10 within the search window indicates activity beyond normal user error.

**`unique_users`** — Distinct usernames attempted from the same IP. High value suggests **password spraying** across accounts; low value with high `failure_count` suggests a **dictionary attack** against a specific account.

**`src_ip`** — Origin of the authentication attempts. Enrich with GEO-IP and threat intelligence to determine whether the source is a known scanner, Tor exit node, or internal host (which may indicate lateral movement rather than external attack).

---

## Extended Query — Higher Fidelity

```spl
index=windows sourcetype="WinEventLog:Security" EventCode=4625 LogonType IN (3, 10)
| stats count as failure_count dc(user) as unique_users by src_ip
| where failure_count > 10
| eval spray=if(unique_users > 5, "Password Spray", "Targeted Attack")
| sort -failure_count
```

This version filters to network and RDP logon types, adds an `eval` field classifying the attack pattern, and sorts by highest failure count for triage prioritization.

---

## Tuning Recommendations

The `failure_count > 10` threshold should be adjusted based on the environment's baseline. A domain controller will have higher authentication noise than a workstation. A starting point for time-scoped alerting:

- Add `earliest=-15m` to scope to recent activity
- Consider `failure_count > 20` on high-traffic systems to reduce false positives
- Suppress known internal scanning tools or monitoring agents by adding `NOT src_ip IN (<allowlist>)`

---

## MITRE ATT&CK Relevance

| Technique | ID | Detail |
|-----------|----|--------|
| Brute Force: Password Spraying | T1110.003 | High `unique_users` per IP — one password tried across many accounts |
| Brute Force: Credential Stuffing | T1110.004 | High `failure_count` against few usernames — known credential pairs being tested |
| Valid Accounts | T1078 | Monitor for Event ID 4624 (successful logon) from the same `src_ip` post-detection — indicates brute force succeeded |
| Lateral Movement via SMB/RDP | T1021 | LogonType 3 or 10 failures from an internal IP may indicate lateral movement attempts |
